use crate::state::AppState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;

use super::framing::{encode_chunk, read_frame, FLAG_RAW};
use super::mux::MuxStream;

// ==================== Target stream enum for unified handling ====================

pub enum TargetStream {
    Direct(TcpStream),
    Proxy(TlsStream<TcpStream>),
    Mux(MuxStream),
}

// ==================== Track / forward helpers ====================

/// Track bytes copied with atomic counters (lock-free per-chunk updates)
pub async fn track_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    counter: &AtomicU64,
    conn_counter: &AtomicU64,
) -> Result<(), std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        conn_counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(())
}

/// Bidirectional forwarding with live per-chunk data tracking.
pub async fn forward_bidirectional<R1, W1, R2, W2>(
    mut cr: R1,
    mut cw: W1,
    mut tr: R2,
    mut tw: W2,
    id: u32,
    state: Arc<AppState>,
) where
    R1: tokio::io::AsyncRead + Unpin,
    W1: tokio::io::AsyncWrite + Unpin,
    R2: tokio::io::AsyncRead + Unpin,
    W2: tokio::io::AsyncWrite + Unpin,
{
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let up_conn = Arc::new(AtomicU64::new(0));
    let down_conn = Arc::new(AtomicU64::new(0));

    let up_clone = up.clone();
    let down_clone = down.clone();
    let up_conn_clone = up_conn.clone();
    let down_conn_clone = down_conn.clone();

    let state_clone = Arc::clone(&state);
    let flush_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let u = up_clone.load(Ordering::Relaxed);
            let d = down_clone.load(Ordering::Relaxed);
            let uc = up_conn_clone.load(Ordering::Relaxed);
            let dc = down_conn_clone.load(Ordering::Relaxed);

            let mut conns = state_clone.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.up = uc;
                info.data.down = dc;
            }
            drop(conns);

            let mut total_df = state_clone.total_dataflow.write().await;
            total_df.up = total_df.up.max(u);
            total_df.down = total_df.down.max(d);
            total_df.total = total_df.up + total_df.down;
        }
    });

    tokio::select! {
        r = track_copy(&mut cr, &mut tw, &up, &up_conn) => {
            if let Err(e) = r { log::debug!("c2t pipe closed: {}", e); }
        }
        r = track_copy(&mut tr, &mut cw, &down, &down_conn) => {
            if let Err(e) = r { log::debug!("t2c pipe closed: {}", e); }
        }
    }

    flush_handle.abort();

    let u = up.load(Ordering::Relaxed);
    let d = down.load(Ordering::Relaxed);
    let uc = up_conn.load(Ordering::Relaxed);
    let dc = down_conn.load(Ordering::Relaxed);

    {
        let mut conns = state.connections.write().await;
        if let Some(info) = conns.get_mut(&id) {
            info.data.up = uc;
            info.data.down = dc;
        }
    }
    {
        let mut total_df = state.total_dataflow.write().await;
        total_df.up = total_df.up.max(u);
        total_df.down = total_df.down.max(d);
        total_df.total = total_df.up + total_df.down;
    }
}

/// Forward bidirectional using TargetStream
pub async fn forward_target_stream(
    mut client: TcpStream,
    target: TargetStream,
    id: u32,
    state: Arc<AppState>,
) {
    match target {
        TargetStream::Direct(mut t) => {
            let (cr, cw) = client.split();
            let (tr, tw) = t.split();
            forward_bidirectional(cr, cw, tr, tw, id, state).await;
        }
        TargetStream::Proxy(t) => {
            forward_padded_bidirectional(client, t, id, state).await;
        }
        TargetStream::Mux(s) => {
            forward_mux_bidirectional(client, s, id, state).await;
        }
    }
}

/// 走代理时使用：上行分帧 + padding；下行握手阶段解帧，收到 RAW 标记后裸透传。
///
/// 这样外层 TLS 的 record 长度不再与内层 TLS 一一对应，同时大流量方向几乎零开销。
pub async fn forward_padded_bidirectional(
    mut client: TcpStream,
    target: TlsStream<TcpStream>,
    id: u32,
    state: Arc<AppState>,
) {
    let (mut cr, mut cw) = client.split();
    let (mut tr, mut tw) = tokio::io::split(target);

    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let up_conn = Arc::new(AtomicU64::new(0));
    let down_conn = Arc::new(AtomicU64::new(0));

    let up_clone = up.clone();
    let down_clone = down.clone();
    let up_conn_clone = up_conn.clone();
    let down_conn_clone = down_conn.clone();

    let state_clone = Arc::clone(&state);
    let flush_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let u = up_clone.load(Ordering::Relaxed);
            let d = down_clone.load(Ordering::Relaxed);
            let uc = up_conn_clone.load(Ordering::Relaxed);
            let dc = down_conn_clone.load(Ordering::Relaxed);

            let mut conns = state_clone.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.up = uc;
                info.data.down = dc;
            }
            drop(conns);

            let mut total_df = state_clone.total_dataflow.write().await;
            total_df.up = total_df.up.max(u);
            total_df.down = total_df.down.max(d);
            total_df.total = total_df.up + total_df.down;
        }
    });

    // c -> t：原始字节 -> 分帧 + padding
    let c2t = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut out = Vec::with_capacity(20 * 1024);
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            out.clear();
            encode_chunk(&buf[..n], true, &mut out);
            if tw.write_all(&out).await.is_err() {
                break;
            }
            up.fetch_add(n as u64, Ordering::Relaxed);
            up_conn.fetch_add(n as u64, Ordering::Relaxed);
        }
        let _ = tw.shutdown().await;
    };

    // t -> c：解帧；收到 RAW 标记后剩余字节直接透传
    let t2c = async {
        let mut payload = Vec::with_capacity(8 * 1024);
        loop {
            let flag = match read_frame(&mut tr, &mut payload).await {
                Ok(f) => f,
                Err(e) => {
                    log::debug!("t2c frame read error: {}", e);
                    break;
                }
            };
            if !payload.is_empty() {
                if cw.write_all(&payload).await.is_err() {
                    break;
                }
                down.fetch_add(payload.len() as u64, Ordering::Relaxed);
                down_conn.fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            if flag == FLAG_RAW {
                if let Err(e) = track_copy(&mut tr, &mut cw, &down, &down_conn).await {
                    log::debug!("t2c raw pipe closed: {}", e);
                }
                break;
            }
        }
        let _ = cw.shutdown().await;
    };

    tokio::join!(c2t, t2c);
    flush_handle.abort();

    let u = up.load(Ordering::Relaxed);
    let d = down.load(Ordering::Relaxed);
    let uc = up_conn.load(Ordering::Relaxed);
    let dc = down_conn.load(Ordering::Relaxed);

    {
        let mut conns = state.connections.write().await;
        if let Some(info) = conns.get_mut(&id) {
            info.data.up = uc;
            info.data.down = dc;
        }
    }
    {
        let mut total_df = state.total_dataflow.write().await;
        total_df.up = total_df.up.max(u);
        total_df.down = total_df.down.max(d);
        total_df.total = total_df.up + total_df.down;
    }
}

/// Mux 模式：这条连接与其他流共享同一条已认证的 TLS 隧道。
pub async fn forward_mux_bidirectional(
    mut client: TcpStream,
    stream: MuxStream,
    id: u32,
    state: Arc<AppState>,
) {
    let (mut cr, mut cw) = client.split();
    let (mut reader, writer) = stream.split();

    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let up_conn = Arc::new(AtomicU64::new(0));
    let down_conn = Arc::new(AtomicU64::new(0));

    let up_clone = up.clone();
    let down_clone = down.clone();
    let up_conn_clone = up_conn.clone();
    let down_conn_clone = down_conn.clone();

    let state_clone = Arc::clone(&state);
    let flush_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let u = up_clone.load(Ordering::Relaxed);
            let d = down_clone.load(Ordering::Relaxed);
            let uc = up_conn_clone.load(Ordering::Relaxed);
            let dc = down_conn_clone.load(Ordering::Relaxed);

            let mut conns = state_clone.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.up = uc;
                info.data.down = dc;
            }
            drop(conns);

            let mut total_df = state_clone.total_dataflow.write().await;
            total_df.up = total_df.up.max(u);
            total_df.down = total_df.down.max(d);
            total_df.total = total_df.up + total_df.down;
        }
    });

    // 本地 -> mux 流
    let c2t = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if writer.send(&buf[..n]).await.is_err() {
                break;
            }
            up.fetch_add(n as u64, Ordering::Relaxed);
            up_conn.fetch_add(n as u64, Ordering::Relaxed);
        }
        writer.shutdown().await;
    };

    // mux 流 -> 本地
    let t2c = async {
        loop {
            match reader.recv().await {
                Ok(Some(data)) => {
                    if cw.write_all(&data).await.is_err() {
                        break;
                    }
                    down.fetch_add(data.len() as u64, Ordering::Relaxed);
                    down_conn.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Ok(None) => break,
                Err(e) => {
                    log::debug!("mux stream read error: {}", e);
                    break;
                }
            }
        }
        let _ = cw.shutdown().await;
    };

    tokio::join!(c2t, t2c);
    flush_handle.abort();

    let u = up.load(Ordering::Relaxed);
    let d = down.load(Ordering::Relaxed);
    let uc = up_conn.load(Ordering::Relaxed);
    let dc = down_conn.load(Ordering::Relaxed);

    {
        let mut conns = state.connections.write().await;
        if let Some(info) = conns.get_mut(&id) {
            info.data.up = uc;
            info.data.down = dc;
        }
    }
    {
        let mut total_df = state.total_dataflow.write().await;
        total_df.up = total_df.up.max(u);
        total_df.down = total_df.down.max(d);
        total_df.total = total_df.up + total_df.down;
    }
}
