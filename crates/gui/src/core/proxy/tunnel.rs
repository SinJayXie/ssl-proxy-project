use crate::state::AppState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;

use super::framing::{encode_chunk, read_frame, FLAG_PADDING, FLAG_RAW};
use super::mux::MuxStream;

// ==================== Target stream enum for unified handling ====================

pub enum TargetStream {
    Direct(TcpStream),
    Proxy(TlsStream<TcpStream>),
    Mux(MuxStream),
}

// ==================== Per-connection stats helpers ====================

/// 每连接四向计数器（上行/下行总量 + 本连接增量）。
struct ConnStats {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    up_conn: Arc<AtomicU64>,
    down_conn: Arc<AtomicU64>,
}

impl ConnStats {
    fn new() -> Self {
        Self {
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            up_conn: Arc::new(AtomicU64::new(0)),
            down_conn: Arc::new(AtomicU64::new(0)),
        }
    }

    fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
            self.up_conn.load(Ordering::Relaxed),
            self.down_conn.load(Ordering::Relaxed),
        )
    }
}

/// 每 500ms 把连接计数刷入 connections / total_dataflow。
///
/// 计数无变化（空闲连接）时跳过写锁，避免大量连接时与 UI 读取互相竞争；
/// 观察到的数据与"每 tick 无条件写"完全一致（总量用 max，连接数据等值覆盖）。
fn spawn_stats_flusher(state: Arc<AppState>, id: u32, s: ConnStats) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last = (0u64, 0u64, 0u64, 0u64);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let cur = s.snapshot();
            if cur == last {
                continue;
            }
            last = cur;

            let mut conns = state.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.up = cur.2;
                info.data.down = cur.3;
            }
            drop(conns);

            let mut total_df = state.total_dataflow.write().await;
            total_df.up = total_df.up.max(cur.0);
            total_df.down = total_df.down.max(cur.1);
            total_df.total = total_df.up + total_df.down;
        }
    })
}

/// 连接结束后做一次权威刷写（与改动前逐条连接的收尾逻辑一致）。
async fn finalize_stats(state: &Arc<AppState>, id: u32, s: &ConnStats) {
    let (u, d, uc, dc) = s.snapshot();
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
    // 64KB：高吞吐下减少 syscall 次数（原 8KB）
    let mut buf = vec![0u8; 64 * 1024];
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
    let stats = ConnStats::new();
    let flush_handle = spawn_stats_flusher(Arc::clone(&state), id, ConnStats {
        up: Arc::clone(&stats.up),
        down: Arc::clone(&stats.down),
        up_conn: Arc::clone(&stats.up_conn),
        down_conn: Arc::clone(&stats.down_conn),
    });

    // half-close：任一方向 EOF 后只关闭"对应写半边"，另一方向继续转发，
    // 直到双方都结束（HTTP/1.1、WebSocket、SSH 等依赖半关闭的协议需要）。
    let c2t = async {
        let r = track_copy(&mut cr, &mut tw, &stats.up, &stats.up_conn).await;
        let _ = tw.shutdown().await;
        r
    };
    let t2c = async {
        let r = track_copy(&mut tr, &mut cw, &stats.down, &stats.down_conn).await;
        let _ = cw.shutdown().await;
        r
    };

    let (c2t_res, t2c_res) = tokio::join!(c2t, t2c);
    if let Err(e) = c2t_res {
        log::debug!("c2t pipe closed: {}", e);
    }
    if let Err(e) = t2c_res {
        log::debug!("t2c pipe closed: {}", e);
    }

    flush_handle.abort();
    finalize_stats(&state, id, &stats).await;
}

/// Forward bidirectional using TargetStream
///
/// client 已泛型化：SOCKS5/HTTP 路径传 `TcpStream`，TUN 数据面传
/// `SmolTcpStream`（协议转发逻辑单一来源，见 TUN 设计方案）。
pub async fn forward_target_stream<C>(
    client: C,
    target: TargetStream,
    id: u32,
    state: Arc<AppState>,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match target {
        TargetStream::Direct(mut t) => {
            let (cr, cw) = tokio::io::split(client);
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
pub async fn forward_padded_bidirectional<C>(
    client: C,
    target: TlsStream<TcpStream>,
    id: u32,
    state: Arc<AppState>,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut tr, mut tw) = tokio::io::split(target);

    let stats = ConnStats::new();
    let flush_handle = spawn_stats_flusher(Arc::clone(&state), id, ConnStats {
        up: Arc::clone(&stats.up),
        down: Arc::clone(&stats.down),
        up_conn: Arc::clone(&stats.up_conn),
        down_conn: Arc::clone(&stats.down_conn),
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
            stats.up.fetch_add(n as u64, Ordering::Relaxed);
            stats.up_conn.fetch_add(n as u64, Ordering::Relaxed);
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
            if flag == FLAG_PADDING {
                continue;
            }
            if !payload.is_empty() {
                if cw.write_all(&payload).await.is_err() {
                    break;
                }
                stats.down.fetch_add(payload.len() as u64, Ordering::Relaxed);
                stats.down_conn.fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            if flag == FLAG_RAW {
                if let Err(e) = track_copy(&mut tr, &mut cw, &stats.down, &stats.down_conn).await {
                    log::debug!("t2c raw pipe closed: {}", e);
                }
                break;
            }
        }
        let _ = cw.shutdown().await;
    };

    tokio::join!(c2t, t2c);
    flush_handle.abort();
    finalize_stats(&state, id, &stats).await;
}

/// Mux 模式：这条连接与其他流共享同一条已认证的 TLS 隧道。
pub async fn forward_mux_bidirectional<C>(
    client: C,
    stream: MuxStream,
    id: u32,
    state: Arc<AppState>,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut reader, writer) = stream.split();

    let stats = ConnStats::new();
    let flush_handle = spawn_stats_flusher(Arc::clone(&state), id, ConnStats {
        up: Arc::clone(&stats.up),
        down: Arc::clone(&stats.down),
        up_conn: Arc::clone(&stats.up_conn),
        down_conn: Arc::clone(&stats.down_conn),
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
            stats.up.fetch_add(n as u64, Ordering::Relaxed);
            stats.up_conn.fetch_add(n as u64, Ordering::Relaxed);
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
                    stats.down.fetch_add(data.len() as u64, Ordering::Relaxed);
                    stats.down_conn.fetch_add(data.len() as u64, Ordering::Relaxed);
                    // 已消费：返还下载方向窗口，避免服务端单流窗口耗尽
                    reader.ack(data.len()).await;
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
    finalize_stats(&state, id, &stats).await;
}
