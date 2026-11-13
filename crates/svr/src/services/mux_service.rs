//! Mux 服务：一条已认证的 TLS 连接上承载多条逻辑流。
//!
//! 与 trojan-go 的做法一致：连接级认证只做一次，之后每个目标连接对应一个
//! `sid`，所有流共享同一条 TLS 隧道，省掉反复的 TCP + TLS 握手。
//!
//! UDP：`FLAG_UDP`（=6）帧承载 UDP 数据报（payload 与非 mux 隧道一致，见
//! `udp_relay_service.rs`），按 payload 中的 `stream_id` 维护 NAT 会话；服务端
//! 未启用 UDP 时收到该帧将安全拒绝（关闭整条连接）。
//!
//! 流控：
//! - 客户端请求且能力协商通过时，每条流有独立的 256KB 窗口（`FLAG_WINDOW`），
//!   避免单个慢流把整条连接堵死；
//! - 未协商窗口（旧客户端）时回退到连接级背压，保持兼容。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::UPSTREAM_CONNECT_TIMEOUT_SECS;
use crate::services::mux::{
    encode_ctl, encode_data, encode_window, parse_open, read_frame, FLAG_DATA, FLAG_FIN, FLAG_OPEN,
    FLAG_PADDING, FLAG_PING, FLAG_PONG, FLAG_RST, FLAG_UDP, FLAG_UDP_CLOSE, FLAG_WINDOW,
    MAX_STREAMS, STREAM_WINDOW,
};
use crate::services::udp_relay_service::{parse_udp_packet, UdpRelay, UdpSettings};
use crate::utils::ssrf;

/// 每流命令缓冲（帧数）
const STREAM_CMD_BUFFER: usize = 64;
/// 出站帧队列容量
const FRAME_QUEUE: usize = 512;
/// 连接空闲超时（客户端每 25s 发 PING，留足余量）
const MUX_IDLE_TIMEOUT_SECS: u64 = 90;

enum StreamCmd {
    Data(Bytes),
    Fin,
}

/// 单条逻辑流的运行时入口
struct StreamHandle {
    /// 上传方向的命令发送端；`None` = 客户端已发 FIN（半关闭，下载方向仍在进行）
    cmd_tx: Option<mpsc::Sender<StreamCmd>>,
    /// 下行（服务端 → 客户端）窗口；窗口未启用时不使用
    window: Arc<Semaphore>,
    /// 流任务句柄：连接结束时必须中止，避免半开上游长期占用
    task: JoinHandle<()>,
}

/// 处理一条 mux 连接，直到对端关闭、空闲超时或出错
///
/// - `udp` 为 `None`（`udp.enabled=false`）时，收到 UDP 流帧将关闭整条连接；
/// - `allow_private` 为 TCP 上游的 SSRF 开关（默认关闭）；
/// - `window_enabled` 由 mux 首包扩展位 + 服务端能力协商决定。
pub async fn serve<S>(
    client: S,
    peer_ip: &str,
    udp: Option<Arc<UdpSettings>>,
    allow_private: bool,
    window_enabled: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(client);
    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(FRAME_QUEUE);

    // 写任务：所有流与控制帧串行写出，避免并发写 TLS
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = frame_rx.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let udp_relay = udp.map(|settings| Arc::new(UdpRelay::new(settings, frame_tx.clone(), true)));

    let mut streams: HashMap<u32, StreamHandle> = HashMap::new();
    // 流任务自然结束事件（避免在连接读循环里持锁等待）
    let (closed_tx, mut closed_rx) = mpsc::channel::<u32>(MAX_STREAMS);
    let mut payload = Vec::with_capacity(8 * 1024);

    loop {
        // 先回收已结束的流；不阻塞，也不取消正在进行的帧读取
        while let Ok(sid) = closed_rx.try_recv() {
            streams.remove(&sid);
        }

        let (flag, sid) = match timeout(
            Duration::from_secs(MUX_IDLE_TIMEOUT_SECS),
            read_frame(&mut reader, &mut payload),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::debug!("[Mux] read frame end: {}", e);
                break;
            }
            Err(_) => {
                tracing::info!("[Mux] idle timeout, close session (peer={})", peer_ip);
                break;
            }
        };

        match flag {
            FLAG_OPEN => {
                let Some((host, port)) = parse_open(&payload) else {
                    let _ = frame_tx.send(encode_ctl(FLAG_RST, sid)).await;
                    continue;
                };
                if streams.len() >= MAX_STREAMS || streams.contains_key(&sid) {
                    tracing::debug!("[Mux] reject stream {} (limit or duplicate)", sid);
                    let _ = frame_tx.send(encode_ctl(FLAG_RST, sid)).await;
                    continue;
                }
                let (cmd_tx, cmd_rx) = mpsc::channel(STREAM_CMD_BUFFER);
                let window = Arc::new(Semaphore::new(STREAM_WINDOW));
                tracing::debug!("[Mux] open stream {} -> {}:{}", sid, host, port);
                let task = spawn_stream(
                    sid,
                    host,
                    port,
                    cmd_rx,
                    frame_tx.clone(),
                    allow_private,
                    window_enabled,
                    window.clone(),
                    closed_tx.clone(),
                );
                streams.insert(
                    sid,
                    StreamHandle {
                        cmd_tx: Some(cmd_tx),
                        window,
                        task,
                    },
                );
            }
            FLAG_DATA => {
                let tx = streams.get(&sid).and_then(|h| h.cmd_tx.clone());
                let mut failed = false;
                if let Some(tx) = tx {
                    failed = tx
                        .send(StreamCmd::Data(Bytes::copy_from_slice(&payload)))
                        .await
                        .is_err();
                }
                if failed {
                    if let Some(handle) = streams.remove(&sid) {
                        handle.task.abort();
                    }
                }
            }
            FLAG_WINDOW => {
                if window_enabled && payload.len() >= 4 {
                    let credit = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    if let Some(handle) = streams.get(&sid) {
                        // 窗口上限 = 初始值，防止对端无限放大
                        let free = STREAM_WINDOW.saturating_sub(handle.window.available_permits());
                        handle
                            .window
                            .add_permits((credit as usize).min(free));
                    }
                }
            }
            FLAG_UDP => {
                let Some(relay) = &udp_relay else {
                    // 安全拒绝：UDP 未启用，关闭整条连接
                    tracing::warn!("[Mux] udp disabled, close mux connection (peer={})", peer_ip);
                    break;
                };
                match parse_udp_packet(&payload) {
                    Some((stream_id, host, port, dgram)) => {
                        if relay.has_session(stream_id) {
                            // 已建会话：同步转发（快路径）
                            relay.relay(stream_id, sid, &host, port, dgram).await;
                        } else {
                            // 首包建会话可能涉及 DNS/绑定：异步执行，避免阻塞
                            // 整条 mux 连接（否则同连接上的 TCP 流会一起卡住）
                            let relay = relay.clone();
                            let dgram = dgram.to_vec();
                            tokio::spawn(async move {
                                relay.relay(stream_id, sid, &host, port, &dgram).await;
                            });
                        }
                    }
                    None => tracing::debug!("[Mux] malformed udp frame (sid={})", sid),
                }
            }
            FLAG_UDP_CLOSE => {
                // 客户端回收 UDP 会话：按帧 sid（= payload stream_id）摘除 NAT 表项；
                // 未启用 UDP 时无会话可回收，忽略即可
                if let Some(relay) = &udp_relay {
                    relay.close_session(sid);
                }
            }
            FLAG_FIN => {
                // 半关闭：只结束上传方向，下载方向继续（等上游 EOF / 连接结束）
                let tx = streams.get_mut(&sid).and_then(|h| h.cmd_tx.take());
                if let Some(tx) = tx {
                    let _ = tx.send(StreamCmd::Fin).await;
                }
            }
            FLAG_RST => {
                if let Some(handle) = streams.remove(&sid) {
                    handle.task.abort();
                }
            }
            FLAG_PING => {
                let _ = frame_tx.send(encode_ctl(FLAG_PONG, sid)).await;
            }
            FLAG_PONG => {}
            FLAG_PADDING => {}
            _ => {
                let _ = frame_tx.send(encode_ctl(FLAG_RST, sid)).await;
            }
        }
    }

    // 连接结束：中止所有流任务（上游 half-open 时不会自行退出），再关闭写任务
    drop(udp_relay);
    for (_, handle) in streams.drain() {
        handle.task.abort();
    }
    drop(closed_tx);
    drop(frame_tx);
    let _ = writer_task.await;

    tracing::info!("[Mux] connection closed (peer={})", peer_ip);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_stream(
    sid: u32,
    host: String,
    port: u16,
    cmd_rx: mpsc::Receiver<StreamCmd>,
    frame_tx: mpsc::Sender<Vec<u8>>,
    allow_private: bool,
    window_enabled: bool,
    window: Arc<Semaphore>,
    closed_tx: mpsc::Sender<u32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        stream_loop(
            sid,
            host,
            port,
            cmd_rx,
            frame_tx,
            allow_private,
            window_enabled,
            window,
        )
        .await;
        let _ = closed_tx.send(sid).await;
    })
}

#[allow(clippy::too_many_arguments)]
async fn stream_loop(
    sid: u32,
    host: String,
    port: u16,
    mut cmd_rx: mpsc::Receiver<StreamCmd>,
    frame_tx: mpsc::Sender<Vec<u8>>,
    allow_private: bool,
    window_enabled: bool,
    window: Arc<Semaphore>,
) {
    let upstream = match timeout(
        Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
        async {
            let target = ssrf::resolve_target(&host, port, allow_private).await?;
            Ok::<TcpStream, anyhow::Error>(TcpStream::connect(target).await?)
        },
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(
                "[Mux] stream {} upstream rejected {}:{}: {}",
                sid,
                host,
                port,
                e
            );
            let _ = frame_tx.send(encode_ctl(FLAG_RST, sid)).await;
            return;
        }
        Err(_) => {
            tracing::debug!("[Mux] stream {} upstream connect timeout: {}:{}", sid, host, port);
            let _ = frame_tx.send(encode_ctl(FLAG_RST, sid)).await;
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    let (mut up_r, mut up_w) = upstream.into_split();

    // 客户端 -> 上游：写入成功后返还窗口额度
    let upload = async {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                StreamCmd::Data(b) => {
                    if up_w.write_all(&b).await.is_err() {
                        break;
                    }
                    if window_enabled {
                        let _ = frame_tx.send(encode_window(sid, b.len() as u32)).await;
                    }
                }
                StreamCmd::Fin => {
                    let _ = up_w.shutdown().await;
                }
            }
        }
        let _ = up_w.shutdown().await;
    };

    // 上游 -> 客户端：先申请窗口额度，再入帧队列
    let download = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match up_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if window_enabled {
                match window.clone().acquire_many_owned(n as u32).await {
                    Ok(permit) => permit.forget(),
                    Err(_) => return,
                }
            }
            let frame = encode_data(sid, &buf[..n]);
            if frame_tx.send(frame).await.is_err() {
                return;
            }
        }
        let _ = frame_tx.send(encode_ctl(FLAG_FIN, sid)).await;
    };

    tokio::join!(upload, download);
    tracing::debug!("[Mux] stream {} closed", sid);
}
