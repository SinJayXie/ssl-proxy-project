//! Mux 服务：一条已认证的 TLS 连接上承载多条逻辑流。
//!
//! 与 trojan-go 的做法一致：连接级认证只做一次，之后每个目标连接对应一个
//! `sid`，所有流共享同一条 TLS 隧道，省掉反复的 TCP + TLS 握手。
//!
//! UDP：`FLAG_UDP`（=6）帧承载 UDP 数据报（payload 与非 mux 隧道一致，见
//! `udp_relay_service.rs`），按 payload 中的 `stream_id` 维护 NAT 会话；服务端
//! 未启用 UDP 时收到该帧将安全拒绝（关闭整条连接）。
//!
//! 流控采用连接级背压：某个流的命令缓冲区满时暂停整条连接的读取。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::config::UPSTREAM_CONNECT_TIMEOUT_SECS;
use crate::services::mux::{
    encode_ctl, encode_data, parse_open, read_frame, FLAG_DATA, FLAG_FIN, FLAG_OPEN, FLAG_PING,
    FLAG_PONG, FLAG_RST, FLAG_UDP, FLAG_UDP_CLOSE, MAX_STREAMS,
};
use crate::services::udp_relay_service::{parse_udp_packet, UdpRelay, UdpSettings};

/// 每流命令缓冲（帧数）
const STREAM_CMD_BUFFER: usize = 64;
/// 出站帧队列容量
const FRAME_QUEUE: usize = 512;

enum StreamCmd {
    Data(Bytes),
    Fin,
}

/// 处理一条 mux 连接，直到对端关闭或出错
///
/// `udp` 为 `None`（`udp.enabled=false`）时，收到 UDP 流帧将关闭整条连接。
pub async fn serve<S>(
    client: S,
    peer_ip: &str,
    udp: Option<Arc<UdpSettings>>,
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

    let mut streams: HashMap<u32, mpsc::Sender<StreamCmd>> = HashMap::new();
    let mut payload = Vec::with_capacity(8 * 1024);

    loop {
        let (flag, sid) = match read_frame(&mut reader, &mut payload).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("[Mux] read frame end: {}", e);
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
                streams.insert(sid, cmd_tx);
                tracing::debug!("[Mux] open stream {} -> {}:{}", sid, host, port);
                spawn_stream(sid, host, port, cmd_rx, frame_tx.clone());
            }
            FLAG_DATA => {
                if let Some(tx) = streams.get(&sid) {
                    // 连接级背压：缓冲区满时暂停整条连接读取
                    if tx
                        .send(StreamCmd::Data(Bytes::copy_from_slice(&payload)))
                        .await
                        .is_err()
                    {
                        streams.remove(&sid);
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
                if let Some(tx) = streams.remove(&sid) {
                    let _ = tx.send(StreamCmd::Fin).await;
                }
            }
            FLAG_RST => {
                streams.remove(&sid);
            }
            FLAG_PING => {
                let _ = frame_tx.send(encode_ctl(FLAG_PONG, sid)).await;
            }
            FLAG_PONG => {}
            _ => {
                let _ = frame_tx.send(encode_ctl(FLAG_RST, sid)).await;
            }
        }
    }

    // 连接结束：丢弃所有流命令发送端，让流任务自然退出；中止 UDP 会话
    drop(udp_relay);
    streams.clear();
    drop(frame_tx);
    let _ = writer_task.await;

    tracing::info!("[Mux] connection closed (peer={})", peer_ip);
    Ok(())
}

fn spawn_stream(
    sid: u32,
    host: String,
    port: u16,
    mut cmd_rx: mpsc::Receiver<StreamCmd>,
    frame_tx: mpsc::Sender<Vec<u8>>,
) {
    tokio::spawn(async move {
        let upstream = match timeout(
            Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                tracing::debug!("[Mux] stream {} upstream connect failed: {}:{}", sid, host, port);
                let _ = frame_tx.send(encode_ctl(FLAG_RST, sid)).await;
                return;
            }
        };
        let _ = upstream.set_nodelay(true);
        let (mut up_r, mut up_w) = upstream.into_split();

        // 客户端 -> 上游
        let upload = async {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    StreamCmd::Data(b) => {
                        if up_w.write_all(&b).await.is_err() {
                            break;
                        }
                    }
                    StreamCmd::Fin => {
                        let _ = up_w.shutdown().await;
                    }
                }
            }
            let _ = up_w.shutdown().await;
        };

        // 上游 -> 客户端
        let download = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match up_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let frame = encode_data(sid, &buf[..n]);
                if frame_tx.send(frame).await.is_err() {
                    return;
                }
            }
            let _ = frame_tx.send(encode_ctl(FLAG_FIN, sid)).await;
        };

        tokio::join!(upload, download);
        tracing::debug!("[Mux] stream {} closed", sid);
    });
}
