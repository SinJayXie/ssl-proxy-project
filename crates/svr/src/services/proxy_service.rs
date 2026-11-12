//! 代理服务：私有协议 v2 认证 + 透明 TCP 隧道 / UDP relay。
//!
//! 1. 用 [`authenticate_protocol_ext`] 校验首包（HMAC-SHA256 + 时间戳）；
//! 2. 认证失败 / 非协议流量 → 回落为伪装 HTTP 响应；
//! 3. 认证成功 → 连接目标 `host:port`，回写 `[0x10, 0xff] || ack_mac`，
//!    然后用 `copy_bidirectional` 做零解析双向管道；
//! 4. UDP：认证首包 `port = 0` 标记 UDP 隧道（host 非空、仅参与 MAC），开启
//!    `udp.enabled` 后进入 UDP relay（详见 [`udp_relay_service`]）。
//!
//! UDP 能力协商：客户端首包 MAC 后携带扩展位时，ACK 末尾追加 1 字节能力位
//! （bit0 = [`CAP_UDP`]，`udp.enabled` 时置位）。

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::UPSTREAM_CONNECT_TIMEOUT_SECS;
use crate::core::service::Service;
use crate::services::forward_service::ForwardService;
use crate::services::framing::{
    append_frame, encode_chunk, read_frame, FLAG_RAW, FRAME_HEADER, PAD_LIMIT_BYTES,
};
use crate::services::initial_stream::InitialThenStream;
use crate::services::mux_service;
use crate::services::udp_relay_service::{self, UdpSettings};
use crate::utils::protocol::{
    ack_mac, authenticate_protocol_ext, AuthInfo, CAP_UDP, HEADER_LEN, MAC_LEN, TUNNEL_ACK,
};

pub struct ProxyService {
    password: String,
    forward: Arc<ForwardService>,
    mux_enabled: bool,
    /// UDP relay 配置；`None` = 未启用（`udp.enabled=false`，默认）
    udp: Option<Arc<UdpSettings>>,
}

impl ProxyService {
    pub fn new(
        password: String,
        forward: Arc<ForwardService>,
        mux_enabled: bool,
        udp: Option<Arc<UdpSettings>>,
    ) -> Self {
        Self {
            password,
            forward,
            mux_enabled,
            udp,
        }
    }

    /// 认证 + 隧道 / mux / 回落
    ///
    /// - `tls_stream`：已 TLS 握手的客户端连接（不含已读首包）；
    /// - `initial`：先前已从 `tls_stream` 读出的首包字节。
    pub async fn authenticate(&self, tls_stream: TlsStream, initial: Bytes, peer_ip: &str) {
        let now = unix_now();
        match authenticate_protocol_ext(&initial, &self.password, now) {
            Some((auth, ext)) => {
                // 首包实际长度：HEADER(14) + hostLen + MAC(32) [+ 扩展位 1]。
                // 客户端可能在收到 ACK 前就管线发送帧数据（UDP 隧道即如此），
                // 这些字节已在首包读取时进入缓冲，必须回注到流首，否则会被吞掉。
                let packet_len =
                    HEADER_LEN + auth.host.len() + MAC_LEN + usize::from(ext.is_some());
                let leftover = initial.slice(packet_len.min(initial.len())..);
                let mut tls_stream = InitialThenStream::new(leftover, tls_stream);

                // hostLen = 0：mux 连接，一条 TLS 承载多条逻辑流
                if auth.host.is_empty() {
                    if !self.mux_enabled {
                        tracing::warn!("[Proxy] mux disabled, reject session from {}", peer_ip);
                        return;
                    }
                    if self.write_ack(&mut tls_stream, &auth, ext).await.is_err() {
                        return;
                    }
                    tracing::info!("[Proxy] mux session up (peer_ip={})", peer_ip);
                    if let Err(e) = mux_service::serve(tls_stream, peer_ip, self.udp.clone()).await {
                        tracing::debug!("[Mux] session end: {}", e);
                    }
                    return;
                }

                match self.open_tunnel(tls_stream, &auth, ext).await {
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        "[Proxy] tunnel open failed -> {}:{} : {}",
                        auth.host,
                        auth.port,
                        e
                    ),
                }
                return;
            }
            None => {
                tracing::debug!(
                    "[Proxy] protocol auth failed from {} (len={}), fallback",
                    peer_ip,
                    initial.len()
                );
            }
        }
        // 回落：把首包与 TLS 流合并后交给 ForwardService
        let wrapped = InitialThenStream::new(initial, tls_stream);
        self.forward.handle(wrapped, Bytes::new(), peer_ip).await;
    }

    /// 回写 `[0x10, 0xff] || ACK MAC [|| 能力位]`（证明服务端持有密码）
    ///
    /// 仅当客户端首包携带扩展位（`ext` 为 `Some`）时，才在 MAC 之后追加 1 字节
    /// 服务端能力位；旧客户端（无扩展位）不得多发，否则能力字节会被其当作
    /// 隧道数据污染数据流。能力位 bit0 = `CAP_UDP`：`udp.enabled` 且客户端
    /// 请求 UDP 能力时置位，否则为 0x00。
    async fn write_ack<S: AsyncWrite + Unpin>(
        &self,
        tls_stream: &mut S,
        auth: &AuthInfo,
        ext: Option<u8>,
    ) -> Result<()> {
        let mut ack = Vec::with_capacity(TUNNEL_ACK.len() + 32 + 1);
        ack.extend_from_slice(&TUNNEL_ACK);
        ack.extend_from_slice(&ack_mac(
            &self.password,
            auth.timestamp,
            auth.port,
            &auth.host,
        ));
        if ext.is_some() {
            let cap = if self.udp.is_some() { CAP_UDP } else { 0x00 };
            ack.push(cap);
        }
        tls_stream.write_all(&ack).await?;
        Ok(())
    }

    async fn open_tunnel(
        &self,
        mut tls_stream: TunnelStream,
        auth: &AuthInfo,
        ext: Option<u8>,
    ) -> Result<()> {
        // port = 0 标记非 mux UDP 隧道：每报文目标取自帧 payload，host 仅参与 MAC
        if auth.port == 0 {
            // 无论 udp 是否启用都要回 ACK：客户端据此读取能力位
            // （udp.enabled=false 时能力位为 0x00，客户端随即降级为直连）
            self.write_ack(&mut tls_stream, auth, ext).await?;
            let Some(settings) = self.udp.clone() else {
                tracing::warn!(
                    "[Proxy] udp disabled, reject udp tunnel after capability ack (host={})",
                    auth.host
                );
                return Ok(());
            };
            tracing::info!("[Proxy] udp tunnel up (host={})", auth.host);
            return udp_relay_service::serve_tunnel(tls_stream, settings).await;
        }

        // 1. 上游连接（带超时）
        let upstream = timeout(
            Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            TcpStream::connect((auth.host.as_str(), auth.port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("upstream connect timeout"))??;

        upstream.set_nodelay(true)?;

        // 2. 应答：[0x10, 0xff] + ACK MAC（证明服务端同样持有密码）
        self.write_ack(&mut tls_stream, auth, ext).await?;

        tracing::info!("[Proxy] tunnel up -> {}:{} (peer_ip={})", auth.host, auth.port, "");

        // 3. 分帧双向转发：上行全程解帧，下行仅前 PAD_LIMIT_BYTES 参与 padding
        let (mut client_r, mut client_w) = tokio::io::split(tls_stream);
        let (mut up_r, mut up_w) = upstream.into_split();

        let c2s = async move {
            let mut payload = Vec::with_capacity(8 * 1024);
            let mut total: u64 = 0;
            loop {
                let flag = read_frame(&mut client_r, &mut payload).await?;
                if !payload.is_empty() {
                    up_w.write_all(&payload).await?;
                    total += payload.len() as u64;
                }
                if flag == FLAG_RAW {
                    total += tokio::io::copy(&mut client_r, &mut up_w).await?;
                    break;
                }
            }
            let _ = up_w.shutdown().await;
            Ok::<u64, std::io::Error>(total)
        };

        let s2c = async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut out = Vec::with_capacity(20 * 1024);
            let mut upstream_bytes: u64 = 0;
            let mut sent: u64 = 0;
            let mut raw_mode = false;

            loop {
                let n = up_r.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                if raw_mode {
                    client_w.write_all(&buf[..n]).await?;
                    sent += n as u64;
                    continue;
                }

                out.clear();
                encode_chunk(&buf[..n], true, &mut out);
                client_w.write_all(&out).await?;
                sent += out.len() as u64;
                upstream_bytes += n as u64;

                // 握手阶段 padding 结束：通知客户端后续为裸流
                if upstream_bytes >= PAD_LIMIT_BYTES {
                    let mut mark = Vec::with_capacity(FRAME_HEADER);
                    append_frame(&mut mark, &[], 0, FLAG_RAW);
                    client_w.write_all(&mark).await?;
                    raw_mode = true;
                }
            }
            let _ = client_w.shutdown().await;
            Ok::<u64, std::io::Error>(sent)
        };

        let (c2s_res, s2c_res) = tokio::join!(c2s, s2c);
        match (c2s_res, s2c_res) {
            (Ok(c2s_bytes), Ok(s2c_bytes)) => {
                tracing::info!(
                    "[Proxy] tunnel closed (c->s={} B, s->c wire={} B)",
                    c2s_bytes,
                    s2c_bytes
                );
            }
            (a, b) => {
                if let Err(e) = &a {
                    tracing::debug!("[Proxy] c->s pipe error: {}", e);
                }
                if let Err(e) = &b {
                    tracing::debug!("[Proxy] s->c pipe error: {}", e);
                }
            }
        }
        Ok(())
    }
}

/// 当前 Unix 时间戳（秒）
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 简化的 TLS 流别名
type TlsStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
/// 认证后移交通道的流类型（首包之后的缓冲字节优先吐出）
type TunnelStream = InitialThenStream<TlsStream>;

#[async_trait]
impl Service for ProxyService {
    fn name(&self) -> &str {
        "ProxyService"
    }
    async fn start(&self) -> Result<()> {
        let masked = mask_password(&self.password);
        tracing::info!(
            "[Proxy] ready (password={}, udp={})",
            masked,
            if self.udp.is_some() { "enabled" } else { "disabled" }
        );
        Ok(())
    }
}

fn mask_password(pwd: &str) -> String {
    if pwd.len() <= 4 {
        return "****".into();
    }
    let head = &pwd[..2];
    let tail = &pwd[pwd.len() - 2..];
    format!("{}{}{}", head, "*".repeat(pwd.len() - 4), tail)
}

// 抑制未使用警告（S 是 trait bound 占位）
#[allow(dead_code)]
fn _assert_async<S: AsyncRead + AsyncWrite + Unpin>() {}
