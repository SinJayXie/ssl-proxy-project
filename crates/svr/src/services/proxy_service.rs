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
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::UPSTREAM_CONNECT_TIMEOUT_SECS;
use crate::core::service::Service;
use crate::libs::replay_guard;
use crate::libs::rate_limit::{RateLimit, RateLimitConfig};
use crate::services::forward_service::ForwardService;
use crate::services::framing::{
    append_frame, append_padding_frame, encode_chunk, read_frame, FLAG_PADDING, FLAG_RAW,
    FRAME_HEADER, PAD_LIMIT_BYTES,
};
use crate::services::initial_stream::InitialThenStream;
use crate::services::mux_service;
use crate::services::udp_relay_service::{self, UdpSettings};
use crate::utils::protocol::{
    ack_mac, ack_mac_v3, authenticate_protocol_ext, AuthInfo, CAP_MUX_WINDOW, CAP_UDP,
    EXT_MUX_WINDOW, EXT_UDP, HEADER_LEN, HEADER_LEN_V3, MAC_LEN, MAGIC, TUNNEL_ACK, VERSION_V3,
};
use crate::utils::ssrf;

pub struct ProxyService {
    password: String,
    forward: Arc<ForwardService>,
    mux_enabled: bool,
    /// UDP relay 配置；`None` = 未启用（`udp.enabled=false`，默认）
    udp: Option<Arc<UdpSettings>>,
    /// 允许连接回环 / 内网目标（TCP SSRF 防护开关，默认关闭）
    allow_private: bool,
    /// 认证失败限流：只统计"看起来是私有协议但校验失败"的连接，防密码爆破
    auth_failures: RateLimit,
}

impl ProxyService {
    pub fn new(
        password: String,
        forward: Arc<ForwardService>,
        mux_enabled: bool,
        udp: Option<Arc<UdpSettings>>,
        allow_private: bool,
        rate_limit: RateLimitConfig,
    ) -> Self {
        Self {
            password,
            forward,
            mux_enabled,
            udp,
            allow_private,
            auth_failures: RateLimit::new(rate_limit),
        }
    }

    /// 认证 + 隧道 / mux / 回落
    ///
    /// - `tls_stream`：已 TLS 握手的客户端连接（不含已读首包）；
    /// - `initial`：先前已从 `tls_stream` 读出的首包字节。
    pub async fn authenticate(&self, tls_stream: TlsStream, initial: Bytes, peer_ip: &str) {
        let now = unix_now();
        // 只对"首字节匹配私有协议魔数"的失败计入认证失败：正常访客的回落流量
        // 不计入，避免把伪装站点的高频访问误判为爆破。黑名单内直接跳过 HMAC 校验，
        // 行为与认证失败一致（仍回落），不破坏伪装表现。
        let looks_like_protocol = initial.len() >= MAGIC.len()
            && initial[0] == MAGIC[0]
            && initial[1] == MAGIC[1];
        let auth = if looks_like_protocol && !self.auth_failures.is_blacklisted(peer_ip) {
            authenticate_protocol_ext(&initial, &self.password, now)
        } else {
            None
        };
        match auth {
            Some((auth, ext)) => {
                // 重放防护：v3 的 nonce 参与签名，同一秒内的合法连接 MAC 也互不相同，
                // 可以安全地按 MAC 去重。v2 旧客户端没有 nonce（同秒同目标 MAC 相同），
                // 只能兼容放行，建议客户端升级到 v3。
                let header_len = if auth.version == VERSION_V3 {
                    HEADER_LEN_V3
                } else {
                    HEADER_LEN
                };
                if auth.version == VERSION_V3 {
                    let mac_start = header_len + auth.host.len();
                    let mac: [u8; MAC_LEN] = match initial
                        .get(mac_start..mac_start + MAC_LEN)
                        .and_then(|s| s.try_into().ok())
                    {
                        Some(m) => m,
                        None => return,
                    };
                    if !replay_guard::accept(mac) {
                        tracing::warn!(
                            "[Proxy] replayed handshake from {} (host={}:{}), fallback",
                            peer_ip,
                            auth.host,
                            auth.port
                        );
                        let forwarded = initial.clone();
                        let wrapped = InitialThenStream::new(initial, tls_stream);
                        self.auth_failures.record(peer_ip);
                        self.forward.handle(wrapped, forwarded, peer_ip).await;
                        return;
                    }
                }

                // 首包实际长度：HEADER(v2 14 / v3 22) + hostLen + MAC(32) [+ 扩展位 1]。
                // 客户端可能在收到 ACK 前就管线发送帧数据（UDP 隧道即如此），
                // 这些字节已在首包读取时进入缓冲，必须回注到流首，否则会被吞掉。
                let packet_len =
                    header_len + auth.host.len() + MAC_LEN + usize::from(ext.is_some());
                let leftover = initial.slice(packet_len.min(initial.len())..);
                let mut tls_stream = InitialThenStream::new(leftover, tls_stream);

                // hostLen = 0：mux 连接，一条 TLS 承载多条逻辑流
                if auth.host.is_empty() {
                    if !self.mux_enabled {
                        tracing::warn!("[Proxy] mux disabled, reject session from {}", peer_ip);
                        return;
                    }
                    if self
                        .write_ack(&mut tls_stream, &auth, ext, true)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    tracing::info!("[Proxy] mux session up (peer_ip={})", peer_ip);
                    let window_enabled = ext
                        .map(|e| e & EXT_MUX_WINDOW != 0)
                        .unwrap_or(false);
                    if let Err(e) = mux_service::serve(
                        tls_stream,
                        peer_ip,
                        self.udp.clone(),
                        self.allow_private,
                        window_enabled,
                    )
                    .await
                    {
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
                if looks_like_protocol {
                    // 协议形状正确但校验失败：计入认证失败限流
                    self.auth_failures.record(peer_ip);
                }
                tracing::debug!(
                    "[Proxy] protocol auth failed from {} (len={}), fallback",
                    peer_ip,
                    initial.len()
                );
            }
        }
        // 回落：把首包与 TLS 流合并后交给 ForwardService
        let forwarded = initial.clone();
        let wrapped = InitialThenStream::new(initial, tls_stream);
        self.forward.handle(wrapped, forwarded, peer_ip).await;
    }

    /// 回写 `[0x10, 0xff] || ACK MAC [|| 能力位]`（证明服务端持有密码）
    ///
    /// 服务端能力位；旧客户端（无扩展位）不得多发，否则能力字节会被其当作
    /// 隧道数据污染数据流。
    ///
    /// - bit0 `CAP_UDP`：客户端请求 UDP 且 `udp.enabled`；
    /// - bit1 `CAP_MUX_WINDOW`：客户端请求 mux 流级窗口（仅 mux 首包会置位）。
    async fn write_ack<S: AsyncWrite + Unpin>(
        &self,
        tls_stream: &mut S,
        auth: &AuthInfo,
        ext: Option<u8>,
        mux_mode: bool,
    ) -> Result<()> {
        let mut ack = Vec::with_capacity(TUNNEL_ACK.len() + 32 + 1 + 1200);
        ack.extend_from_slice(&TUNNEL_ACK);
        let mac = if auth.version == VERSION_V3 {
            ack_mac_v3(
                &self.password,
                auth.timestamp,
                auth.nonce,
                auth.port,
                &auth.host,
            )
        } else {
            ack_mac(&self.password, auth.timestamp, auth.port, &auth.host)
        };
        ack.extend_from_slice(&mac);
        if let Some(ext) = ext {
            let mut cap = 0u8;
            if ext & EXT_UDP != 0 && self.udp.is_some() {
                cap |= CAP_UDP;
            }
            if ext & EXT_MUX_WINDOW != 0 {
                cap |= CAP_MUX_WINDOW;
            }
            ack.push(cap);
        }

        // 首条下行 record 若只有 34~35B，会形成明显的小包指纹。
        // 追加一个纯填充帧，并与 ACK 一次写出，客户端会直接丢弃。
        // v2 旧客户端不认识填充帧；v3 老式客户端（无 ext）也不发/不收填充帧。
        if auth.version == VERSION_V3 && ext.is_some() {
            let pad_len = rand::thread_rng().gen_range(400..=900);
            if mux_mode {
                ack.extend_from_slice(&crate::services::mux::encode_padding_frame(pad_len));
            } else {
                append_padding_frame(&mut ack, pad_len);
            }
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
            self.write_ack(&mut tls_stream, auth, ext, false).await?;
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

        // 1. 上游连接（DNS 解析 + SSRF 校验 + 连接，统一超时）
        let upstream = timeout(
            Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            async {
                let target =
                    ssrf::resolve_target(&auth.host, auth.port, self.allow_private).await?;
                Ok::<TcpStream, anyhow::Error>(TcpStream::connect(target).await?)
            },
        )
        .await
        .map_err(|_| anyhow::anyhow!("upstream connect timeout"))??;

        upstream.set_nodelay(true)?;

        // 2. 应答：[0x10, 0xff] + ACK MAC（证明服务端同样持有密码）
        self.write_ack(&mut tls_stream, auth, ext, false).await?;

        tracing::info!("[Proxy] tunnel up -> {}:{} (peer_ip={})", auth.host, auth.port, "");

        // 3. 分帧双向转发：上行全程解帧，下行仅前 PAD_LIMIT_BYTES 参与 padding
        let (mut client_r, mut client_w) = tokio::io::split(tls_stream);
        let (mut up_r, mut up_w) = upstream.into_split();

        let c2s = async move {
            let mut payload = Vec::with_capacity(8 * 1024);
            let mut total: u64 = 0;
            loop {
                let flag = read_frame(&mut client_r, &mut payload).await?;
                if flag == FLAG_PADDING {
                    // 纯填充帧：只用于撑大首条 record，不转发
                    continue;
                }
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
