use crate::dns;
use crate::state::AppState;
use crate::types::{ConnectionInfo, GeoInfo, RuleConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use native_tls::TlsConnector;
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use tokio_native_tls::TlsStream;

use super::mux::{MuxConfig, MUX};
use super::tunnel::TargetStream;

// ==================== Protocol v2 (matches server utils/protocol.rs) ====================

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 协议魔数
pub(crate) const MAGIC: [u8; 2] = [0x10, 0xff];
/// 协议版本
const VERSION: u8 = 2;
/// HMAC-SHA256 输出长度
pub(crate) const MAC_LEN: usize = 32;

/// 首包签名域前缀
const REQ_PREFIX: &[u8] = b"ssl-proxy-v2";
/// 隧道应答签名域前缀
pub(crate) const ACK_PREFIX: &[u8] = b"ssl-proxy-v2-ack";

/// 客户端首包扩展位（MAC 之后追加 1 字节）：bit0 = 请求 UDP 能力
pub(crate) const EXT_UDP: u8 = 0x01;
/// 服务端 ACK 能力位（ACK MAC 之后追加 1 字节）：bit0 = 支持 UDP 转发
pub(crate) const CAP_UDP: u8 = 0x01;
/// UDP 能力探测超时：ACK MAC 之后等待服务端能力位的最长时间
///
/// 旧版服务端不会发送能力字节，超时即视为不支持。
const CAP_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn compute_mac(password: &str, prefix: &[u8], timestamp: u64, port: u16, host: &str) -> [u8; MAC_LEN] {
    let mut mac =
        HmacSha256::new_from_slice(password.as_bytes()).expect("HMAC 支持任意长度密钥");
    mac.update(prefix);
    mac.update(&timestamp.to_be_bytes());
    mac.update(&port.to_be_bytes());
    mac.update(host.as_bytes());

    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; MAC_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// v2 首包及用于校验服务端 ACK 的时间戳
///
/// `bytes` 末尾固定含 1 字节 UDP 扩展位（请求 UDP 能力，见 [`EXT_UDP`]）。
pub struct ProtocolHeader {
    pub bytes: Vec<u8>,
    pub timestamp: u64,
}

// ==================== Protocol header (v2) ====================

/// 编码 v2 首包
///
/// `request_udp = true` 时在 MAC 之后追加 1 字节 UDP 扩展位（[`EXT_UDP`]），
/// 新版服务端据此在 ACK MAC 之后回 1 字节能力位。
///
/// 普通 TCP 隧道必须传 `false`：旧版服务端不会回能力位，客户端若跟进读取
/// 就会白等探测超时，甚至在"目标先说话"的协议上吞掉第一个真实数据字节。
pub fn create_protocol_header(
    host: &str,
    port: u16,
    password: &str,
    request_udp: bool,
) -> ProtocolHeader {
    let timestamp = unix_now();
    let mac = compute_mac(password, REQ_PREFIX, timestamp, port, host);
    let host_bytes = host.as_bytes();

    let mut bytes = Vec::with_capacity(14 + host_bytes.len() + MAC_LEN + usize::from(request_udp));
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.push(host_bytes.len() as u8);
    bytes.extend_from_slice(host_bytes);
    bytes.extend_from_slice(&mac);
    if request_udp {
        bytes.push(EXT_UDP);
    }

    ProtocolHeader { bytes, timestamp }
}

// ==================== UDP capability probe ====================

/// ACK MAC 校验通过后，带短超时尝试再读 1 字节服务端能力位
///
/// - 新版服务端（客户端首包携带扩展位时）会在 ACK MAC 后追加 1 字节能力位；
/// - 旧版服务端不发任何后续字节：超时 / EOF / 读错一律视为不支持（返回 false）。
pub(crate) async fn probe_udp_capability(stream: &mut TlsStream<TcpStream>) -> bool {
    let mut cap = [0u8; 1];
    match timeout(CAP_PROBE_TIMEOUT, stream.read(&mut cap)).await {
        Ok(Ok(1)) => cap[0] & CAP_UDP != 0,
        _ => false,
    }
}

// ==================== Proxy connection ====================

/// 建立 TCP + TLS 连接；`skip_verify` 为 true 时不校验证书与主机名。
pub(crate) async fn tls_handshake(
    proxy_server: &str,
    proxy_port: u16,
    sni_name: &str,
    skip_verify: bool,
) -> Result<TlsStream<TcpStream>, String> {
    let stream = TcpStream::connect(format!("{}:{}", proxy_server, proxy_port))
        .await
        .map_err(|e| e.to_string())?;
    let _ = stream.set_nodelay(true);

    let connector = TokioTlsConnector::from(
        TlsConnector::builder()
            .danger_accept_invalid_certs(skip_verify)
            .danger_accept_invalid_hostnames(skip_verify)
            .build()
            .map_err(|e| e.to_string())?,
    );

    connector
        .connect(sni_name, stream)
        .await
        .map_err(|e| e.to_string())
}

/// 代理隧道握手结果（非 mux 路径）
pub struct ProxyConnection {
    /// 已通过双向认证的 TLS 隧道
    pub stream: TlsStream<TcpStream>,
}

/// 建立普通（TCP）代理隧道。
///
/// 首包**不携带** UDP 扩展位，因此服务端不会在 ACK 后追加能力位，客户端
/// 也不会做探测读取——避免多一次超时等待或吞掉目标的首个数据字节。
pub async fn connect_proxy(
    proxy_server: &str,
    proxy_port: u16,
    host: &str,
    port: u16,
    password: &str,
    danger_accept_invalid_certs: bool,
    sni_name: &str,
) -> Result<ProxyConnection, String> {
    // Step 1: TLS 握手；开关打开时直接跳过证书/主机名校验（自签证书场景）
    let mut tls_stream = tls_handshake(
        proxy_server,
        proxy_port,
        sni_name,
        danger_accept_invalid_certs,
    )
    .await?;

    // Step 2: 发送 v2 首包（时间戳 + HMAC，密码不参与传输）
    let header = create_protocol_header(host, port, password, false);
    tls_stream
        .write_all(&header.bytes)
        .await
        .map_err(|e| e.to_string())?;

    // Step 3: 读取 [0x10, 0xff] + 32B ACK MAC，并做常量时间比对
    let mut ack = [0u8; 2 + MAC_LEN];
    tls_stream
        .read_exact(&mut ack)
        .await
        .map_err(|e| format!("Failed to read proxy response: {}", e))?;

    if ack[0] != MAGIC[0] || ack[1] != MAGIC[1] {
        return Err(format!(
            "Proxy rejected: [{:#04x}, {:#04x}]",
            ack[0], ack[1]
        ));
    }

    let expected = compute_mac(password, ACK_PREFIX, header.timestamp, port, host);
    if ack[2..] != expected {
        return Err("Proxy server authentication failed (ACK MAC mismatch)".to_string());
    }

    Ok(ProxyConnection {
        stream: tls_stream,
    })
}

/// UDP 隧道建连错误分类
#[derive(Debug)]
pub enum UdpTunnelError {
    /// 服务端不支持 UDP（旧版服务端 / `udp.enabled=false`）：调用方应降级直连
    Unsupported(String),
    /// 传输或认证失败：不应降级，避免把 UDP 流量漏成直连
    Transport(String),
}

/// 建立非 mux UDP 隧道（认证首包 `port = 0`）并完成能力协商。
///
/// 与 TCP 隧道的区别：
/// - 首包携带 UDP 扩展位，服务端据此回能力位；
/// - 读 ACK 失败（服务端在 ACK 前关闭）判定为"不支持 UDP"——旧版服务端会把
///   `port = 0` 当作普通目标连接失败后直接断开；
/// - 能力位未置位同样判定为"不支持 UDP"（新版服务端 `udp.enabled=false`）。
pub async fn connect_udp_tunnel(
    proxy_server: &str,
    proxy_port: u16,
    host: &str,
    password: &str,
    danger_accept_invalid_certs: bool,
    sni_name: &str,
) -> Result<TlsStream<TcpStream>, UdpTunnelError> {
    let mut tls_stream = tls_handshake(
        proxy_server,
        proxy_port,
        sni_name,
        danger_accept_invalid_certs,
    )
    .await
    .map_err(UdpTunnelError::Transport)?;

    let header = create_protocol_header(host, 0, password, true);
    tls_stream
        .write_all(&header.bytes)
        .await
        .map_err(|e| UdpTunnelError::Transport(e.to_string()))?;

    let mut ack = [0u8; 2 + MAC_LEN];
    if let Err(e) = tls_stream.read_exact(&mut ack).await {
        // ACK 之前就断开 = 服务端不认识 port=0 的 UDP 隧道
        return Err(UdpTunnelError::Unsupported(format!(
            "server closed before tunnel ack: {}",
            e
        )));
    }
    if ack[0] != MAGIC[0] || ack[1] != MAGIC[1] {
        return Err(UdpTunnelError::Transport(format!(
            "unexpected tunnel ack: [{:#04x}, {:#04x}]",
            ack[0], ack[1]
        )));
    }
    let expected = compute_mac(password, ACK_PREFIX, header.timestamp, 0, host);
    if ack[2..] != expected {
        return Err(UdpTunnelError::Transport(
            "proxy server authentication failed (ACK MAC mismatch)".to_string(),
        ));
    }

    if probe_udp_capability(&mut tls_stream).await {
        Ok(tls_stream)
    } else {
        Err(UdpTunnelError::Unsupported(
            "server did not advertise UDP support".to_string(),
        ))
    }
}

// ==================== Rule matching ====================

/// Match host against a HOST rule pattern.
/// Supports wildcard: `*.domain.com` matches `domain.com` and `sub.domain.com`.
pub fn match_host(host: &str, pattern: &str) -> bool {
    if let Some(domain) = pattern.strip_prefix("*.") {
        host == domain || host.ends_with(&format!(".{}", domain))
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Find the first matching rule and return its mode ("PROXY" or "DIRECT").
/// HOST rules are prioritized over GEO rules regardless of array order.
/// Returns None if no rule matches.
pub fn match_rules(host: &str, geo_code: &str, rules: &[RuleConfig]) -> Option<String> {
    // Pass 1: check HOST rules first (more specific)
    for rule in rules {
        if rule.rule_type == "HOST" && match_host(host, &rule.match_str) {
            log::debug!(
                "Rule HOST matched: {} → {}, mode={}",
                host, rule.match_str, rule.mode
            );
            return Some(rule.mode.clone());
        }
    }
    // Pass 2: check GEO rules (broader)
    for rule in rules {
        if rule.rule_type == "GEO" && rule.match_str.eq_ignore_ascii_case(geo_code) {
            log::debug!(
                "Rule GEO matched: {} → {}, mode={}",
                host, rule.match_str, rule.mode
            );
            return Some(rule.mode.clone());
        }
    }
    None
}

// ==================== Connection result ====================

pub struct ConnectionResult {
    pub target: TargetStream,
    pub id: u32,
    pub _geo_info: GeoInfo,
    pub _is_direct: bool,
}

// ==================== Resolve + connect to target (shared by SOCKS5 and HTTP handlers) ====================

pub async fn resolve_and_connect(
    host: &str,
    port: u16,
    is_domain: bool,
    state: &Arc<AppState>,
) -> Option<ConnectionResult> {
    let config = state.config.read().await;
    let proxy_server = config.proxy_server.clone();
    let proxy_port = config.proxy_port;
    let proxy_password = config.proxy_password.clone();
    let directs = config.directs.clone();
    let danger_accept_invalid_certs = config.danger_accept_invalid_certs;
    let mux_enabled = config.mux_enabled;
    let sni_name = if config.sni_name.is_empty() {
        // Extract hostname from proxy_server (strip port if present)
        proxy_server.split(':').next().unwrap_or(&proxy_server).to_string()
    } else {
        config.sni_name.clone()
    };
    drop(config);

    // DNS lookup for domain
    let ip = if is_domain {
        match dns::lookup(state, host).await {
            Ok(ip) => ip,
            Err(e) => {
                log::error!("DNS lookup failed for {}: {}", host, e);
                return None;
            }
        }
    } else {
        host.to_string()
    };

    // Geo lookup
    let geo_info = if let Some(country) = state.geo_manager.get_country_by_ip(&ip) {
        GeoInfo {
            country: country.country,
            alpha2_code: country.alpha2_code,
            alpha3_code: country.alpha3_code,
            numeric: country.numeric,
        }
    } else {
        GeoInfo {
            country: "Unknown".to_string(),
            alpha2_code: "UNK".to_string(),
            alpha3_code: "UNK".to_string(),
            numeric: 0,
        }
    };

    // Determine if direct connection.
    // Priority: no proxy → direct; rules.yaml → first match wins; config.directs → fallback.
    let is_direct = if proxy_server.is_empty() {
        // No upstream proxy configured — force direct
        true
    } else {
        let rules = state.rules.read().await;
        if let Some(mode) = match_rules(host, &geo_info.alpha2_code, &rules) {
            drop(rules);
            mode == "DIRECT"
        } else {
            drop(rules);
            // Fall back to legacy config.directs (regions from settings, case-insensitive)
            geo_info.alpha2_code == "PRIVATE" || directs.iter().any(|d| d.eq_ignore_ascii_case(&geo_info.alpha2_code))
        }
    };

    // Generate connection ID
    let id = {
        let mut cid = state.connection_id.write().await;
        *cid += 1;
        *cid
    };

    // Create connection info
    let conn_info = ConnectionInfo {
        host: host.to_string(),
        port,
        id,
        ip: ip.clone(),
        conn_type: if is_direct { "DIRECT".to_string() } else { "PROXY".to_string() },
        create_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        geo: geo_info.clone(),
        data: crate::types::DataFlow::new(),
        latency_ms: 0,
    };

    {
        let mut conns = state.connections.write().await;
        conns.insert(id, conn_info);
    }

    let time = std::time::Instant::now();

    if is_direct {
        let target = match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(t) => t,
            Err(e) => {
                log::error!("Direct connect failed for {}:{}: {}", host, port, e);
                let mut conns = state.connections.write().await;
                conns.remove(&id);
                return None;
            }
        };

        log::info!(
            "[DIRECT] Connected: {}:{}, Time: {}ms, Country: {}",
            host,
            port,
            time.elapsed().as_millis(),
            geo_info.country
        );

        // Store latency
        {
            let mut conns = state.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.latency_ms = time.elapsed().as_millis() as u64;
            }
        }

        Some(ConnectionResult {
            target: TargetStream::Direct(target),
            id,
            _geo_info: geo_info,
            _is_direct: true,
        })
    } else if mux_enabled {
        // 复用模式：共享一条 TLS 隧道，只做一次 TCP + TLS 握手
        let mux_cfg = MuxConfig {
            server: proxy_server.clone(),
            port: proxy_port,
            password: proxy_password.clone(),
            skip_verify: danger_accept_invalid_certs,
            sni: sni_name.clone(),
        };
        match MUX.open(&mux_cfg, host, port).await {
            Ok(stream) => {
                log::info!(
                    "[MUX] Connected: {}:{}, Time: {}ms, Country: {}",
                    host,
                    port,
                    time.elapsed().as_millis(),
                    geo_info.country
                );
                {
                    let mut conns = state.connections.write().await;
                    if let Some(info) = conns.get_mut(&id) {
                        info.latency_ms = time.elapsed().as_millis() as u64;
                    }
                }
                Some(ConnectionResult {
                    target: TargetStream::Mux(stream),
                    id,
                    _geo_info: geo_info,
                    _is_direct: false,
                })
            }
            Err(e) => {
                log::error!("Mux connection failed for {}:{}: {}", host, port, e);
                let mut conns = state.connections.write().await;
                conns.remove(&id);
                None
            }
        }
    } else {
        let conn = match connect_proxy(&proxy_server, proxy_port, host, port, &proxy_password, danger_accept_invalid_certs, &sni_name).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("Proxy connection failed for {}:{}: {}", host, port, e);
                let mut conns = state.connections.write().await;
                conns.remove(&id);
                return None;
            }
        };

        log::info!(
            "[PROXY] Connected: {}:{}, Time: {}ms, Country: {}",
            host,
            port,
            time.elapsed().as_millis(),
            geo_info.country
        );

        // Store latency
        {
            let mut conns = state.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.latency_ms = time.elapsed().as_millis() as u64;
            }
        }

        Some(ConnectionResult {
            target: TargetStream::Proxy(conn.stream),
            id,
            _geo_info: geo_info,
            _is_direct: false,
        })
    }
}
