//! SOCKS5 UDP ASSOCIATE 本地中继：解析 SOCKS5 UDP 报文头、按目标建/复用
//! UDP 会话，会话按路由决策走 direct（本机 UDP socket）或 proxy（TLS 隧道）。
//!
//! 会话生命周期：
//! - 每个「目标 (host, port)」一个会话，按需创建、空闲超时回收；
//! - direct：会话独享一个本机 UDP socket（connect 到目标）；
//! - proxy 非 mux：会话独享一条上游 TLS 隧道（随会话结束关闭）；
//! - proxy mux：会话对应 mux 连接上的一条 [`MuxUdpStream`];
//! - 隧道断开会话失效，客户端在应用下一次发包时重建会话；
//! - ASSOCIATE 控制连接断开时回收该 ASSOCIATE 的全部 UDP 会话。

use crate::dns;
use crate::state::AppState;
use crate::types::{ConnectionInfo, DataFlow, GeoInfo, UdpMode};
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_native_tls::TlsStream;

use super::connect::{connect_udp_tunnel, match_rules, UdpTunnelError};
use super::framing::{append_udp_frame, parse_udp_packet, read_frame, FLAG_UDP};
use super::mux::{MuxConfig, MuxUdpStream, MUX};

/// UDP 会话空闲超时：超时未收发任何报文则回收会话（与服务端默认回收时间一致）
const SESSION_IDLE: Duration = Duration::from_secs(60);
/// 每会话入站报文缓冲（报文数）；打满时丢弃新报文（UDP 语义）
const SESSION_QUEUE: usize = 128;
/// 单个 UDP 报文（SOCKS5 头 + payload）的接收缓冲上限
const DGRAM_BUF: usize = 65536;
/// 非 mux 模式下每条隧道只承载一个 UDP 会话，stream_id 固定为 1
const NON_MUX_STREAM_ID: u32 = 1;
/// 服务端不支持 UDP 后的熔断时长（秒）：期间直接降级，不再逐包重试握手
const TUNNEL_RETRY_COOLDOWN_SECS: u64 = 60;

/// 非 mux UDP 隧道熔断截止时间（Unix 秒）；0 = 未熔断
static TUNNEL_RETRY_AT: AtomicU64 = AtomicU64::new(0);
/// 会话代号：用于安全地按 key 摘除自己创建的会话条目
static SESSION_GEN: AtomicU64 = AtomicU64::new(1);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 由主机字符串 + 端口构造 `SocketAddr`
///
/// 回包/直连路径上的主机都是 IP 字面量；用 `SocketAddr::new` 而不是字符串
/// 拼接，否则 IPv6 会被拼成非法地址（`2001:db8::1:53` 不是 `SocketAddr`）。
fn parse_peer(host: &str, port: u16) -> Option<SocketAddr> {
    host.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

// ==================== SOCKS5 UDP 请求头解析 ====================

/// SOCKS5 UDP 报文头解析错误
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksUdpParseError {
    /// 报文被截断
    Truncated,
    /// FRAG ≠ 0：不支持分片，静默丢弃
    Frag,
    /// 未知地址类型
    BadAtyp,
}

/// 解析后的 SOCKS5 UDP 请求头
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksUdpRequest {
    pub host: String,
    pub port: u16,
    pub is_domain: bool,
    /// 头部长度（RSV + FRAG + ATYP + ADDR + PORT），payload 从此偏移开始
    pub header_len: usize,
}

/// 解析 SOCKS5 UDP 报文头：`RSV(2B) FRAG(1B) ATYP(1B) DST.ADDR DST.PORT + payload`
pub fn parse_socks_udp_request(buf: &[u8]) -> Result<SocksUdpRequest, SocksUdpParseError> {
    if buf.len() < 4 {
        return Err(SocksUdpParseError::Truncated);
    }
    if buf[2] != 0 {
        return Err(SocksUdpParseError::Frag);
    }
    let atyp = buf[3];
    let (host, is_domain, mut off) = match atyp {
        1 => {
            if buf.len() < 4 + 4 {
                return Err(SocksUdpParseError::Truncated);
            }
            (
                format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]),
                false,
                8,
            )
        }
        3 => {
            if buf.len() < 5 {
                return Err(SocksUdpParseError::Truncated);
            }
            let len = buf[4] as usize;
            if buf.len() < 5 + len {
                return Err(SocksUdpParseError::Truncated);
            }
            (
                String::from_utf8_lossy(&buf[5..5 + len]).to_string(),
                true,
                5 + len,
            )
        }
        4 => {
            if buf.len() < 4 + 16 {
                return Err(SocksUdpParseError::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            (Ipv6Addr::from(octets).to_string(), false, 20)
        }
        _ => return Err(SocksUdpParseError::BadAtyp),
    };
    if buf.len() < off + 2 {
        return Err(SocksUdpParseError::Truncated);
    }
    let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
    off += 2;

    Ok(SocksUdpRequest {
        host,
        port,
        is_domain,
        header_len: off,
    })
}

/// 封装发往应用的 SOCKS5 UDP 回包头：`RSV(0) FRAG(0) ATYP ADDR PORT + payload`
///
/// 仅支持 IP 源地址（服务端/上游回包必然来自具体 IP）。
pub fn wrap_socks5_udp_reply(peer: SocketAddr, dgram: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + 17 + dgram.len());
    out.extend_from_slice(&[0u8, 0, 0]); // RSV(2) + FRAG(0)
    match peer.ip() {
        std::net::IpAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&peer.port().to_be_bytes());
    out.extend_from_slice(dgram);
    Some(out)
}

// ==================== 路由决策 ====================

/// UDP 路由决策结果
pub struct UdpRouteDecision {
    pub is_direct: bool,
    /// 解析出的目标 IP（direct 出口使用；proxy 路径仅用于 GEO 判定）
    pub ip: String,
    pub geo: GeoInfo,
}

/// 纯路由决策：与 TCP 路径（`resolve_and_connect`）的规则链保持一致。
///
/// - 未配置上游代理 → 直连；
/// - `udpMode=direct` → 一律直连（命中代理规则也强制直连）；
/// - HOST/GEO 规则首个命中决定 direct/proxy；
/// - 无规则命中时回退 `directs`/PRIVATE（与 TCP 回退一致）。
pub fn decide_udp_route(
    has_upstream: bool,
    rule_mode: Option<&str>,
    geo_code: &str,
    directs: &[String],
    udp_mode: UdpMode,
) -> bool {
    if !has_upstream {
        return true;
    }
    if udp_mode != UdpMode::Proxy {
        return true;
    }
    if let Some(mode) = rule_mode {
        return mode.eq_ignore_ascii_case("DIRECT");
    }
    geo_code == "PRIVATE" || directs.iter().any(|d| d.eq_ignore_ascii_case(geo_code))
}

/// 为 UDP 目标做完整路由决策：DNS 解析（复用 `dns.rs`）+ GEO + 规则链
async fn resolve_udp_route(
    state: &Arc<AppState>,
    host: &str,
    udp_mode: UdpMode,
) -> Option<UdpRouteDecision> {
    let is_domain = host.parse::<std::net::IpAddr>().is_err();

    let ip = if is_domain {
        match dns::lookup(state, host).await {
            Ok(ip) => ip,
            Err(e) => {
                log::error!("UDP DNS lookup failed for {}: {}", host, e);
                return None;
            }
        }
    } else {
        host.to_string()
    };

    let geo_info = match state.geo_manager.get_country_by_ip(&ip) {
        Some(country) => GeoInfo {
            country: country.country.clone(),
            alpha2_code: country.alpha2_code.clone(),
            alpha3_code: country.alpha3_code.clone(),
            numeric: country.numeric,
        },
        None => GeoInfo {
            country: "Unknown".to_string(),
            alpha2_code: "UNK".to_string(),
            alpha3_code: "UNK".to_string(),
            numeric: 0,
        },
    };

    let (has_upstream, directs) = {
        let config = state.config.read().await;
        (!config.proxy_server.is_empty(), config.directs.clone())
    };
    let rule_mode = {
        let rules = state.rules.read().await;
        match_rules(host, &geo_info.alpha2_code, &rules)
    };

    let is_direct = decide_udp_route(
        has_upstream,
        rule_mode.as_deref(),
        &geo_info.alpha2_code,
        &directs,
        udp_mode,
    );

    Some(UdpRouteDecision {
        is_direct,
        ip,
        geo: geo_info,
    })
}

// ==================== 降级（每进程一次） ====================

/// 服务端不支持 UDP 时降级为 direct 的告警，每进程只记一次避免刷屏
static UDP_DEGRADE_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_udp_degraded_once() {
    if !UDP_DEGRADE_WARNED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "UDP relay: server does not support UDP forwarding (capability negotiation failed); \
             proxy-rule UDP traffic falls back to DIRECT"
        );
    }
}

// ==================== ASSOCIATE 生命周期 ====================

/// 会话入站消息：应用发来的一个数据报
struct UdpIn {
    origin: SocketAddr,
    data: Vec<u8>,
}

/// 会话表条目：`tx` 在会话创建前就已注册，创建期间到达的报文先排队
struct SessionHandle {
    tx: mpsc::Sender<UdpIn>,
    /// 会话代号：创建失败 / 退出时只摘除自己这一条
    generation: u64,
}

type SessionMap = Arc<Mutex<HashMap<(String, u16), SessionHandle>>>;

/// 处理一个 UDP ASSOCIATE：绑定本地 UDP 中继、回复 BND.ADDR/BND.PORT、
/// 维持控制连接直到客户端断开，随后回收全部 UDP 会话。
pub async fn start_associate(mut control: TcpStream, state: Arc<AppState>, udp_mode: UdpMode) {
    // 1. 绑定本地 UDP 中继端口（复用绑定地址配置，缺省 127.0.0.1，端口随机）
    let (bind_ip, bnd_ip) = {
        let config = state.config.read().await;
        let first = config
            .bind_ips
            .first()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        // 0.0.0.0 上绑定的中继对应用不可见，BND.ADDR 回环地址
        let bnd = if first == "0.0.0.0" {
            "127.0.0.1".to_string()
        } else {
            first.clone()
        };
        (first, bnd)
    };

    let relay = match UdpSocket::bind((bind_ip.as_str(), 0)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("Failed to bind UDP relay socket on {}: {}", bind_ip, e);
            return;
        }
    };
    let bnd_port = match relay.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            log::error!("UDP relay local_addr failed: {}", e);
            return;
        }
    };

    // 2. 回复成功 + BND.ADDR/BND.PORT
    let mut reply = vec![5u8, 0x00, 0x00, 0x01];
    match bnd_ip.parse::<std::net::Ipv4Addr>() {
        Ok(v4) => reply.extend_from_slice(&v4.octets()),
        Err(_) => reply.extend_from_slice(&[127, 0, 0, 1]),
    }
    reply.extend_from_slice(&bnd_port.to_be_bytes());
    if control.write_all(&reply).await.is_err() {
        return;
    }

    log::info!(
        "[UDP] ASSOCIATE relay on {}:{} (mode={:?})",
        bind_ip,
        bnd_port,
        udp_mode
    );

    // 3. 主循环：接收应用 UDP 报文 + 监控控制连接
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let mut dgram_buf = vec![0u8; DGRAM_BUF];
    let mut ctrl_buf = [0u8; 512];

    loop {
        tokio::select! {
            read = control.read(&mut ctrl_buf) => match read {
                Ok(0) | Err(_) => break, // 控制连接断开：回收全部会话
                Ok(_) => {}              // 控制连接上的数据：SOCKS5 规范未定义，丢弃
            },
            recv = relay.recv_from(&mut dgram_buf) => match recv {
                Ok((n, origin)) => {
                    handle_datagram(&relay, origin, &dgram_buf[..n], &sessions, &state, udp_mode)
                        .await;
                }
                Err(e) => {
                    log::debug!("UDP relay recv error: {}", e);
                    break;
                }
            },
        }
    }

    // 4. 回收该 ASSOCIATE 的全部 UDP 会话（drop 发送端 → 会话任务自行退出清理）
    sessions.lock().await.clear();
    log::debug!("[UDP] ASSOCIATE closed, sessions reaped");
}

/// 处理一个应用发来的 SOCKS5 UDP 数据报
///
/// 会话未命中时先注册占位（含入站队列）再异步建会话：DNS + TLS 握手不再
/// 阻塞整个 ASSOCIATE 收包循环，创建期间到达的报文先排队，不丢首包。
async fn handle_datagram(
    relay: &Arc<UdpSocket>,
    origin: SocketAddr,
    buf: &[u8],
    sessions: &SessionMap,
    state: &Arc<AppState>,
    udp_mode: UdpMode,
) {
    let req = match parse_socks_udp_request(buf) {
        Ok(r) => r,
        Err(SocksUdpParseError::Frag) => return, // FRAG ≠ 0：静默丢弃
        Err(e) => {
            log::debug!("Drop malformed SOCKS5 UDP datagram from {origin}: {e:?}");
            return;
        }
    };
    let dgram = &buf[req.header_len..];
    let key = (req.host.clone(), req.port);

    // 查/建占位（不持锁跨 await）
    let (tx, creation) = {
        let mut map = sessions.lock().await;
        match map.get(&key) {
            Some(h) if !h.tx.is_closed() => (h.tx.clone(), None),
            _ => {
                map.remove(&key);
                let (tx, rx) = mpsc::channel(SESSION_QUEUE);
                let generation = SESSION_GEN.fetch_add(1, Ordering::Relaxed);
                map.insert(
                    key.clone(),
                    SessionHandle {
                        tx: tx.clone(),
                        generation,
                    },
                );
                (tx, Some((rx, generation)))
            }
        }
    };

    if let Some((rx, generation)) = creation {
        tokio::spawn(create_session(
            state.clone(),
            relay.clone(),
            sessions.clone(),
            udp_mode,
            key,
            generation,
            rx,
        ));
    }

    // 队列打满时丢弃（UDP 语义，不阻塞主循环）
    let _ = tx.try_send(UdpIn {
        origin,
        data: dgram.to_vec(),
    });
}

/// 会话隧道形态
enum Tunnel {
    Direct,
    Tls(TlsStream<TcpStream>),
    Mux(MuxUdpStream),
}

/// 会话创建任务：路由决策 → 建隧道 → 注册连接条目并启动转发任务
async fn create_session(
    state: Arc<AppState>,
    relay: Arc<UdpSocket>,
    sessions: SessionMap,
    udp_mode: UdpMode,
    key: (String, u16),
    generation: u64,
    rx: mpsc::Receiver<UdpIn>,
) {
    let (host, port) = (key.0.clone(), key.1);

    let Some(decision) = resolve_udp_route(&state, &host, udp_mode).await else {
        unregister_session(&sessions, &key, generation).await;
        return;
    };
    let Some(tunnel) = build_tunnel(&state, &decision, &host, port).await else {
        unregister_session(&sessions, &key, generation).await;
        return;
    };

    // 注册连接条目（协议标识 UDP）
    let proxied = !matches!(&tunnel, Tunnel::Direct);
    let id = {
        let mut cid = state.connection_id.write().await;
        *cid += 1;
        *cid
    };
    let conn_info = ConnectionInfo {
        host: host.clone(),
        port,
        id,
        ip: decision.ip.clone(),
        conn_type: if proxied { "UDP-PROXY" } else { "UDP" }.to_string(),
        create_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        geo: decision.geo,
        data: DataFlow::new(),
        latency_ms: 0,
    };
    state.connections.write().await.insert(id, conn_info);

    let stats = SessionStats::default();
    let flush = stats.clone().spawn_flush(state.clone(), id);

    let runner = match tunnel {
        Tunnel::Direct => tokio::spawn(run_direct_session(
            relay.clone(),
            rx,
            stats.clone(),
            decision.ip.clone(),
            port,
        )),
        Tunnel::Tls(tls) => tokio::spawn(run_proxy_tls_session(
            relay.clone(),
            rx,
            stats.clone(),
            tls,
            NON_MUX_STREAM_ID,
            host.clone(),
            port,
        )),
        Tunnel::Mux(stream) => tokio::spawn(run_proxy_mux_session(
            relay.clone(),
            rx,
            stats.clone(),
            stream,
            host.clone(),
            port,
        )),
    };

    // 会话退出后自清理（空闲超时 / 隧道断开）
    let state2 = state.clone();
    let sessions2 = sessions.clone();
    tokio::spawn(async move {
        let _ = runner.await;
        flush.abort();
        finalize_session(&state2, id, &stats, &sessions2, &key, generation).await;
    });
}

/// 按路由决策建立会话隧道
async fn build_tunnel(
    state: &Arc<AppState>,
    decision: &UdpRouteDecision,
    host: &str,
    port: u16,
) -> Option<Tunnel> {
    if decision.is_direct {
        return Some(Tunnel::Direct);
    }

    let (mux_enabled, proxy_server, proxy_port, proxy_password, skip_verify, sni_name) = {
        let config = state.config.read().await;
        let sni = if config.sni_name.is_empty() {
            config
                .proxy_server
                .split(':')
                .next()
                .unwrap_or(&config.proxy_server)
                .to_string()
        } else {
            config.sni_name.clone()
        };
        (
            config.mux_enabled,
            config.proxy_server.clone(),
            config.proxy_port,
            config.proxy_password.clone(),
            config.danger_accept_invalid_certs,
            sni,
        )
    };

    if mux_enabled {
        let mux_cfg = MuxConfig {
            server: proxy_server,
            port: proxy_port,
            password: proxy_password,
            skip_verify,
            sni: sni_name,
        };
        return match MUX.open_udp(&mux_cfg).await {
            Ok(stream) => Some(Tunnel::Mux(stream)),
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                warn_udp_degraded_once();
                Some(Tunnel::Direct)
            }
            Err(e) => {
                log::error!("UDP mux session failed for {}:{}: {}", host, port, e);
                None
            }
        };
    }

    // 非 mux UDP 隧道契约：认证首包 port=0 标记 UDP 隧道（host 填目标、仅参与
    // MAC），每个数据报的真实目标取自 FLAG_UDP 帧 payload；ACK MAC 校验同样按
    // port=0 + 目标 host 计算，两端必须一致。
    let now = unix_now();
    if now < TUNNEL_RETRY_AT.load(Ordering::Relaxed) {
        // 熔断期内：已知服务端不支持 UDP，直接走直连，不再逐包重试握手
        return Some(Tunnel::Direct);
    }
    match connect_udp_tunnel(
        &proxy_server,
        proxy_port,
        host,
        &proxy_password,
        skip_verify,
        &sni_name,
    )
    .await
    {
        Ok(tls) => {
            TUNNEL_RETRY_AT.store(0, Ordering::Relaxed);
            Some(Tunnel::Tls(tls))
        }
        Err(UdpTunnelError::Unsupported(reason)) => {
            TUNNEL_RETRY_AT.store(now + TUNNEL_RETRY_COOLDOWN_SECS, Ordering::Relaxed);
            warn_udp_degraded_once();
            log::warn!(
                "UDP proxy unsupported for {}:{} ({}), falling back to DIRECT",
                host,
                port,
                reason
            );
            Some(Tunnel::Direct)
        }
        Err(UdpTunnelError::Transport(e)) => {
            log::error!("UDP proxy tunnel failed for {}:{}: {}", host, port, e);
            None
        }
    }
}

/// 摘除会话条目（仅当条目仍属于本次创建）
async fn unregister_session(sessions: &SessionMap, key: &(String, u16), generation: u64) {
    let mut map = sessions.lock().await;
    if map.get(key).map(|h| h.generation) == Some(generation) {
        map.remove(key);
    }
}

/// 会话收尾：写入最终流量、移除连接条目、从会话表摘除自己
async fn finalize_session(
    state: &Arc<AppState>,
    id: u32,
    stats: &SessionStats,
    sessions: &SessionMap,
    key: &(String, u16),
    generation: u64,
) {
    stats.flush(state, id).await;
    state.connections.write().await.remove(&id);
    unregister_session(sessions, key, generation).await;
}

// ==================== 流量统计 ====================

/// 单个 UDP 会话的流量计数
///
/// `up`/`down` 是会话累计值（写入连接列表）；`reported_*` 是已并入全局计数
/// 的水位，`flush` 只累加增量，多会话并发时全局 UDP 计数才不会少报。
#[derive(Clone, Default)]
struct SessionStats {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    reported_up: Arc<AtomicU64>,
    reported_down: Arc<AtomicU64>,
}

impl SessionStats {
    fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// 周期性把会话流量刷入连接列表与全局 UDP 计数
    fn spawn_flush(self, state: Arc<AppState>, id: u32) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.flush(&state, id).await;
            }
        })
    }

    async fn flush(&self, state: &Arc<AppState>, id: u32) {
        let u = self.up.load(Ordering::Relaxed);
        let d = self.down.load(Ordering::Relaxed);
        {
            let mut conns = state.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.up = u;
                info.data.down = d;
            }
        }

        let du = u.saturating_sub(self.reported_up.swap(u, Ordering::Relaxed));
        let dd = d.saturating_sub(self.reported_down.swap(d, Ordering::Relaxed));
        if du == 0 && dd == 0 {
            return;
        }

        let mut df = state.udp_dataflow.write().await;
        df.up = df.up.saturating_add(du);
        df.down = df.down.saturating_add(dd);
        df.total = df.up.saturating_add(df.down);
    }
}

// ==================== 会话任务 ====================

/// direct 会话：本机 UDP socket 直发目标，回包按 SOCKS5 UDP 头封装送回应用
async fn run_direct_session(
    relay: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<UdpIn>,
    stats: SessionStats,
    target_ip: String,
    target_port: u16,
) {
    let Some(target) = parse_peer(&target_ip, target_port) else {
        log::error!(
            "UDP direct session has invalid target {}:{}",
            target_ip,
            target_port
        );
        return;
    };

    // 按目标地址族绑定：IPv6 目标不能用 0.0.0.0
    let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("UDP direct session socket bind failed: {}", e);
            return;
        }
    };
    if let Err(e) = sock.connect(target).await {
        log::error!("UDP direct session connect to {} failed: {}", target, e);
        return;
    }

    let mut rbuf = vec![0u8; DGRAM_BUF];
    let mut last_origin: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(m) => {
                    last_origin = Some(m.origin);
                    match sock.send(&m.data).await {
                        Ok(_) => stats.add_up(m.data.len()),
                        Err(e) => {
                            log::debug!("UDP direct send to {} failed: {}", target, e);
                        }
                    }
                }
                None => break, // 控制连接断开 / 会话被替换
            },
            recv = sock.recv_from(&mut rbuf) => match recv {
                Ok((n, peer)) => {
                    if let Some(origin) = last_origin {
                        if let Some(reply) = wrap_socks5_udp_reply(peer, &rbuf[..n]) {
                            if relay.send_to(&reply, origin).await.is_ok() {
                                stats.add_down(n);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::debug!("UDP direct recv from {} failed: {}", target, e);
                    break;
                }
            },
            _ = tokio::time::sleep(SESSION_IDLE) => break, // 空闲回收
        }
    }
}

/// proxy 非_mux 会话：独占一条 TLS 隧道，每个 UDP 数据报一个 FLAG_UDP 帧
async fn run_proxy_tls_session(
    relay: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<UdpIn>,
    stats: SessionStats,
    tls: TlsStream<TcpStream>,
    stream_id: u32,
    host: String,
    port: u16,
) {
    let (mut tr, mut tw) = tokio::io::split(tls);
    let mut payload = Vec::with_capacity(16 * 1024);
    let mut last_origin: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(m) => {
                    last_origin = Some(m.origin);
                    let mut out = Vec::with_capacity(m.data.len() + 300);
                    if append_udp_frame(&mut out, stream_id, &host, port, &m.data) {
                        if tw.write_all(&out).await.is_ok() {
                            stats.add_up(m.data.len());
                        } else {
                            log::debug!("UDP tunnel write failed ({}:{}), session dead", host, port);
                            break; // 隧道断开：会话失效，下次发包重建
                        }
                    } else {
                        log::debug!("UDP datagram to {}:{} exceeds frame limit, dropped", host, port);
                    }
                }
                None => break,
            },
            read = read_frame(&mut tr, &mut payload) => match read {
                Ok(FLAG_UDP) => {
                    if let Some(pkt) = parse_udp_packet(&payload) {
                        if let Some(origin) = last_origin {
                            if let Some(peer) = parse_peer(&pkt.host, pkt.port) {
                                if let Some(reply) = wrap_socks5_udp_reply(peer, pkt.dgram) {
                                    if relay.send_to(&reply, origin).await.is_ok() {
                                        stats.add_down(pkt.dgram.len());
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(_) => {} // 其他帧类型：UDP 隧道不应出现，忽略
                Err(e) => {
                    log::debug!("UDP tunnel closed ({}:{}): {}", host, port, e);
                    break;
                }
            },
            _ = tokio::time::sleep(SESSION_IDLE) => break,
        }
    }
    let _ = tw.shutdown().await;
}

/// proxy mux 会话：mux 连接上的一条 [`MuxUdpStream`]
async fn run_proxy_mux_session(
    relay: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<UdpIn>,
    stats: SessionStats,
    mut stream: MuxUdpStream,
    host: String,
    port: u16,
) {
    let mut last_origin: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(m) => {
                    last_origin = Some(m.origin);
                    match stream.send_dgram(&host, port, &m.data).await {
                        Ok(true) => stats.add_up(m.data.len()),
                        Ok(false) => {
                            log::debug!(
                                "UDP datagram to {}:{} exceeds frame limit, dropped",
                                host,
                                port
                            );
                        }
                        Err(e) => {
                            log::debug!("UDP mux send failed ({}:{}): {}, session dead", host, port, e);
                            break; // 隧道断开：会话失效，下次发包重建
                        }
                    }
                }
                None => break,
            },
            read = stream.recv_dgram() => match read {
                Ok(Some((rhost, rport, dgram))) => {
                    if let Some(origin) = last_origin {
                        if let Some(peer) = parse_peer(&rhost, rport) {
                            if let Some(reply) = wrap_socks5_udp_reply(peer, &dgram) {
                                if relay.send_to(&reply, origin).await.is_ok() {
                                    stats.add_down(dgram.len());
                                }
                            }
                        }
                    }
                }
                Ok(None) => break, // 服务端关闭会话或隧道断开
                Err(e) => {
                    log::debug!("UDP mux stream dead ({}:{}): {}", host, port, e);
                    break;
                }
            },
            _ = tokio::time::sleep(SESSION_IDLE) => break,
        }
    }
    stream.close().await;
}

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn socks_udp_request_parses_ipv4() {
        let mut buf = vec![0u8, 0, 0, 1, 8, 8, 8, 8];
        buf.extend_from_slice(&53u16.to_be_bytes());
        buf.extend_from_slice(b"query");
        let req = parse_socks_udp_request(&buf).unwrap();
        assert_eq!(req.host, "8.8.8.8");
        assert_eq!(req.port, 53);
        assert!(!req.is_domain);
        assert_eq!(req.header_len, 10);
        assert_eq!(&buf[req.header_len..], b"query");
    }

    #[test]
    fn socks_udp_request_keeps_domain() {
        let mut buf = vec![0u8, 0, 0, 3, 11];
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.push(1);
        let req = parse_socks_udp_request(&buf).unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert!(req.is_domain);
        assert_eq!(req.header_len, 18);
    }

    #[test]
    fn socks_udp_request_parses_ipv6() {
        let mut buf = vec![0u8, 0, 0, 4];
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buf.extend_from_slice(&53u16.to_be_bytes());
        let req = parse_socks_udp_request(&buf).unwrap();
        assert_eq!(req.host, "2001:db8::1");
        assert!(!req.is_domain);
        assert_eq!(req.header_len, 22);
    }

    #[test]
    fn socks_udp_fragment_is_rejected() {
        let buf = [0u8, 0, 1, 1, 8, 8, 8, 8, 0, 53];
        assert_eq!(
            parse_socks_udp_request(&buf),
            Err(SocksUdpParseError::Frag)
        );
    }

    #[test]
    fn socks_udp_truncated_and_bad_atyp() {
        assert_eq!(
            parse_socks_udp_request(&[0, 0, 0]),
            Err(SocksUdpParseError::Truncated)
        );
        assert_eq!(
            parse_socks_udp_request(&[0, 0, 0, 1, 8, 8]),
            Err(SocksUdpParseError::Truncated)
        );
        assert_eq!(
            parse_socks_udp_request(&[0, 0, 0, 9, 8, 8, 8, 8, 0, 53]),
            Err(SocksUdpParseError::BadAtyp)
        );
    }

    #[test]
    fn peer_addr_handles_ipv6_and_rejects_domains() {
        assert_eq!(
            parse_peer("8.8.8.8", 53),
            Some("8.8.8.8:53".parse().unwrap())
        );
        // IPv6 必须走 SocketAddr::new，字符串拼接会解析失败
        assert_eq!(
            parse_peer("2001:db8::1", 443),
            Some("[2001:db8::1]:443".parse().unwrap())
        );
        assert!(parse_peer("example.com", 53).is_none());
    }

    #[test]
    fn socks_udp_reply_roundtrip() {
        let peer: SocketAddr = "8.8.4.4:53".parse().unwrap();
        let reply = wrap_socks5_udp_reply(peer, b"answer").unwrap();
        assert_eq!(&reply[..3], &[0, 0, 0]);
        assert_eq!(reply[3], 1);
        assert_eq!(&reply[4..8], &[8, 8, 4, 4]);
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), 53);
        assert_eq!(&reply[10..], b"answer");

        let peer6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let reply6 = wrap_socks5_udp_reply(peer6, b"x").unwrap();
        assert_eq!(reply6[3], 4);
    }

    #[test]
    fn route_off_mode_always_direct() {
        assert!(decide_udp_route(true, Some("PROXY"), "US", &dirs(&[]), UdpMode::Direct));
    }

    #[test]
    fn route_without_upstream_is_direct() {
        assert!(decide_udp_route(false, Some("PROXY"), "US", &dirs(&[]), UdpMode::Proxy));
    }

    #[test]
    fn route_proxy_mode_follows_rules() {
        // 命中代理规则 → 走隧道
        assert!(!decide_udp_route(true, Some("PROXY"), "US", &dirs(&[]), UdpMode::Proxy));
        // 命中直连规则 → 直连
        assert!(decide_udp_route(true, Some("DIRECT"), "US", &dirs(&[]), UdpMode::Proxy));
    }

    #[test]
    fn route_proxy_mode_falls_back_to_directs() {
        assert!(decide_udp_route(true, None, "PRIVATE", &dirs(&[]), UdpMode::Proxy));
        assert!(decide_udp_route(true, None, "cn", &dirs(&["CN"]), UdpMode::Proxy));
        assert!(!decide_udp_route(true, None, "US", &dirs(&["CN"]), UdpMode::Proxy));
    }

    /// 集成测试：udpMode=off 时 cmd=0x03 回复 reply=0x07 且不监听 UDP 中继
    #[tokio::test]
    async fn udp_associate_rejected_when_off() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-udp-assoc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = Arc::new(AppState::new(dir.clone(), dir.clone()));
        assert_eq!(state.config.read().await.udp_mode, UdpMode::Off);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let st = state.clone();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            super::super::socks5::handle_socks5_client(sock, st).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // greeting：版本字节已被协议检测消费，这里直接发 nauth=1 + NO_AUTH
        client.write_all(&[0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);

        // request: cmd=0x03 (UDP ASSOCIATE)
        client
            .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x07, "udpMode=off must reply command not supported");

        // 服务端回复后关闭连接
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "connection must be closed after 0x07 reply");

        // 未监听任何 UDP 中继端口：状态无 UDP 会话
        assert!(state.connections.read().await.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
