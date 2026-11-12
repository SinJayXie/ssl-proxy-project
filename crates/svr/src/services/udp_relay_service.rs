//! UDP relay：TLS 隧道内的 UDP 数据报转发。
//!
//! - 按 `stream_id` 维护 NAT 会话表（未命中则绑定临时端口新建，回包按同
//!   `stream_id` 封帧写回隧道写半边）；
//! - 会话空闲超时回收（默认 60s，可配置）；
//! - 防滥用：每会话每秒令牌桶限速（超限丢包）、SSRF 拦截（回环 / 内网 /
//!   链路本地 / 本机地址，域名解析后同样检查）。
//!
//! ## UDP 帧 payload（非 mux / mux、上下行双向一致）
//!
//! ```text
//! +-----------+------+--------+------+-----------+-------+
//! | stream_id | atyp |  addr  | port | dgram_len | dgram |
//! +-----------+------+--------+------+-----------+-------+
//!   u32 BE      1B     变长    2B BE    2B BE      变长
//! ```
//!
//! - `atyp`：1 = IPv4（4B）、3 = 域名（1B len + N）、4 = IPv6（16B）；
//! - `stream_id` 由客户端分配，服务端按其维护 NAT；
//! - 域名由服务端解析（与 TCP 转发一致使用系统解析器），解析后做 SSRF 检查。
//!
//! ## 非 mux UDP 隧道
//!
//! 认证首包 `port = 0` 标记 UDP 隧道（host 非空、仅参与 MAC；每个数据报的
//! 目标取自帧 payload）。一条隧道独占一个 UDP 会话，全程保持分帧模式，每个
//! UDP 数据报一个 [`framing::FLAG_UDP`] 帧。[`mux::FLAG_UDP`]（=6）为 mux 模式
//! 下的 UDP 流类型，payload 与非 mux 完全一致。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::services::framing::{self, append_frame as append_tunnel_frame, read_frame, FLAG_UDP};
use crate::services::mux;

/// UDP 帧地址类型：IPv4
pub const ATYP_IPV4: u8 = 1;
/// UDP 帧地址类型：域名
pub const ATYP_DOMAIN: u8 = 3;
/// UDP 帧地址类型：IPv6
pub const ATYP_IPV6: u8 = 4;

/// 出站帧队列容量（与 mux_service 对齐）
const FRAME_QUEUE: usize = 512;
/// 单条隧道并发 UDP 会话上限
const MAX_SESSIONS: usize = 256;
/// 回包小帧 padding 阈值（与 mux `encode_data` 风格一致）
const SMALL_DGRAM: usize = 1024;
/// 单个数据报最大长度（IPv4 UDP 载荷上限）
const MAX_DGRAM: usize = 65535;

/// UDP relay 运行时配置（来自 `udp` 配置块；`enabled=false` 时不构建）
#[derive(Debug, Clone)]
pub struct UdpSettings {
    /// 会话空闲超时：超时无上下行报文则回收 socket
    pub timeout: Duration,
    /// 每会话每秒报文数上限（令牌桶，容量 = 速率）
    pub rate_limit: u32,
}

// -----------------------------------------------------------------------------
// UDP 帧 payload 编解码
// -----------------------------------------------------------------------------

fn push_udp_packet(
    out: &mut Vec<u8>,
    stream_id: u32,
    atyp: u8,
    addr: &[u8],
    port: u16,
    dgram: &[u8],
) {
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.push(atyp);
    out.extend_from_slice(addr);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&(dgram.len() as u16).to_be_bytes());
    out.extend_from_slice(dgram);
}

/// 编码 UDP 帧 payload（目标可为 IP 或域名；协议参考实现，供客户端 / 集成测试复用）
///
/// 编码结果需能装进单个隧道帧（≤ [`framing::MAX_PAYLOAD`]），超限返回 `None`。
#[allow(dead_code)]
pub fn encode_udp_packet(stream_id: u32, host: &str, port: u16, dgram: &[u8]) -> Option<Vec<u8>> {
    if dgram.len() > MAX_DGRAM {
        return None;
    }
    let (atyp, addr): (u8, Vec<u8>) = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        (ATYP_IPV4, v4.octets().to_vec())
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        (ATYP_IPV6, v6.octets().to_vec())
    } else {
        let bytes = host.as_bytes();
        if bytes.is_empty() || bytes.len() > u8::MAX as usize {
            return None;
        }
        // 域名：1B len + N
        let mut prefixed = Vec::with_capacity(1 + bytes.len());
        prefixed.push(bytes.len() as u8);
        prefixed.extend_from_slice(bytes);
        (ATYP_DOMAIN, prefixed)
    };
    // 帧头外总长：stream_id(4) + atyp(1) + addr + port(2) + dgram_len(2)
    let total = 4 + 1 + addr.len() + 2 + 2 + dgram.len();
    if total > framing::MAX_PAYLOAD {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    push_udp_packet(&mut out, stream_id, atyp, &addr, port, dgram);
    Some(out)
}

/// 编码回包 UDP 帧 payload（目标为已知 `SocketAddr`，永不失败）
fn encode_reply_packet(stream_id: u32, target: SocketAddr, dgram: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 16 + 2 + 2 + dgram.len());
    match target.ip() {
        IpAddr::V4(v4) => push_udp_packet(&mut out, stream_id, ATYP_IPV4, &v4.octets(), target.port(), dgram),
        IpAddr::V6(v6) => push_udp_packet(&mut out, stream_id, ATYP_IPV6, &v6.octets(), target.port(), dgram),
    }
    out
}

/// 解析 UDP 帧 payload → `(stream_id, host, port, dgram)`
///
/// `host` 为 IP 字符串或域名（由调用方决定是否解析）。
pub fn parse_udp_packet(payload: &[u8]) -> Option<(u32, String, u16, &[u8])> {
    let mut p = payload;
    if p.len() < 5 {
        return None;
    }
    let stream_id = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
    let atyp = p[4];
    p = &p[5..];

    let host = match atyp {
        ATYP_IPV4 => {
            if p.len() < 4 {
                return None;
            }
            let host = Ipv4Addr::new(p[0], p[1], p[2], p[3]).to_string();
            p = &p[4..];
            host
        }
        ATYP_DOMAIN => {
            if p.is_empty() {
                return None;
            }
            let n = p[0] as usize;
            if p.len() < 1 + n {
                return None;
            }
            let host = std::str::from_utf8(&p[1..1 + n]).ok()?.to_string();
            p = &p[1 + n..];
            host
        }
        ATYP_IPV6 => {
            if p.len() < 16 {
                return None;
            }
            let mut seg = [0u16; 8];
            for (i, seg_v) in seg.iter_mut().enumerate() {
                *seg_v = u16::from_be_bytes([p[i * 2], p[i * 2 + 1]]);
            }
            let host = Ipv6Addr::from(seg).to_string();
            p = &p[16..];
            host
        }
        _ => return None,
    };

    if p.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([p[0], p[1]]);
    let dgram_len = u16::from_be_bytes([p[2], p[3]]) as usize;
    p = &p[4..];
    if p.len() < dgram_len {
        return None;
    }
    Some((stream_id, host, port, &p[..dgram_len]))
}

// -----------------------------------------------------------------------------
// SSRF 防护
// -----------------------------------------------------------------------------

/// 服务端本机地址集合（进程内惰性缓存一次）
fn local_addresses() -> &'static HashSet<IpAddr> {
    static SET: OnceLock<HashSet<IpAddr>> = OnceLock::new();
    SET.get_or_init(|| {
        let mut set = HashSet::new();
        // localhost 解析（通常为 127.0.0.1 / ::1）
        if let Ok(addrs) = ("localhost", 0u16).to_socket_addrs() {
            for addr in addrs {
                set.insert(addr.ip());
            }
        }
        // 默认路由出口地址（UDP connect 只选路，不实际发包）
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    set.insert(addr.ip());
                }
            }
        }
        set
    })
}

/// 判断目标 IP 是否禁止转发（SSRF 防护）
///
/// 覆盖：127.0.0.0/8、10/8、172.16/12、192.168/16、169.254/16、0.0.0.0/8、
/// ::1、fe80::/10、fc00::/7、IPv4 映射 IPv6（::ffff:x.y.z.w 按内网规则复查）
/// 以及本机地址。
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    let forbidden = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 127                                    // 127.0.0.0/8
                || o[0] == 10                              // 10/8
                || o[0] == 0                               // 0.0.0.0/8
                || (o[0] == 172 && o[1] & 0xf0 == 16)      // 172.16/12
                || (o[0] == 192 && o[1] == 168)            // 192.168/16
                || (o[0] == 169 && o[1] == 254)            // 169.254/16
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()                               // ::1
                || (s[0] & 0xffc0) == 0xfe80               // fe80::/10
                || (s[0] & 0xfe00) == 0xfc00               // fc00::/7
                || (s[0] == 0
                    && s[1] == 0
                    && s[2] == 0
                    && s[3] == 0
                    && s[4] == 0
                    && s[5] == 0xffff
                    && is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(
                        (s[6] >> 8) as u8,
                        s[6] as u8,
                        (s[7] >> 8) as u8,
                        s[7] as u8,
                    ))) ) // ::ffff:x.y.z.w 映射地址按 IPv4 规则复查
        }
    };
    forbidden || local_addresses().contains(&ip)
}

// -----------------------------------------------------------------------------
// 每会话令牌桶限速
// -----------------------------------------------------------------------------

/// 简单令牌桶：容量 = 速率 = `rate` 报文/秒，超限丢包
struct TokenBucket {
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        let rate = rate.max(1) as f64;
        Self {
            tokens: rate,
            rate,
            last: Instant::now(),
        }
    }

    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate)
            .min(self.rate);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// -----------------------------------------------------------------------------
// NAT 会话表
// -----------------------------------------------------------------------------

/// 会话共享状态（连接读循环与回包任务共同持有）
struct SessionInner {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    /// 最近一次上下行活跃时间
    active: Mutex<Instant>,
    bucket: Mutex<TokenBucket>,
}

struct UdpSession {
    inner: Arc<SessionInner>,
    /// 回包任务句柄（隧道关闭时中止）
    task: JoinHandle<()>,
}

/// 每条隧道连接一个 relay 实例；NAT 表随隧道生命周期存亡
pub struct UdpRelay {
    settings: Arc<UdpSettings>,
    sessions: Arc<DashMap<u32, UdpSession>>,
    /// 隧道写半边的出站帧队列（非 mux 为专用写任务，mux 为连接级写任务）
    frame_tx: mpsc::Sender<Vec<u8>>,
    /// true = mux 模式（回包为 `mux::FLAG_UDP` 帧），false = 非 mux 隧道
    mux: bool,
}

impl UdpRelay {
    pub fn new(settings: Arc<UdpSettings>, frame_tx: mpsc::Sender<Vec<u8>>, mux: bool) -> Self {
        Self {
            settings,
            sessions: Arc::new(DashMap::new()),
            frame_tx,
            mux,
        }
    }

    /// 转发一个来自隧道的 UDP 数据报（按需建会话；限速 / SSRF 不通过则丢包）
    pub async fn relay(&self, stream_id: u32, reply_sid: u32, host: &str, port: u16, dgram: &[u8]) {
        let Some(inner) = self.session_for(stream_id, reply_sid, host, port).await else {
            return;
        };

        // 每会话速率限制：超限丢包
        if !inner.bucket.lock().expect("bucket poisoned").try_take() {
            tracing::debug!(
                "[Udp] session {} rate limited, drop {}B -> {}:{}",
                stream_id,
                dgram.len(),
                host,
                port
            );
            return;
        }

        *inner.active.lock().expect("active poisoned") = Instant::now();
        if let Err(e) = inner.socket.send(dgram).await {
            tracing::debug!("[Udp] session {} send failed: {}", stream_id, e);
        }
    }

    /// 查 NAT 表；未命中则解析目标、SSRF 检查、绑定临时端口并 spawn 回包任务
    async fn session_for(
        &self,
        stream_id: u32,
        reply_sid: u32,
        host: &str,
        port: u16,
    ) -> Option<Arc<SessionInner>> {
        if let Some(session) = self.sessions.get(&stream_id) {
            return Some(session.inner.clone());
        }
        if self.sessions.len() >= MAX_SESSIONS {
            tracing::warn!("[Udp] session table full, drop stream {}", stream_id);
            return None;
        }

        // 解析目标（IP 字面量本地完成；域名走系统解析器，与 TCP 转发一致）
        let target = match tokio::net::lookup_host((host, port)).await {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    tracing::debug!("[Udp] resolve {} returned no address", host);
                    return None;
                }
            },
            Err(e) => {
                tracing::debug!("[Udp] resolve {} failed: {}", host, e);
                return None;
            }
        };

        // SSRF：解析后的地址同样检查（含本机地址）
        if is_forbidden_ip(target.ip()) {
            tracing::warn!("[Udp] blocked forbidden target {} (stream {})", target, stream_id);
            return None;
        }

        let bind_addr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::debug!("[Udp] bind {} failed: {}", bind_addr, e);
                return None;
            }
        };
        if socket.connect(target).await.is_err() {
            tracing::debug!("[Udp] connect {} failed", target);
            return None;
        }

        let inner = Arc::new(SessionInner {
            socket,
            target,
            active: Mutex::new(Instant::now()),
            bucket: Mutex::new(TokenBucket::new(self.settings.rate_limit)),
        });
        let task = self.spawn_recv(stream_id, reply_sid, inner.clone());
        self.sessions.insert(
            stream_id,
            UdpSession {
                inner: inner.clone(),
                task,
            },
        );
        tracing::debug!("[Udp] session {} up -> {} (mux={})", stream_id, target, self.mux);
        Some(inner)
    }

    /// 客户端请求回收会话（mux [`crate::services::mux::FLAG_UDP_CLOSE`]）：
    /// 摘除 NAT 表项并中止对应回包任务
    pub fn close_session(&self, stream_id: u32) {
        if let Some((_, session)) = self.sessions.remove(&stream_id) {
            tracing::debug!("[Udp] session {} closed by peer", stream_id);
            session.task.abort();
        }
    }

    /// 回包任务：目标 → 隧道；空闲超时自回收
    fn spawn_recv(&self, stream_id: u32, reply_sid: u32, inner: Arc<SessionInner>) -> JoinHandle<()> {
        let sessions = self.sessions.clone();
        let frame_tx = self.frame_tx.clone();
        let mux_mode = self.mux;
        let idle = self.settings.timeout;

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DGRAM];
            loop {
                match timeout(idle, inner.socket.recv_from(&mut buf)).await {
                    Ok(Ok((n, _from))) => {
                        // socket 已 connect，只会收到目标回包
                        *inner.active.lock().expect("active poisoned") = Instant::now();
                        let payload = encode_reply_packet(stream_id, inner.target, &buf[..n]);
                        let pad_len = if payload.len() <= SMALL_DGRAM {
                            rand::thread_rng().gen_range(0..=96)
                        } else {
                            rand::thread_rng().gen_range(0..=16)
                        };
                        let frame = encode_reply_frame(mux_mode, reply_sid, &payload, pad_len);
                        if frame_tx.send(frame).await.is_err() {
                            break; // 隧道已关闭
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("[Udp] session {} recv error: {}", stream_id, e);
                        break;
                    }
                    Err(_) => {
                        // 超时窗口内有下行活动（relay 更新 active）则续期
                        if inner.active.lock().expect("active poisoned").elapsed() >= idle {
                            tracing::debug!("[Udp] session {} idle, reclaim", stream_id);
                            break;
                        }
                    }
                }
            }
            sessions.remove(&stream_id);
        })
    }
}

/// 封装回包帧：mux 模式为 `mux::FLAG_UDP`（sid 回显），非 mux 为隧道 `FLAG_UDP` 帧
fn encode_reply_frame(mux_mode: bool, reply_sid: u32, payload: &[u8], pad_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(mux::MUX_HEADER + payload.len() + pad_len);
    if mux_mode {
        mux::append_frame(&mut out, mux::FLAG_UDP, reply_sid, payload, pad_len);
    } else {
        append_tunnel_frame(&mut out, payload, pad_len, FLAG_UDP);
    }
    out
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        // 隧道结束：中止所有回包任务并回收 socket
        for entry in self.sessions.iter() {
            entry.value().task.abort();
        }
        self.sessions.clear();
    }
}

// -----------------------------------------------------------------------------
// 非 mux UDP 隧道入口
// -----------------------------------------------------------------------------

/// 处理一条非 mux 的 UDP 隧道（认证首包 `port = 0` 标记）。
///
/// 全程保持分帧模式：每个 UDP 数据报一个 [`FLAG_UDP`] 帧；收到其他帧视为
/// 协议违规并关闭连接。连接关闭时所有会话一并回收。
pub async fn serve_tunnel<S>(client: S, settings: Arc<UdpSettings>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(client);
    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(FRAME_QUEUE);

    // 写任务：回包帧串行写出
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = frame_rx.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let relay = UdpRelay::new(settings, frame_tx.clone(), false);
    let mut payload = Vec::with_capacity(8 * 1024);
    loop {
        let flag = match read_frame(&mut reader, &mut payload).await {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("[Udp] tunnel read end: {}", e);
                break;
            }
        };
        if flag != FLAG_UDP {
            // UDP 隧道只承载 FLAG_UDP 帧（客户端不发 FLAG_RAW）
            tracing::debug!("[Udp] unexpected frame flag {} on udp tunnel, close", flag);
            break;
        }
        match parse_udp_packet(&payload) {
            Some((stream_id, host, port, dgram)) => {
                relay.relay(stream_id, stream_id, &host, port, dgram).await;
            }
            None => tracing::debug!("[Udp] malformed udp frame, drop ({}B)", payload.len()),
        }
    }

    drop(relay);
    drop(frame_tx);
    let _ = writer_task.await;
    tracing::debug!("[Udp] tunnel closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_roundtrip_ipv4() {
        let payload = encode_udp_packet(0x0102_0304, "1.2.3.4", 8080, b"abc").unwrap();
        let (sid, host, port, dgram) = parse_udp_packet(&payload).unwrap();
        assert_eq!(sid, 0x0102_0304);
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 8080);
        assert_eq!(dgram, b"abc");
    }

    #[test]
    fn udp_packet_roundtrip_domain_and_ipv6() {
        let payload = encode_udp_packet(7, "example.com", 443, b"dns").unwrap();
        let (sid, host, port, dgram) = parse_udp_packet(&payload).unwrap();
        assert_eq!(sid, 7);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(dgram, b"dns");

        let payload = encode_udp_packet(1, "2001:db8::1", 53, &[]).unwrap();
        let (sid, host, port, dgram) = parse_udp_packet(&payload).unwrap();
        assert_eq!(sid, 1);
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 53);
        assert!(dgram.is_empty());
    }

    #[test]
    fn parse_rejects_malformed_payload() {
        assert!(parse_udp_packet(&[]).is_none());
        assert!(parse_udp_packet(&[0, 0, 0, 1, 9]).is_none()); // 未知 atyp
        // atyp=v4 但地址不足
        assert!(parse_udp_packet(&[0, 0, 0, 1, 1, 1, 2, 3, 0, 80, 0, 3]).is_none());
        // dgram_len 超出剩余长度
        let mut p = Vec::new();
        p.extend_from_slice(&1u32.to_be_bytes());
        p.push(ATYP_IPV4);
        p.extend_from_slice(&[1, 2, 3, 4]);
        p.extend_from_slice(&80u16.to_be_bytes());
        p.extend_from_slice(&100u16.to_be_bytes());
        p.extend_from_slice(b"short");
        assert!(parse_udp_packet(&p).is_none());
    }

    #[test]
    fn encode_rejects_oversize_datagram() {
        let big = vec![0u8; MAX_DGRAM + 1];
        assert!(encode_udp_packet(1, "1.2.3.4", 80, &big).is_none());
    }

    #[test]
    fn forbidden_ip_covers_private_ranges() {
        for ip in [
            "127.0.0.1", "127.8.8.8", "10.0.0.1", "10.255.1.1", "172.16.0.1", "172.31.255.255",
            "192.168.1.1", "169.254.10.10", "0.0.0.0", "0.1.2.3", "::1", "fe80::1", "febf::1",
            "fc00::1", "fd12:3455:1234::1", "::ffff:127.0.0.1", "::ffff:10.0.0.2",
        ] {
            assert!(
                is_forbidden_ip(ip.parse().unwrap()),
                "{} 应被判为禁止目标",
                ip
            );
        }
    }

    #[test]
    fn public_ip_is_allowed() {
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "2001:4860:4860::8888"] {
            assert!(
                !is_forbidden_ip(ip.parse().unwrap()),
                "{} 不应被判为禁止目标",
                ip
            );
        }
    }

    #[test]
    fn token_bucket_blocks_when_exhausted() {
        let mut bucket = TokenBucket::new(2);
        assert!(bucket.try_take());
        assert!(bucket.try_take());
        assert!(!bucket.try_take(), "容量 2 应在瞬间打满后拒绝");
    }
}
