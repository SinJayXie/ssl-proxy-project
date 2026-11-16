//! TUN 流量出站处理：把协议栈事件接到统一决策引擎。
//!
//! - PROXY → `resolve_and_connect` 进入 TLS 隧道，复用 `forward_target_stream`
//!   的全部协议转发逻辑（padding 分帧 / mux）；
//! - DIRECT → `socket2::bind_device_by_index` 绑定物理网卡后直连，
//!   确保出站包不被 TUN 二次捕获（防自环）；
//! - DIRECT 域名解析走**绑定物理网卡的直连 DNS**，绝不经过自身劫持
//!   （否则解析结果永远是 fake-ip，形成解析环路）；
//! - 解析结果落在 fake-ip 池内一律视为"未解析"（fail-closed 后备）；
//! - UDP PROXY 复用已有的 `connect_udp_tunnel` + FLAG_UDP 帧格式进入 TLS 隧道，
//!   与 SOCKS5 UDP ASSOCIATE 共用同一套服务端能力协商与帧协议。
//!
//! UDP 会话按 smoltcp socket handle 复用：首包建立出站（直连 socket / TLS 隧道）
//! 并注册到会话表，后续报文经 channel 交给同一会话，避免每包重建隧道。

use crate::core::proxy::connect::{connect_udp_tunnel, match_rules, resolve_and_connect};
use crate::core::proxy::framing::{append_udp_frame, parse_udp_packet, read_frame, FLAG_UDP};
use crate::core::proxy::route::{
    classify, DecisionReason, Outbound as RouteOutbound, RouteDecision, RouteInput,
};
use crate::core::proxy::tunnel::forward_target_stream;
use crate::core::state::AppState;
use crate::core::tun::dns::is_in_fake_ip_pool;
use crate::core::tun::netstack::{FlowEvent, SmolTcpStream, SmolUdpSocket, StackShared};
use smoltcp::iface::SocketHandle;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// UDP 出站会话：后续应用报文通过 `tx` 交给已建立的会话任务。
type UdpSessionMap = Arc<Mutex<HashMap<SocketHandle, (u64, mpsc::Sender<Vec<u8>>)>>>;
static UDP_SESSION_GEN: AtomicU64 = AtomicU64::new(1);

/// 运行时环境：物理接口索引与直连 DNS 服务器（由 runner 探测后传入）。
#[derive(Clone)]
pub struct OutboundEnv {
    /// 物理网卡 ifIndex（None = 未绑定，仅用于非 Windows/测试）。
    pub physical_if: Option<u32>,
    /// 直连解析用 DNS 服务器（绑定物理网卡查询）。
    pub nameservers: Vec<String>,
    /// 已建立的 UDP 会话（按 socket handle 复用，避免每包重建隧道）。
    udp_sessions: UdpSessionMap,
}

impl OutboundEnv {
    pub fn new(physical_if: Option<u32>, nameservers: Vec<String>) -> Self {
        Self {
            physical_if,
            nameservers,
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// 事件入口：由 runner 的事件循环调用。
pub async fn handle_event(state: Arc<AppState>, shared: StackShared, ev: FlowEvent, env: OutboundEnv) {
    match ev {
        FlowEvent::Tcp { handle, local, remote: _ } => {
            handle_tcp(state, shared, handle, local, env).await
        }
        FlowEvent::Udp { handle, local, remote, payload } => {
            handle_udp(state, shared, handle, local, remote, payload, env).await
        }
    }
}

/// 已警告过“无映射”的 fake-ip（每次会话每 IP 只警告一次，防刷屏）。
fn warned_no_mapping() -> &'static Mutex<std::collections::HashSet<IpAddr>> {
    static S: once_cell::sync::Lazy<Mutex<std::collections::HashSet<IpAddr>>> =
        once_cell::sync::Lazy::new(|| Mutex::new(std::collections::HashSet::new()));
    &S
}

/// fake-ip 反查目标域名（fail-closed）：
/// - 目标在 fake-ip 池内 → 必须查到映射，查不到返回 Err（可能是应用
///   自身缓存了上个会话的 fake-ip；mihomo 同样拒绝，绝不按 IP 直连）；
/// - 池外 → host 就是 IP 本身。
fn host_of(shared: &StackShared, ip: IpAddr, fake_range: &str) -> Result<String, ()> {
    if is_in_fake_ip_pool(&ip, fake_range) {
        let core = shared.lock();
        if let Some(host) = core.fake_map.find_host_by_ip(&ip.to_string()) {
            return Ok(host.to_string());
        }
        drop(core);
        if warned_no_mapping()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ip)
        {
            log::warn!(
                "TUN fake-ip {ip} 无映射（应用缓存了上个会话的 fake-ip），fail-closed 拒绝该流；映射持久化生效后不再出现"
            );
        }
        return Err(());
    }
    Ok(ip.to_string())
}

/// 直连 DNS 查询：socket 绑定物理网卡（IP_UNICAST_IF）后向 `direct-nameservers`
/// 发标准 A 查询。TUN strict-route 会把普通 socket 的 DNS 捕获进自身劫持
/// （结果永远是 fake-ip），因此分流决策的解析必须走物理接口绕开 TUN。
/// 结果复用全局 `dns_cache`，避免每个新流都发查询。
async fn direct_dns_lookup(state: &Arc<AppState>, env: &OutboundEnv, domain: &str) -> Option<String> {
    if let Some(ip) = state.dns_cache.read().await.get(domain) {
        return Some(ip.clone());
    }
    let ns = env.nameservers.first()?.parse::<std::net::Ipv4Addr>().ok()?;
    let if_idx = env.physical_if?;
    let domain = domain.trim_end_matches('.').to_string();
    let domain_for_query = domain.clone();

    let ip = tokio::task::spawn_blocking(move || -> Option<String> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
        bind_unicast_if(&sock, true, if_idx).ok()?;
        sock.bind(&"0.0.0.0:0".parse::<SocketAddr>().ok()?.into()).ok()?;
        sock.connect(&SocketAddr::from((ns, 53)).into()).ok()?;
        sock.set_nonblocking(false).ok()?;

        let mut query = trust_dns_proto::op::Message::new();
        query.set_id(rand::random::<u16>());
        query.set_message_type(trust_dns_proto::op::MessageType::Query);
        query.set_op_code(trust_dns_proto::op::OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(trust_dns_proto::op::Query::query(
            trust_dns_proto::rr::Name::from_ascii(domain_for_query.as_str()).ok()?,
            trust_dns_proto::rr::RecordType::A,
        ));
        sock.send(query.to_vec().ok()?.as_slice()).ok()?;

        let mut buf = vec![std::mem::MaybeUninit::<u8>::uninit(); 4096];
        sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        let n = sock.recv(&mut buf).ok()?;
        let bytes: Vec<u8> = buf[..n]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        let resp = trust_dns_proto::op::Message::from_vec(&bytes).ok()?;
        resp.answers().iter().find_map(|a| {
            a.data().and_then(|d| d.as_a()).map(|v4| v4.0.to_string())
        })
    })
    .await
    .ok()??;

    state
        .dns_cache
        .write()
        .await
        .insert(domain, ip.clone());
    Some(ip)
}

/// 统一决策（语义与 connect.rs 的 SOCKS/HTTP 路径一致）。
/// 返回 Some(ip) 表示可直连；Proxy 无 IP（域名交给服务端解析）。
async fn decide_for_tun(
    state: &Arc<AppState>,
    env: &OutboundEnv,
    host: &str,
    fake_range: &str,
) -> Result<crate::core::proxy::route::RouteDecision, String> {
    let config = state.config.read().await;
    let has_upstream = !config.proxy_server.is_empty();
    let directs = config.directs.clone();
    drop(config);

    let mut resolved = if host.parse::<IpAddr>().is_ok() {
        Some(host.to_string())
    } else {
        direct_dns_lookup(state, env, host).await
    };
    // fail-closed 后备：解析结果落在 fake-ip 池内 = 被自身 DNS 劫持污染，
    // 禁止当作真实 IP 直连（会再次进入 TUN 形成环路）。
    if let Some(ip) = resolved.as_ref().and_then(|s| s.parse::<IpAddr>().ok())
        && is_in_fake_ip_pool(&ip, fake_range)
    {
        log::warn!("TUN DNS 污染防护: {host} 解析到 fake-ip，按未解析处理");
        resolved = None;
    }

    // strict-route 安全不变量：私网/loopback/链路本地/CGNAT 目标必须 DIRECT，
    // 绝不走代理（防代理端 SSRF）。兼容模式下这些目标由路由例外绕过 TUN，
    // 不会走到这里；严格模式下它们进 TUN，必须在这里兜住。
    // 该判定优先于 HOST/GEO 规则——即便规则写 PROXY，私网也不进隧道。
    if let Some(ip) = resolved.as_ref().and_then(|s| s.parse::<IpAddr>().ok())
        && crate::core::tun::route::must_direct_ip(&ip)
    {
        log::debug!("TUN strict-route: 私网/本地目标 {ip} 强制 DIRECT");
        return Ok(RouteDecision {
            outbound: RouteOutbound::Direct,
            reason: DecisionReason::PrivateNetwork,
            resolved_ip: resolved,
        });
    }

    let geo_code = resolved
        .as_ref()
        .and_then(|ip| state.geo_manager.get_country_by_ip(ip))
        .map(|c| c.alpha2_code.clone())
        .unwrap_or_else(|| "UNK".to_string());

    let rules = state.rules.read().await;
    let mode = match_rules(host, &geo_code, &rules);
    drop(rules);

    Ok(classify(&RouteInput {
        has_upstream,
        rule_mode: mode.as_deref(),
        geo_code: &geo_code,
        directs: &directs,
        resolved_ip: resolved.as_deref(),
        force_direct: false,
    }))
}

async fn handle_tcp(
    state: Arc<AppState>,
    shared: StackShared,
    handle: SocketHandle,
    local: SocketAddr,
    env: OutboundEnv,
) {
    let fake_range = shared.lock().cfg.fake_ip_range.clone();
    let host = match host_of(&shared, local.ip(), &fake_range) {
        Ok(h) => h,
        Err(()) => return, // host_of 已去重警告；drop stream → 关闭连接
    };
    let port = local.port();
    let stream = SmolTcpStream::new(&shared, handle);

    // DNS 劫持（TCP:53）：与 UDP 路径成对上线，防止 TCP DNS 泄漏真实查询。
    // TCP DNS 帧 = 2 字节大端长度 + DNS 报文；应答同样加长度前缀。
    // 配置在独立作用域取出，确保 MutexGuard 不跨越 await。
    let (hijack, fake4, fake6) = {
        let core = shared.lock();
        (
            core.cfg.dns_hijack.clone(),
            core.cfg.fake_ip_range.clone(),
            core.cfg.fake_ip_range6.clone(),
        )
    };
    if port == 53 && crate::core::tun::dns::should_hijack_dns(&local.ip(), 53, &hijack) {
        serve_tcp_dns(stream, shared, fake4, fake6, host).await;
        return;
    }

    let decision = match decide_for_tun(&state, &env, &host, &fake_range).await {
        Ok(d) => d,
        Err(e) => {
            log::error!("TUN 决策失败 {host}:{port}: {e}");
            return; // drop stream → 关闭连接
        }
    };
    if decision.outbound == crate::core::proxy::route::Outbound::Reject {
        log::debug!("TUN 拒绝 {host}:{port}（无出口）");
        return;
    }

    if decision.is_direct() {
        let ip = match decision.resolved_ip {
            Some(ip) => ip,
            None => {
                log::warn!("TUN 直连 {host}:{port} 无可用解析结果，放弃（不裸连）");
                return;
            }
        };
        match connect_direct(&ip, port, env.physical_if).await {
            Ok(target) => {
                let mut target = target;
                let mut stream = stream;
                if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut target).await {
                    log::debug!("TUN direct pump {host}:{port} 结束: {e}");
                }
            }
            Err(e) => log::error!("TUN 直连 {ip}:{port} 失败: {e}"),
        }
        return;
    }

    // PROXY：复用完整隧道路径（含 mux / padding / 连接表统计）。
    let is_domain = host.parse::<IpAddr>().is_err();
    match resolve_and_connect(&host, port, is_domain, &state).await {
        Some(result) => {
            forward_target_stream(stream, result.target, result.id, state).await;
        }
        None => log::error!("TUN 代理出站失败 {host}:{port}"),
    }
}

/// TCP:53 DNS 劫持应答：逐条读取「2 字节长度 + DNS 报文」，
/// 用 fake-ip 池应答并登记映射，绝不转发真实 DNS 查询。
async fn serve_tcp_dns(
    mut stream: SmolTcpStream,
    shared: StackShared,
    pool_v4: String,
    pool_v6: String,
    host: String,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut len_buf = [0u8; 2];
    loop {
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            break;
        }
        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).await.is_err() {
            break;
        }

        // 持锁仅做映射登记，不跨 await。
        let answer = {
            let mut core = shared.lock();
            crate::core::tun::dns::answer_query(&payload, &mut core.fake_map, &pool_v4, &pool_v6)
        };
        let Ok(resp) = answer else {
            log::debug!("TUN TCP DNS 查询无法应答（fail-closed）: {host}");
            break;
        };
        if resp.len() > u16::MAX as usize {
            break;
        }
        let mut framed = Vec::with_capacity(resp.len() + 2);
        framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
        framed.extend_from_slice(&resp);
        if stream.write_all(&framed).await.is_err() {
            break;
        }
    }
}

/// 绑定物理网卡的直连 TCP。失败 fail-closed（绝不裸连，防止自环）。
async fn connect_direct(
    ip: &str,
    port: u16,
    if_index: Option<u32>,
) -> std::io::Result<tokio::net::TcpStream> {
    let ip = ip.to_string();
    let std_stream = tokio::task::spawn_blocking(move || {
        let addr: SocketAddr = format!("{ip}:{port}")
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if let Some(idx) = if_index {
            bind_unicast_if(&sock, addr.is_ipv4(), idx)?;
        }
        sock.set_tcp_nodelay(true)?;
        sock.set_nonblocking(false)?;
        sock.connect(&addr.into())?;
        sock.set_nonblocking(true)?;
        Ok::<std::net::TcpStream, std::io::Error>(std::net::TcpStream::from(sock))
    })
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))??;
    tokio::net::TcpStream::from_std(std_stream)
}

/// 通过 `IP_UNICAST_IF`/`IPV6_UNICAST_IF` 把出站 socket 绑定到物理接口
/// （MSDN 要求接口索引为 network byte order）。
/// socket2 在 Windows 上没有该 API，直接调用 ws2_32。
#[cfg(target_os = "windows")]
fn bind_unicast_if(sock: &Socket, ipv4: bool, if_index: u32) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, IPV6_UNICAST_IF, SOCKET,
    };

    let (level, optname) = if ipv4 {
        (IPPROTO_IP.0, IP_UNICAST_IF)
    } else {
        (IPPROTO_IPV6.0, IPV6_UNICAST_IF)
    };
    let idx = if_index.to_be();
    let raw = SOCKET(sock.as_raw_socket() as usize);
    let rc = unsafe { setsockopt(raw, level, optname, Some(idx.to_ne_bytes().as_slice())) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 非 Windows 无 TUN（device::open 直接报错），此分支不可达。
#[cfg(not(target_os = "windows"))]
fn bind_unicast_if(_sock: &Socket, _ipv4: bool, _if_index: u32) -> std::io::Result<()> {
    Ok(())
}

/// 一个 UDP 流的出站形态：直连 socket 或 TLS 隧道（非 mux）。
enum UdpUpstream {
    Direct(tokio::net::UdpSocket),
    Proxy(tokio::io::ReadHalf<tokio_native_tls::TlsStream<tokio::net::TcpStream>>,
          tokio::io::WriteHalf<tokio_native_tls::TlsStream<tokio::net::TcpStream>>),
}

async fn handle_udp(
    state: Arc<AppState>,
    shared: StackShared,
    handle: SocketHandle,
    local: SocketAddr,
    remote: SocketAddr,
    payload: Vec<u8>,
    env: OutboundEnv,
) {
    let port = local.port();
    // DNS：轮询线程已劫持应答；到达这里的 53 包都是未劫持目标，丢弃防泄漏。
    if port == 53 {
        log::debug!("TUN UDP:53 未命中劫持规则，丢弃 {remote}");
        return;
    }

    // 会话复用：命中则把报文交给已有会话，不重建隧道/socket。
    let tx = {
        let sessions = env.udp_sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.get(&handle).map(|(_, tx)| tx.clone())
    };
    if let Some(tx) = tx {
        let _ = tx.try_send(payload);
        return;
    }

    let fake_range = shared.lock().cfg.fake_ip_range.clone();
    let host = match host_of(&shared, local.ip(), &fake_range) {
        Ok(h) => h,
        Err(()) => return, // host_of 已去重警告
    };
    let decision = match decide_for_tun(&state, &env, &host, &fake_range).await {
        Ok(d) => d,
        Err(_) => return,
    };
    if decision.outbound == RouteOutbound::Reject {
        return;
    }

    // 首包：建立出站。先占位注册 channel，避免建隧道期间并发包重建会话。
    let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
    let generation = UDP_SESSION_GEN.fetch_add(1, Ordering::Relaxed);
    {
        let mut sessions = env.udp_sessions.lock().unwrap_or_else(|e| e.into_inner());
        if sessions.contains_key(&handle) {
            return; // 并发首包已被另一任务接管
        }
        sessions.insert(handle, (generation, tx.clone()));
    }

    let (upstream, dst) = match decision.outbound {
        RouteOutbound::Direct => {
            match decision.resolved_ip.as_deref().and_then(|ip| {
                format!("{ip}:{port}").parse::<SocketAddr>().ok()
                    .and_then(|dst| connect_direct_udp(env.physical_if).map(|s| (s, dst)))
            }) {
                Some((s, dst)) => (UdpUpstream::Direct(s), dst),
                None => {
                    unregister_udp_session(&env, handle, generation);
                    return;
                }
            }
        }
        RouteOutbound::Proxy => {
            match build_proxy_udp(&state, &host).await {
                Some(u) => (u, local), // 代理路径真实目标由 FLAG_UDP 帧携带，dst.port() = 目标端口
                None => {
                    unregister_udp_session(&env, handle, generation);
                    return;
                }
            }
        }
        RouteOutbound::Reject => unreachable!(),
    };

    if tx.send(payload).await.is_err() {
        unregister_udp_session(&env, handle, generation);
        return;
    }

    let smol = SmolUdpSocket::new(&shared, handle);
    let env2 = env.clone();
    tokio::spawn(async move {
        pump_udp(smol, remote, dst, upstream, rx, host).await;
        unregister_udp_session(&env2, handle, generation);
    });
}

fn unregister_udp_session(env: &OutboundEnv, handle: SocketHandle, generation: u64) {
    let mut sessions = env.udp_sessions.lock().unwrap_or_else(|e| e.into_inner());
    if sessions.get(&handle).map(|(g, _)| *g) == Some(generation) {
        sessions.remove(&handle);
    }
}

/// 建立 UDP 代理隧道：复用 SOCKS5 UDP 的能力协商（port=0 + UDP 扩展位）。
async fn build_proxy_udp(state: &Arc<AppState>, host: &str) -> Option<UdpUpstream> {
    let config = state.config.read().await;
    let proxy_server = config.proxy_server.clone();
    let proxy_port = config.proxy_port;
    let password = config.proxy_password.clone();
    let skip_verify = config.danger_accept_invalid_certs;
    let sni = config.sni_name.clone();
    drop(config);

    if proxy_server.is_empty() {
        return None;
    }
    // TUN 开启时系统 DNS 被劫持：TCP 目标用预解析 IP，TLS 身份仍按 sni。
    let proxy_connect_addr = state
        .proxy_resolved_ip
        .read()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| proxy_server.clone());
    // 认证 head 以 host 参与 MAC、port=0 标记 UDP 隧道；真实目标在 FLAG_UDP 帧里。
    match connect_udp_tunnel(&proxy_connect_addr, proxy_port, host, &password, skip_verify, &sni).await {
        Ok(tls) => {
            let (r, w) = tokio::io::split(tls);
            Some(UdpUpstream::Proxy(r, w))
        }
        Err(e) => {
            log::error!("TUN UDP 代理隧道失败 {host}: {:?}", e);
            None
        }
    }
}

/// 绑定物理网卡的直连 UDP socket（直连出站专用）。
fn connect_direct_udp(if_index: Option<u32>) -> Option<tokio::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    if let Some(idx) = if_index {
        bind_unicast_if(&sock, true, idx).ok()?;
    }
    sock.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into()).ok()?;
    sock.set_nonblocking(true).ok()?;
    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock)).ok()
}

/// UDP 会话泵：应用报文 → 出站；出站回包 → 伪装成 fake-ip 源发回应用。
async fn pump_udp(
    smol: SmolUdpSocket,
    remote: SocketAddr,
    dst: SocketAddr,
    upstream: UdpUpstream,
    mut rx: mpsc::Receiver<Vec<u8>>,
    host: String,
) {
    let mut buf = vec![0u8; 65535];
    let idle = Duration::from_secs(60);
    match upstream {
        UdpUpstream::Direct(sock) => loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(data) => { if sock.send_to(&data, dst).await.is_err() { break; } }
                    None => break,
                },
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, _)) => { if smol.send_to(&buf[..n], remote).await.is_err() { break; } }
                    Err(_) => break,
                },
                _ = tokio::time::sleep(idle) => break,
            }
        },
        UdpUpstream::Proxy(mut reader, mut writer) => loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(data) => {
                        let mut frame = Vec::with_capacity(data.len() + 300);
                        if append_udp_frame(&mut frame, 1, &host, dst.port(), &data) {
                            if writer.write_all(&frame).await.is_err() { break; }
                        }
                    }
                    None => break,
                },
                frame = read_frame(&mut reader, &mut buf) => match frame {
                    Ok(FLAG_UDP) => {
                        if let Some(pkt) = parse_udp_packet(&buf) {
                            if smol.send_to(&pkt.dgram, remote).await.is_err() { break; }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                },
                _ = tokio::time::sleep(idle) => break,
            }
        },
    }
    log::debug!("TUN UDP 会话结束 {host}:{remote}");
}
