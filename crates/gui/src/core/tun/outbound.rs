//! TUN 流量出站处理：把协议栈事件接到统一决策引擎。
//!
//! - PROXY → `resolve_and_connect` 进入 TLS 隧道，复用 `forward_target_stream`
//!   的全部协议转发逻辑（padding 分帧 / mux）；
//! - DIRECT → `socket2::bind_device_by_index` 绑定物理网卡后直连，
//!   确保出站包不被 TUN 二次捕获（防自环）；
//! - DIRECT 域名解析走**绑定物理网卡的直连 DNS**，绝不经过自身劫持
//!   （否则解析结果永远是 fake-ip，形成解析环路）；
//! - 解析结果落在 fake-ip 池内一律视为"未解析"（fail-closed 后备）。
//!
//! 已知边界（阶段 C 计划）：TUN 的 UDP 代理路径尚未接入隧道，仅支持直连。

use crate::core::proxy::connect::{match_rules, resolve_and_connect};
use crate::core::proxy::route::{classify, RouteInput};
use crate::core::proxy::tunnel::forward_target_stream;
use crate::core::state::AppState;
use crate::core::tun::dns::is_in_fake_ip_pool;
use smoltcp::iface::SocketHandle;
use crate::core::tun::netstack::{FlowEvent, SmolTcpStream, SmolUdpSocket, StackShared};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// 运行时环境：物理接口索引与直连 DNS 服务器（由 runner 探测后传入）。
#[derive(Debug, Clone)]
pub struct OutboundEnv {
    /// 物理网卡 ifIndex（None = 未绑定，仅用于非 Windows/测试）。
    pub physical_if: Option<u32>,
    /// 直连解析用 DNS 服务器（绑定物理网卡查询）。
    pub nameservers: Vec<String>,
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

/// fake-ip 反查目标域名；查不到时用 IP 字符串本身作为 host。
fn host_of(shared: &StackShared, ip: IpAddr) -> String {
    let core = shared.lock();
    core.fake_map
        .find_host_by_ip(&ip.to_string())
        .map(|s| s.to_string())
        .unwrap_or_else(|| ip.to_string())
}

/// 统一决策（语义与 connect.rs 的 SOCKS/HTTP 路径一致）。
/// 返回 Some(ip) 表示可直连；Proxy 无 IP（域名交给服务端解析）。
async fn decide_for_tun(
    state: &Arc<AppState>,
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
        crate::core::dns::lookup(state, host).await.ok()
    };
    // fail-closed 后备：解析结果落在 fake-ip 池内 = 被自身 DNS 劫持污染，
    // 禁止当作真实 IP 直连（会再次进入 TUN 形成环路）。
    if let Some(ip) = resolved.as_ref().and_then(|s| s.parse::<IpAddr>().ok()) {
        if is_in_fake_ip_pool(&ip, fake_range) {
            log::warn!("TUN DNS 污染防护: {host} 解析到 fake-ip，按未解析处理");
            resolved = None;
        }
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
    let host = host_of(&shared, local.ip());
    let port = local.port();
    let fake_range = shared.lock().cfg.fake_ip_range.clone();
    let stream = SmolTcpStream::new(&shared, handle);

    let decision = match decide_for_tun(&state, &host, &fake_range).await {
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
            None => return,
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

#[allow(clippy::too_many_arguments)]
async fn handle_udp(
    state: Arc<AppState>,
    shared: StackShared,
    handle: SocketHandle,
    local: SocketAddr,
    remote: SocketAddr,
    payload: Vec<u8>,
    env: OutboundEnv,
) {
    let host = host_of(&shared, local.ip());
    let port = local.port();
    let fake_range = shared.lock().cfg.fake_ip_range.clone();
    let smol = SmolUdpSocket::new(&shared, handle);

    // DNS：轮询线程已劫持应答；到达这里的 53 包都是未劫持目标，丢弃防泄漏。
    if port == 53 {
        log::debug!("TUN UDP:53 未命中劫持规则，丢弃 {remote}");
        return;
    }

    let decision = match decide_for_tun(&state, &host, &fake_range).await {
        Ok(d) => d,
        Err(_) => return,
    };
    if !decision.is_direct() {
        // 阶段 C：UDP 代理路径复用 udp_relay 隧道会话。
        log::warn!("TUN UDP 代理暂未接入，丢弃 {host}:{port}（仅支持直连）");
        return;
    }
    let ip = match decision.resolved_ip {
        Some(ip) => ip,
        None => return,
    };

    let sock = match connect_direct_udp(env.physical_if) {
        Ok(s) => s,
        Err(e) => {
            log::error!("TUN 直连 UDP socket 失败: {e}");
            return;
        }
    };
    let dst: SocketAddr = match format!("{ip}:{port}").parse() {
        Ok(a) => a,
        Err(_) => return,
    };
    if sock.send_to(&payload, dst).await.is_err() {
        return;
    }

    // NAT 泵：真实服务端回复 → 伪装回 fake-ip 源发回应用。
    let mut buf = vec![0u8; 65535];
    let idle = Duration::from_secs(60);
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, _from)) => {
                        if smol.send_to(&buf[..n], remote).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            _ = tokio::time::sleep(idle) => break,
        }
    }
}

/// 绑定物理网卡的 UDP socket（直连出站专用）。
fn connect_direct_udp(if_index: Option<u32>) -> std::io::Result<tokio::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if let Some(idx) = if_index {
        bind_unicast_if(&sock, true, idx)?;
    }
    sock.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())?;
    sock.set_nonblocking(true)?;
    Ok(tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))?)
}
