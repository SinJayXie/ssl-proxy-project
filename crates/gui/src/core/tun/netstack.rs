//! 用户态协议栈：smoltcp 终结 TUN 上的 TCP/UDP，DNS 就近应答，其余流量
//! 经统一决策引擎出站（见 [`super::outbound`]）。
//!
//! 结构：
//! - 单个 std 线程持有 `Interface` + `SocketSet`，驱动 smoltcp 轮询；
//! - 应用侧通过 `StackShared`（Mutex + 唤醒通道）以 `SmolTcpStream` /
//!   `SmolUdpSocket` 参与 I/O，waker 注册表由轮询线程统一唤醒；
//! - TCP：入站 SYN 先建好监听 socket 再注入报文，握手完成后发 `FlowEvent`；
//! - UDP：按目的端点建 socket；53 端口命中劫持规则时在轮询线程内用
//!   fake-ip 应答（fail-closed，绝不转发真实 DNS）。

use crate::core::tun::config::TunConfig;
use crate::core::tun::device::TunDevice;
use crate::core::tun::dns::{answer_query, should_hijack_dns, FakeIpMap};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address,
    Ipv4Packet, TcpPacket, UdpPacket,
};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, UNIX_EPOCH};

/// TCP socket 收/发缓冲（每流 64 KiB）。
const TCP_BUF: usize = 64 * 1024;

/// 由轮询线程发给 tokio 侧的新流量。
#[derive(Debug)]
pub enum FlowEvent {
    /// TCP 握手完成。`local` 是应用连接的目的端点（多为 fake-ip）。
    Tcp {
        handle: SocketHandle,
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// 需要出站的 UDP 流（DNS 劫持不产生此事件）。附带首包 payload。
    Udp {
        handle: SocketHandle,
        local: SocketAddr,
        remote: SocketAddr,
        payload: Vec<u8>,
    },
}

/// 共享句柄：tokio 任务通过它访问协议栈 socket。
#[derive(Clone)]
pub struct StackShared {
    inner: Arc<Mutex<StackCore>>,
    wake_tx: std::sync::mpsc::Sender<()>,
}

impl StackShared {
    pub fn lock(&self) -> MutexGuard<'_, StackCore> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 清空内存中的 fake-ip 映射（设置页"清空 fake-ip"按钮）。
    /// 已建立的连接不受影响，新查询会重新分配地址。
    pub fn clear_fake_map(&self) {
        let mut core = self.lock();
        let n = core.fake_map.len();
        core.fake_map = FakeIpMap::new();
        drop(core);
        log::info!("已清空 {n} 条 fake-ip 映射");
    }

    /// 请求立即轮询一次（写入数据后调用）。
    pub fn wake(&self) {
        let _ = self.wake_tx.send(());
    }
}

/// 轮询线程拥有的全部状态。
pub struct StackCore {
    iface: Interface,
    sockets: SocketSet<'static>,
    /// socket handle → 等待 I/O 的 waker（每次轮询后统一唤醒）。
    pub wakers: HashMap<SocketHandle, Vec<Waker>>,
    device_tx: std::sync::mpsc::Sender<Vec<u8>>,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    queue: VecDeque<Vec<u8>>,
    /// 已按目的端点建好监听的 TCP socket（等待握手）。
    tcp_pending: HashMap<IpEndpoint, SocketHandle>,
    /// 半开连接建立时间，用于回收客户端放弃的握手（否则永久占用 SocketSet）。
    pending_at: HashMap<SocketHandle, std::time::Instant>,
    /// 已完成握手、事件已发出的 TCP 流。
    pub tcp_flows: HashMap<SocketHandle, IpEndpoint>,
    /// UDP socket：端点 → handle。
    pub udp_flows: HashMap<IpEndpoint, SocketHandle>,
    /// UDP socket 最近一次收包时间，用于回收空闲会话。
    udp_at: HashMap<SocketHandle, std::time::Instant>,
    /// 已被 reaper 从 SocketSet 移除的 handle。流封装（SmolTcpStream 等）
    /// 可能比 SocketSet 条目活得更久（tokio split 双持有），访问前必须检查。
    removed_sockets: std::collections::HashSet<SocketHandle>,
    /// handle → socket 类型。smoltcp 会复用索引，旧流封装持有的 handle 可能
    /// 指向新 socket；类型不匹配时 `get_mut::<Tcp>` 会 panic（release 静默退出），
    /// 因此访问前必须核对类型。
    kinds: HashMap<SocketHandle, SocketKind>,
    /// WinTun adapter/session 的所有权标记，协议栈析构时才关闭网卡。
    keepalive: Option<Box<dyn Send>>,
    pub events: std::sync::mpsc::Sender<FlowEvent>,
    pub fake_map: FakeIpMap,
    pub cfg: TunConfig,
}

/// SocketSet 中该 handle 当前承载的协议类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Udp,
}

impl StackCore {
    fn register_waker(&mut self, handle: SocketHandle, cx: &Context<'_>) {
        self.wakers.entry(handle).or_default().push(cx.waker().clone());
    }

    /// 该 handle 当前是否仍是一个**可访问的 TCP socket**。
    fn tcp_live(&self, handle: SocketHandle) -> bool {
        !self.removed_sockets.contains(&handle)
            && self.kinds.get(&handle) == Some(&SocketKind::Tcp)
    }

    /// 该 handle 当前是否仍是一个**可访问的 UDP socket**。
    fn udp_live(&self, handle: SocketHandle) -> bool {
        !self.removed_sockets.contains(&handle)
            && self.kinds.get(&handle) == Some(&SocketKind::Udp)
    }

    /// (半开 TCP, 活跃 TCP, UDP) 数量，用于运行期诊断（泄漏/卡顿排查）。
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        (
            self.tcp_pending.len(),
            self.tcp_flows.len(),
            self.udp_flows.len(),
            self.queue.len(),
        )
    }

    fn wake_all(&mut self) {
        for (_, ws) in self.wakers.drain() {
            for w in ws {
                w.wake();
            }
        }
    }
}

/// 把 wintun 通道桥接为 smoltcp `Device`。
struct CoreDevice<'a> {
    rx_queue: &'a mut VecDeque<Vec<u8>>,
    tx: &'a std::sync::mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

struct RxToken(Vec<u8>);
struct TxToken<'a>(&'a std::sync::mpsc::Sender<Vec<u8>>);

impl Device for CoreDevice<'_> {
    type RxToken<'a> = RxToken where Self: 'a;
    type TxToken<'a> = TxToken<'a> where Self: 'a;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((RxToken(pkt), TxToken(self.tx)))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut pkt = self.0;
        f(&mut pkt)
    }
}

impl smoltcp::phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        let _ = self.0.send(buf);
        result
    }
}

/// 启动轮询线程，返回共享句柄。`fake_map` 传入持久化恢复的映射表。
pub fn spawn(
    device: TunDevice,
    cfg: TunConfig,
    events_tx: std::sync::mpsc::Sender<FlowEvent>,
    fake_map: FakeIpMap,
) -> StackShared {
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
    let stop = device.stop.clone();
    let shared = StackShared {
        inner: Arc::new(Mutex::new(StackCore {
            iface: build_iface(device.mtu, &cfg),
            sockets: SocketSet::new(vec![]),
            wakers: HashMap::new(),
            device_tx: device.tx.clone(),
            rx: device.rx,
            queue: VecDeque::new(),
            tcp_pending: HashMap::new(),
            pending_at: HashMap::new(),
            tcp_flows: HashMap::new(),
            udp_flows: HashMap::new(),
            udp_at: HashMap::new(),
            removed_sockets: std::collections::HashSet::new(),
            kinds: HashMap::new(),
            // 网卡会话由协议栈持有：线程退出、StackCore 析构后才关闭。
            keepalive: device.keepalive,
            events: events_tx,
            fake_map,
            cfg: cfg.clone(),
        })),
        wake_tx: wake_tx.clone(),
    };

    let loop_shared = shared.clone();
    std::thread::Builder::new()
        .name("tun-stack".into())
        .spawn(move || {
            poll_loop(loop_shared, wake_rx);
            // 协议栈退出即停止读线程，避免其继续空转并持有网卡会话。
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        })
        .expect("spawn tun stack thread");
    shared
}

fn build_iface(mtu: u16, cfg: &TunConfig) -> Interface {
    let config = Config::new(HardwareAddress::Ip);
    let mut queue = VecDeque::new();
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut dev = CoreDevice { rx_queue: &mut queue, tx: &tx, mtu: mtu as usize };
    let mut iface = Interface::new(config, &mut dev, now());
    let gateway: Ipv4Address = gateway_ip(cfg).into();
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(gateway), 30))
            .expect("push tun addr");
    });
    let _ = iface.routes_mut().add_default_ipv4_route(gateway);
    // AnyIP：TUN 是路由设备，入站 IP 包的目标（fake-ip、真实公网 IP）
    // 几乎都不是网卡自身地址 198.18.0.1/30。不开 AnyIP，smoltcp 会把
    // 非"发给自己"的包全部丢弃——DNS 劫持与 fake-ip 出站就全都失灵。
    iface.set_any_ip(true);
    iface
}

fn gateway_ip(cfg: &TunConfig) -> std::net::Ipv4Addr {
    cfg.fake_ip_range
        .split_once('/')
        .and_then(|(a, _)| a.parse().ok())
        .unwrap_or_else(|| "198.18.0.1".parse().unwrap())
}

fn now() -> Instant {
    Instant::from_millis(
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as i64,
    )
}

fn to_socket_addr(ep: IpEndpoint) -> SocketAddr {
    SocketAddr::new(
        match ep.addr {
            IpAddress::Ipv4(v4) => std::net::IpAddr::V4(v4.into()),
            IpAddress::Ipv6(v6) => std::net::IpAddr::V6(v6.into()),
        },
        ep.port,
    )
}

/// 主轮询循环。
fn poll_loop(shared: StackShared, wake_rx: std::sync::mpsc::Receiver<()>) {
    loop {
        match wake_rx.recv_timeout(Duration::from_millis(20)) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
        let mut core = shared.lock();
        // 背压：队列满时停止取包（留在通道里），而不是取出来后静默丢弃
        // ——丢弃会让 TCP 直接卡住重传。
        while core.queue.len() < 512 {
            match core.rx.try_recv() {
                Ok(pkt) => {
                    prepare_inbound(&mut core, &pkt);
                    core.queue.push_back(pkt);
                }
                Err(_) => break,
            }
        }

        {
            let StackCore { iface, queue, device_tx, sockets, cfg, .. } = &mut *core;
            let mtu = cfg.mtu as usize;
            let mut dev = CoreDevice { rx_queue: queue, tx: device_tx, mtu };
            let started = std::time::Instant::now();
            let _ = iface.poll(now(), &mut dev, sockets);
            // 单次 poll 超过 200ms 说明协议栈被拖住（socket 泄漏/包风暴），
            // 这是整机卡死的直接前兆，必须留证据。
            let spent = started.elapsed();
            if spent > Duration::from_millis(200) {
                log::warn!("TUN 协议栈单次 poll 耗时 {spent:?}");
            }
        }

        scan_flows(&mut core);
        core.wake_all();
    }
}

/// 入站包预检：TCP SYN / UDP 先建 socket，保证 smoltcp 能匹配到本地端点。
fn prepare_inbound(core: &mut StackCore, pkt: &[u8]) {
    let Ok(ip) = Ipv4Packet::new_checked(pkt) else { return };
    let dst_addr = IpAddress::Ipv4(ip.dst_addr());
    match ip.next_header() {
        IpProtocol::Tcp => {
            let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else { return };
            if !tcp.syn() || tcp.ack() {
                return;
            }
            let ep = IpEndpoint { addr: dst_addr, port: tcp.dst_port() };
            if core.tcp_pending.contains_key(&ep) || core.udp_flows.contains_key(&ep) {
                return;
            }
            let mut sock = tcp::Socket::new(
                smoltcp::socket::tcp::SocketBuffer::new(vec![0; TCP_BUF]),
                smoltcp::socket::tcp::SocketBuffer::new(vec![0; TCP_BUF]),
            );
            if sock
                .listen(IpListenEndpoint { addr: Some(ep.addr), port: ep.port })
                .is_ok()
            {
                let h = core.sockets.add(sock);
                // 索引可能被回收后复用，必须清掉"已移除"标记，否则新 socket 会被当成已死。
                core.removed_sockets.remove(&h);
                core.kinds.insert(h, SocketKind::Tcp);
                core.pending_at.insert(h, std::time::Instant::now());
                core.tcp_pending.insert(ep, h);
            }
        }
        IpProtocol::Udp => {
            let Ok(udp) = UdpPacket::new_checked(ip.payload()) else { return };
            let ep = IpEndpoint { addr: dst_addr, port: udp.dst_port() };
            if core.udp_flows.contains_key(&ep) || core.tcp_pending.contains_key(&ep) {
                return;
            }
            let mut sock = smoltcp::socket::udp::Socket::new(
                smoltcp::socket::udp::PacketBuffer::new(
                    (0..128)
                        .map(|_| smoltcp::storage::PacketMetadata::EMPTY)
                        .collect::<Vec<_>>(),
                    vec![0; 65535],
                ),
                smoltcp::socket::udp::PacketBuffer::new(
                    (0..128)
                        .map(|_| smoltcp::storage::PacketMetadata::EMPTY)
                        .collect::<Vec<_>>(),
                    vec![0; 65535],
                ),
            );
            if sock.bind(ep).is_ok() {
                let h = core.sockets.add(sock);
                core.removed_sockets.remove(&h);
                core.kinds.insert(h, SocketKind::Udp);
                core.udp_at.insert(h, std::time::Instant::now());
                core.udp_flows.insert(ep, h);
            }
        }
        _ => {}
    }
}

/// 握手完成 → 发 TCP 事件；UDP 可读 → DNS 就近应答或发出站事件。
fn scan_flows(core: &mut StackCore) {
    let ready: Vec<IpEndpoint> = core
        .tcp_pending
        .iter()
        .filter(|(_, h)| {
            let s: &tcp::Socket = core.sockets.get(**h);
            s.state() != tcp::State::Listen
        })
        .map(|(ep, _)| *ep)
        .collect();
    for ep in ready {
        if let Some(h) = core.tcp_pending.remove(&ep) {
            core.pending_at.remove(&h);
            let remote = {
                let s: &tcp::Socket = core.sockets.get(h);
                s.remote_endpoint().unwrap_or(ep)
            };
            core.tcp_flows.insert(h, ep);
            let _ = core.events.send(FlowEvent::Tcp {
                handle: h,
                local: to_socket_addr(ep),
                remote: to_socket_addr(remote),
            });
        }
    }

    let handles: Vec<(IpEndpoint, SocketHandle)> =
        core.udp_flows.iter().map(|(e, h)| (*e, *h)).collect();
    for (local, h) in handles {
        let (payload, remote) = {
            let sock: &mut smoltcp::socket::udp::Socket = core.sockets.get_mut(h);
            if !sock.can_recv() {
                continue;
            }
            let mut tmp = vec![0u8; 65535];
            match sock.recv_slice(&mut tmp) {
                Ok((n, meta)) => (tmp[..n].to_vec(), meta.endpoint),
                Err(_) => continue,
            }
        };
        core.udp_at.insert(h, std::time::Instant::now());
        // DNS 劫持：轮询线程内直接应答（fail-closed）。
        let local_ip = match local.addr {
            IpAddress::Ipv4(v4) => std::net::IpAddr::V4(v4.into()),
            IpAddress::Ipv6(v6) => std::net::IpAddr::V6(v6.into()),
        };
        if local.port == 53
            && should_hijack_dns(&local_ip, 53, &core.cfg.dns_hijack)
        {
            let answer = answer_query(
                &payload,
                &mut core.fake_map,
                &core.cfg.fake_ip_range,
                &core.cfg.fake_ip_range6,
            );
            if let Ok(resp) = answer {
                let sock: &mut smoltcp::socket::udp::Socket = core.sockets.get_mut(h);
                let _ = sock.send_slice(&resp, remote);
            }
            continue;
        }
        // 非 DNS：交给 tokio 出站处理。
        let _ = core.events.send(FlowEvent::Udp {
            handle: h,
            local: to_socket_addr(local),
            remote: to_socket_addr(remote),
            payload,
        });
    }
}

/// 半开连接未被完成的最长存活时间（客户端 RST/放弃 SYN 后立即回收）。
const PENDING_TTL: Duration = Duration::from_secs(45);
/// UDP 会话空闲回收时间（超过即释放 socket，后续报文会重新建立）。
const UDP_IDLE_TTL: Duration = Duration::from_secs(120);
/// socket 总量告警阈值：正常使用在几十个量级。
const SOCKET_WARN_LIMIT: usize = 1024;

/// 回收已结束/超时/空闲的 socket。
///
/// 三种都必须回收，否则 SocketSet 无界增长，`iface.poll` 每轮遍历全部
/// socket，几分钟后就会把界面和网络一起拖死：
/// - 已关闭的 TCP 流；
/// - 握手未完成的 TCP（旧实现只在握手成功后删条目，被放弃的连接永久滞留）；
/// - 长时间无流量的 UDP 会话（旧实现从不回收）。
pub fn reap_closed(core: &mut StackCore) {
    let now = std::time::Instant::now();

    let dead_tcp: Vec<SocketHandle> = core
        .tcp_flows
        .keys()
        .copied()
        .filter(|h| {
            let s: &tcp::Socket = core.sockets.get(*h);
            s.state() == tcp::State::Closed && !core.wakers.contains_key(h)
        })
        .collect();
    for h in dead_tcp {
        core.tcp_flows.remove(&h);
        core.sockets.remove(h);
        // 流封装可能仍存活（tokio split 的另一半），记录避免其 drop/读写 panic。
        core.removed_sockets.insert(h);
        core.kinds.remove(&h);
    }

    let stale_pending: Vec<(IpEndpoint, SocketHandle)> = core
        .tcp_pending
        .iter()
        .filter(|(_, h)| {
            let s: &tcp::Socket = core.sockets.get(**h);
            s.state() == tcp::State::Closed
                || core
                    .pending_at
                    .get(*h)
                    .is_some_and(|t| now.duration_since(*t) > PENDING_TTL)
        })
        .map(|(ep, h)| (*ep, *h))
        .collect();
    for (ep, h) in stale_pending {
        core.tcp_pending.remove(&ep);
        core.pending_at.remove(&h);
        core.sockets.remove(h);
        core.removed_sockets.insert(h);
        core.kinds.remove(&h);
    }

    let idle_udp: Vec<(IpEndpoint, SocketHandle)> = core
        .udp_flows
        .iter()
        .filter(|(_, h)| {
            !core.wakers.contains_key(*h)
                && core
                    .udp_at
                    .get(*h)
                    .is_some_and(|t| now.duration_since(*t) > UDP_IDLE_TTL)
        })
        .map(|(ep, h)| (*ep, *h))
        .collect();
    for (ep, h) in idle_udp {
        core.udp_flows.remove(&ep);
        core.udp_at.remove(&h);
        core.sockets.remove(h);
        core.removed_sockets.insert(h);
        core.kinds.remove(&h);
    }

    let total = core.tcp_pending.len() + core.tcp_flows.len() + core.udp_flows.len();
    if total > SOCKET_WARN_LIMIT {
        log::warn!(
            "TUN socket 数异常增长: {total}（pending={} flows={} udp={}）",
            core.tcp_pending.len(),
            core.tcp_flows.len(),
            core.udp_flows.len()
        );
    }
}

// ==================== tokio 适配层 ====================

/// smoltcp TCP socket 的 tokio AsyncRead/AsyncWrite 封装。
/// 生命周期与 SocketSet 中的 handle 一致；drop 时主动关闭连接。
pub struct SmolTcpStream {
    shared: StackShared,
    handle: SocketHandle,
}

impl SmolTcpStream {
    pub fn new(shared: &StackShared, handle: SocketHandle) -> Self {
        Self { shared: shared.clone(), handle }
    }
}

impl Drop for SmolTcpStream {
    fn drop(&mut self) {
        let mut core = self.shared.lock();
        // reaper 可能已移除该 socket（流封装比 SocketSet 条目活得久）。
        if !core.tcp_live(self.handle) {
            core.wakers.remove(&self.handle);
            return;
        }
        core.sockets.get_mut::<tcp::Socket>(self.handle).close();
        core.wakers.remove(&self.handle);
        self.shared.wake();
    }
}

impl tokio::io::AsyncRead for SmolTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut core = self.shared.lock();
        if !core.tcp_live(self.handle) {
            return Poll::Ready(Ok(())); // 已被回收 → EOF
        }
        let sock = core.sockets.get_mut::<tcp::Socket>(self.handle);
        if sock.may_recv() {
            let mut tmp = [0u8; 8192];
            // 必须按调用方 ReadBuf 的剩余容量截断：copy_bidirectional / TLS
            // 可能只给几字节空间，超出会触发 ReadBuf::put_slice 的 panic
            //（release 下 panic=abort，表现为进程静默退出）。
            let capacity = buf.remaining().min(tmp.len());
            if capacity == 0 {
                return Poll::Ready(Ok(()));
            }
            let n = sock
                .recv(|data| {
                    let n = data.len().min(capacity);
                    tmp[..n].copy_from_slice(&data[..n]);
                    (n, n)
                })
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            if n > 0 {
                buf.put_slice(&tmp[..n]);
                return Poll::Ready(Ok(()));
            }
        } else if sock.state() == tcp::State::Closed {
            return Poll::Ready(Ok(())); // 对端关闭 → EOF（buf 未填充即 EOF）
        }
        core.register_waker(self.handle, cx);
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for SmolTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut core = self.shared.lock();
        if !core.tcp_live(self.handle) {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let sock = core.sockets.get_mut::<tcp::Socket>(self.handle);
        if !sock.can_send() {
            core.register_waker(self.handle, cx);
            return Poll::Pending;
        }
        match sock.send_slice(buf) {
            Ok(n) if n > 0 => {
                drop(core);
                self.shared.wake();
                return Poll::Ready(Ok(n));
            }
            Ok(_) => {}
            Err(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
        }
        core.register_waker(self.handle, cx);
        Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut core = self.shared.lock();
        if !core.tcp_live(self.handle) {
            return Poll::Ready(Ok(()));
        }
        core.sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(core);
        self.shared.wake();
        Poll::Ready(Ok(()))
    }
}

/// smoltcp UDP socket 的异步封装：recv_from / send_to。
pub struct SmolUdpSocket {
    shared: StackShared,
    handle: SocketHandle,
}

impl SmolUdpSocket {
    pub fn new(shared: &StackShared, handle: SocketHandle) -> Self {
        Self { shared: shared.clone(), handle }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| {
            let mut core = self.shared.lock();
            if !core.udp_live(self.handle) {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            let sock: &mut smoltcp::socket::udp::Socket = core.sockets.get_mut(self.handle);
            if sock.can_recv() {
                let (n, meta) = sock
                    .recv_slice(buf)
                    .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                return Poll::Ready(Ok((n, to_socket_addr(meta.endpoint))));
            }
            core.register_waker(self.handle, cx);
            Poll::Pending
        })
        .await
    }

    pub async fn send_to(&self, buf: &[u8], remote: SocketAddr) -> std::io::Result<()> {
        let remote_ep = IpEndpoint {
            addr: match remote.ip() {
                std::net::IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from(v4)),
                std::net::IpAddr::V6(v6) => IpAddress::Ipv6(v6.into()),
            },
            port: remote.port(),
        };
        std::future::poll_fn(|cx| {
            let mut core = self.shared.lock();
            if !core.udp_live(self.handle) {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            let sock: &mut smoltcp::socket::udp::Socket = core.sockets.get_mut(self.handle);
            match sock.send_slice(buf, remote_ep) {
                Ok(()) => {
                    drop(core);
                    self.shared.wake();
                    Poll::Ready(Ok(()))
                }
                Err(_) => {
                    core.register_waker(self.handle, cx);
                    Poll::Pending
                }
            }
        })
        .await
    }
}

impl Drop for SmolUdpSocket {
    fn drop(&mut self) {
        let mut core = self.shared.lock();
        core.wakers.remove(&self.handle);
    }
}
