//! TUN 生命周期编排（fail-closed）。
//!
//! 启动顺序严格遵守依赖关系：
//! 1. 配置校验 → 2. 解析代理服务器 IP → 3. **装路由前**探测物理网卡
//! → 4. 打开 WinTun（同时验证管理员能力）→ 5. 校验探测结果非 TUN
//! → 6. 安装路由（失败即回滚中止）→ 7. 启动协议栈与事件泵。
//!
//! 任何一步失败都对称回滚（路由 down + 网卡关闭），绝不停留在半开状态。

use crate::core::state::AppState;
use crate::core::tun::config::TunConfig;
use crate::core::tun::netinfo;
use crate::core::tun::outbound::{self, OutboundEnv};
use crate::core::tun::recovery::RouteSnapshot;
use crate::core::tun::route::build_route_excludes;
use crate::core::tun::routes;
use crate::core::tun::{device, netstack};
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};

/// 进程内唯一 TUN 实例（TUN 网卡天然单例）。
pub struct TunManager {
    /// 当前生效配置（用于热重载 Equal 判定：未变则不重建网卡）。
    active_cfg: Option<TunConfig>,
    shared: Option<netstack::StackShared>,
    /// 协议栈线程句柄：停用时 join，确保网卡会话在线程退出后才关闭。
    stack_thread: Option<std::thread::JoinHandle<()>>,
    down_cmds: Vec<String>,
    /// 实际启用的网卡名（可能因冲突轮转为 "SSLProxy-1" 等）。
    device_name: Option<String>,
    /// 实际网卡的 ifIndex。
    if_index: Option<u32>,
}

static MANAGER: OnceCell<Mutex<TunManager>> = OnceCell::new();

fn manager() -> &'static Mutex<TunManager> {
    MANAGER.get_or_init(|| Mutex::new(TunManager {
        active_cfg: None,
        shared: None,
        stack_thread: None,
        down_cmds: vec![],
        device_name: None,
        if_index: None,
    }))
}

/// 运行中的 TUN 只读状态（诊断/日志用）。
#[derive(Debug, Clone)]
pub struct TunStatus {
    pub device_name: String,
    pub if_index: u32,
    pub route_scope: crate::core::tun::config::TunRouteScope,
    pub fakeip_count: usize,
    pub tcp_pending: usize,
    pub tcp_active: usize,
    pub udp_active: usize,
    pub queued: usize,
}

/// 未启用返回 None；调用不得阻塞 UI（只做一次短锁）。
pub fn status() -> Option<TunStatus> {
    let m = manager();
    let g = m.lock().unwrap_or_else(|e| e.into_inner());
    let shared = g.shared.as_ref()?;
    let cfg = g.active_cfg.as_ref()?;
    let fakeip_count = shared.fakeip_count();
    let (tcp_pending, tcp_active, udp_active, queued) = shared.lock().stats();
    Some(TunStatus {
        device_name: g
            .device_name
            .clone()
            .unwrap_or_else(|| cfg.device_name.clone()),
        if_index: g.if_index.unwrap_or(0),
        route_scope: cfg.route_scope,
        fakeip_count,
        tcp_pending,
        tcp_active,
        udp_active,
        queued,
    })
}

/// 按当前配置对齐 TUN 状态（保存配置 / 启动时调用）。
///
/// 注意：不持有 `MutexGuard` 跨 await——启动的异步步骤（DNS 解析、
/// netstack 启动）在锁外执行，完成后短暂加锁登记。
/// 判定热重载动作，供 apply 使用（纯逻辑，便于单测）。
fn decide_action(enabled: bool, running: bool, cfg_changed: bool) -> Action {
    match (enabled, running) {
        (true, false) => Action::Start,
        (false, true) => Action::Stop,
        // 已运行且配置变化 → 重建；配置未变 → 只刷新状态，不碰网卡。
        (true, true) if cfg_changed => Action::Restart,
        _ => Action::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Start,
    Stop,
    Restart,
    None,
}

pub async fn apply(state: Arc<AppState>) {
    // 非 Windows 平台不提供 TUN：不读配置、不建网卡、不改路由。
    if !crate::core::tun::TUN_SUPPORTED {
        return;
    }
    let cfg = state.config.read().await.tun.clone();
    let config_dir = state.config_dir.clone();

    // 决策 + 先停止（持锁，无 await）。
    let action = {
        let m = manager();
        let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
        let running = g.shared.is_some();
        let cfg_changed = g
            .active_cfg
            .as_ref()
            .map(|active| !active.equal(&cfg))
            .unwrap_or(false);
        let action = decide_action(cfg.enable, running, cfg_changed);
        if matches!(action, Action::Stop | Action::Restart) {
            stop_inner(&mut g, Some(&config_dir));
            if let Ok(mut w) = state.tun_dns_bypass.write() {
                *w = None;
            }
        }
        action
    };

    match action {
        Action::Start | Action::Restart => match start(state, &cfg).await {
            Ok((shared, stack_thread, down, device_name, if_index)) => {
                let m = manager();
                let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
                if g.shared.is_some() {
                    // 并发触发的重复启动：先回滚本次结果再登记旧实例。
                    routes::execute(&down);
                    shared.request_stop();
                    let _ = stack_thread.join();
                    shared.close_device();
                    crate::core::tun::device::remove_adapter(&device_name);
                    return;
                }
                g.active_cfg = Some(cfg.clone());
                g.shared = Some(shared);
                g.stack_thread = Some(stack_thread);
                g.down_cmds = down;
                g.device_name = Some(device_name);
                g.if_index = Some(if_index);
                log::info!(
                    "TUN enabled{}",
                    if action == Action::Restart { " (config changed, rebuilt)" } else { "" }
                );
            }
            Err(e) => log::error!("TUN start failed (rolled back): {e}"),
        },
        Action::Stop => log::info!("TUN stopped, routes rolled back"),
        Action::None => {}
    }
}

async fn start(
    state: Arc<AppState>,
    cfg: &TunConfig,
) -> Result<
    (
        netstack::StackShared,
        std::thread::JoinHandle<()>,
        Vec<String>,
        String,
        u32,
    ),
    String,
> {
    cfg.validate()?;

    // 1. 代理服务器 IP（域名先经现有 resolver 解析，供路由例外防自环）。
    let config = state.config.read().await;
    let proxy_server = config.proxy_server.clone();
    drop(config);
    let mut proxy_ips: Vec<String> = Vec::new();
    if !proxy_server.is_empty() {
        if proxy_server.parse::<std::net::IpAddr>().is_ok() {
            proxy_ips.push(proxy_server.clone());
        } else {
            match crate::core::dns::lookup(&state, &proxy_server).await {
                Ok(ip) => proxy_ips.push(ip),
                Err(e) => return Err(format!("failed to resolve proxy server {proxy_server}: {e}")),
            }
        }
        // 登记 TUN 启动前解析的 IP：TUN 开启后系统 DNS 被自身劫持，
        // 隧道出站（connect_proxy / MUX / UDP 隧道）必须用该 IP 直连，
        // TLS 证书校验仍按配置域名（sni_name）进行。
        if let Ok(mut w) = state.proxy_resolved_ip.write() {
            *w = proxy_ips.first().cloned();
        }
    }

    // 例外基集：代理节点 IP（防自环）+ 用户显式排除。
    // 私网段是否例外由 routes::build_program 按 cfg.strict_route 决定：
    // - 兼容模式：私网段绕过 TUN（局域网直连）；
    // - 严格模式：私网段也进 TUN，由分流引擎的 must_direct_ip 判定直连。
    let exclude_list = build_route_excludes(&proxy_ips, &cfg.route_exclude_address);

    // 2. 装路由之前探测物理网卡（此后默认路由指向 TUN，探测只会返回 TUN）。
    let probe_target: std::net::Ipv4Addr = proxy_ips
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "1.1.1.1".parse().unwrap());
    let phys = netinfo::find_route_to(probe_target)
        .ok_or_else(|| "failed to probe physical adapter (IpHelper unavailable)".to_string())?;

    // 3. 打开网卡（无管理员权限在这里快速失败）。
    let tun_dev = device::open(cfg)?;
    netinfo::validate_physical(&phys, tun_dev.if_index)?;
    let tun_if_index = tun_dev.if_index;

    // 4. 路由：失败立即回滚。
    let tun_gateway: std::net::Ipv4Addr = cfg
        .fake_ip_range
        .split_once('/')
        .and_then(|(a, _)| a.parse().ok())
        .ok_or_else(|| "invalid fake-ip-range".to_string())?;
    let program = routes::build_program(cfg, tun_dev.if_index, tun_gateway, &phys, &exclude_list);
    let failures = routes::execute(&program.up);
    if !failures.is_empty() {
        routes::execute(&program.down);
        return Err(format!("failed to install routes: {:?}", failures));
    }

    // 路由已生效：立刻写崩溃恢复快照（即使后续崩溃也能在下次启动清理）。
    // 网卡名可能因冲突轮转发生变化，快照必须记录实际名称。
    // auto-route 关闭时没有安装任何路由，也就不需要快照。
    if !program.up.is_empty() {
        let snapshot =
            RouteSnapshot::new(std::process::id(), tun_dev.name.clone(), program.down.clone());
        if let Err(e) = snapshot.save(&state.config_dir) {
            routes::execute(&program.down);
            return Err(format!("failed to write TUN route snapshot (routes rolled back): {e}"));
        }
    }

    // 5. 协议栈 + 事件泵。fake-ip 映射持久化恢复（应用缓存跨重启可反查）。
    let (ev_tx, ev_rx) = std::sync::mpsc::channel::<netstack::FlowEvent>();
    let fake_map = crate::core::tun::dns::FakeIpMap::load_from(&fakeip_path(&state.config_dir));
    // 实际网卡名可能因冲突轮转，随启动结果返回并登记到 manager。
    let tun_name = tun_dev.name.clone();
    let (shared, stack_thread) = netstack::spawn(tun_dev, cfg.clone(), ev_tx, fake_map);
    let env = OutboundEnv::new(
        Some(phys.if_index),
        Some(tun_if_index),
        phys.local_ipv4,
        cfg.direct_nameservers.clone(),
    );
    // 登记 DNS 绕行参数：TUN 期间所有解析都必须走物理网卡，否则会被
    // 自身劫持应答成 fake-ip，污染缓存并让分流退化为直连。
    if let Ok(mut w) = state.tun_dns_bypass.write() {
        *w = Some(crate::core::state::TunDnsBypass {
            if_index: phys.if_index,
            local_ipv4: phys.local_ipv4,
            nameservers: cfg.direct_nameservers.clone(),
            fake_ip_range: cfg.fake_ip_range.clone(),
        });
    }
    spawn_event_pump(state.clone(), shared.clone(), ev_rx, env);
    spawn_reaper(shared.clone());
    spawn_fakeip_saver(state.config_dir.clone(), shared.clone());
    spawn_egress_monitor(state.clone(), tun_if_index, shared.stop_flag());

    // 清理系统 DNS 缓存：上次 TUN 会话的 fake-ip 可能仍被 OS 缓存，
    // 应用拿到缓存后不会重新查询，反查将失败（fail-closed 拒绝该流）。
    flush_system_dns_cache();

    log::info!(
        "TUN data plane ready: {} ifIndex={} gw={} physical gateway={}, strict-route={}, {} baseline route excludes",
        cfg.device_name,
        phys.if_index,
        tun_gateway,
        phys.gateway,
        cfg.strict_route,
        exclude_list.len()
    );
    log::info!(
        "TUN physical egress: ifIndex={} source address={:?}",
        phys.if_index,
        phys.local_ipv4
    );
    Ok((
        shared,
        stack_thread,
        program.down,
        tun_name,
        tun_if_index,
    ))
}

/// 清空 Windows 系统 DNS 缓存（TUN 启停时调用，防 fake-ip 残留缓存）。
#[cfg(target_os = "windows")]
fn flush_system_dns_cache() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    match std::process::Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(_) => log::info!("system DNS cache flushed"),
        Err(e) => log::warn!("failed to flush system DNS cache (may affect fake-ip reverse lookup): {e}"),
    }
}

#[cfg(not(target_os = "windows"))]
fn flush_system_dns_cache() {}

/// 后台刷新 DNS 缓存（不阻塞调用线程）。
///
/// 退出路径（托盘/UI 退出按钮）跑在 GPUI 主线程上，`ipconfig /flushdns`
/// 可能耗时 1~3 秒，同步调用会让窗口看上去卡死。
#[cfg(target_os = "windows")]
fn flush_system_dns_cache_async() {
    std::thread::Builder::new()
        .name("flush-dns".into())
        .spawn(flush_system_dns_cache)
        .ok();
}

#[cfg(not(target_os = "windows"))]
fn flush_system_dns_cache_async() {}

/// fake-ip 持久化文件：config_dir/fakeip.json。
fn fakeip_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("fakeip.json")
}

/// 近实时保存 fake-ip 映射：每秒检查一次，只有新增映射时才落盘。
///
/// 浏览器会长时间缓存 fake-ip，若映射丢失（进程被强杀/重启）连接会被
/// fail-closed 拒绝（浏览器报 ERR_CONNECTION_CLOSED），因此尽可能缩短
/// 「已分配但未落盘」的窗口。
fn spawn_fakeip_saver(config_dir: std::path::PathBuf, shared: netstack::StackShared) {
    let rt = tokio::runtime::Handle::try_current().ok();
    if let Some(rt) = rt {
        rt.spawn(async move {
            let path = fakeip_path(&config_dir);
            let mut saved_len = usize::MAX;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                // 停用 TUN 后退出：停止流程已同步落盘过，这里不再需要轮询。
                if shared.is_stopping() {
                    break;
                }
                let (entries, len) = {
                    let core = shared.lock();
                    (core.fake_map.entries(), core.fake_map.len())
                };
                if len == saved_len {
                    continue;
                }
                saved_len = len;
                let path = path.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    std::fs::write(
                        path.with_extension("json.tmp"),
                        serde_json::to_string(&entries)
                            .unwrap_or_else(|_| "[]".to_string()),
                    )
                    .and_then(|_| std::fs::rename(
                        path.with_extension("json.tmp"),
                        &path,
                    ))
                })
                .await
                {
                    log::warn!("failed to save fake-ip mappings: {e:?}");
                }
            }
        });
    }
}

fn stop_inner(m: &mut TunManager, config_dir: Option<&std::path::Path>) {
    // 停止前先落盘 fake-ip 映射，保证下次启动可反查应用残留缓存。
    if let Some(shared) = &m.shared {
        if let Some(dir) = config_dir {
            if let Err(e) = shared.lock().fake_map.save_to(&fakeip_path(dir)) {
                log::warn!("failed to save fake-ip mappings: {e}");
            }
        }
    }
    // 先回滚路由，再拆网卡：反序会让流量在"无网卡、仍有路由"的窗口被黑洞。
    routes::execute(&m.down_cmds);
    m.down_cmds.clear();

    // 协议栈线程 → 网卡读写线程 → 会话/网卡句柄，必须按此顺序释放，
    // 否则线程仍在使用已关闭的会话（且网卡永远不关闭，残留设备节点）。
    if let Some(shared) = &m.shared {
        shared.request_stop();
    }
    if let Some(thread) = m.stack_thread.take() {
        let _ = thread.join();
    }
    if let Some(shared) = &m.shared {
        shared.close_device();
    }

    // 基础网卡名（清理同名重复设备时用；在清空 active_cfg 前取出）。
    let base_name = m.active_cfg.as_ref().map(|cfg| cfg.device_name.clone());
    m.active_cfg = None;
    m.shared = None; // 丢弃共享句柄 → 协议栈状态与通道随之释放
    let removed_name = m.device_name.take();
    m.if_index = None;

    // 从系统卸载虚拟网卡设备（SetupAPI 尽力而为；句柄已关闭）。
    if let Some(name) = &removed_name {
        crate::core::tun::device::remove_adapter(name);
    }
    // 同一基础名下可能有旧版本遗留的重复设备（`SSLProxy 2` 等），一并清掉。
    if let Some(base) = base_name {
        crate::core::tun::device::remove_leftover_adapters(&base);
    }

    // 停止后 fake-ip 不再可达，清缓存让应用尽快重新走真实 DNS（后台执行，不阻塞退出）。
    flush_system_dns_cache_async();
    if let Some(dir) = config_dir {
        if let Err(e) = RouteSnapshot::clear(dir) {
            log::warn!("failed to clear TUN route snapshot: {e}");
        }
    }
}

/// 进程退出/重启前的同步回滚（不经 tokio，保证顺序执行）。
pub fn stop_before_exit(config_dir: &std::path::Path) {
    let mut m = match manager().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if m.shared.is_some() {
        stop_inner(&mut m, Some(config_dir));
        log::info!("TUN stopped before process restart");
    }
}

/// 启动自检：回滚上次异常退出残留的 TUN 路由（崩溃恢复），并清理历次遗留的
/// 虚拟网卡（旧版本停用 TUN 时不会卸载设备）。
/// 在 Core 构造后、apply_tun 之前调用，避免残留路由干扰物理网卡探测。
pub fn recover_on_startup(config_dir: &std::path::Path, device_name: &str) {
    if !crate::core::tun::TUN_SUPPORTED {
        return;
    }
    match crate::core::tun::recovery::pending_rollback(config_dir) {
        Ok(Some(cmds)) => {
            let failures = routes::execute(&cmds);
            if failures.is_empty() {
                log::info!("TUN crash recovery complete: residual routes from last run removed");
            } else {
                log::error!("TUN crash recovery partially failed: {:?}", failures);
            }
            if let Err(e) = RouteSnapshot::clear(config_dir) {
                log::warn!("failed to clear residual TUN route snapshot: {e}");
            }
        }
        Ok(None) => {}
        Err(e) => log::error!("failed to read TUN route snapshot (skipping crash recovery): {e}"),
    }

    // 顺序必须在路由回滚之后：删除设备实例会连带移除挂在该接口上的路由，
    // 先删设备会让上面的回滚命令因"找不到路由"而报失败。
    let removed = crate::core::tun::device::remove_leftover_adapters(device_name);
    if removed > 0 {
        log::info!("removed {removed} leftover TUN adapter(s) on startup");
    }
}

/// 流量事件 → tokio 出站处理。
fn spawn_event_pump(
    state: Arc<AppState>,
    shared: netstack::StackShared,
    ev_rx: std::sync::mpsc::Receiver<netstack::FlowEvent>,
    env: OutboundEnv,
) {
    let rt = tokio::runtime::Handle::try_current().ok();
    let stop = shared.stop_flag();
    std::thread::Builder::new()
        .name("tun-events".into())
        .spawn(move || loop {
            // 带超时接收：本线程持有 StackShared，若不看停止信号会永久阻塞，
            // 协议栈状态（含心跳任务）便无法释放。
            let ev = match ev_rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(ev) => ev,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let state = state.clone();
            let shared = shared.clone();
            let env = env.clone();
            match &rt {
                Some(rt) => {
                    rt.spawn(outbound::handle_event(state, shared, ev, env));
                }
                None => break,
            }
        })
        .expect("spawn tun event pump");
}

/// 清空 fake-ip 映射：内存表 + 持久化文件，并刷新系统 DNS 缓存。
///
/// 应用缓存的旧 fake-ip 会因此反查失败（fail-closed 拒绝），
/// 刷新 DNS 缓存可促使其尽快重新查询。
pub fn clear_fakeip(state: &AppState) -> Result<usize, String> {
    let cleared = {
        let m = manager();
        let g = m.lock().unwrap_or_else(|e| e.into_inner());
        match &g.shared {
            Some(shared) => {
                let n = shared.lock().fake_map.len();
                shared.clear_fake_map();
                n
            }
            None => 0,
        }
    };
    let path = fakeip_path(&state.config_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("failed to delete {:?}: {e}", path)),
    }
    flush_system_dns_cache_async();
    Ok(cleared)
}

/// 每 15s 复查默认出口：网卡/VPN 切换后更新 DNS 绕行参数并记录日志。
///
/// 直连出站本身按目标实时解析（netinfo::resolve_egress），这里只负责
/// 让 DNS 查询与日志跟上变化，避免出现「直连已切换、DNS 还绑旧网卡」。
fn spawn_egress_monitor(
    state: Arc<AppState>,
    tun_if_index: u32,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let rt = tokio::runtime::Handle::try_current().ok();
    if let Some(rt) = rt {
        rt.spawn(async move {
            let mut last = netinfo::default_egress(tun_if_index);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                // 停用 TUN 后退出，避免每次启停都留下一个常驻轮询任务。
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let current = netinfo::default_egress(tun_if_index);
                let changed = match (last, current) {
                    (Some(a), Some(b)) => {
                        a.if_index != b.if_index || a.local_ipv4 != b.local_ipv4
                    }
                    (None, None) => false,
                    _ => true,
                };
                if !changed {
                    continue;
                }
                // PhysicalRoute 是 Copy，这里保留值语义用于下一次比较。
                log::info!(
                    "TUN default egress changed: ifIndex={:?} source address={:?}",
                    current.map(|r| r.if_index),
                    current.and_then(|r| r.local_ipv4)
                );
                last = current;
                if let Some(route) = current {
                    if let Ok(mut guard) = state.tun_dns_bypass.write() {
                        if let Some(bypass) = guard.as_mut() {
                            bypass.if_index = route.if_index;
                            bypass.local_ipv4 = route.local_ipv4;
                        }
                    }
                }
            }
        });
    }
}

/// 周期回收关闭/超时的 socket，并每 10s 打一条心跳（泄漏/卡死排查）。
fn spawn_reaper(shared: netstack::StackShared) {
    let rt = tokio::runtime::Handle::try_current().ok();
    if let Some(rt) = rt {
        rt.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                // 停用 TUN 后必须退出，否则心跳会一直打，且本任务持有
                // StackShared 使协议栈状态无法释放。
                if shared.is_stopping() {
                    break;
                }
                let mut core = shared.lock();
                netstack::reap_closed(&mut core);
                let (pending, flows, udp, queued) = core.stats();
                log::info!("TUN heartbeat: pending={pending} tcp={flows} udp={udp} queued={queued}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_starts_empty() {
        let m = manager().lock().unwrap();
        assert!(m.shared.is_none());
        assert!(m.down_cmds.is_empty());
        assert!(m.device_name.is_none());
        assert!(m.if_index.is_none());
    }

    #[test]
    fn status_is_none_before_start() {
        // 测试进程内没有真实 TUN（需要管理员权限与 wintun.dll），
        // 因此 manager 始终保持未启动状态，status() 必须返回 None。
        assert!(status().is_none());
    }

    #[test]
    fn hot_reload_decision_matrix() {
        // 未启用 + 未运行 → 无操作
        assert_eq!(decide_action(false, false, false), Action::None);
        // 启用 + 未运行 → 首次启动
        assert_eq!(decide_action(true, false, false), Action::Start);
        // 未启用 + 运行中 → 停止
        assert_eq!(decide_action(false, true, false), Action::Stop);
        // 运行中 + 配置未变 → 无操作（不重建网卡）
        assert_eq!(decide_action(true, true, false), Action::None);
        // 运行中 + 配置变化 → 重建
        assert_eq!(decide_action(true, true, true), Action::Restart);
    }
}
