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
    down_cmds: Vec<String>,
}

static MANAGER: OnceCell<Mutex<TunManager>> = OnceCell::new();

fn manager() -> &'static Mutex<TunManager> {
    MANAGER.get_or_init(|| Mutex::new(TunManager {
        active_cfg: None,
        shared: None,
        down_cmds: vec![],
    }))
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
        }
        action
    };

    match action {
        Action::Start | Action::Restart => match start(state, &cfg).await {
            Ok((shared, down)) => {
                let m = manager();
                let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
                if g.shared.is_some() {
                    // 并发触发的重复启动：先回滚本次结果再登记旧实例。
                    routes::execute(&down);
                    return;
                }
                g.active_cfg = Some(cfg.clone());
                g.shared = Some(shared);
                g.down_cmds = down;
                log::info!(
                    "TUN 已启用{}",
                    if action == Action::Restart { "（配置已变更，重建完成）" } else { "" }
                );
            }
            Err(e) => log::error!("TUN 启动失败（已回滚）: {e}"),
        },
        Action::Stop => log::info!("TUN 已停止，路由已回滚"),
        Action::None => {}
    }
}

async fn start(
    state: Arc<AppState>,
    cfg: &TunConfig,
) -> Result<(netstack::StackShared, Vec<String>), String> {
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
                Err(e) => return Err(format!("解析代理服务器 {proxy_server} 失败: {e}")),
            }
        }
    }

    let mut exclude_list = build_route_excludes(&proxy_ips, &cfg.route_exclude_address);
    exclude_list.extend(routes::default_v4_excludes());
    exclude_list.sort();
    exclude_list.dedup();

    // 2. 装路由之前探测物理网卡（此后默认路由指向 TUN，探测只会返回 TUN）。
    let probe_target: std::net::Ipv4Addr = proxy_ips
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "1.1.1.1".parse().unwrap());
    let phys = netinfo::find_route_to(probe_target)
        .ok_or_else(|| "无法探测物理网卡（IpHelper 不可用）".to_string())?;

    // 3. 打开网卡（无管理员权限在这里快速失败）。
    let tun_dev = device::open(cfg)?;
    netinfo::validate_physical(&phys, tun_dev.if_index)?;

    // 4. 路由：失败立即回滚。
    let tun_gateway: std::net::Ipv4Addr = cfg
        .fake_ip_range
        .split_once('/')
        .and_then(|(a, _)| a.parse().ok())
        .ok_or_else(|| "fake-ip-range 无效".to_string())?;
    let program = routes::build_program(cfg, tun_dev.if_index, tun_gateway, &phys, &exclude_list);
    let failures = routes::execute(&program.up);
    if !failures.is_empty() {
        routes::execute(&program.down);
        return Err(format!("安装路由失败: {:?}", failures));
    }

    // 路由已生效：立刻写崩溃恢复快照（即使后续崩溃也能在下次启动清理）。
    let snapshot = RouteSnapshot::new(std::process::id(), cfg.device_name.clone(), program.down.clone());
    if let Err(e) = snapshot.save(&state.config_dir) {
        routes::execute(&program.down);
        return Err(format!("写入 TUN 路由快照失败（已回滚路由）: {e}"));
    }

    // 5. 协议栈 + 事件泵。
    let (ev_tx, ev_rx) = std::sync::mpsc::channel::<netstack::FlowEvent>();
    let shared = netstack::spawn(tun_dev, cfg.clone(), ev_tx);
    let env = OutboundEnv::new(Some(phys.if_index), cfg.direct_nameservers.clone());
    spawn_event_pump(state.clone(), shared.clone(), ev_rx, env);
    spawn_reaper(shared.clone());

    log::info!(
        "TUN 数据面就绪: {} ifIndex={} gw={} 物理网关={}，排除 {} 条网段",
        cfg.device_name,
        phys.if_index,
        tun_gateway,
        phys.gateway,
        exclude_list.len()
    );
    Ok((shared, program.down))
}

fn stop_inner(m: &mut TunManager, config_dir: Option<&std::path::Path>) {
    routes::execute(&m.down_cmds);
    m.down_cmds.clear();
    m.active_cfg = None;
    m.shared = None; // 丢弃共享句柄 → 通道关闭 → 协议栈线程退出 → 网卡关闭
    if let Some(dir) = config_dir {
        if let Err(e) = RouteSnapshot::clear(dir) {
            log::warn!("清理 TUN 路由快照失败: {e}");
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
        log::info!("TUN 已在进程重启前停止");
    }
}

/// 启动自检：回滚上次异常退出残留的 TUN 路由（崩溃恢复）。
/// 在 Core 构造后、apply_tun 之前调用，避免残留路由干扰物理网卡探测。
pub fn recover_on_startup(config_dir: &std::path::Path) {
    match crate::core::tun::recovery::pending_rollback(config_dir) {
        Ok(Some(cmds)) => {
            let failures = routes::execute(&cmds);
            if failures.is_empty() {
                log::info!("TUN 崩溃恢复完成：已撤销上次残留路由");
            } else {
                log::error!("TUN 崩溃恢复部分失败: {:?}", failures);
            }
            if let Err(e) = RouteSnapshot::clear(config_dir) {
                log::warn!("清理残留 TUN 路由快照失败: {e}");
            }
        }
        Ok(None) => {}
        Err(e) => log::error!("读取 TUN 路由快照失败（跳过崩溃恢复）: {e}"),
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
    std::thread::Builder::new()
        .name("tun-events".into())
        .spawn(move || {
            for ev in ev_rx {
                let state = state.clone();
                let shared = shared.clone();
                let env = env.clone();
                match &rt {
                    Some(rt) => rt.spawn(outbound::handle_event(state, shared, ev, env)),
                    None => break,
                };
            }
        })
        .expect("spawn tun event pump");
}

/// 周期回收关闭的 socket。
fn spawn_reaper(shared: netstack::StackShared) {
    let rt = tokio::runtime::Handle::try_current().ok();
    if let Some(rt) = rt {
        rt.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let mut core = shared.lock();
                netstack::reap_closed(&mut core);
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
