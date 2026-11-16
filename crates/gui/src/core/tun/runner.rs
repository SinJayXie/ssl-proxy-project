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
use crate::core::tun::route::build_route_excludes;
use crate::core::tun::routes;
use crate::core::tun::{device, netstack};
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};

/// 进程内唯一 TUN 实例（TUN 网卡天然单例）。
pub struct TunManager {
    shared: Option<netstack::StackShared>,
    down_cmds: Vec<String>,
}

static MANAGER: OnceCell<Mutex<TunManager>> = OnceCell::new();

fn manager() -> &'static Mutex<TunManager> {
    MANAGER.get_or_init(|| Mutex::new(TunManager { shared: None, down_cmds: vec![] }))
}

/// 按当前配置对齐 TUN 状态（保存配置 / 启动时调用）。
///
/// 注意：不持有 `MutexGuard` 跨 await——启动的异步步骤（DNS 解析、
/// netstack 启动）在锁外执行，完成后短暂加锁登记。
pub async fn apply(state: Arc<AppState>) {
    let cfg = state.config.read().await.tun.clone();

    // 决策阶段（持锁，无 await）。
    enum Action {
        Start,
        Stop,
        None,
    }
    let action = {
        let m = manager();
        let g = m.lock().unwrap_or_else(|e| e.into_inner());
        if cfg.enable && g.shared.is_none() {
            Action::Start
        } else if !cfg.enable && g.shared.is_some() {
            Action::Stop
        } else {
            Action::None
        }
    };

    match action {
        Action::Start => match start(state, &cfg).await {
            Ok((shared, down)) => {
                let m = manager();
                let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
                if g.shared.is_some() {
                    // 并发触发的重复启动：先回滚本次结果再登记旧实例。
                    routes::execute(&down);
                    return;
                }
                g.shared = Some(shared);
                g.down_cmds = down;
                log::info!("TUN 已启用");
            }
            Err(e) => log::error!("TUN 启动失败（已回滚）: {e}"),
        },
        Action::Stop => {
            let m = manager();
            let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
            stop_inner(&mut g);
            log::info!("TUN 已停止，路由已回滚");
        }
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

    // 5. 协议栈 + 事件泵。
    let (ev_tx, ev_rx) = std::sync::mpsc::channel::<netstack::FlowEvent>();
    let shared = netstack::spawn(tun_dev, cfg.clone(), ev_tx);
    let env = OutboundEnv {
        physical_if: Some(phys.if_index),
        nameservers: cfg.direct_nameservers.clone(),
    };
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

fn stop_inner(m: &mut TunManager) {
    routes::execute(&m.down_cmds);
    m.down_cmds.clear();
    m.shared = None; // 丢弃共享句柄 → 通道关闭 → 协议栈线程退出 → 网卡关闭
}

/// 进程退出/重启前的同步回滚（不经 tokio，保证顺序执行）。
pub fn stop_before_exit() {
    let mut m = match manager().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if m.shared.is_some() {
        stop_inner(&mut m);
        log::info!("TUN 已在进程重启前停止");
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
}
