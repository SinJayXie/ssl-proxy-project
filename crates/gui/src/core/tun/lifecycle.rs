//! TUN 生命周期状态机与能力门控（fail-closed）。
//!
//! 对应 Verge `core/runstate/health.rs:61-102` 的 tun_capable 检测和
//! `core/manager/state.rs:29-44` 的"非管理员强制关闭 TUN"。核心原则：
//! - 能力未知或不足时，TUN 必须保持关闭（fail-closed），不得半开残留路由；
//! - 启动/停止不对称的副作用（路由、DNS）必须由状态机统一编排；
//! - 构造失败时对称回滚。
//!
//! 真正的网卡/路由 syscall 由后续设备层实现；本模块先定型状态转换规则。

/// TUN 能力来源。当前项目尚未引入 Windows Service，因此服务路径预留。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunCapability {
    /// 以管理员身份运行，可创建网卡与改路由。
    Admin,
    /// Windows Service 可用（SYSTEM 权限），预留。
    Service,
    /// 无能力：TUN 不可用。
    None,
}

impl TunCapability {
    pub fn is_capable(&self) -> bool {
        matches!(self, TunCapability::Admin | TunCapability::Service)
    }
}

/// TUN 运行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunState {
    /// 关闭（默认 / 能力不足 / 已回滚）。
    Disabled,
    /// 已通过能力检测，准备启动。
    Ready,
    /// 运行中（网卡与路由已建立）。
    Running,
    /// 启动失败，正在或已经回滚。
    Failed,
}

/// 能力门控：能力不足时强制关闭。返回是否允许启用 TUN。
///
/// `requested` 为用户是否请求开启；`capability` 为当前进程能力。
pub fn gate_tun_enable(requested: bool, capability: TunCapability) -> bool {
    requested && capability.is_capable()
}

/// 启动转换：能力不足时不得离开 Disabled（fail-closed）。
pub fn transition_start(state: TunState, capability: TunCapability) -> TunState {
    match state {
        TunState::Disabled if capability.is_capable() => TunState::Ready,
        TunState::Disabled => TunState::Disabled, // 无能力：保持关闭
        other => other,
    }
}

/// 就绪 → 运行：仅在 Ready 状态且设备层报告成功后调用。
pub fn transition_running(state: TunState, device_ok: bool) -> TunState {
    if state == TunState::Ready && device_ok {
        TunState::Running
    } else if state == TunState::Ready {
        TunState::Failed
    } else {
        state
    }
}

/// 停止/回滚：任何状态都应能回到 Disabled，保证退出时不残留。
pub fn transition_stop(_state: TunState) -> TunState {
    TunState::Disabled
}

/// 启动失败时必须回滚到 Disabled，而不是停在 Failed 残留半开状态。
pub fn rollback_on_failure(state: TunState) -> TunState {
    match state {
        TunState::Failed | TunState::Ready => TunState::Disabled,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_detection() {
        assert!(TunCapability::Admin.is_capable());
        assert!(TunCapability::Service.is_capable());
        assert!(!TunCapability::None.is_capable());
    }

    #[test]
    fn no_capability_cannot_enable() {
        assert!(!gate_tun_enable(true, TunCapability::None));
        assert!(gate_tun_enable(true, TunCapability::Admin));
        assert!(gate_tun_enable(true, TunCapability::Service));
        assert!(!gate_tun_enable(false, TunCapability::Admin));
    }

    #[test]
    fn start_fails_closed_without_capability() {
        assert_eq!(
            transition_start(TunState::Disabled, TunCapability::None),
            TunState::Disabled
        );
        assert_eq!(
            transition_start(TunState::Disabled, TunCapability::Admin),
            TunState::Ready
        );
    }

    #[test]
    fn device_failure_marks_failed_then_rolls_back() {
        let failed = transition_running(TunState::Ready, false);
        assert_eq!(failed, TunState::Failed);
        assert_eq!(rollback_on_failure(failed), TunState::Disabled);
    }

    #[test]
    fn successful_start_reaches_running() {
        assert_eq!(transition_running(TunState::Ready, true), TunState::Running);
    }

    #[test]
    fn any_state_can_stop_to_disabled() {
        for state in [
            TunState::Disabled,
            TunState::Ready,
            TunState::Running,
            TunState::Failed,
        ] {
            assert_eq!(transition_stop(state), TunState::Disabled);
        }
    }

    #[test]
    fn running_state_is_not_rolled_back_by_failure_hook() {
        // 已运行的实例失败应由显式 stop 处理，回滚钩子只处理启动阶段。
        assert_eq!(rollback_on_failure(TunState::Running), TunState::Running);
    }
}
