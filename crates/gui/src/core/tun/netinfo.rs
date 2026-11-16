//! 物理网卡探测（Windows IpHelper）。
//!
//! **必须在安装 TUN 路由之前调用**：默认路由指向 TUN 后，`GetBestRoute`
//! 只会返回 TUN 自己。探测结果（物理接口索引 + 网关）供：
//! - 直连出站 `bind_device_by_index`（防 TUN 自环）；
//! - 代理节点 IP 的路由例外（走物理网关而非 TUN）。
//!
//! fail-closed：探测失败返回 `None`，调用方应中止启用 TUN。

/// 一次 GetBestRoute 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRoute {
    /// 出接口索引（IP_UNICAST_IF / bind_device_by_index 用）。
    pub if_index: u32,
    /// 下一跳网关（路由例外命令用）。
    pub gateway: std::net::Ipv4Addr,
}

/// 探测到达 `ip` 的物理路由。TUN 路由尚未安装时返回真实物理路径。
pub fn find_route_to(ip: std::net::Ipv4Addr) -> Option<PhysicalRoute> {
    #[cfg(target_os = "windows")]
    {
        imp::get_best_route(u32::from(ip)).map(|(if_index, gw_u32)| PhysicalRoute {
            if_index,
            gateway: std::net::Ipv4Addr::from(gw_u32),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = ip;
        None
    }
}

/// 安全不变量：探测结果不得是 TUN 自身（否则出站全部自环）。
pub fn validate_physical(route: &PhysicalRoute, tun_if_index: u32) -> Result<(), String> {
    if route.if_index == tun_if_index {
        return Err(format!(
            "接口探测返回 TUN 自身（ifIndex {}），拒绝启用以防自环",
            tun_if_index
        ));
    }
    if route.gateway.is_unspecified() {
        return Err("物理网关无效（未指定）".into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
mod imp {
    use windows::Win32::NetworkManagement::IpHelper::GetBestRoute;
    use windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARDROW;

    /// 返回 (ifIndex, gateway u32 network-order)。
    pub(super) fn get_best_route(dest: u32) -> Option<(u32, u32)> {
        let mut row = MIB_IPFORWARDROW::default();
        // dwDestAddr/dwSourceAddr 均为 network byte order 的 u32；source 0 表示任意。
        let rc = unsafe { GetBestRoute(dest, 0, &mut row) };
        if rc != 0 {
            return None;
        }
        Some((row.dwForwardIfIndex, row.dwForwardNextHop))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_tun_interface() {
        let r = PhysicalRoute {
            if_index: 42,
            gateway: "192.168.1.1".parse().unwrap(),
        };
        assert!(validate_physical(&r, 42).is_err());
    }

    #[test]
    fn validate_rejects_unspecified_gateway() {
        let r = PhysicalRoute {
            if_index: 7,
            gateway: "0.0.0.0".parse().unwrap(),
        };
        assert!(validate_physical(&r, 42).is_err());
    }

    #[test]
    fn validate_accepts_real_route() {
        let r = PhysicalRoute {
            if_index: 7,
            gateway: "192.168.1.1".parse().unwrap(),
        };
        assert!(validate_physical(&r, 42).is_ok());
    }
}
