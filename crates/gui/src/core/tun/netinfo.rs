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
    /// 该接口的 IPv4 地址。直连 socket 必须绑定它：仅设 IP_UNICAST_IF 时
    /// Windows 仍可能按主路由表选中 TUN 地址作为源地址，包从物理网卡
    /// 发出后源地址不可达（表现为 SYN 超时 10060）。
    pub local_ipv4: Option<std::net::Ipv4Addr>,
}

/// 探测到达 `ip` 的物理路由。TUN 路由尚未安装时返回真实物理路径。
pub fn find_route_to(ip: std::net::Ipv4Addr) -> Option<PhysicalRoute> {
    #[cfg(target_os = "windows")]
    {
        imp::get_best_route(u32::from(ip).to_be()).map(|(if_index, gw_u32)| PhysicalRoute {
            if_index,
            gateway: next_hop_to_ipv4(gw_u32),
            local_ipv4: imp::local_ipv4_for_if(if_index),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = ip;
        None
    }
}

/// 把 IpHelper 返回的下一跳（**网络字节序** u32）转成地址。
///
/// `Ipv4Addr::from(u32)` 按主机字节序解释，直接传会把 192.168.2.1 变成
/// 1.2.168.192（字节倒置），进而让 `route add <网段> <网关>` 失败。
pub fn next_hop_to_ipv4(raw: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(u32::from_be(raw))
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

    /// 取指定接口的第一个 IPv4 单播地址（直连 socket 的源地址）。
    pub(super) fn local_ipv4_for_if(if_index: u32) -> Option<std::net::Ipv4Addr> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            GetAdaptersAddresses, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

        const ERROR_BUFFER_OVERFLOW: u32 = 111;
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
            GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_SKIP_DNS_SERVER.0,
        );

        let mut size: u32 = 16 * 1024;
        for _ in 0..2 {
            let mut buf = vec![0u8; size as usize];
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_INET.0 as u32,
                    flags,
                    None,
                    Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                    &mut size,
                )
            };
            if rc == ERROR_BUFFER_OVERFLOW {
                continue; // size 已被更新为所需长度
            }
            if rc != 0 {
                return None;
            }

            let mut cursor = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !cursor.is_null() {
                let adapter = unsafe { &*cursor };
                if unsafe { adapter.Anonymous1.Anonymous.IfIndex } == if_index {
                    let mut unicast = adapter.FirstUnicastAddress;
                    while !unicast.is_null() {
                        let ua = unsafe { &*unicast };
                        let sockaddr = unsafe { &*ua.Address.lpSockaddr };
                        if sockaddr.sa_family == AF_INET {
                            let sin = unsafe { &*(ua.Address.lpSockaddr as *const SOCKADDR_IN) };
                            let ip = std::net::Ipv4Addr::from(u32::from_be(unsafe {
                                sin.sin_addr.S_un.S_addr
                            }));
                            if !ip.is_unspecified() && !ip.is_loopback() {
                                return Some(ip);
                            }
                        }
                        unicast = ua.Next;
                    }
                }
                cursor = adapter.Next;
            }
            return None;
        }
        None
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
            local_ipv4: None,
        };
        assert!(validate_physical(&r, 42).is_err());
    }

    #[test]
    fn validate_rejects_unspecified_gateway() {
        let r = PhysicalRoute {
            if_index: 7,
            gateway: "0.0.0.0".parse().unwrap(),
            local_ipv4: None,
        };
        assert!(validate_physical(&r, 42).is_err());
    }

    #[test]
    fn validate_accepts_real_route() {
        let r = PhysicalRoute {
            if_index: 7,
            gateway: "192.168.1.1".parse().unwrap(),
            local_ipv4: None,
        };
        assert!(validate_physical(&r, 42).is_ok());
    }

    #[test]
    fn next_hop_uses_network_byte_order() {
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        // IpHelper 返回 0x0102A8C0 表示 192.168.2.1（网络字节序），
        // 直接 Ipv4Addr::from 会得到 1.2.168.192。
        assert_eq!(next_hop_to_ipv4(0x0102_A8C0), ip("192.168.2.1"));
        // 10.0.0.1 的字节为 0A 00 00 01，小端读成 u32 是 0x0100_000A。
        assert_eq!(next_hop_to_ipv4(0x0100_000A), ip("10.0.0.1"));
        // 对称地址不受影响。
        assert_eq!(next_hop_to_ipv4(0x0808_0808), ip("8.8.8.8"));
    }
}
