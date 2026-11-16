//! TUN 路由安全：防自环、代理节点自动排除、接口探测校验。
//!
//! 对应 mihomo `listener/sing_tun/server.go:614-643`（接口查找防自环）与
//! `12.5.4`（Mihomo 不会自动排除代理节点 IP，需增强）。这些是纯函数，
//! 真正的 syscall（写路由表 / setsockopt）由后续设备层执行，但**决策**在这里
//! 定型并可测试——避免把安全不变量散落到平台代码里。

use std::net::IpAddr;

/// 接口探测结果。失败时用确定无效值，绝不返回 TUN 自身。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceProbe {
    /// 探测到可用的物理接口名。
    Physical(String),
    /// 无效：探测失败，调用方应让拨号失败（fail-closed），不得回环进 TUN。
    Invalid,
}

impl InterfaceProbe {
    pub fn name(&self) -> Option<&str> {
        match self {
            InterfaceProbe::Physical(name) => Some(name),
            InterfaceProbe::Invalid => None,
        }
    }
}

/// 模拟 mihomo `FindInterfaceName` 的防自环判定。
///
/// 输入：按优先级排序的候选接口名（已由平台层按目的地址/默认路由查出）与
/// TUN 设备名。规则：
/// 1. 空 / `<nil>` / TUN 自身一律丢弃；
/// 2. 第一个有效候选作为物理出口；
/// 3. 全无效返回 Invalid（注释语义："to avoid lookback"）。
pub fn pick_physical_interface(candidates: &[&str], tun_device: &str) -> InterfaceProbe {
    for name in candidates {
        let trimmed = name.trim();
        let rejected = trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("<nil>")
            || trimmed.eq_ignore_ascii_case("<invalid>")
            || trimmed.eq_ignore_ascii_case(tun_device);
        if !rejected {
            return InterfaceProbe::Physical(trimmed.to_string());
        }
    }
    InterfaceProbe::Invalid
}

/// 判断目标 IP 是否属于"必须直连、绝不进隧道"的地址段。
/// 覆盖私网、loopback、链路本地、未指定、多播、IPv4 共享地址（100.64/10）。
/// 防止代理服务端 SSRF，以及本机服务绕远路。
pub fn must_direct_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || is_benchmarking(v4)
                || v4.is_documentation()
                || is_carrier_grade_nat(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
        }
    }
}

/// IPv4 198.18.0.0/15（基准测试段，`Ipv4Addr::is_benchmarking` 尚不稳定）。
/// fake-ip 池即取自该段，但 fake-ip 在进入本函数前必须已被反查为域名，
/// 否则应被拒绝（见 dns::resolve_fake_ip）。
fn is_benchmarking(v4: &std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// IPv4 100.64.0.0/10（运营商级 NAT）必须直连，不应交给远端代理。
fn is_carrier_grade_nat(v4: &std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// 把代理节点的出口 IP 加入 TUN 排除网段，防止隧道出站包再次进入 TUN 形成自环。
///
/// - 单个 IPv4 → `<ip>/32`，IPv6 → `<ip>/128`；
/// - 已是 CIDR 的地址原样保留（用户可能配置了一个网段）；
/// - 域名不入此列表（域名解析出的 IP 由 resolver 层处理）：调用方应在
///   `proxy-server-nameserver` 解析后用真实 IP 调用本函数；
/// - 去重后排序，保证热重载 `equal` 稳定。
pub fn build_route_excludes(proxy_ips: &[String], extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = extra.to_vec();
    for ip in proxy_ips {
        let value = ip.trim();
        if value.is_empty() {
            continue;
        }
        let normalized = if value.contains('/') {
            value.to_string()
        } else {
            match value.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => format!("{}/32", value),
                Ok(IpAddr::V6(_)) => format!("{}/128", value),
                Err(_) => continue, // 域名或非 IP：跳过，交给 DNS 层
            }
        };
        out.push(normalized);
    }
    out.sort();
    out.dedup();
    out
}

/// 出站 socket 是否应绑定物理接口。loopback 目标不绑定（绑定会失败）；
/// 其余 DIRECT / PROXY 出站都应绑定，避免再次被 TUN 默认路由捕获。
pub fn should_bind_physical_interface(target: &IpAddr) -> bool {
    !target.is_loopback() && !target.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn interface_probe_rejects_tun_itself() {
        let probe = pick_physical_interface(&["SSLProxy", "Ethernet"], "SSLProxy");
        assert_eq!(probe, InterfaceProbe::Physical("Ethernet".into()));
        assert_eq!(probe.name(), Some("Ethernet"));
    }

    #[test]
    fn interface_probe_rejects_nil_and_empty() {
        let probe = pick_physical_interface(&["<nil>", "", "  "], "SSLProxy");
        assert_eq!(probe, InterfaceProbe::Invalid);
        assert_eq!(probe.name(), None);
    }

    #[test]
    fn interface_probe_all_tun_fails_closed() {
        // 宁可返回无效值让拨号失败，也不能返回 TUN 自己形成环路。
        let probe = pick_physical_interface(&["SSLProxy", "<invalid>"], "SSLProxy");
        assert_eq!(probe, InterfaceProbe::Invalid);
    }

    #[test]
    fn private_and_loopback_ips_must_direct() {
        for s in [
            "127.0.0.1",
            "192.168.1.10",
            "10.0.0.1",
            "172.16.5.4",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(must_direct_ip(&ip(s)), "{} should be direct", s);
        }
    }

    #[test]
    fn public_ips_not_forced_direct() {
        for s in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(!must_direct_ip(&ip(s)), "{} should be proxyable", s);
        }
    }

    #[test]
    fn carrier_grade_nat_boundary() {
        assert!(must_direct_ip(&ip("100.64.0.0")));
        assert!(must_direct_ip(&ip("100.127.255.255")));
        assert!(!must_direct_ip(&ip("100.63.255.255")));
        assert!(!must_direct_ip(&ip("100.128.0.0")));
    }

    #[test]
    fn build_excludes_auto_adds_proxy_ip_and_dedups() {
        let excludes = build_route_excludes(
            &["1.2.3.4".into(), "1.2.3.4".into(), "2001:db8::1".into()],
            &["192.168.0.0/16".into()],
        );
        assert_eq!(
            excludes,
            vec![
                "1.2.3.4/32".to_string(),
                "192.168.0.0/16".to_string(),
                "2001:db8::1/128".to_string(),
            ]
        );
    }

    #[test]
    fn build_excludes_skips_domain_and_keeps_cidr() {
        let excludes = build_route_excludes(&["example.com".into(), "10.0.0.0/8".into()], &[]);
        assert_eq!(excludes, vec!["10.0.0.0/8".to_string()]);
    }

    #[test]
    fn loopback_target_skips_binding() {
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert!(!should_bind_physical_interface(&v4));
        assert!(!should_bind_physical_interface(&v6));
        assert!(!should_bind_physical_interface(&unspecified));
        assert!(should_bind_physical_interface(&ip("8.8.8.8")));
    }
}
