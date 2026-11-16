//! TUN 系统路由的生成与执行（Windows `route` 命令）。
//!
//! 设计对应研究方案 12.5/12.6：
//! - 默认路由指向 TUN（metric 100，低优先级）；
//! - 代理节点 IP 与私网段写成指向**物理网关**的 metric 1 主机路由，
//!   保证隧道出站与直连出站绝不二次进入 TUN（防自环死锁）；
//! - down 程序与 up 对称，崩溃/退出时由 runner 按序回滚。
//!
//! 命令生成是纯函数（可测）；`execute` 只负责跑 `route.exe`。

use super::config::TunConfig;
use super::netinfo::PhysicalRoute;
use std::net::Ipv4Addr;

/// 一组上下对称的路由命令（`route add …` / `route delete …`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProgram {
    pub up: Vec<String>,
    pub down: Vec<String>,
}

/// 无论如何都必须绕过 TUN 的地址（用户态协议栈无法处理或会自环）：
/// loopback、链路本地（ARP/DHCP/云元数据）、多播（mDNS/SSDP）。
pub fn always_excludes() -> Vec<String> {
    vec![
        "127.0.0.0/8".into(),
        "169.254.0.0/16".into(),
        "224.0.0.0/4".into(),
    ]
}

/// 私网/CGNAT 网段：仅兼容模式（strict_route=false）在路由层绕过 TUN。
/// strict 模式下这些流量必须进 TUN 经分流引擎判定（由 `outbound::decide_for_tun`
/// 的 `must_direct_ip` 保证其 DIRECT，不会误走代理）。
pub fn private_excludes() -> Vec<String> {
    vec![
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "100.64.0.0/10".into(),
    ]
}

/// 兼容模式的完整默认例外（= must + private）。
pub fn default_v4_excludes() -> Vec<String> {
    let mut out = always_excludes();
    out.extend(private_excludes());
    out
}

/// 按 strict_route 计算最终路由例外。
///
/// - `base`：代理节点 IP + 用户显式配置的 `route-exclude-address`（始终保留）；
/// - 兼容模式追加私网段（局域网不进 TUN，性能好）；
/// - 严格模式不追加私网段（所有流量进 TUN，杜绝绕过分流与 DNS 劫持）。
pub fn effective_excludes(strict_route: bool, base: &[String]) -> Vec<String> {
    let mut out = base.to_vec();
    out.extend(always_excludes());
    if !strict_route {
        out.extend(private_excludes());
    }
    out.sort();
    out.dedup();
    out
}

/// `prefix_len` → 子网掩码。
pub fn cidr_to_mask(prefix: u8) -> Ipv4Addr {
    let v = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    Ipv4Addr::from(v)
}

/// 解析 CIDR 列表，仅保留 IPv4 项（IPv6 路由本阶段暂不支持，静默跳过）。
pub fn parse_v4_cidrs(cidrs: &[String]) -> Vec<(Ipv4Addr, u8)> {
    cidrs
        .iter()
        .filter_map(|s| {
            let (addr, prefix) = s.split_once('/')?;
            let addr: Ipv4Addr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            (prefix <= 32).then_some((addr, prefix))
        })
        .collect()
}

/// 生成 up/down 路由程序。
///
/// - `tun_gateway`：TUN 自身地址（198.18.0.1），默认路由下一跳；
/// - `physical`：装路由**之前**探测的物理接口/网关；
/// - `excludes`：需绕过 TUN 的基集网段（代理节点 IP + 用户显式排除，来自
///   [`super::route::build_route_excludes`]）；函数内部按 `tun.strict_route`
///   调用 [`effective_excludes`] 决定是否追加私网段。
pub fn build_program(
    tun: &TunConfig,
    tun_if_index: u32,
    tun_gateway: Ipv4Addr,
    physical: &PhysicalRoute,
    excludes: &[String],
) -> RouteProgram {
    let mut up = Vec::new();
    let mut down = Vec::new();
    // 按 strict_route 决定私网段是否写例外（严格模式不写 → 私网流量也进 TUN）。
    let excludes = effective_excludes(tun.strict_route, excludes);

    // 默认路由 → TUN。metric 100 低于所有例外路由（metric 1）。
    let default = format!(
        "route add 0.0.0.0 mask 0.0.0.0 {tun_gateway} metric 100 if {tun_if_index}"
    );
    up.push(default);
    down.push(format!(
        "route delete 0.0.0.0 mask 0.0.0.0 {tun_gateway}"
    ));

    // 例外：指向物理网关，metric 1 必胜 TUN 默认路由。
    for (addr, prefix) in parse_v4_cidrs(&excludes) {
        let mask = cidr_to_mask(prefix);
        up.push(format!(
            "route add {addr} mask {mask} {} metric 1 if {}",
            physical.gateway, physical.if_index
        ));
        down.push(format!(
            "route delete {addr} mask {mask} {}",
            physical.gateway
        ));
    }

    RouteProgram { up, down }
}

/// 执行路由命令，返回失败的命令（fail-closed：up 有失败应中止启用）。
pub fn execute(cmds: &[String]) -> Vec<(String, String)> {
    let mut failures = Vec::new();
    for cmd in cmds {
        let mut parts = cmd.split_whitespace();
        let (program, args) = match (parts.next(), parts.collect::<Vec<_>>()) {
            (Some(p), a) if !a.is_empty() => (p, a),
            _ => continue,
        };
        let out = std::process::Command::new(program).args(&args).output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                // route.exe 把错误写在 stdout（stderr 常为空），两者都收。
                let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let msg = if stderr.is_empty() { stdout } else { stderr };
                failures.push((cmd.clone(), msg));
            }
            Err(e) => failures.push((cmd.clone(), e.to_string())),
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tun::config::TunConfig;

    fn physical() -> PhysicalRoute {
        PhysicalRoute {
            if_index: 12,
            gateway: "192.168.1.1".parse().unwrap(),
            local_ipv4: None,
        }
    }

    #[test]
    fn cidr_mask_math() {
        assert_eq!(cidr_to_mask(8).to_string(), "255.0.0.0");
        assert_eq!(cidr_to_mask(24).to_string(), "255.255.255.0");
        assert_eq!(cidr_to_mask(32).to_string(), "255.255.255.255");
        assert_eq!(cidr_to_mask(10).to_string(), "255.192.0.0");
    }

    #[test]
    fn program_routes_tunnel_default_and_excludes_physical() {
        let tun = TunConfig::default();
        let excludes = vec!["1.2.3.4/32".to_string(), "10.0.0.0/8".to_string()];
        let prog = build_program(&tun, 77, "198.18.0.1".parse().unwrap(), &physical(), &excludes);

        assert!(prog.up.iter().any(|c| c.contains("route add 0.0.0.0 mask 0.0.0.0 198.18.0.1 metric 100 if 77")));
        // 例外走物理网关 + metric 1。
        assert!(prog.up.iter().any(|c| c.contains("route add 1.2.3.4 mask 255.255.255.255 192.168.1.1 metric 1 if 12")));
        assert!(prog.up.iter().any(|c| c.contains("route add 10.0.0.0 mask 255.0.0.0 192.168.1.1 metric 1 if 12")));
        // down 对称删除。
        assert!(prog.down.iter().any(|c| c.contains("route delete 0.0.0.0 mask 0.0.0.0 198.18.0.1")));
        assert!(prog.down.iter().any(|c| c.contains("route delete 1.2.3.4 mask 255.255.255.255 192.168.1.1")));
    }

    #[test]
    fn parse_v4_skips_ipv6_and_garbage() {
        let got = parse_v4_cidrs(&[
            "1.2.3.4/32".into(),
            "2001:db8::/64".into(),
            "bad".into(),
            "1.2.3.4/99".into(),
        ]);
        assert_eq!(got, vec![("1.2.3.4".parse().unwrap(), 32)]);
    }

    #[test]
    fn default_excludes_cover_private_space() {
        let e = default_v4_excludes();
        assert!(e.contains(&"192.168.0.0/16".to_string()));
        assert!(e.contains(&"100.64.0.0/10".to_string()));
    }

    #[test]
    fn strict_route_excludes_private_but_keeps_must_excludes() {
        let base = vec!["1.2.3.4/32".to_string()];
        let strict = effective_excludes(true, &base);
        let compat = effective_excludes(false, &base);

        // 代理节点 IP 两种模式都排除（防自环）。
        assert!(strict.contains(&"1.2.3.4/32".to_string()));
        assert!(compat.contains(&"1.2.3.4/32".to_string()));
        // 必须例外两种模式都有（协议栈无法处理）。
        assert!(strict.contains(&"127.0.0.0/8".to_string()));
        assert!(strict.contains(&"169.254.0.0/16".to_string()));
        assert!(strict.contains(&"224.0.0.0/4".to_string()));
        // 关键差异：严格模式不把私网段写成路由例外（流量进 TUN 经分流引擎）。
        assert!(!strict.contains(&"192.168.0.0/16".to_string()));
        assert!(!strict.contains(&"10.0.0.0/8".to_string()));
        assert!(compat.contains(&"192.168.0.0/16".to_string()));
        assert!(compat.contains(&"10.0.0.0/8".to_string()));
    }

    #[test]
    fn program_honors_strict_route_flag() {
        let strict = TunConfig {
            strict_route: true,
            ..Default::default()
        };
        let prog = build_program(&strict, 77, "198.18.0.1".parse().unwrap(), &physical(), &[]);
        // 严格模式：私网不写例外 → 下表中没有 192.168.0.0 的 add。
        assert!(!prog.up.iter().any(|c| c.contains("route add 192.168.0.0")));
        // 必须例外仍在。
        assert!(prog.up.iter().any(|c| c.contains("route add 127.0.0.0")));

        let compat = TunConfig {
            strict_route: false,
            ..Default::default()
        };
        let prog = build_program(&compat, 77, "198.18.0.1".parse().unwrap(), &physical(), &[]);
        assert!(prog.up.iter().any(|c| c.contains("route add 192.168.0.0")));
    }
}
