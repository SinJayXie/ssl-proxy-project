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

/// 默认排除网段（IPv4）：私网/链路本地/多播/CGNAT，不进 TUN。
pub fn default_v4_excludes() -> Vec<String> {
    vec![
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "169.254.0.0/16".into(),
        "100.64.0.0/10".into(),
        "224.0.0.0/4".into(),
    ]
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
/// - `excludes`：需绕过 TUN 的网段（含代理节点 IP，来自
///   [`super::route::build_route_excludes`] 与 [`default_v4_excludes`]）。
pub fn build_program(
    _tun: &TunConfig,
    tun_if_index: u32,
    tun_gateway: Ipv4Addr,
    physical: &PhysicalRoute,
    excludes: &[String],
) -> RouteProgram {
    let mut up = Vec::new();
    let mut down = Vec::new();

    // 默认路由 → TUN。metric 100 低于所有例外路由（metric 1）。
    let default = format!(
        "route add 0.0.0.0 mask 0.0.0.0 {tun_gateway} metric 100 if {tun_if_index}"
    );
    up.push(default);
    down.push(format!(
        "route delete 0.0.0.0 mask 0.0.0.0 {tun_gateway}"
    ));

    // 例外：指向物理网关，metric 1 必胜 TUN 默认路由。
    for (addr, prefix) in parse_v4_cidrs(excludes) {
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
            Ok(o) => failures.push((
                cmd.clone(),
                String::from_utf8_lossy(&o.stderr).trim().to_string(),
            )),
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
}
