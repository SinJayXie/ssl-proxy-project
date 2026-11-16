//! TUN 配置模型与归一化。
//!
//! 对应 mihomo `listener/config/tun.go` 与 Verge 的默认模板。首版只包含
//! Windows TUN 真正需要的字段；重点是 `sort`/`equal`（热重载判定）与
//! CIDR 校验——避免"只改了列表顺序就重建网卡引发断网抖动"。
//!
//! 注意：本模块只负责配置与控制面逻辑，不创建任何网卡（设备层尚未接入）。

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// TUN 用户态协议栈。Windows 推荐 smoltcp / gvisor；system 在 Windows 意义有限。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunStack {
    System,
    Gvisor,
    Smoltcp,
}

impl Default for TunStack {
    fn default() -> Self {
        TunStack::Smoltcp
    }
}

impl TunStack {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunStack::System => "system",
            TunStack::Gvisor => "gvisor",
            TunStack::Smoltcp => "smoltcp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "system" => Some(TunStack::System),
            "gvisor" => Some(TunStack::Gvisor),
            "smoltcp" => Some(TunStack::Smoltcp),
            _ => None,
        }
    }
}

/// TUN 运行时配置。默认关闭，启用与否由 setting.yaml 的 tun 段决定。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TunConfig {
    pub enable: bool,
    pub stack: TunStack,
    pub device_name: String,
    pub mtu: u16,
    /// 自动把全网段路由指向 TUN。
    pub auto_route: bool,
    /// 严格路由：兼容优先时为 false，追求必不泄漏时为 true。
    pub strict_route: bool,
    /// 探测带默认网关的物理网卡作为 DIRECT 出口。
    pub auto_detect_interface: bool,
    /// DNS 劫持目标，如 "any:53" / "198.18.0.2:53"。
    pub dns_hijack: Vec<String>,
    /// 排除网段：这些网段不进 TUN，直接走物理网卡。
    pub route_exclude_address: Vec<String>,
    /// fake-ip IPv4 池（TUN 网关取该段的下一跳）。
    pub fake_ip_range: String,
    /// fake-ip IPv6 池；IPv6 关闭或不可用时清空。
    pub fake_ip_range6: String,
    /// TUN 直连出站的专用解析 DNS（绑定物理网卡查询，绕开自身劫持）。
    pub direct_nameservers: Vec<String>,
}

/// 默认 fake-ip 段，与 mihomo 一致：网关 198.18.0.1，DNS 198.18.0.2。
pub const DEFAULT_FAKE_IP_RANGE: &str = "198.18.0.1/16";
pub const DEFAULT_FAKE_IP_RANGE6: &str = "2001:2::0/64";

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enable: false,
            stack: TunStack::default(),
            device_name: "SSLProxy".to_string(),
            mtu: 1500,
            auto_route: true,
            strict_route: false,
            auto_detect_interface: true,
            dns_hijack: vec!["any:53".to_string()],
            route_exclude_address: Vec::new(),
            fake_ip_range: DEFAULT_FAKE_IP_RANGE.to_string(),
            fake_ip_range6: DEFAULT_FAKE_IP_RANGE6.to_string(),
            direct_nameservers: vec!["223.5.5.5".to_string(), "119.29.29.29".to_string()],
        }
    }
}

impl TunConfig {
    /// 归一化列表顺序（CIDR / 劫持目标排序去重），供 `equal` 做热重载判定。
    pub fn sort(&mut self) {
        self.route_exclude_address.sort();
        self.route_exclude_address.dedup();
        self.dns_hijack.sort();
        self.dns_hijack.dedup();
    }

    /// 语义相等：先各自排序再比较，列表顺序差异不会触发网卡重建。
    pub fn equal(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.sort();
        b.sort();
        a == b
    }

    /// 校验所有 CIDR 字段与 DNS 劫持目标格式。返回第一个错误。
    pub fn validate(&self) -> Result<(), String> {
        if !(576..=9000).contains(&self.mtu) {
            return Err(format!("tun.mtu out of range: {}", self.mtu));
        }
        if self.device_name.trim().is_empty() {
            return Err("tun.device_name must not be empty".to_string());
        }
        validate_cidr(&self.fake_ip_range).map_err(|e| format!("tun.fake-ip-range: {}", e))?;
        if !self.fake_ip_range6.trim().is_empty() {
            validate_cidr(&self.fake_ip_range6)
                .map_err(|e| format!("tun.fake-ip-range6: {}", e))?;
        }
        for cidr in &self.route_exclude_address {
            validate_cidr(cidr)
                .map_err(|e| format!("tun.route-exclude-address {}: {}", cidr, e))?;
        }
        for target in &self.dns_hijack {
            validate_dns_hijack(target).map_err(|e| format!("tun.dns-hijack {}: {}", target, e))?;
        }
        // strict-route 把全部流量赶进 TUN。若不同时劫持 DNS，应用会先解析到
        // 真实 IP，域名规则退化为 IP 规则，DNS 查询本身也可能绕过分流。
        if self.strict_route && self.dns_hijack.is_empty() {
            return Err("tun.strict-route requires non-empty tun.dns-hijack".to_string());
        }
        Ok(())
    }
}

/// 校验 CIDR：必须包含 '/'，地址可解析，前缀长度在地址族范围内。
pub fn validate_cidr(value: &str) -> Result<(), String> {
    let (addr, prefix) = value
        .split_once('/')
        .ok_or_else(|| "missing '/' separator".to_string())?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("invalid prefix: {}", prefix))?;
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) if prefix <= 32 => Ok(()),
        Ok(IpAddr::V4(_)) => Err(format!("IPv4 prefix {} > 32", prefix)),
        Ok(IpAddr::V6(_)) if prefix <= 128 => Ok(()),
        Ok(IpAddr::V6(_)) => Err(format!("IPv6 prefix {} > 128", prefix)),
        Err(_) => Err(format!("invalid IP address: {}", addr)),
    }
}

/// 校验 DNS 劫持目标："any:53" / "0.0.0.0:53" / "198.18.0.2:53" / "[::]:53"。
pub fn validate_dns_hijack(value: &str) -> Result<(), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| "missing ':' separator".to_string())?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid port: {}", port))?;
    if port == 0 {
        return Err("port must not be 0".to_string());
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("any") || host.is_empty() || host == "0.0.0.0" || host == "::" {
        return Ok(());
    }
    host.parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("invalid host: {}", host))
}

/// 从 fake-ip 池推导 TUN 网关与 DNS 地址（取网络地址 +1 / +2，前缀 /30）。
/// 对应 mihomo config/config.go:1687-1707 的行为。
pub fn tun_gateway_from_fake_ip(fake_range: &str) -> Result<(String, String), String> {
    validate_cidr(fake_range)?;
    let (addr, _) = fake_range.split_once('/').unwrap();
    let ip: IpAddr = addr.parse().unwrap();
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let gw = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3].max(1));
            let dns = Ipv4Addr::from(u32::from(gw).saturating_add(1));
            Ok((gw.to_string(), dns.to_string()))
        }
        IpAddr::V6(v6) => {
            let gw = v6;
            let mut seg = gw.segments();
            let last = seg[7].saturating_add(1);
            seg[7] = last;
            let dns = Ipv6Addr::from(seg);
            Ok((gw.to_string(), dns.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled_and_valid() {
        let cfg = TunConfig::default();
        assert!(!cfg.enable);
        assert_eq!(cfg.stack, TunStack::Smoltcp);
        assert!(cfg.validate().is_ok(), "{:?}", cfg.validate());
    }

    #[test]
    fn sort_makes_reordered_lists_equal() {
        let mut a = TunConfig::default();
        a.route_exclude_address = vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()];
        let mut b = a.clone();
        b.route_exclude_address.reverse();
        assert_ne!(a.route_exclude_address, b.route_exclude_address);
        assert!(a.equal(&b), "仅列表顺序不同不应触发网卡重建");
    }

    #[test]
    fn equal_detects_real_change() {
        let a = TunConfig::default();
        let mut b = a.clone();
        b.enable = true;
        assert!(!a.equal(&b));
    }

    #[test]
    fn validate_rejects_bad_cidr() {
        assert!(validate_cidr("192.168.1.1").is_err());
        assert!(validate_cidr("192.168.1.0/33").is_err());
        assert!(validate_cidr("999.1.1.1/24").is_err());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("2001:2::/64").is_ok());
        assert!(validate_cidr("2001:2::/129").is_err());
    }

    #[test]
    fn validate_rejects_bad_dns_hijack() {
        assert!(validate_dns_hijack("any:53").is_ok());
        assert!(validate_dns_hijack("198.18.0.2:53").is_ok());
        assert!(validate_dns_hijack("[::]:53").is_ok());
        assert!(validate_dns_hijack("any:0").is_err());
        assert!(validate_dns_hijack("not-an-ip:53").is_err());
        assert!(validate_dns_hijack("any").is_err());
    }

    #[test]
    fn strict_route_requires_dns_hijack() {
        let cfg = TunConfig {
            strict_route: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok(), "默认带 any:53，严格模式应合法");

        let cfg = TunConfig {
            strict_route: true,
            dns_hijack: vec![],
            ..Default::default()
        };
        assert!(cfg.validate().is_err(), "严格模式不劫持 DNS 会让域名规则失效");

        let cfg = TunConfig {
            strict_route: false,
            dns_hijack: vec![],
            ..Default::default()
        };
        assert!(cfg.validate().is_ok(), "兼容模式允许不劫持 DNS");
    }

    #[test]
    fn gateway_derived_from_fake_ip_pool() {
        let (gw, dns) = tun_gateway_from_fake_ip(DEFAULT_FAKE_IP_RANGE).unwrap();
        assert_eq!(gw, "198.18.0.1");
        assert_eq!(dns, "198.18.0.2");
    }

    #[test]
    fn stack_parse_roundtrip() {
        for s in ["system", "gvisor", "smoltcp"] {
            assert_eq!(TunStack::parse(s).unwrap().as_str(), s);
        }
        assert!(TunStack::parse("bogus").is_none());
    }
}
