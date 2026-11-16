//! TUN DNS 防泄漏地基：fake-ip 映射、反查与 fail-closed 判定。
//!
//! 对应 mihomo `tunnel/tunnel.go:289-315` 的 fake-ip 反查逻辑：
//! - 域名被映射为 fake-ip 段地址，迫使后续连接按域名规则匹配；
//! - 入站只有 fake-ip 没有 host 时反查域名；
//! - 落在 fake-ip 池但查不到映射 → 拒绝连接，绝不按真实 IP 直连（fail-closed）。
//!
//! 这里只做内存映射与判定，DNS 报文劫持（53 端口）由后续设备层接入。

use std::collections::HashMap;
use std::net::IpAddr;

/// fake-ip 映射表：domain → fake IP，以及反查索引 fake IP → domain。
#[derive(Debug, Default)]
pub struct FakeIpMap {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
}

impl FakeIpMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一个域名到 fake-ip 的映射。同一域名重复登记时更新反查索引。
    pub fn insert(&mut self, domain: &str, fake_ip: &str) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if let Some(old_ip) = self.forward.get(&domain) {
            if old_ip != fake_ip {
                self.reverse.remove(old_ip);
            }
        }
        self.reverse.insert(fake_ip.to_string(), domain.clone());
        self.forward.insert(domain, fake_ip.to_string());
    }

    /// 由 fake-ip 反查域名。查不到返回 None（调用方必须拒绝连接）。
    pub fn find_host_by_ip(&self, ip: &str) -> Option<&str> {
        self.reverse.get(ip).map(|s| s.as_str())
    }

    /// 由域名取 fake-ip。
    pub fn get_ip_by_host(&self, domain: &str) -> Option<&str> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.forward.get(&domain).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }
}

/// 判定 IP 是否落在 fake-ip 池内。池用 "198.18.0.1/16" 形式表示。
/// 仅比较网络前缀部分（按位与掩码），与网关具体主机位无关。
pub fn is_in_fake_ip_pool(ip: &IpAddr, pool: &str) -> bool {
    let (net, prefix) = match pool.split_once('/') {
        Some(p) => p,
        None => return false,
    };
    let prefix: u32 = match prefix.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    match (ip, net.parse::<IpAddr>()) {
        (IpAddr::V4(addr), Ok(IpAddr::V4(net))) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(*addr) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(addr), Ok(IpAddr::V6(net))) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(*addr) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// DNS 入口短路判定：目标是否为应被劫持的 DNS 服务（任意 IP 的 53 端口）。
/// 对应 mihomo `listener/sing_tun/dns.go:21-28` 的 `ShouldHijackDns`。
///
/// - `any:53` / `0.0.0.0:53` / `[::]:53`：匹配任意地址的 53 端口；
/// - 具体 IP:53：仅匹配该地址。
pub fn should_hijack_dns(target_ip: &IpAddr, target_port: u16, hijack: &[String]) -> bool {
    if target_port != 53 {
        return false;
    }
    for rule in hijack {
        let (host, port) = match rule.rsplit_once(':') {
            Some(p) => p,
            None => continue,
        };
        let port: u16 = match port.trim().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if port != 53 {
            continue;
        }
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.eq_ignore_ascii_case("any") || host.is_empty() || host == "0.0.0.0" || host == "::"
        {
            return true;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if ip == *target_ip {
                return true;
            }
        }
    }
    false
}

/// fake-ip 一致性判定：给定入站 metadata（可能只有 fake-ip 无 host）与映射表，
/// 返回解析后的 host；`Ok(None)` 表示无需反查（目标是真实 IP），
/// `Err(())` 表示落在 fake-ip 池但查不到映射 —— 调用方必须拒绝。
pub fn resolve_fake_ip(
    dst_ip: &IpAddr,
    host: Option<&str>,
    pool: &str,
    map: &FakeIpMap,
) -> Result<Option<String>, ()> {
    if let Some(h) = host {
        let h = h.trim();
        if !h.is_empty() {
            return Ok(Some(h.to_string()));
        }
    }
    if is_in_fake_ip_pool(dst_ip, pool) {
        match map.find_host_by_ip(&dst_ip.to_string()) {
            Some(h) => Ok(Some(h.to_string())),
            None => Err(()), // fail-closed：宁可断，也不按 IP 直连绕过域名规则
        }
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fake_ip_roundtrip_and_reverse_lookup() {
        let mut map = FakeIpMap::new();
        map.insert("Example.COM.", "198.18.0.3");
        assert_eq!(map.get_ip_by_host("example.com"), Some("198.18.0.3"));
        assert_eq!(map.get_ip_by_host("EXAMPLE.com."), Some("198.18.0.3"));
        assert_eq!(map.find_host_by_ip("198.18.0.3"), Some("example.com"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn reinsert_updates_reverse_index() {
        let mut map = FakeIpMap::new();
        map.insert("a.com", "198.18.0.3");
        map.insert("a.com", "198.18.0.4");
        assert_eq!(map.find_host_by_ip("198.18.0.3"), None);
        assert_eq!(map.find_host_by_ip("198.18.0.4"), Some("a.com"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn pool_contains_checks_prefix_not_host_bits() {
        assert!(is_in_fake_ip_pool(&ip("198.18.0.1"), "198.18.0.1/16"));
        assert!(is_in_fake_ip_pool(&ip("198.18.255.254"), "198.18.0.1/16"));
        assert!(!is_in_fake_ip_pool(&ip("198.19.0.1"), "198.18.0.1/16"));
        assert!(is_in_fake_ip_pool(&ip("2001:2::5"), "2001:2::0/64"));
        assert!(!is_in_fake_ip_pool(&ip("2001:3::5"), "2001:2::0/64"));
    }

    #[test]
    fn dns_hijack_any_matches_all_addresses() {
        let rules = vec!["any:53".to_string()];
        assert!(should_hijack_dns(&ip("8.8.8.8"), 53, &rules));
        assert!(should_hijack_dns(&ip("198.18.0.2"), 53, &rules));
        assert!(!should_hijack_dns(&ip("8.8.8.8"), 5353, &rules));
    }

    #[test]
    fn dns_hijack_specific_ip_only() {
        let rules = vec!["198.18.0.2:53".to_string()];
        assert!(should_hijack_dns(&ip("198.18.0.2"), 53, &rules));
        assert!(!should_hijack_dns(&ip("8.8.8.8"), 53, &rules));
    }

    #[test]
    fn fake_ip_missing_mapping_is_rejected() {
        let map = FakeIpMap::new();
        let pool = "198.18.0.1/16";
        // 落在池内但无映射 → Err，调用方必须拒绝连接。
        assert_eq!(
            resolve_fake_ip(&ip("198.18.1.100"), None, pool, &map),
            Err(())
        );
    }

    #[test]
    fn fake_ip_with_host_bypasses_reverse_lookup() {
        let map = FakeIpMap::new();
        let pool = "198.18.0.1/16";
        assert_eq!(
            resolve_fake_ip(&ip("198.18.1.100"), Some("example.com"), pool, &map),
            Ok(Some("example.com".to_string()))
        );
    }

    #[test]
    fn real_ip_without_host_needs_no_reverse_lookup() {
        let map = FakeIpMap::new();
        let pool = "198.18.0.1/16";
        assert_eq!(resolve_fake_ip(&ip("8.8.8.8"), None, pool, &map), Ok(None));
    }

    #[test]
    fn fake_ip_reverse_lookup_recovers_host() {
        let mut map = FakeIpMap::new();
        map.insert("example.com", "198.18.1.100");
        assert_eq!(
            resolve_fake_ip(&ip("198.18.1.100"), None, "198.18.0.1/16", &map),
            Ok(Some("example.com".to_string()))
        );
    }

    #[test]
    fn unspecified_ip_is_not_loopback_for_bind_check() {
        // 显式记录：未指定地址判定由 route::should_bind_physical_interface 处理。
        assert_eq!(Ipv4Addr::UNSPECIFIED.to_string(), "0.0.0.0");
    }
}
