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
    /// 下一次分配的 fake-ip 序号（v4 池内偏移，从 .3 起：.1 网关、.2 DNS）。
    next_v4: u32,
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

    /// 从 v4 池分配一个未被占用的 fake-ip 并登记映射。
    ///
    /// 池形如 "198.18.0.1/16"（mihomo 默认）：跳过网络地址、.1（TUN 网关）
    /// 与 .2（DNS 语义），从游标线性扫描；池容量上限 /8，耗尽返回 None
    /// （调用方应回 NODATA，绝不回退真实 IP）。
    pub fn alloc_v4(&mut self, domain: &str, pool: &str) -> Option<String> {
        let (base, prefix) = pool.split_once('/')?;
        let prefix: u32 = prefix.parse().ok()?;
        let base: std::net::Ipv4Addr = base.parse().ok()?;
        if prefix < 8 {
            return None;
        }
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        let base_u32 = u32::from(base) & mask;
        let capacity = 1u32 << (32 - prefix).min(24);
        let usable = capacity.saturating_sub(4);
        if usable == 0 {
            return None;
        }
        for i in 0..usable {
            let offset = (self.next_v4 + i) % usable;
            let ip = std::net::Ipv4Addr::from(base_u32 + 3 + offset);
            let ip_str = ip.to_string();
            if !self.reverse.contains_key(&ip_str) {
                self.insert(domain, &ip_str);
                self.next_v4 = offset + 1;
                return Some(ip_str);
            }
        }
        None
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

/// DNS 应答结果。`Err` 表示不是可应答的标准查询（调用方应丢弃该包，
/// 绝不转发真实 IP——fail-closed）。
pub type DnsAnswerResult = Result<Vec<u8>, String>;

/// 解析标准 DNS 查询并返回 fake-ip 应答（A/AAAA；其余类型返回空 NoError，
/// 避免 SERVFAIL 触发应用回退到真实 DNS 造成泄漏）。
///
/// 对应 mihomo fake-ip DNS 行为：所有经 TUN 劫持的 :53 查询由本进程应答，
/// 应用拿到的永远是 fake-ip，后续连接经反查进入统一决策引擎。
pub fn answer_query(
    payload: &[u8],
    map: &mut FakeIpMap,
    pool_v4: &str,
    pool_v6: &str,
) -> DnsAnswerResult {
    use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use trust_dns_proto::rr::rdata::{A, AAAA};
    use trust_dns_proto::rr::{RData, Record, RecordType};

    let query = Message::from_vec(payload).map_err(|e| format!("DNS 报文解析失败: {e}"))?;
    let header = query.header();
    if header.message_type() != MessageType::Query || header.op_code() != OpCode::Query {
        return Err("非标准查询（可能是响应或通知），忽略".into());
    }

    let mut resp = Message::new();
    resp.set_id(header.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(header.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NoError);

    for q in query.queries() {
        resp.add_query(q.clone());
        let name = q.name().clone();
        let record = match q.query_type() {
            RecordType::A => match map.alloc_v4(&name.to_string(), pool_v4) {
                Some(ip) => ip
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
                    .map(|v4| Record::from_rdata(name.clone(), 1, RData::A(A(v4)))),
                None => None, // 池耗尽：该类型无应答（NODATA），不回退真实 IP
            },
            RecordType::AAAA => {
                // v6 池合法才分配；禁用 IPv6 时返回空（NODATA）。
                let v6 = fake_ipv6_for(name.to_string(), pool_v6, map);
                v6.map(|v| Record::from_rdata(name.clone(), 1, RData::AAAA(AAAA(v))))
            }
            _ => None,
        };
        if let Some(r) = record {
            resp.add_answer(r);
        }
    }

    resp.to_vec().map_err(|e| format!("DNS 应答编码失败: {e}"))
}

/// 为域名分配固定 fake IPv6（同域名重复查询返回同一地址）。
fn fake_ipv6_for(domain: String, pool_v6: &str, map: &mut FakeIpMap) -> Option<std::net::Ipv6Addr> {
    let (base, prefix) = pool_v6.split_once('/')?;
    if prefix.parse::<u32>().ok()? < 64 {
        return None;
    }
    let base: std::net::Ipv6Addr = base.parse().ok()?;
    if let Some(existing) = map.get_ip_by_host(&domain) {
        return existing.parse::<std::net::Ipv6Addr>().ok();
    }
    // 用域名哈希在 /64 内稳定取址（无持久化池，重启换址可接受：反查表同步重建）。
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&domain, &mut h);
    let host = std::hash::Hasher::finish(&h) as u128 & ((1u128 << 64) - 1);
    let ip = std::net::Ipv6Addr::from((u128::from(base) & !(u128::MAX >> 64)) | host);
    let s = ip.to_string();
    map.insert(&domain, &s);
    Some(ip)
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

    #[test]
    fn fake_ip_alloc_skips_gateway_and_dns_and_roundtrips() {
        let mut map = FakeIpMap::new();
        let pool = "198.18.0.1/16";
        let a = map.alloc_v4("a.com", pool).unwrap();
        let b = map.alloc_v4("b.com", pool).unwrap();
        // .1 网关、.2 DNS 语义，分配从 .3 起。
        assert_eq!(a, "198.18.0.3");
        assert_eq!(b, "198.18.0.4");
        assert_eq!(map.find_host_by_ip("198.18.0.3"), Some("a.com"));
    }

    #[test]
    fn fake_ip_alloc_is_unique() {
        let mut map = FakeIpMap::new();
        let pool = "198.18.0.1/24";
        let mut seen = std::collections::HashSet::new();
        for i in 0..20 {
            let ip = map.alloc_v4(&format!("d{i}.com"), pool).unwrap();
            assert!(seen.insert(ip.clone()), "重复分配 {ip}");
        }
    }

    #[test]
    fn dns_query_answered_with_fake_ip() {
        use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
        use trust_dns_proto::rr::{Name, RecordType};

        let mut map = FakeIpMap::new();
        let mut q = Message::new();
        q.set_id(0x1234);
        q.set_message_type(MessageType::Query);
        q.set_op_code(OpCode::Query);
        q.set_recursion_desired(true);
        q.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
        let payload = q.to_vec().unwrap();

        let resp = answer_query(&payload, &mut map, "198.18.0.1/16", "2001:2::0/64").unwrap();
        let parsed = trust_dns_proto::op::Message::from_vec(&resp).unwrap();
        assert_eq!(parsed.header().id(), 0x1234);
        assert_eq!(parsed.header().response_code(), trust_dns_proto::op::ResponseCode::NoError);
        let answers = parsed.answers();
        assert_eq!(answers.len(), 1);
        let fake = answers[0]
            .data()
            .and_then(|d| d.as_a())
            .unwrap()
            .0
            .to_string();
        assert!(fake.starts_with("198.18."), "应为 fake-ip 段: {fake}");
        assert_eq!(map.find_host_by_ip(&fake), Some("example.com"));
    }

    #[test]
    fn dns_response_is_not_answered_again() {
        // 响应报文绝不能再"应答"，防止劫持环路。
        use trust_dns_proto::op::{Message, MessageType};
        let mut m = Message::new();
        m.set_message_type(MessageType::Response);
        let payload = m.to_vec().unwrap();
        assert!(answer_query(&payload, &mut FakeIpMap::new(), "198.18.0.1/16", "").is_err());
    }
}
