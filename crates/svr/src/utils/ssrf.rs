//! SSRF 防护：解析目标地址并拦截回环 / 内网 / 链路本地 / 保留地址。
//!
//! TCP 隧道与 UDP relay 共用同一套判定，避免"UDP 拦了、TCP 没拦"的缺口：
//! 一旦密码泄露，攻击者不能把服务器当作访问内网或云厂商 metadata 的跳板。
//! 需要访问内网的场景由配置项 `server.allow-private-targets` 显式放行。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::OnceLock;

/// 服务端本机地址集合（进程内惰性缓存一次）
fn local_addresses() -> &'static HashSet<IpAddr> {
    static SET: OnceLock<HashSet<IpAddr>> = OnceLock::new();
    SET.get_or_init(|| {
        let mut set = HashSet::new();
        // localhost 解析（通常为 127.0.0.1 / ::1）
        if let Ok(addrs) = ("localhost", 0u16).to_socket_addrs() {
            for addr in addrs {
                set.insert(addr.ip());
            }
        }
        // 默认路由出口地址（UDP connect 只选路，不实际发包）
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    set.insert(addr.ip());
                }
            }
        }
        set
    })
}

/// 判断目标 IP 是否禁止转发（SSRF 防护）
///
/// 覆盖：127.0.0.0/8、10/8、100.64/10（CGNAT，含云厂商 metadata）、172.16/12、
/// 192.168/16、169.254/16、192.0.0/24、192.88.99/24、198.18/15、0.0.0.0/8、
/// 组播 224/4、保留 240/4（含广播 255.255.255.255）；IPv6 覆盖 ::1、::、
/// fe80::/10、fec0::/10、fc00::/7、组播 ff00::/8、6to4 2002::/16、
/// Teredo 2001::/32、NAT64 64:ff9b::/96（提取内嵌 IPv4 复查）与
/// 64:ff9b:1::/48、IPv4 映射 / IPv4-compatible 地址（::ffff:x.y.z.w、::x.y.z.w
/// 按 IPv4 规则复查），以及本机地址。
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    let forbidden = match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => is_forbidden_v6(v6),
    };
    forbidden || local_addresses().contains(&ip)
}

/// IPv4 禁止转发判定
fn is_forbidden_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 127                                     // 127.0.0.0/8
        || o[0] == 10                               // 10/8
        || o[0] == 0                                // 0.0.0.0/8
        || (o[0] == 172 && o[1] & 0xf0 == 16)       // 172.16/12
        || (o[0] == 192 && o[1] == 168)             // 192.168/16
        || (o[0] == 169 && o[1] == 254)             // 169.254/16
        || (o[0] == 100 && (o[1] & 0xc0) == 64)     // 100.64/10（阿里云 100.100.100.200 等）
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)  // 192.0.0.0/24
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24（6to4 relay anycast）
        || (o[0] == 198 && (o[1] & 0xfe) == 18)     // 198.18/15
        || o[0] >= 224                              // 组播 224/4 + 保留 240/4（含广播）
}

/// 取 IPv6 低 32 位内嵌的 IPv4
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

/// IPv6 禁止转发判定
fn is_forbidden_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    if v6.is_loopback() || v6.is_unspecified() {
        return true;                                // ::1 / ::
    }
    if (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0 {
        return true;                                // fe80::/10 链路本地 + fec0::/10 站点本地
    }
    if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xff00) == 0xff00 {
        return true;                                // fc00::/7 ULA + ff00::/8 组播
    }
    if s[0] == 0x2002 || (s[0] == 0x2001 && s[1] == 0x0000) {
        return true;                                // 6to4 2002::/16 + Teredo 2001::/32
    }
    if s[0] == 0x0064 && s[1] == 0xff9b {
        if s[2] == 0x0001 {
            return true;                            // NAT64 本地使用前缀 64:ff9b:1::/48
        }
        if s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
            // NAT64 知名前缀 64:ff9b::/96：按内嵌 IPv4 规则复查
            return is_forbidden_v4(embedded_v4(s[6], s[7]));
        }
    }
    // ::ffff:x.y.z.w（IPv4 映射）与已废弃的 ::x.y.z.w（IPv4-compatible）
    let v4_tail =
        s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && (s[5] == 0xffff || s[5] == 0);
    v4_tail && is_forbidden_v4(embedded_v4(s[6], s[7]))
}

/// 解析目标并返回第一个可用地址。
///
/// - `allow_private = true`：直接返回解析结果（内网/回环可用）；
/// - 否则跳过所有禁止地址；全被拦截或解析为空时返回错误。
///
/// 返回解析后的 [`SocketAddr`] 而不是主机名，既避免连接阶段二次解析，
/// 也消除 DNS rebinding 的时间窗口。
pub async fn resolve_target(
    host: &str,
    port: u16,
    allow_private: bool,
) -> anyhow::Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("resolve {}:{} failed: {}", host, port, e))?;

    let mut blocked = None;
    for addr in addrs.by_ref() {
        if allow_private || !is_forbidden_ip(addr.ip()) {
            return Ok(addr);
        }
        blocked = Some(addr);
    }

    match blocked {
        Some(addr) => anyhow::bail!(
            "target {}:{} resolves to forbidden address {} (SSRF blocked)",
            host,
            port,
            addr
        ),
        None => anyhow::bail!("target {}:{} has no address", host, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_ip_covers_private_ranges() {
        for ip in [
            "127.0.0.1", "127.8.8.8", "10.0.0.1", "10.255.1.1", "172.16.0.1", "172.31.255.255",
            "192.168.1.1", "169.254.10.10", "0.0.0.0", "0.1.2.3", "::1", "fe80::1", "febf::1",
            "fc00::1", "fd12:3455:1234::1", "::ffff:127.0.0.1", "::ffff:10.0.0.2",
            // CGNAT / 云厂商 metadata、保留段、组播与广播
            "100.64.0.1", "100.100.100.200", "100.127.255.254", "192.0.0.8", "198.18.0.1",
            "198.19.255.255", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
            "192.88.99.1",
            // IPv6 过渡 / NAT64 / 站点本地 / IPv4-compatible 绕过路径
            "::", "ff02::1", "fec0::1", "2002:a9fe:a9fe::1", "2001::1",
            "64:ff9b::127.0.0.1", "64:ff9b::169.254.169.254", "64:ff9b::10.0.0.1",
            "64:ff9b:1::1", "::7f00:1",
        ] {
            assert!(
                is_forbidden_ip(ip.parse().unwrap()),
                "{} 应被判为禁止目标",
                ip
            );
        }
    }

    #[test]
    fn public_ip_is_allowed() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "172.15.255.255",
            "100.63.255.255",
            "198.20.0.1",
            "2001:4860:4860::8888",
            // NAT64 内嵌公网 IPv4 不应误拦
            "64:ff9b::8.8.8.8",
        ] {
            assert!(
                !is_forbidden_ip(ip.parse().unwrap()),
                "{} 不应被判为禁止目标",
                ip
            );
        }
    }

    #[tokio::test]
    async fn resolve_target_blocks_loopback_by_default() {
        let err = resolve_target("127.0.0.1", 80, false).await.unwrap_err();
        assert!(err.to_string().contains("SSRF blocked"), "err={err}");
    }

    #[tokio::test]
    async fn resolve_target_allows_loopback_when_configured() {
        let addr = resolve_target("127.0.0.1", 80, true).await.unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
