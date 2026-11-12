use std::net::ToSocketAddrs;

/// Convert IPv4 octets [a,b,c,d] to a u32 big-endian value.
#[allow(dead_code)]
pub fn ip_from_octets(octets: [u8; 4]) -> u32 {
    u32::from_be_bytes(octets)
}

/// Convert a u32 big-endian IP to a string like "8.8.8.8".
pub fn ip_to_str(ip: u32) -> String {
    let octets = ip_to_octets(ip);
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// Convert a u32 big-endian IP to octets.
pub fn ip_to_octets(ip: u32) -> [u8; 4] {
    ip.to_be_bytes()
}

/// Parse an IPv4 string like "8.8.8.8" into a u32 big-endian value.
/// Returns `None` if the string is not a valid IPv4 address.
pub fn str_to_ip(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse::<u8>().ok()?;
    }
    Some(u32::from_be_bytes(octets))
}

/// Shorthand for `str_to_ip`. Same as above.
pub fn ip_from_str(s: &str) -> Option<u32> {
    str_to_ip(s)
}

/// Resolve a hostname or IP string to a u32 big-endian IPv4 value.
/// Supports:
/// - Plain IPv4 addresses like "8.8.8.8"
/// - Domains (DNS resolution, requires `std::net::ToSocketAddrs`)
///
/// Returns `None` if resolution fails or the result is not IPv4.
pub fn resolve_host(s: &str) -> Option<u32> {
    // Try plain IPv4 first
    if let Some(ip) = str_to_ip(s) {
        return Some(ip);
    }

    // DNS resolution
    let host = s.split(':').next().unwrap_or(s);
    let addr_str = format!("{}:0", host);
    let addrs: Vec<std::net::SocketAddr> = addr_str.to_socket_addrs().ok()?.collect();
    for addr in addrs {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            return Some(u32::from_be_bytes(v4.octets()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_roundtrip() {
        let ip = ip_from_octets([8, 8, 8, 8]);
        assert_eq!(ip_to_str(ip), "8.8.8.8");
        assert_eq!(str_to_ip("8.8.8.8"), Some(ip));
        assert_eq!(str_to_ip("invalid"), None);
    }

    #[test]
    fn test_resolve_host_ipv4() {
        assert_eq!(resolve_host("8.8.8.8"), Some(0x08080808));
        assert_eq!(resolve_host("127.0.0.1"), Some(0x7F000001));
    }

    #[test]
    fn test_resolve_host_invalid() {
        assert_eq!(resolve_host("invalid.invalid.invalid"), None);
    }
}
