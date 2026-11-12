//! 私有协议 v2：HMAC-SHA256 双向认证（与客户端 `core/proxy/connect.rs` 保持一致）
//!
//! ## 首包格式
//!
//! ```text
//! +----+----+----+---------------+--------+----------+----------+----------+
//! | 10 | ff | 02 |   timestamp   |  port  | hostLen  |   host   |   mac    |
//! +----+----+----+---------------+--------+----------+----------+----------+
//!  1B   1B   1B     8B BE(u64)      2B BE     1B       N byte     32B
//! ```
//!
//! - `mac = HMAC-SHA256(password, "ssl-proxy-v2" || timestamp || port || host)`
//! - 密码不参与传输；服务端用本地密码重算并做常量时间比对；
//! - `timestamp` 参与签名且受时间窗约束（[`MAX_CLOCK_SKEW_SECS`]），用于阻止重放。
//!
//! ## 隧道应答
//!
//! 认证成功后服务端回写 `[0x10, 0xff] || ack_mac(32B)`，其中
//! `ack_mac = HMAC-SHA256(password, "ssl-proxy-v2-ack" || timestamp || port || host)`。
//! 客户端校验通过才能确认对端确实持有密码（双向认证）。
//!
//! ## UDP 能力协商
//!
//! - 客户端可在首包 MAC 之后追加 1 字节扩展位（bit0 = [`EXT_UDP`]，声明请求 UDP 能力）；
//! - 服务端**仅当**首包携带扩展位时，在 TUNNEL_ACK 的 MAC 之后追加 1 字节能力位
//!   （bit0 = [`CAP_UDP`]，表示支持 UDP 转发）；旧客户端未携带扩展位时不得多发，
//!   否则能力字节会被旧客户端当作隧道数据污染数据流；
//! - 旧版本互操作：旧服务端把扩展位当多余字节忽略（其解析只校验 HEADER + MAC
//!   长度下限），握手不受影响；旧客户端遇到新版服务端时，ACK 后不会有能力位。

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 协议魔数
pub const MAGIC: [u8; 2] = [0x10, 0xFF];
/// 协议版本
pub const VERSION: u8 = 2;
/// 隧道建立成功应答前缀（其后紧跟 32 字节 ACK MAC）
pub const TUNNEL_ACK: [u8; 2] = MAGIC;

/// MAC 长度（HMAC-SHA256）
pub const MAC_LEN: usize = 32;
/// 固定头部长度：magic(2) + version(1) + timestamp(8) + port(2) + hostLen(1)
pub const HEADER_LEN: usize = 14;
/// 允许的双端时钟偏差（秒）
pub const MAX_CLOCK_SKEW_SECS: u64 = 120;

/// 客户端首包扩展位（MAC 之后追加 1 字节）：bit0 = 请求 UDP 能力
#[allow(dead_code)]
pub const EXT_UDP: u8 = 0x01;
/// 服务端 ACK 能力位（ACK MAC 之后追加 1 字节）：bit0 = 支持 UDP 转发
#[allow(dead_code)]
pub const CAP_UDP: u8 = 0x01;

const REQ_PREFIX: &[u8] = b"ssl-proxy-v2";
const ACK_PREFIX: &[u8] = b"ssl-proxy-v2-ack";

/// 私有协议认证成功后的解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthInfo {
    pub host: String,
    pub port: u16,
    pub timestamp: u64,
}

/// 判断首包是否为 HTTP/1.x 请求行
///
/// 规则：首行中包含 `HTTP/1.` 且出现位置 `> 0`。
pub fn check_is_http_protocol(buf: &[u8]) -> bool {
    // 找到首行结束位置
    let line_end = buf
        .iter()
        .position(|&b| b == b'\r')
        .unwrap_or(buf.len().min(2048));
    let first_line = &buf[..line_end];

    // 必须包含 "HTTP/1."，且首次出现的位置 > 0
    if let Some(pos) = first_line.windows(7).position(|w| w == b"HTTP/1.") {
        pos > 0
    } else {
        false
    }
}

/// 计算 HMAC-SHA256（固定 32 字节输出）
fn compute_mac(password: &str, prefix: &[u8], timestamp: u64, port: u16, host: &str) -> [u8; MAC_LEN] {
    let mut mac =
        HmacSha256::new_from_slice(password.as_bytes()).expect("HMAC 支持任意长度密钥");
    mac.update(prefix);
    mac.update(&timestamp.to_be_bytes());
    mac.update(&port.to_be_bytes());
    mac.update(host.as_bytes());

    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; MAC_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// 首包签名（协议参考实现，供接入方 / 集成测试构造首包）
#[allow(dead_code)]
pub fn request_mac(password: &str, timestamp: u64, port: u16, host: &str) -> [u8; MAC_LEN] {
    compute_mac(password, REQ_PREFIX, timestamp, port, host)
}

/// 隧道应答签名（服务端 -> 客户端）
pub fn ack_mac(password: &str, timestamp: u64, port: u16, host: &str) -> [u8; MAC_LEN] {
    compute_mac(password, ACK_PREFIX, timestamp, port, host)
}

/// 编码 v2 首包（协议参考实现；服务端集成测试复用）
#[allow(dead_code)]
pub fn encode_packet(host: &str, port: u16, password: &str, timestamp: u64) -> Vec<u8> {
    let mac = request_mac(password, timestamp, port, host);
    let host_bytes = host.as_bytes();

    let mut buf = Vec::with_capacity(HEADER_LEN + host_bytes.len() + MAC_LEN);
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.push(host_bytes.len() as u8);
    buf.extend_from_slice(host_bytes);
    buf.extend_from_slice(&mac);
    buf
}

/// 编码 v2 首包（扩展版）：MAC 之后追加 1 字节扩展位 `ext`
///
/// 旧版服务端把这 1 字节当多余数据忽略；新版服务端据此进行 UDP 能力协商。
#[allow(dead_code)]
pub fn encode_packet_ext(host: &str, port: u16, password: &str, timestamp: u64, ext: u8) -> Vec<u8> {
    let mut buf = encode_packet(host, port, password, timestamp);
    buf.push(ext);
    buf
}

/// 解析并校验 v2 首包
///
/// `password` 为服务端本地密码，`now` 为当前 Unix 时间戳（秒）。
/// 任何一项校验失败都返回 `None`（调用方据此回落到 HTTP 伪装）。
#[allow(dead_code)]
pub fn authenticate_protocol(data: &[u8], password: &str, now: u64) -> Option<AuthInfo> {
    authenticate_protocol_ext(data, password, now).map(|(info, _)| info)
}

/// 解析并校验 v2 首包（扩展版），返回认证信息与可选的客户端扩展位
///
/// - `data` 为整块读出的首包 buffer，可能包含首包之后的多余字节（一律忽略）；
/// - 旧格式（HEADER + host + MAC 后无数据）→ 扩展位为 `None`；
/// - 新格式（MAC 后紧跟 1 字节扩展位）→ 扩展位为 `Some(b)`。
pub fn authenticate_protocol_ext(
    data: &[u8],
    password: &str,
    now: u64,
) -> Option<(AuthInfo, Option<u8>)> {
    if data.len() < HEADER_LEN + MAC_LEN {
        return None;
    }
    if data[0] != MAGIC[0] || data[1] != MAGIC[1] || data[2] != VERSION {
        return None;
    }

    let timestamp = u64::from_be_bytes(data[3..11].try_into().ok()?);
    let port = u16::from_be_bytes([data[11], data[12]]);
    let host_len = data[13] as usize;

    // hostLen = 0 表示「mux 连接」：认证通过后整条连接进入多路复用模式
    let host_end = HEADER_LEN + host_len;
    if data.len() < host_end + MAC_LEN {
        return None;
    }

    // 时间窗校验：挡重放
    if timestamp.abs_diff(now) > MAX_CLOCK_SKEW_SECS {
        return None;
    }

    let host = std::str::from_utf8(&data[HEADER_LEN..host_end]).ok()?;

    // 常量时间比对首包 MAC
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).ok()?;
    mac.update(REQ_PREFIX);
    mac.update(&timestamp.to_be_bytes());
    mac.update(&port.to_be_bytes());
    mac.update(host.as_bytes());
    mac.verify_slice(&data[host_end..host_end + MAC_LEN]).ok()?;

    // 扩展位：MAC 之后紧跟的 1 字节（旧格式客户端不发，此处为 None）
    let ext = data.get(host_end + MAC_LEN).copied();

    Some((
        AuthInfo {
            host: host.to_string(),
            port,
            timestamp,
        },
        ext,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "unit-test-pwd";
    const NOW: u64 = 1_760_000_000;

    #[test]
    fn http_protocol_detection() {
        assert!(check_is_http_protocol(b"GET / HTTP/1.1\r\nHost: x"));
        assert!(check_is_http_protocol(b"POST /api HTTP/1.0\r\n"));
        assert!(!check_is_http_protocol(b"HTTP/1.1 200 OK\r\n"));
        assert!(!check_is_http_protocol(b"\x10\xff\x00\x00\x00"));
    }

    #[test]
    fn v2_packet_roundtrip() {
        let pkt = encode_packet("example.com", 8443, PWD, NOW);
        let info = authenticate_protocol(&pkt, PWD, NOW).expect("合法首包应通过");
        assert_eq!(info.host, "example.com");
        assert_eq!(info.port, 8443);
        assert_eq!(info.timestamp, NOW);
    }

    #[test]
    fn v2_old_packet_parses_without_ext() {
        // 旧 14B + host + MAC 格式：新函数解析不受影响，扩展位为 None
        let pkt = encode_packet("example.com", 443, PWD, NOW);
        let (info, ext) = authenticate_protocol_ext(&pkt, PWD, NOW).expect("旧格式应通过");
        assert_eq!(info.host, "example.com");
        assert_eq!(info.port, 443);
        assert_eq!(info.timestamp, NOW);
        assert!(ext.is_none(), "旧格式不应解析出扩展位");
    }

    #[test]
    fn v2_ext_packet_roundtrip() {
        // 新格式：MAC 之后追加 1 字节扩展位
        let pkt = encode_packet_ext("example.com", 8443, PWD, NOW, EXT_UDP);
        let (info, ext) = authenticate_protocol_ext(&pkt, PWD, NOW).expect("扩展首包应通过");
        assert_eq!(info.host, "example.com");
        assert_eq!(info.port, 8443);
        assert_eq!(info.timestamp, NOW);
        assert_eq!(ext, Some(EXT_UDP));
    }

    #[test]
    fn v2_ext_mux_packet_roundtrip() {
        // mux 首包（hostLen = 0）同样可携带扩展位
        let pkt = encode_packet_ext("", 0, PWD, NOW, EXT_UDP);
        let (info, ext) = authenticate_protocol_ext(&pkt, PWD, NOW).expect("mux 扩展首包应通过");
        assert!(info.host.is_empty());
        assert_eq!(info.port, 0);
        assert_eq!(ext, Some(EXT_UDP));
    }

    #[test]
    fn v2_old_authenticate_still_accepts_ext_packet() {
        // 旧函数语义：首包之后的多余字节（含扩展位）被忽略，认证仍成功
        let pkt = encode_packet_ext("example.com", 443, PWD, NOW, EXT_UDP);
        let info = authenticate_protocol(&pkt, PWD, NOW).expect("旧函数应容忍扩展字节");
        assert_eq!(info.port, 443);
    }

    #[test]
    fn v2_ext_packet_tolerates_trailing_bytes() {
        // 调用方传整块 buffer：扩展位之后再有多余字节，也只解析 1 字节扩展位
        let mut pkt = encode_packet_ext("example.com", 443, PWD, NOW, EXT_UDP);
        pkt.extend_from_slice(b"trailing-junk");
        let (info, ext) = authenticate_protocol_ext(&pkt, PWD, NOW).expect("应通过");
        assert_eq!(info.port, 443);
        assert_eq!(ext, Some(EXT_UDP));
    }

    #[test]
    fn v2_accepts_within_clock_window() {
        let pkt = encode_packet("example.com", 443, PWD, NOW);
        assert!(authenticate_protocol(&pkt, PWD, NOW + MAX_CLOCK_SKEW_SECS).is_some());
        assert!(authenticate_protocol(&pkt, PWD, NOW - MAX_CLOCK_SKEW_SECS).is_some());
    }

    #[test]
    fn v2_rejects_expired_timestamp() {
        let pkt = encode_packet("example.com", 443, PWD, NOW);
        assert!(authenticate_protocol(&pkt, PWD, NOW + MAX_CLOCK_SKEW_SECS + 1).is_none());
        assert!(authenticate_protocol(&pkt, PWD, NOW - MAX_CLOCK_SKEW_SECS - 1).is_none());
    }

    #[test]
    fn v2_rejects_wrong_password() {
        let pkt = encode_packet("example.com", 443, "other-pwd", NOW);
        assert!(authenticate_protocol(&pkt, PWD, NOW).is_none());
    }

    #[test]
    fn v2_rejects_tampered_fields() {
        let mut pkt = encode_packet("example.com", 443, PWD, NOW);
        // 篡改 host（长度不变）应导致 MAC 校验失败
        let host_start = HEADER_LEN;
        pkt[host_start] = b'E';
        assert!(authenticate_protocol(&pkt, PWD, NOW).is_none());
    }

    #[test]
    fn v2_rejects_bad_magic_and_version() {
        let pkt = encode_packet("h", 1, PWD, NOW);

        let mut bad_magic = pkt.clone();
        bad_magic[0] = 0x00;
        assert!(authenticate_protocol(&bad_magic, PWD, NOW).is_none());

        let mut bad_version = pkt.clone();
        bad_version[2] = 1;
        assert!(authenticate_protocol(&bad_version, PWD, NOW).is_none());
    }

    #[test]
    fn v2_rejects_truncated_packet() {
        let pkt = encode_packet("example.com", 443, PWD, NOW);
        for cut in [0usize, 2, HEADER_LEN, HEADER_LEN + 3, pkt.len() - 1] {
            assert!(
                authenticate_protocol(&pkt[..cut], PWD, NOW).is_none(),
                "截断到 {cut} 字节不应通过"
            );
        }
    }

    #[test]
    fn v2_accepts_mux_mode_with_empty_host() {
        // hostLen = 0 表示 mux 连接
        let pkt = encode_packet("", 0, PWD, NOW);
        let info = authenticate_protocol(&pkt, PWD, NOW).expect("mux 首包应通过");
        assert!(info.host.is_empty());
        assert_eq!(info.port, 0);
    }

    #[test]
    fn ack_mac_differs_from_request_mac() {
        let req = request_mac(PWD, NOW, 443, "example.com");
        let ack = ack_mac(PWD, NOW, 443, "example.com");
        assert_ne!(req, ack);
        assert_eq!(ack.len(), MAC_LEN);
    }

    #[test]
    fn private_packet_is_not_http() {
        let pkt = encode_packet("example.com", 8443, PWD, NOW);
        assert!(!check_is_http_protocol(&pkt));
    }
}
