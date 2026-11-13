//! 隧道分帧与 padding：打散 TLS-in-TLS 的长度指纹。
//!
//! **本格式必须与服务端 `svr/src/services/framing.rs` 完全一致。**
//!
//! ```text
//! +------+--------+--------+----------+-----+
//! | flag | len u16| padLen | payload  | pad |
//! +------+--------+--------+----------+-----+
//!   1B      2B       1B       len       padLen
//! ```
//!
//! - `flag = 0`：普通数据帧；
//! - `flag = 1`：本帧之后为裸字节流，不再解帧。
//! - `flag = 2`：UDP 数据帧，payload 为 UDP 包编码（见下）。
//!
//! ## UDP 包编码（隧道 UDP 帧 payload，双向一致）
//!
//! ```text
//! +-----------+------+--------+--------+-----------+-------+
//! | stream_id | atyp |  addr  |  port  | dgram_len | dgram |
//! +-----------+------+--------+--------+-----------+-------+
//!    4B BE      1B      变长     2B BE     2B BE      变长
//! ```
//!
//! - `atyp = 1`：IPv4（4B）；`atyp = 3`：域名（1B len + N）；`atyp = 4`：IPv6（16B）；
//! - `stream_id` 由客户端为每个 UDP 会话分配（递增），服务端按其做 NAT；
//! - 域名目标保留域名（atyp=3），由服务端解析。

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

/// 普通数据帧
pub const FLAG_PAD: u8 = 0;
/// 本帧后切换为裸字节流
pub const FLAG_RAW: u8 = 1;
/// UDP 数据帧（payload 为 [`encode_udp_packet`] 编码的 UDP 包）
pub const FLAG_UDP: u8 = 2;
/// 纯填充帧：接收方丢弃 payload（用于撑大首条 TLS record）
pub const FLAG_PADDING: u8 = 3;

/// 帧头长度：flag(1) + len(2) + padLen(1)
pub const FRAME_HEADER: usize = 4;
/// 单帧 payload 上限
pub const MAX_PAYLOAD: usize = u16::MAX as usize;
/// 小包分片阈值
pub const SMALL_PAYLOAD: usize = 2048;

/// 追加一帧到 `out`
pub fn append_frame(out: &mut Vec<u8>, payload: &[u8], pad_len: usize, flag: u8) {
    debug_assert!(payload.len() <= MAX_PAYLOAD);
    let pad_len = pad_len.min(u8::MAX as usize);

    out.push(flag);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.push(pad_len as u8);
    out.extend_from_slice(payload);

    if pad_len > 0 {
        let start = out.len();
        out.resize(start + pad_len, 0);
        rand::thread_rng().fill(&mut out[start..]);
    }
}

/// 编码一个纯填充帧（接收方丢弃）
pub fn encode_padding_frame(payload_len: usize) -> Vec<u8> {
    let mut payload = vec![0u8; payload_len.min(MAX_PAYLOAD)];
    rand::thread_rng().fill(&mut payload[..]);
    let mut out = Vec::with_capacity(FRAME_HEADER + payload.len());
    append_frame(&mut out, &payload, 0, FLAG_PADDING);
    out
}

/// 按策略编码一段待发送数据（上行：小包随机切片 + 随机填充）
pub fn encode_chunk(buf: &[u8], pad: bool, out: &mut Vec<u8>) {
    if buf.is_empty() {
        return;
    }
    if !pad || buf.len() > SMALL_PAYLOAD {
        let pad_len = if pad {
            rand::thread_rng().gen_range(0..=32)
        } else {
            0
        };
        append_frame(out, buf, pad_len, FLAG_PAD);
        return;
    }

    let mut rng = rand::thread_rng();
    let mut off = 0;
    while off < buf.len() {
        let remain = buf.len() - off;
        let take = rng.gen_range(64..=512).min(remain);
        let pad_len = rng.gen_range(0..=256);
        append_frame(out, &buf[off..off + take], pad_len, FLAG_PAD);
        off += take;
    }
}

/// 读取一帧：返回 `(flag, payload)`，payload 复用缓冲区。
pub async fn read_frame<R>(reader: &mut R, payload: &mut Vec<u8>) -> io::Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; FRAME_HEADER];
    reader.read_exact(&mut head).await?;

    let flag = head[0];
    let len = u16::from_be_bytes([head[1], head[2]]) as usize;
    let pad_len = head[3] as usize;

    payload.clear();
    payload.resize(len, 0);
    if len > 0 {
        reader.read_exact(payload).await?;
    }

    if pad_len > 0 {
        let mut skip = [0u8; 256];
        let mut left = pad_len;
        while left > 0 {
            let n = left.min(skip.len());
            reader.read_exact(&mut skip[..n]).await?;
            left -= n;
        }
    }

    Ok(flag)
}

// ==================== UDP 包编解码 ====================

/// UDP 包编码固定头部长度：stream_id(4) + atyp(1) + port(2) + dgram_len(2)
const UDP_FIXED: usize = 9;

/// 解析后的 UDP 包
pub struct UdpPacket<'a> {
    /// 会话 ID（服务端 NAT 表键；客户端回包路径不使用，仅保持线上格式对齐）
    #[allow(dead_code)]
    pub stream_id: u32,
    pub host: String,
    pub port: u16,
    pub dgram: &'a [u8],
}

/// 编码 UDP 包：`stream_id || atyp || addr || port || dgram_len || dgram`
///
/// 返回 `None` 表示报文超限（dgram 超过 u16 上限，或编码后超过单帧
/// [`MAX_PAYLOAD`]），调用方应丢弃该报文。
pub fn encode_udp_packet(stream_id: u32, host: &str, port: u16, dgram: &[u8]) -> Option<Vec<u8>> {
    if dgram.len() > u16::MAX as usize {
        return None;
    }

    let mut pkt = Vec::with_capacity(UDP_FIXED + host.len() + 1 + dgram.len());
    pkt.extend_from_slice(&stream_id.to_be_bytes());
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        pkt.push(1);
        pkt.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        pkt.push(4);
        pkt.extend_from_slice(&v6.octets());
    } else {
        // 域名目标：保留域名，由服务端解析
        let host_bytes = host.as_bytes();
        if host_bytes.is_empty() || host_bytes.len() > 255 {
            return None;
        }
        pkt.push(3);
        pkt.push(host_bytes.len() as u8);
        pkt.extend_from_slice(host_bytes);
    }
    pkt.extend_from_slice(&port.to_be_bytes());
    pkt.extend_from_slice(&(dgram.len() as u16).to_be_bytes());
    pkt.extend_from_slice(dgram);

    if pkt.len() > MAX_PAYLOAD {
        return None;
    }
    Some(pkt)
}

/// 解析 UDP 包（[`encode_udp_packet`] 的逆操作）；`dgram` 借用自 payload。
pub fn parse_udp_packet(payload: &[u8]) -> Option<UdpPacket<'_>> {
    if payload.len() < UDP_FIXED {
        return None;
    }
    let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let atyp = payload[4];

    let (host, addr_end) = match atyp {
        1 => {
            if payload.len() < 5 + 4 {
                return None;
            }
            (
                Ipv4Addr::new(payload[5], payload[6], payload[7], payload[8]).to_string(),
                9,
            )
        }
        3 => {
            if payload.len() < 6 {
                return None;
            }
            let len = payload[5] as usize;
            if payload.len() < 6 + len {
                return None;
            }
            (
                String::from_utf8_lossy(&payload[6..6 + len]).to_string(),
                6 + len,
            )
        }
        4 => {
            if payload.len() < 5 + 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[5..21]);
            (Ipv6Addr::from(octets).to_string(), 21)
        }
        _ => return None,
    };

    if payload.len() < addr_end + 4 {
        return None;
    }
    let port = u16::from_be_bytes([payload[addr_end], payload[addr_end + 1]]);
    let dgram_len = u16::from_be_bytes([payload[addr_end + 2], payload[addr_end + 3]]) as usize;
    let dgram_start = addr_end + 4;
    if payload.len() < dgram_start + dgram_len {
        return None;
    }

    Some(UdpPacket {
        stream_id,
        host,
        port,
        dgram: &payload[dgram_start..dgram_start + dgram_len],
    })
}

/// 将一个 UDP 报文编码为**单个** `FLAG_UDP` 帧并追加到 `out`
///
/// padding 策略沿用 [`encode_chunk`] 的阈值：小报文多填充、大报文少填充；
/// 与数据帧不同，UDP 报文不可切片，超限时报文直接丢弃（返回 `false`）。
pub fn append_udp_frame(
    out: &mut Vec<u8>,
    stream_id: u32,
    host: &str,
    port: u16,
    dgram: &[u8],
) -> bool {
    let Some(pkt) = encode_udp_packet(stream_id, host, port, dgram) else {
        return false;
    };
    let pad_len = if dgram.len() <= SMALL_PAYLOAD {
        rand::thread_rng().gen_range(0..=256)
    } else {
        rand::thread_rng().gen_range(0..=32)
    };
    append_frame(out, &pkt, pad_len, FLAG_UDP);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn frame_layout_is_stable() {
        let mut out = Vec::new();
        append_frame(&mut out, b"hello", 2, FLAG_PAD);
        assert_eq!(out[0], FLAG_PAD);
        assert_eq!(u16::from_be_bytes([out[1], out[2]]), 5);
        assert_eq!(out[3], 2);
        assert_eq!(&out[4..9], b"hello");
        assert_eq!(out.len(), FRAME_HEADER + 5 + 2);
    }

    #[test]
    fn padding_frame_has_expected_layout() {
        let out = encode_padding_frame(256);
        assert_eq!(out[0], FLAG_PADDING);
        assert_eq!(u16::from_be_bytes([out[1], out[2]]), 256);
        assert_eq!(out.len(), FRAME_HEADER + 256);
    }

    #[tokio::test]
    async fn encode_then_read_recovers_original_bytes() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let mut encoded = Vec::new();
        encode_chunk(&data, true, &mut encoded);

        let (mut tx, mut rx) = tokio::io::duplex(64 * 1024);
        let payload_bytes = encoded.clone();
        tokio::spawn(async move {
            tx.write_all(&payload_bytes).await.unwrap();
        });

        let mut got = Vec::new();
        let mut payload = Vec::new();
        loop {
            match read_frame(&mut rx, &mut payload).await {
                Ok(_) => got.extend_from_slice(&payload),
                Err(_) => break,
            }
        }
        assert_eq!(got, data);
    }

    // ---------- UDP 包编解码 ----------

    #[test]
    fn udp_packet_roundtrip_ipv4() {
        let dgram = b"\x12\x34query-payload";
        let pkt = encode_udp_packet(7, "1.2.3.4", 443, dgram).unwrap();
        assert_eq!(pkt[4], 1);
        let parsed = parse_udp_packet(&pkt).unwrap();
        assert_eq!(parsed.stream_id, 7);
        assert_eq!(parsed.host, "1.2.3.4");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.dgram, dgram);
    }

    #[test]
    fn udp_packet_roundtrip_ipv6() {
        let pkt = encode_udp_packet(9, "2001:db8::1", 8443, b"hi").unwrap();
        assert_eq!(pkt[4], 4);
        let parsed = parse_udp_packet(&pkt).unwrap();
        assert_eq!(parsed.stream_id, 9);
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.dgram, b"hi");
    }

    #[test]
    fn udp_packet_keeps_domain_target() {
        // 域名目标必须保留 atyp=3，由服务端解析
        let pkt = encode_udp_packet(3, "dns.example.com", 53, b"q").unwrap();
        assert_eq!(pkt[4], 3);
        assert_eq!(pkt[5], "dns.example.com".len() as u8);
        let parsed = parse_udp_packet(&pkt).unwrap();
        assert_eq!(parsed.host, "dns.example.com");
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.dgram, b"q");
    }

    #[test]
    fn udp_packet_rejects_oversize_dgram() {
        // dgram_len 是 u16：超过上限的报文必须被丢弃而不是静默截断
        assert!(encode_udp_packet(1, "1.2.3.4", 53, &vec![0u8; u16::MAX as usize + 1]).is_none());
        // u16 内但编码后超过单帧 MAX_PAYLOAD 的报文同样被丢弃
        assert!(encode_udp_packet(1, "1.2.3.4", 53, &vec![0u8; u16::MAX as usize]).is_none());
        // IPv4 目标时的可编码上界：UDP_FIXED(9) + addr(4) + dgram
        let max_dgram = MAX_PAYLOAD - UDP_FIXED - 4;
        assert!(encode_udp_packet(1, "1.2.3.4", 53, &vec![0u8; max_dgram]).is_some());
        assert!(encode_udp_packet(1, "1.2.3.4", 53, &vec![0u8; max_dgram + 1]).is_none());
    }

    #[test]
    fn udp_packet_rejects_truncated_input() {
        let full = encode_udp_packet(5, "example.com", 53, b"payload").unwrap();
        for cut in 0..full.len() {
            assert!(parse_udp_packet(&full[..cut]).is_none(), "cut at {cut}");
        }
        // 未知 atyp
        let mut bad = full.clone();
        bad[4] = 9;
        assert!(parse_udp_packet(&bad).is_none());
        // dgram_len 声明超长（IPv4 包：stream_id(4)+atyp(1)+addr(4)+
        // port(2) 后为 dgram_len(2)，dgram_len 位于 [11..13]）
        let full4 = encode_udp_packet(5, "1.2.3.4", 53, b"payload").unwrap();
        let mut bad4 = full4.clone();
        bad4[11..13].copy_from_slice(&999u16.to_be_bytes());
        assert!(parse_udp_packet(&bad4).is_none());
    }

    #[tokio::test]
    async fn udp_frame_roundtrip_with_padding() {
        let (mut tx, mut rx) = tokio::io::duplex(64 * 1024);
        let frame = {
            let mut out = Vec::new();
            assert!(append_udp_frame(&mut out, 11, "8.8.8.8", 53, b"a-dns-query"));
            out
        };
        tokio::spawn(async move {
            tx.write_all(&frame).await.unwrap();
            tx.shutdown().await.unwrap();
        });

        let mut payload = Vec::new();
        let flag = read_frame(&mut rx, &mut payload).await.unwrap();
        assert_eq!(flag, FLAG_UDP);
        let parsed = parse_udp_packet(&payload).unwrap();
        assert_eq!(parsed.stream_id, 11);
        assert_eq!(parsed.host, "8.8.8.8");
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.dgram, b"a-dns-query");
    }

    #[test]
    fn udp_frame_is_single_frame_per_datagram() {
        let mut out = Vec::new();
        let big = vec![7u8; 8192];
        assert!(append_udp_frame(&mut out, 1, "1.2.3.4", 443, &big));
        // 一个数据报恰好一帧（不可像 encode_chunk 那样切片）：
        // 帧头 flag(1)+len(2)+padLen(1)，len == UDP 包编码长度
        let pkt_len = encode_udp_packet(1, "1.2.3.4", 443, &big).unwrap().len();
        assert_eq!(u16::from_be_bytes([out[1], out[2]]) as usize, pkt_len);
        assert_eq!(out[0], FLAG_UDP);
    }
}
