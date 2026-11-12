//! Mux 帧协议：一条 TLS 连接承载多条逻辑流（参考 trojan-go + smux 的思路）。
//!
//! **本格式必须与客户端 `gui/src/core/proxy/mux.rs` 完全一致。**
//!
//! ```text
//! +------+--------+--------+--------+----------+-----+
//! | flag | sid u32| len u16| padLen | payload  | pad |
//! +------+--------+--------+--------+----------+-----+
//!   1B      4B       2B       1B       len       padLen
//! ```
//!
//! | flag | 含义 |
//! | ---- | ---- |
//! | 0 | DATA：流数据 |
//! | 1 | OPEN：新建流，payload = `port u16 BE | hostLen u8 | host` |
//! | 2 | FIN：发送方向结束（半关闭） |
//! | 3 | RST：中止流 |
//! | 4 | PING：保活 |
//! | 5 | PONG：保活应答 |
//!
//! `sid = 0` 保留给连接级控制帧。

use std::io;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FLAG_DATA: u8 = 0;
pub const FLAG_OPEN: u8 = 1;
pub const FLAG_FIN: u8 = 2;
pub const FLAG_RST: u8 = 3;
pub const FLAG_PING: u8 = 4;
pub const FLAG_PONG: u8 = 5;

/// 帧头：flag(1) + sid(4) + len(2) + padLen(1)
pub const MUX_HEADER: usize = 8;
/// 单帧 payload 上限
pub const MAX_PAYLOAD: usize = u16::MAX as usize;
/// 单连接并发流上限
pub const MAX_STREAMS: usize = 256;

/// 小包 padding 阈值
const SMALL_DATA: usize = 1024;

/// 追加一帧
pub fn append_frame(out: &mut Vec<u8>, flag: u8, sid: u32, payload: &[u8], pad_len: usize) {
    debug_assert!(payload.len() <= MAX_PAYLOAD);
    let pad_len = pad_len.min(u8::MAX as usize);

    out.push(flag);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.push(pad_len as u8);
    out.extend_from_slice(payload);

    if pad_len > 0 {
        let start = out.len();
        out.resize(start + pad_len, 0);
        rand::thread_rng().fill(&mut out[start..]);
    }
}

/// 编码 DATA 帧（小包随机填充，大包几乎零开销）
pub fn encode_data(sid: u32, data: &[u8]) -> Vec<u8> {
    let pad_len = if data.len() <= SMALL_DATA {
        rand::thread_rng().gen_range(0..=96)
    } else {
        rand::thread_rng().gen_range(0..=16)
    };
    let mut out = Vec::with_capacity(MUX_HEADER + data.len() + pad_len);
    append_frame(&mut out, FLAG_DATA, sid, data, pad_len);
    out
}

/// 编码 OPEN 帧（协议参考实现；客户端 / 集成测试复用）
#[allow(dead_code)]
pub fn encode_open(sid: u32, host: &str, port: u16) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut payload = Vec::with_capacity(3 + host_bytes.len());
    payload.extend_from_slice(&port.to_be_bytes());
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);

    let pad_len = rand::thread_rng().gen_range(0..=64);
    let mut out = Vec::with_capacity(MUX_HEADER + payload.len() + pad_len);
    append_frame(&mut out, FLAG_OPEN, sid, &payload, pad_len);
    out
}

/// 编码无 payload 的控制帧
pub fn encode_ctl(flag: u8, sid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(MUX_HEADER);
    append_frame(&mut out, flag, sid, &[], 0);
    out
}

/// 读取一帧，返回 `(flag, sid)`，payload 复用缓冲区
pub async fn read_frame<R>(reader: &mut R, payload: &mut Vec<u8>) -> io::Result<(u8, u32)>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; MUX_HEADER];
    reader.read_exact(&mut head).await?;

    let flag = head[0];
    let sid = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    let len = u16::from_be_bytes([head[5], head[6]]) as usize;
    let pad_len = head[7] as usize;

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

    Ok((flag, sid))
}

/// 解析 OPEN 帧 payload
pub fn parse_open(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 3 {
        return None;
    }
    let port = u16::from_be_bytes([payload[0], payload[1]]);
    let host_len = payload[2] as usize;
    if host_len == 0 || payload.len() < 3 + host_len {
        return None;
    }
    let host = std::str::from_utf8(&payload[3..3 + host_len]).ok()?.to_string();
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn frame_layout_is_stable() {
        let mut out = Vec::new();
        append_frame(&mut out, FLAG_DATA, 0x0102_0304, b"abc", 2);

        assert_eq!(out[0], FLAG_DATA);
        assert_eq!(&out[1..5], &0x0102_0304u32.to_be_bytes());
        assert_eq!(u16::from_be_bytes([out[5], out[6]]), 3);
        assert_eq!(out[7], 2);
        assert_eq!(&out[8..11], b"abc");
        assert_eq!(out.len(), MUX_HEADER + 3 + 2);
    }

    #[test]
    fn open_frame_roundtrips() {
        let frame = encode_open(7, "example.com", 8443);
        // 跳过头，取 payload（padding 在尾部）
        let payload = &frame[MUX_HEADER..MUX_HEADER + 3 + "example.com".len()];
        let (host, port) = parse_open(payload).expect("valid open payload");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[tokio::test]
    async fn read_frame_roundtrips() {
        let data = b"mux data payload".to_vec();
        let frame = encode_data(42, &data);

        let (mut tx, mut rx) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            tx.write_all(&frame).await.unwrap();
        });

        let mut payload = Vec::new();
        let (flag, sid) = read_frame(&mut rx, &mut payload).await.unwrap();
        assert_eq!(flag, FLAG_DATA);
        assert_eq!(sid, 42);
        assert_eq!(payload, data);
    }

    #[test]
    fn small_packets_get_padded() {
        let frame = encode_data(1, b"ping");
        // 至少 5 字节 payload + 可能 padding，整体应大于头部 + 4
        assert!(frame.len() >= MUX_HEADER + 4);
        assert!(frame.len() <= MUX_HEADER + 4 + 96);
    }

    #[test]
    fn parse_open_rejects_empty_host() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&443u16.to_be_bytes());
        payload.push(0);
        assert!(parse_open(&payload).is_none());
    }

    #[test]
    fn parse_open_rejects_truncated() {
        assert!(parse_open(&[0, 80]).is_none());
        let payload = vec![0x01, 0xbb, 5, b'a'];
        assert!(parse_open(&payload).is_none());
    }
}
