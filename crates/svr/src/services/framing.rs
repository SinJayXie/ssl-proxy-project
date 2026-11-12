//! 隧道分帧与 padding：打散 TLS-in-TLS 的长度指纹。
//!
//! **本格式必须与客户端 `gui/src/core/proxy/framing.rs` 完全一致。**
//!
//! ## 帧格式
//!
//! ```text
//! +------+--------+--------+----------+-----+
//! | flag | len u16| padLen | payload  | pad |
//! +------+--------+--------+----------+-----+
//!   1B      2B       1B       len       padLen
//! ```
//!
//! - `flag = 0`：普通数据帧；
//! - `flag = 1`：本帧之后切换为裸字节流（不再解帧），payload 仍有效；
//! - `flag = 2`：UDP 数据报帧（payload 见 [`crate::services::udp_relay_service`]，
//!   仅用于 UDP 隧道，一条隧道连接独占一个 UDP 会话）。
//!
//! ## padding 策略（速度优先）
//!
//! - 小包（≤ [`SMALL_PAYLOAD`]）：随机切片 + 随机填充，打散 ClientHello / 请求头长度特征；
//! - 大包：整段一帧、仅少量填充，避免影响吞吐；
//! - 下行只在前 [`PAD_LIMIT_BYTES`] 字节（覆盖 TLS 握手）内 padding，之后裸透传。

use std::io;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

/// 普通数据帧
pub const FLAG_PAD: u8 = 0;
/// 本帧后切换为裸字节流
pub const FLAG_RAW: u8 = 1;
/// UDP 数据报帧（payload = `stream_id u32 BE || atyp || addr || port u16 BE || dgram_len u16 BE || dgram`）
pub const FLAG_UDP: u8 = 2;

/// 帧头长度：flag(1) + len(2) + padLen(1)
pub const FRAME_HEADER: usize = 4;
/// 单帧 payload 上限
pub const MAX_PAYLOAD: usize = u16::MAX as usize;
/// 小包分片阈值
pub const SMALL_PAYLOAD: usize = 2048;
/// 下行 padding 字节窗口（约等于 TLS 握手流量）
pub const PAD_LIMIT_BYTES: u64 = 16 * 1024;

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

/// 按策略编码一段待发送数据（可能产生多帧）
///
/// `pad == false` 时整段一帧、无填充，用于不需要伪装的场景。
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

/// 读取一帧：返回 `(flag, payload)`，payload 复用 `payload` 缓冲区。
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

    // 丢弃 padding（固定栈缓冲，避免分配）
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn frame_roundtrip_by_layout() {
        let mut out = Vec::new();
        append_frame(&mut out, b"hello", 3, FLAG_PAD);

        assert_eq!(out[0], FLAG_PAD);
        assert_eq!(u16::from_be_bytes([out[1], out[2]]), 5);
        assert_eq!(out[3], 3);
        assert_eq!(&out[4..9], b"hello");
        assert_eq!(out.len(), FRAME_HEADER + 5 + 3);
    }

    #[test]
    fn encode_small_chunk_splits_into_multiple_frames() {
        let mut out = Vec::new();
        let data = vec![7u8; 1024];
        encode_chunk(&data, true, &mut out);
        assert!(out.len() > 1024, "padding 应使输出大于原始数据");
        assert_eq!(out[0], FLAG_PAD);
    }

    #[test]
    fn encode_large_chunk_is_single_frame() {
        let mut out = Vec::new();
        let data = vec![7u8; 8192];
        encode_chunk(&data, true, &mut out);
        // 单帧：4B 头 + 8192 payload + 至多 32B padding
        assert!(out.len() <= FRAME_HEADER + 8192 + 32);
        assert_eq!(u16::from_be_bytes([out[1], out[2]]), 8192);
    }

    #[test]
    fn encode_without_pad_has_no_padding() {
        let mut out = Vec::new();
        encode_chunk(b"abcdef", false, &mut out);
        assert_eq!(out.len(), FRAME_HEADER + 6);
        assert_eq!(out[3], 0);
    }

    #[tokio::test]
    async fn read_frame_roundtrips_encode_output() {
        let data = b"TLS-in-TLS masquerade payload".to_vec();
        let mut encoded = Vec::new();
        encode_chunk(&data, true, &mut encoded);

        let (mut tx, mut rx) = tokio::io::duplex(64 * 1024);
        let encoded_clone = encoded.clone();
        tokio::spawn(async move {
            tx.write_all(&encoded_clone).await.unwrap();
            tx.shutdown().await.unwrap();
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

    #[tokio::test]
    async fn read_frame_reports_raw_flag() {
        let mut encoded = Vec::new();
        append_frame(&mut encoded, b"tail", 0, FLAG_RAW);

        let (mut tx, mut rx) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            tx.write_all(&encoded).await.unwrap();
        });

        let mut payload = Vec::new();
        let flag = read_frame(&mut rx, &mut payload).await.unwrap();
        assert_eq!(flag, FLAG_RAW);
        assert_eq!(payload, b"tail");
    }

    #[tokio::test]
    async fn read_frame_rejects_truncated_stream() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // 声明 10 字节 payload，只发 3 字节
            tx.write_all(&[FLAG_PAD, 0, 10, 0, 1, 2, 3]).await.unwrap();
            tx.shutdown().await.unwrap();
        });

        let mut payload = Vec::new();
        assert!(read_frame(&mut rx, &mut payload).await.is_err());
    }
}
