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

use std::io;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

/// 普通数据帧
pub const FLAG_PAD: u8 = 0;
/// 本帧后切换为裸字节流
pub const FLAG_RAW: u8 = 1;

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
}
