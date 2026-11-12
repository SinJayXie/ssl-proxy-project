//! 把「TLS 已读取的首包」与「剩余 TLS 流」合并为单一 [`AsyncRead`]。
//!
//! 用于在协议分发后，让后续的 HTTP/1.1 解析器或代理管道把首包当作流的一部分。
//!
//! [`AsyncRead`]: tokio::io::AsyncRead

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 将一组 `initial` 字节与底层流拼接：先吐完 `initial`，再透传底层。
pub struct InitialThenStream<S> {
    initial: Option<Bytes>,
    stream: S,
}

impl<S> InitialThenStream<S> {
    pub fn new(initial: Bytes, stream: S) -> Self {
        Self {
            initial: Some(initial),
            stream,
        }
    }

    /// 取出底层流（用于将所有权移交给后续处理）
    #[allow(dead_code)]
    pub fn into_inner(mut self) -> S {
        // 丢弃尚未消费的 initial（如果存在的话）
        self.initial.take();
        self.stream
    }

    #[allow(dead_code)]
    pub fn into_parts(self) -> (Option<Bytes>, S) {
        (self.initial, self.stream)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for InitialThenStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(initial) = self.initial.as_mut() {
            if !initial.is_empty() {
                let n = std::cmp::min(buf.remaining(), initial.len());
                let to_consume = initial.split_to(n);
                buf.put_slice(&to_consume);
                return Poll::Ready(Ok(()));
            }
        }
        self.initial = None;
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for InitialThenStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn yields_initial_bytes_then_underlying_stream() {
        let (mut peer, stream) = tokio::io::duplex(64);
        tokio::spawn(async move {
            peer.write_all(b"def").await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut merged = InitialThenStream::new(Bytes::from_static(b"abc"), stream);
        let mut out = String::new();
        merged.read_to_string(&mut out).await.unwrap();

        assert_eq!(out, "abcdef");
    }

    #[tokio::test]
    async fn empty_initial_passes_through() {
        let (mut peer, stream) = tokio::io::duplex(64);
        tokio::spawn(async move {
            peer.write_all(b"xyz").await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut merged = InitialThenStream::new(Bytes::new(), stream);
        let mut out = String::new();
        merged.read_to_string(&mut out).await.unwrap();

        assert_eq!(out, "xyz");
    }
}
