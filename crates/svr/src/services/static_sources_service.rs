//! 静态资源服务：解析 HTTP/1.1 请求，读取本地文件，gzip 压缩后回写。
//!
//! 与 Node.js `StaticSourcesService.ts` 行为一致：
//! - 仅处理 `GET` / `HEAD`；
//! - `/` 重定向到 `<html>/<index>`；
//! - 缺失文件返回自定义 404；
//! - 命中文件则 200 + gzip + `Content-Type`。

use std::path::{Component, Path, PathBuf};

use anyhow::Result;
use async_compression::tokio::write::GzipEncoder;
use async_trait::async_trait;
use bytes::Bytes;
use httparse::Request;
use mime_guess::from_path;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use super::initial_stream::InitialThenStream;
use crate::core::service::Service;

const NOT_FOUND_HTML: &str = "<!DOCTYPE html><html lang=\"en\"><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>ssl-proxy-svr</center></body></html>";

/// 静态资源服务
#[derive(Clone)]
pub struct StaticSourcesService {
    base: Option<PathBuf>,
    index: String,
}

impl StaticSourcesService {
    pub fn new(base: Option<PathBuf>, index: String) -> Self {
        Self { base, index }
    }

    /// 校验 base 目录是否合法（在 main 启动期调用）
    pub fn validate(&self) -> Result<()> {
        if let Some(base) = &self.base {
            if !base.exists() {
                anyhow::bail!("静态资源目录不存在: {:?}", base);
            }
            if !base.is_dir() {
                anyhow::bail!("静态资源路径不是目录: {:?}", base);
            }
        }
        Ok(())
    }

    /// 处理一个 HTTP/1.1 请求（基于已读取的首包 + TLS 流）。
    ///
    /// 仅处理单次请求-响应后关闭；与原版语义保持一致。
    pub async fn handle<S>(&self, mut stream: InitialThenStream<S>, initial: Bytes)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // 1. 解析 HTTP 请求
        let parsed = match parse_request(&initial) {
            Some(p) => p,
            None => {
                send_simple(&mut stream, 400, "text/plain", "Bad Request").await;
                let _ = stream.shutdown().await;
                return;
            }
        };

        let method = parsed.method;
        let path = parsed.path;

        // 2. 拼接真实文件路径
        let Some(base) = &self.base else {
            send_html(&mut stream, 404, NOT_FOUND_HTML).await;
            let _ = stream.shutdown().await;
            return;
        };

        // 防穿越：解析为安全相对路径，拒绝 `..`、绝对路径、盘符前缀
        let Some(rel) = sanitize_path(&path) else {
            send_html(&mut stream, 403, "Forbidden").await;
            let _ = stream.shutdown().await;
            return;
        };
        let mut file_path = base.clone();
        if rel.as_os_str().is_empty() {
            file_path.push(&self.index);
        } else {
            file_path.push(&rel);
        }

        // 3. 文件存在则输出（gzip），否则 404
        match File::open(&file_path).await {
            Ok(file) => {
                let mime = from_path(&file_path).first_or_octet_stream();
                let len = file
                    .metadata()
                    .await
                    .ok()
                    .map(|m| m.len())
                    .unwrap_or(0);

                if method == "HEAD" {
                    // 简化：仅写头，body 长度 0
                    let header = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Server: ssl-proxy-svr\r\n\
                         Content-Type: {}\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\
                         \r\n",
                        mime
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    return;
                }

                // 压缩后长度不可知：不声明 Content-Length / Transfer-Encoding，
                // 由 Connection: close 界定 body 结束
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Server: ssl-proxy-svr\r\n\
                     Content-Type: {}\r\n\
                     Content-Encoding: gzip\r\n\
                     Connection: close\r\n\
                     \r\n",
                    mime
                );
                let _ = stream.write_all(header.as_bytes()).await;

                // 将流交给 gzip 编码器（零拷贝流式）
                let mut gz = GzipEncoder::new(&mut stream);
                let mut reader = BufReader::with_capacity(8 * 1024, file);
                if let Err(e) = tokio::io::copy(&mut reader, &mut gz).await {
                    tracing::debug!("static copy error: {}", e);
                }
                let _ = gz.shutdown().await;
                let _ = stream.shutdown().await;

                tracing::debug!(
                    "[Static] served {:?} ({} bytes raw) for {} {}",
                    file_path,
                    len,
                    method,
                    path
                );
            }
            Err(_) => {
                send_html(&mut stream, 404, NOT_FOUND_HTML).await;
                let _ = stream.shutdown().await;
            }
        }
    }
}

#[async_trait]
impl Service for StaticSourcesService {
    fn name(&self) -> &str {
        "StaticSourcesService"
    }

    async fn start(&self) -> Result<()> {
        match &self.base {
            Some(base) => tracing::info!("[Static] ready (base={:?}, index={})", base, self.index),
            None => tracing::info!("[Static] ready (no base dir)"),
        }
        Ok(())
    }
}

struct ParsedRequest {
    method: String,
    path: String,
}

fn parse_request(buf: &[u8]) -> Option<ParsedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = Request::new(&mut headers);
    let status = req.parse(buf).ok()?;
    if status.is_partial() {
        return None;
    }
    let method = req.method?.to_string();
    let path = req.path?.to_string();
    Some(ParsedRequest { method, path })
}

fn sanitize_path(p: &str) -> Option<PathBuf> {
    if p.contains('\0') {
        return None;
    }
    // HTTP 请求路径为 origin-form，恒以 `/` 开头，先剥掉前导斜杠
    let p = p.trim_start_matches('/');
    let mut out = PathBuf::new();
    for comp in Path::new(p).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            // 父目录、根、盘符前缀均视为穿越，直接拒绝
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

async fn send_html<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, body: &str) {
    send_simple(stream, status, "text/html; charset=utf-8", body).await
}

async fn send_simple<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    body: &str,
) {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let bytes = body.as_bytes();
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Server: ssl-proxy-svr\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        status, status_text, content_type, bytes.len()
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(bytes).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const INDEX: &str = "<html>index</html>";

    fn temp_html_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ssl-proxy-static-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), INDEX).unwrap();
        dir
    }

    /// 用内存双工流跑一次完整的 handle 流程，返回原始响应字节。
    async fn run(base: Option<PathBuf>, request: &str) -> Vec<u8> {
        let svc = StaticSourcesService::new(base, "index.html".to_string());
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let initial = Bytes::from(request.as_bytes().to_vec());
        let stream = InitialThenStream::new(initial.clone(), server);

        tokio::spawn(async move { svc.handle(stream, initial).await });

        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        out
    }

    fn split(raw: &[u8]) -> (String, Vec<u8>) {
        let pos = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header terminator");
        (
            String::from_utf8_lossy(&raw[..pos]).to_string(),
            raw[pos + 4..].to_vec(),
        )
    }

    #[test]
    fn sanitize_path_keeps_normal_segments() {
        assert_eq!(sanitize_path("/a/b.js").unwrap(), PathBuf::from("a/b.js"));
        assert_eq!(sanitize_path("/a/./b").unwrap(), PathBuf::from("a/b"));
        assert!(sanitize_path("/").unwrap().as_os_str().is_empty());
    }

    #[test]
    fn sanitize_path_rejects_traversal() {
        assert!(sanitize_path("/../etc/passwd").is_none());
        assert!(sanitize_path("/a/../../x").is_none());
        assert!(sanitize_path("/a\0b").is_none());
    }

    #[test]
    fn parse_request_extracts_method_and_path() {
        let parsed = parse_request(b"GET /a/b.html HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/a/b.html");

        assert!(parse_request(b"GET /a/b.html HTTP/1.1\r\nHost: x").is_none());
    }

    #[tokio::test]
    async fn serves_index_with_gzip() {
        let dir = temp_html_dir();
        let raw = run(Some(dir.clone()), "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let (head, body) = split(&raw);

        assert!(head.starts_with("HTTP/1.1 200 OK"), "head={head}");
        assert!(head.contains("Content-Encoding: gzip"), "head={head}");
        assert!(body.starts_with(&[0x1f, 0x8b]), "body 应为 gzip 流");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn head_sends_headers_without_body() {
        let dir = temp_html_dir();
        let raw = run(Some(dir.clone()), "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let (head, body) = split(&raw);

        assert!(head.starts_with("HTTP/1.1 200"), "head={head}");
        assert!(body.is_empty(), "HEAD 不应返回 body");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_file_returns_404() {
        let dir = temp_html_dir();
        let raw = run(Some(dir.clone()), "GET /missing.html HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let (head, _) = split(&raw);
        assert!(head.starts_with("HTTP/1.1 404"), "head={head}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn traversal_returns_403() {
        let dir = temp_html_dir();
        let raw = run(Some(dir.clone()), "GET /../secret HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let (head, _) = split(&raw);
        assert!(head.starts_with("HTTP/1.1 403"), "head={head}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_base_dir_returns_404() {
        let raw = run(None, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let (head, _) = split(&raw);
        assert!(head.starts_with("HTTP/1.1 404"), "head={head}");
    }

    #[tokio::test]
    async fn malformed_request_returns_400() {
        let dir = temp_html_dir();
        let raw = run(Some(dir.clone()), "not-a-request").await;
        let (head, _) = split(&raw);
        assert!(head.starts_with("HTTP/1.1 400"), "head={head}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn validate_rejects_missing_dir() {
        let svc = StaticSourcesService::new(
            Some(PathBuf::from("definitely-not-exists-dir-xyz")),
            "index.html".to_string(),
        );
        assert!(svc.validate().is_err());

        let ok = StaticSourcesService::new(None, "index.html".to_string());
        assert!(ok.validate().is_ok());
    }
}
