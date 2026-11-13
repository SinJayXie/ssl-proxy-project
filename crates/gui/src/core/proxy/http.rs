use crate::state::AppState;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::connect::resolve_and_connect;
use super::tunnel::{forward_target_stream, TargetStream};

// ==================== HTTP / HTTPS proxy handler ====================

/// Find byte sequence in a buffer
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 解析 `host:port` / `[v6]:port` 形式的 authority。
fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_string();
        let port = rest[end + 1..].strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// Parse absolute URL like http://host:port/path or https://host:port/path
/// Returns (host, port, remaining_path)
fn parse_absolute_url(url: &str) -> Option<(&str, u16, &str)> {
    let (url_no_scheme, default_port) = if let Some(rest) = url.strip_prefix("http://") {
        (rest, 80u16)
    } else if let Some(rest) = url.strip_prefix("https://") {
        (rest, 443u16)
    } else {
        return None;
    };

    let slash_pos = url_no_scheme.find('/').unwrap_or(url_no_scheme.len());
    let host_port = &url_no_scheme[..slash_pos];
    let path = if slash_pos < url_no_scheme.len() {
        &url_no_scheme[slash_pos..]
    } else {
        "/"
    };

    // 支持 IPv6 字面量（[::1]:8080）与普通 host:port
    if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Some((host, port, path));
    }

    if let Some(colon_pos) = host_port.rfind(':') {
        let h = &host_port[..colon_pos];
        let p: u16 = host_port[colon_pos + 1..].parse().ok()?;
        Some((h, p, path))
    } else {
        Some((host_port, default_port, path))
    }
}

/// 把客户端首批字节（请求头 + 可能紧随的 body）按目标类型写入上游。
///
/// `TargetStream::Proxy` 必须走隧道分帧，否则服务端会把 HTTP 明文字节当成帧头。
async fn send_initial(target: &mut TargetStream, data: &[u8]) -> std::io::Result<()> {
    match target {
        TargetStream::Direct(t) => t.write_all(data).await,
        TargetStream::Proxy(t) => {
            let mut framed = Vec::with_capacity(data.len() + 128);
            super::framing::encode_chunk(data, true, &mut framed);
            t.write_all(&framed).await
        }
        TargetStream::Mux(s) => s.send(data).await,
    }
}

/// Handle HTTP / HTTPS proxy client
pub async fn handle_http_client(mut client: TcpStream, first_byte: u8, state: Arc<AppState>) {
    // Read the rest of the request headers
    let mut buf = vec![first_byte];
    let mut tmp = [0u8; 8192];
    loop {
        match client.read(&mut tmp).await {
            Ok(n) if n > 0 => {
                buf.extend_from_slice(&tmp[..n]);
                if find_subsequence(&buf, b"\r\n\r\n").is_some() {
                    break;
                }
                if buf.len() > 65536 {
                    log::error!("HTTP request headers too large");
                    return;
                }
            }
            _ => return,
        }
    }

    // Find header boundary
    let headers_end = match find_subsequence(&buf, b"\r\n\r\n") {
        Some(pos) => pos + 4,
        None => return,
    };

    let headers_str = String::from_utf8_lossy(&buf[..headers_end]);
    let mut lines = headers_str.lines();

    let request_line = match lines.next() {
        Some(line) => line,
        None => return,
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        log::error!("Invalid HTTP request line: {}", request_line);
        return;
    }

    let method = parts[0].to_uppercase();
    let url = parts[1];

    if method == "CONNECT" {
        // ---- HTTPS proxy: CONNECT tunnel ----
        let (host, port) = match parse_authority(url) {
            Some(v) => v,
            None => {
                log::error!("Invalid CONNECT target: {}", url);
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return;
            }
        };

        log::info!("[HTTP CONNECT] {}:{}", host, port);

        let is_domain = host.parse::<std::net::IpAddr>().is_err();
        let result = match resolve_and_connect(&host, port, is_domain, &state).await {
            Some(r) => r,
            None => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return;
            }
        };

        // Send 200 Connection Established to client
        let _ = client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await;

        // Bidirectional tunnel（含 half-close 语义）
        forward_target_stream(client, result.target, result.id, state.clone()).await;

        // Cleanup
        let mut conns = state.connections.write().await;
        conns.remove(&result.id);
    } else {
        // ---- HTTP forward proxy: GET/POST/PUT/DELETE etc. ----
        let (host, port, path) = match parse_absolute_url(url) {
            Some(v) => v,
            None => {
                log::error!("Cannot parse absolute URL: {}", url);
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return;
            }
        };

        log::info!("[HTTP {}] {}:{}{}", method, host, port, path);

        let is_domain = host.parse::<std::net::IpAddr>().is_err();
        let mut result = match resolve_and_connect(host, port, is_domain, &state).await {
            Some(r) => r,
            None => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return;
            }
        };

        // Rebuild request with relative URL.
        // `request_line` comes from `str::lines()` and does not include the
        // trailing CRLF, so skip it explicitly before appending the headers.
        let mut new_req = format!("{} {} HTTP/1.1\r\n", method, path).into_bytes();
        let rest = &buf[request_line.len()..headers_end];
        let header_body = rest.strip_prefix(b"\r\n").unwrap_or(rest);
        new_req.extend_from_slice(header_body);
        // 与请求头同批到达的 body 必须一并转发，否则 POST/PUT 会丢数据
        new_req.extend_from_slice(&buf[headers_end..]);

        if let Err(e) = send_initial(&mut result.target, &new_req).await {
            log::error!("Failed to send HTTP request to {}:{}: {}", host, port, e);
            let mut conns = state.connections.write().await;
            conns.remove(&result.id);
            return;
        }

        // 双向转发：后续客户端数据（body / keep-alive / WebSocket）与响应都走同一管道
        forward_target_stream(client, result.target, result.id, state.clone()).await;

        // Cleanup
        let mut conns = state.connections.write().await;
        conns.remove(&result.id);
    }
}
