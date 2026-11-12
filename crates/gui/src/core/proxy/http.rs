use crate::state::AppState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;

use super::connect::resolve_and_connect;
use super::mux::MuxStream;
use super::tunnel::{forward_target_stream, track_copy, TargetStream};

// ==================== HTTP / HTTPS proxy handler ====================

/// Find byte sequence in a buffer
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse absolute URL like http://host:port/path or https://host:port/path
/// Returns (host, port, remaining_path)
fn parse_absolute_url(url: &str) -> Option<(&str, u16, &str)> {
    let url_no_scheme = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
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

    let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
        let h = &host_port[..colon_pos];
        let p: u16 = host_port[colon_pos + 1..].parse().ok()?;
        (h, p)
    } else {
        (host_port, 80u16)
    };

    Some((host, port, path))
}

/// Forward HTTP response data (TcpStream → client) with dataflow tracking
async fn forward_response_tcp(
    mut client: TcpStream,
    mut target: TcpStream,
    id: u32,
    state: Arc<AppState>,
) {
    let down = Arc::new(AtomicU64::new(0));
    let down_conn = Arc::new(AtomicU64::new(0));
    let down_clone = down.clone();
    let down_conn_clone = down_conn.clone();

    let state_clone = Arc::clone(&state);
    let flush_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let d = down_clone.load(Ordering::Relaxed);
            let dc = down_conn_clone.load(Ordering::Relaxed);
            let mut conns = state_clone.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.down = dc;
            }
            drop(conns);
            let mut total_df = state_clone.total_dataflow.write().await;
            total_df.down = total_df.down.max(d);
            total_df.total = total_df.up + total_df.down;
        }
    });

    if let Err(e) = track_copy(&mut target, &mut client, &down, &down_conn).await {
        log::debug!("HTTP response pipe closed: {}", e);
    }

    flush_handle.abort();

    let d = down.load(Ordering::Relaxed);
    let dc = down_conn.load(Ordering::Relaxed);
    {
        let mut conns = state.connections.write().await;
        if let Some(info) = conns.get_mut(&id) {
            info.data.down = dc;
        }
    }
    {
        let mut total_df = state.total_dataflow.write().await;
        total_df.down = total_df.down.max(d);
        total_df.total = total_df.up + total_df.down;
    }
}

/// Forward HTTP response data (TlsStream → client) with dataflow tracking
async fn forward_response_tls(
    mut client: TcpStream,
    mut target: TlsStream<TcpStream>,
    id: u32,
    state: Arc<AppState>,
) {
    let down = Arc::new(AtomicU64::new(0));
    let down_conn = Arc::new(AtomicU64::new(0));
    let down_clone = down.clone();
    let down_conn_clone = down_conn.clone();

    let state_clone = Arc::clone(&state);
    let flush_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let d = down_clone.load(Ordering::Relaxed);
            let dc = down_conn_clone.load(Ordering::Relaxed);
            let mut conns = state_clone.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.down = dc;
            }
            drop(conns);
            let mut total_df = state_clone.total_dataflow.write().await;
            total_df.down = total_df.down.max(d);
            total_df.total = total_df.up + total_df.down;
        }
    });

    if let Err(e) = track_copy(&mut target, &mut client, &down, &down_conn).await {
        log::debug!("HTTP response pipe closed (TLS): {}", e);
    }

    flush_handle.abort();

    let d = down.load(Ordering::Relaxed);
    let dc = down_conn.load(Ordering::Relaxed);
    {
        let mut conns = state.connections.write().await;
        if let Some(info) = conns.get_mut(&id) {
            info.data.down = dc;
        }
    }
    {
        let mut total_df = state.total_dataflow.write().await;
        total_df.down = total_df.down.max(d);
        total_df.total = total_df.up + total_df.down;
    }
}

/// 明文 HTTP 代理走 mux 流时，转发响应回客户端
async fn forward_response_mux(
    mut client: TcpStream,
    stream: MuxStream,
    id: u32,
    state: Arc<AppState>,
) {
    let (mut reader, _writer) = stream.split();

    let down = Arc::new(AtomicU64::new(0));
    let down_conn = Arc::new(AtomicU64::new(0));
    let down_clone = down.clone();
    let down_conn_clone = down_conn.clone();

    let state_clone = Arc::clone(&state);
    let flush_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let d = down_clone.load(Ordering::Relaxed);
            let dc = down_conn_clone.load(Ordering::Relaxed);
            let mut conns = state_clone.connections.write().await;
            if let Some(info) = conns.get_mut(&id) {
                info.data.down = dc;
            }
            drop(conns);
            let mut total_df = state_clone.total_dataflow.write().await;
            total_df.down = total_df.down.max(d);
            total_df.total = total_df.up + total_df.down;
        }
    });

    loop {
        match reader.recv().await {
            Ok(Some(data)) => {
                if client.write_all(&data).await.is_err() {
                    break;
                }
                down.fetch_add(data.len() as u64, Ordering::Relaxed);
                down_conn.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            Ok(None) => break,
            Err(e) => {
                log::debug!("HTTP response pipe closed (mux): {}", e);
                break;
            }
        }
    }

    flush_handle.abort();

    let d = down.load(Ordering::Relaxed);
    let dc = down_conn.load(Ordering::Relaxed);
    {
        let mut conns = state.connections.write().await;
        if let Some(info) = conns.get_mut(&id) {
            info.data.down = dc;
        }
    }
    {
        let mut total_df = state.total_dataflow.write().await;
        total_df.down = total_df.down.max(d);
        total_df.total = total_df.up + total_df.down;
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
        let host_port: Vec<&str> = url.split(':').collect();
        if host_port.len() != 2 {
            log::error!("Invalid CONNECT target: {}", url);
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return;
        }
        let host = host_port[0].to_string();
        let port: u16 = match host_port[1].parse() {
            Ok(p) => p,
            Err(_) => {
                log::error!("Invalid CONNECT port: {}", host_port[1]);
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return;
            }
        };

        log::info!("[HTTP CONNECT] {}:{}", host, port);

        let result = match resolve_and_connect(&host, port, true, &state).await {
            Some(r) => r,
            None => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return;
            }
        };

        // Send 200 Connection Established to client
        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;

        // Bidirectional tunnel
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

        let mut result = match resolve_and_connect(host, port, true, &state).await {
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

        // Send modified request to target
        match &mut result.target {
            TargetStream::Direct(t) => {
                if let Err(e) = t.write_all(&new_req).await {
                    log::error!("Failed to send HTTP request to direct target: {}", e);
                    let mut conns = state.connections.write().await;
                    conns.remove(&result.id);
                    return;
                }
            }
            TargetStream::Proxy(t) => {
                if let Err(e) = t.write_all(&new_req).await {
                    log::error!("Failed to send HTTP request via proxy: {}", e);
                    let mut conns = state.connections.write().await;
                    conns.remove(&result.id);
                    return;
                }
            }
            TargetStream::Mux(s) => {
                if let Err(e) = s.send(&new_req).await {
                    log::error!("Failed to send HTTP request via mux: {}", e);
                    let mut conns = state.connections.write().await;
                    conns.remove(&result.id);
                    return;
                }
            }
        }

        // Forward response back to client
        match result.target {
            TargetStream::Direct(target) => {
                forward_response_tcp(client, target, result.id, state.clone()).await;
            }
            TargetStream::Proxy(target) => {
                forward_response_tls(client, target, result.id, state.clone()).await;
            }
            TargetStream::Mux(target) => {
                forward_response_mux(client, target, result.id, state.clone()).await;
            }
        }

        // Cleanup
        let mut conns = state.connections.write().await;
        conns.remove(&result.id);
    }
}
