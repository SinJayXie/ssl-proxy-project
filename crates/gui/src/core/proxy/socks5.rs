use crate::state::AppState;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::connect::resolve_and_connect;
use super::tunnel::forward_target_stream;

pub const AUTH_NO_PASS: u8 = 0x00;

/// Create a SOCKS5 connection task: resolve, connect, respond, pipe
pub async fn create_connection_task(
    mut client: TcpStream,
    host: &str,
    port: u16,
    is_domain: bool,
    state: Arc<AppState>,
) {
    let result = match resolve_and_connect(host, port, is_domain, &state).await {
        Some(r) => r,
        None => return,
    };

    // Send SOCKS5 success
    let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;

    // Bidirectional pipe
    forward_target_stream(client, result.target, result.id, state.clone()).await;

    // Cleanup
    let mut conns = state.connections.write().await;
    conns.remove(&result.id);
}

/// Handle a SOCKS5 client connection
pub async fn handle_socks5_client(mut client: TcpStream, state: Arc<AppState>) {
    let mut buf = [0u8; 262];

    // Step 1: Read SOCKS5 greeting (version byte already consumed by protocol detection)
    match client.read_exact(&mut buf[..1]).await {
        Ok(_) => {}
        _ => return,
    };
    let nauth = buf[0] as usize;
    if nauth > 255 {
        return;
    }
    if nauth > 0 {
        let _ = client.read_exact(&mut buf[..nauth]).await;
    }

    // Step 2: Negotiate auth method - send NO_AUTH
    let _ = client.write_all(&[5, AUTH_NO_PASS]).await;

    // Step 3: Read SOCKS5 request
    let n = match client.read(&mut buf).await {
        Ok(n) if n >= 7 && buf[0] == 5 && buf[1] == 1 => n,
        Ok(n) => {
            log::error!("Invalid SOCKS5 request: {:02x?}", &buf[..n.min(10)]);
            return;
        }
        _ => return,
    };

    // Step 4: Parse address
    let addr_type = buf[3];
    let (host, port, is_domain) = match addr_type {
        1 => {
            if n < 10 {
                return;
            }
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip, port, false)
        }
        3 => {
            let len = buf[4] as usize;
            if n < 5 + len + 2 {
                return;
            }
            let host = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
            (host, port, true)
        }
        _ => return,
    };

    create_connection_task(client, &host, port, is_domain, state).await;
}
