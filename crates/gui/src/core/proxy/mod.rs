pub mod connect;
mod framing;
mod http;
mod mux;
mod socks5;
mod tunnel;

use crate::state::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use socks5::handle_socks5_client;
use http::handle_http_client;

// ==================== Protocol detection at accept ====================

/// Detect protocol from first byte and dispatch to appropriate handler
async fn handle_client(mut client: TcpStream, state: Arc<AppState>) {
    use std::time::Duration;

    // Peek first byte
    let mut first_byte = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut first_byte)).await {
        Ok(Ok(_)) => {
            if first_byte[0] == 0x05 {
                // SOCKS5: version byte = 0x05
                log::debug!("Detected SOCKS5 protocol");
                handle_socks5_client(client, state).await;
            } else {
                // HTTP/HTTPS proxy: starts with ASCII method name or CONNECT
                log::debug!("Detected HTTP/HTTPS protocol (first byte: {:#04x})", first_byte[0]);
                handle_http_client(client, first_byte[0], state).await;
            }
        }
        Ok(Err(e)) => {
            log::debug!("Read first byte error: {}", e);
        }
        Err(_) => {
            log::debug!("Protocol detection timeout");
        }
    }
}

// ==================== Proxy server (unified SOCKS5 + HTTP/HTTPS) ====================

pub async fn start_socks5_server(state: Arc<AppState>) {
    let (port, bind_ips) = {
        let cfg = state.config.read().await;
        (cfg.socks_port, cfg.bind_ips.clone())
    };

    let ips: Vec<String> = if bind_ips.is_empty() {
        vec!["127.0.0.1".to_string()]
    } else {
        bind_ips
    };

    for ip in &ips {
        let addr = match format!("{}:{}", ip, port).parse::<SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                log::error!("Invalid bind address {}:{}: {}", ip, port, e);
                continue;
            }
        };
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("Failed to bind proxy server on {}: {}", addr, e);
                let code = e.raw_os_error().unwrap_or(-1);
                state.push_error(code).await;
                continue;
            }
        };

        log::info!("Proxy server (SOCKS5 + HTTP/HTTPS) started on {}", addr);

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, _)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            handle_client(socket, state).await;
                        });
                    }
                    Err(e) => {
                        log::error!("Accept error on {}: {}", addr, e);
                    }
                }
            }
        });
    }
}
