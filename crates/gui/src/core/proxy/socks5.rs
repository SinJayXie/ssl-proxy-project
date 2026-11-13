use crate::state::AppState;
use crate::types::UdpMode;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::connect::resolve_and_connect;
use super::tunnel::forward_target_stream;
use super::udp_relay;

pub const AUTH_NO_PASS: u8 = 0x00;

// SOCKS5 命令码
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
// SOCKS5 应答码
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// 发送一个 SOCKS5 应答（BND.ADDR/PORT 统一为 0.0.0.0:0）
async fn send_reply(client: &mut TcpStream, code: u8) {
    let _ = client
        .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await;
}

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
///
/// 版本字节已由上游的协议探测消费。全程使用 `read_exact` 逐字段读取，
/// 避免请求被 TCP 分段时把合法握手误判为非法。
pub async fn handle_socks5_client(mut client: TcpStream, state: Arc<AppState>) {
    // Step 1: 读认证方法列表（nmethods + methods）
    let mut nmethods = [0u8; 1];
    if client.read_exact(&mut nmethods).await.is_err() {
        return;
    }
    if nmethods[0] == 0 {
        let _ = client.write_all(&[5, 0xFF]).await;
        return;
    }
    let mut methods = vec![0u8; nmethods[0] as usize];
    if client.read_exact(&mut methods).await.is_err() {
        return;
    }

    // Step 2: 只支持 NO_AUTH；客户端未提供时按规范拒绝
    if !methods.contains(&AUTH_NO_PASS) {
        let _ = client.write_all(&[5, 0xFF]).await;
        return;
    }
    if client.write_all(&[5, AUTH_NO_PASS]).await.is_err() {
        return;
    }

    // Step 3: 读请求头 VER / CMD / RSV / ATYP
    let mut head = [0u8; 4];
    if client.read_exact(&mut head).await.is_err() {
        return;
    }
    if head[0] != 5 || head[2] != 0 {
        send_reply(&mut client, REPLY_GENERAL_FAILURE).await;
        return;
    }

    // Step 4: 按 ATYP 读取目标地址（支持 IPv4 / 域名 / IPv6）
    let (host, is_domain) = match head[3] {
        1 => {
            let mut addr = [0u8; 4];
            if client.read_exact(&mut addr).await.is_err() {
                return;
            }
            (
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
                false,
            )
        }
        3 => {
            let mut len = [0u8; 1];
            if client.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut domain = vec![0u8; len[0] as usize];
            if client.read_exact(&mut domain).await.is_err() {
                return;
            }
            (
                String::from_utf8_lossy(&domain).to_string(),
                true,
            )
        }
        4 => {
            let mut addr = [0u8; 16];
            if client.read_exact(&mut addr).await.is_err() {
                return;
            }
            (Ipv6Addr::from(addr).to_string(), false)
        }
        _ => {
            send_reply(&mut client, REPLY_ATYP_NOT_SUPPORTED).await;
            return;
        }
    };

    let mut port_bytes = [0u8; 2];
    if client.read_exact(&mut port_bytes).await.is_err() {
        return;
    }
    let port = u16::from_be_bytes(port_bytes);

    match head[1] {
        CMD_CONNECT => create_connection_task(client, &host, port, is_domain, state).await,
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate(client, state).await;
        }
        _ => {
            log::error!(
                "Unsupported SOCKS5 command: 0x{:02x} (target {}:{})",
                head[1],
                host,
                port
            );
            send_reply(&mut client, REPLY_CMD_NOT_SUPPORTED).await;
        }
    }
}

/// 处理 SOCKS5 UDP ASSOCIATE（cmd=0x03）
///
/// - `udpMode=off`：回复 reply=0x07（Command not supported）并关闭连接；
/// - 其余模式：绑定本地 UDP 中继、回复 BND.ADDR/BND.PORT，维持控制连接
///   直到客户端断开（期间回收该 ASSOCIATE 的全部 UDP 会话）。
async fn handle_udp_associate(mut client: TcpStream, state: Arc<AppState>) {
    let udp_mode = state.config.read().await.udp_mode;
    if udp_mode == UdpMode::Off {
        // 与旧版行为一致：拒绝并关闭
        let _ = client
            .write_all(&[5, REPLY_CMD_NOT_SUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0])
            .await;
        log::debug!("SOCKS5 UDP ASSOCIATE rejected (udpMode=off)");
        return;
    }
    udp_relay::start_associate(client, state, udp_mode).await;
}
