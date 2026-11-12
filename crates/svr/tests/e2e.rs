//! 端到端集成测试：真实 TLS 连接 → 首包识别 → 协议分流（静态站点 / 私有协议隧道）。
//!
//! 每个用例都会完整装配 `StaticSourcesService` + `ForwardService` + `ProxyService` + `SocketService`，
//! 用临时自签证书在随机端口上启动，再用 rustls 客户端发起真实 TLS 请求。

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use ssl_proxy_svr::config::ServerConfig as ServerCfg;
use ssl_proxy_svr::core::service::ServiceRegister;
use ssl_proxy_svr::libs::rate_limit::RateLimitConfig;
use ssl_proxy_svr::services::forward_service::ForwardService;
use ssl_proxy_svr::services::framing::{append_frame, encode_chunk, read_frame, FLAG_UDP};
use ssl_proxy_svr::services::mux::{
    append_frame as append_mux_frame, encode_ctl, encode_data, encode_open,
    read_frame as read_mux_frame, FLAG_UDP as MUX_FLAG_UDP, FLAG_UDP_CLOSE as MUX_FLAG_UDP_CLOSE,
};
use ssl_proxy_svr::services::proxy_service::ProxyService;
use ssl_proxy_svr::services::socket_service::{load_tls_config, SocketService};
use ssl_proxy_svr::services::static_sources_service::StaticSourcesService;
use ssl_proxy_svr::services::udp_relay_service::{
    encode_udp_packet, is_forbidden_ip, parse_udp_packet, UdpSettings,
};
use ssl_proxy_svr::utils::protocol::{
    ack_mac, encode_packet, encode_packet_ext, EXT_UDP, MAC_LEN, TUNNEL_ACK,
};

const PASSWORD: &str = "e2e-secret-password";
const INDEX_BODY: &str = "<html><body>masquerade site</body></html>";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_REQUESTS: u32 = 300;

type ClientStream = tokio_rustls::client::TlsStream<TcpStream>;

static SEQ: AtomicU64 = AtomicU64::new(0);

// -----------------------------------------------------------------------------
// 测试用服务端装配
// -----------------------------------------------------------------------------

/// 在随机端口上启动完整服务栈，并在临时目录写入证书与静态站点。
struct Harness {
    port: u16,
    register: ServiceRegister,
    cert: CertificateDer<'static>,
    dir: PathBuf,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with_options(DEFAULT_MAX_REQUESTS, None).await
    }

    async fn start_with_rate_limit(max_requests: u32) -> Self {
        Self::start_with_options(max_requests, None).await
    }

    /// `udp_enabled = true` 时按默认参数启用 UDP relay（timeout=60s, rate=100）
    async fn start_with_udp(udp_enabled: bool) -> Self {
        Self::start_with_options(
            DEFAULT_MAX_REQUESTS,
            udp_enabled.then(|| UdpSettings {
                timeout: Duration::from_secs(60),
                rate_limit: 100,
            }),
        )
        .await
    }

    async fn start_with_options(max_requests: u32, udp: Option<UdpSettings>) -> Self {
        let dir = unique_dir();
        let html_dir = dir.join("html");
        std::fs::create_dir_all(&html_dir).expect("create html dir");
        std::fs::write(html_dir.join("index.html"), INDEX_BODY).expect("write index.html");

        let (cert_pem, key_pem, cert_der) = make_cert();
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        std::fs::write(&cert_path, cert_pem).expect("write cert");
        std::fs::write(&key_path, key_pem).expect("write key");

        let tls_cfg = load_tls_config(Some(cert_path.as_path()), Some(key_path.as_path()), None)
            .expect("load tls config");

        let port = free_port().await;

        let static_sources = Arc::new(StaticSourcesService::new(
            Some(html_dir),
            "index.html".to_string(),
        ));
        let forward = Arc::new(ForwardService::new(
            static_sources.clone(),
            RateLimitConfig {
                max_requests,
                rate_time: Duration::from_secs(60),
                black_time: Duration::from_secs(600),
            },
        ));
        let udp = udp.map(Arc::new);
        let proxy = Arc::new(ProxyService::new(
            PASSWORD.to_string(),
            forward.clone(),
            true,
            udp,
        ));
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        let socket = Arc::new(SocketService::new(
            ServerCfg {
                listen: "127.0.0.1".to_string(),
                port,
                password: PASSWORD.to_string(),
                mux: true,
            },
            tls_cfg,
            forward.clone(),
            proxy.clone(),
            shutdown_tx,
            Arc::new(AtomicUsize::new(0)),
        ));

        let register = ServiceRegister::new()
            .add(static_sources)
            .add(forward)
            .add(proxy)
            .add(socket);
        register.start_all().await.expect("start all services");

        Self {
            port,
            register,
            cert: cert_der,
            dir,
        }
    }

    async fn connect(&self) -> ClientStream {
        connect_tls(self.port, self.cert.clone()).await
    }

    async fn stop(self) {
        self.register.stop_all().await.expect("stop all services");
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // 用例 panic 时也能清理临时目录
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn unique_dir() -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "ssl-proxy-e2e-{}-{}",
        std::process::id(),
        seq
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// 生成一张自签证书，返回 (证书 PEM, 私钥 PEM, 证书 DER)
fn make_cert() -> (String, String, CertificateDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("gen cert");
    let cert_der = cert.der().clone();
    (cert.pem(), key_pair.serialize_pem(), cert_der)
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind :0");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

async fn connect_tls(port: u16, cert: CertificateDer<'static>) -> ClientStream {
    let mut roots = RootCertStore::empty();
    roots.add(cert).expect("add root cert");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .expect("tls handshake")
}

// -----------------------------------------------------------------------------
// 请求/响应辅助
// -----------------------------------------------------------------------------

/// 发送原始请求并读到 EOF（服务端 `Connection: close`）。
async fn send_and_read(stream: &mut ClientStream, request: &[u8]) -> Vec<u8> {
    stream.write_all(request).await.expect("write request");
    stream.flush().await.expect("flush");
    read_to_eof(stream).await
}

async fn read_to_eof(stream: &mut ClientStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

fn split_response(raw: &[u8]) -> (String, Vec<u8>) {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header terminator in response: {:?}", String::from_utf8_lossy(raw)));
    (
        String::from_utf8_lossy(&raw[..pos]).to_string(),
        raw[pos + 4..].to_vec(),
    )
}

async fn gunzip(data: Vec<u8>) -> String {
    use async_compression::tokio::bufread::GzipDecoder;

    let mut decoder =
        GzipDecoder::new(tokio::io::BufReader::new(std::io::Cursor::new(data)));
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .await
        .expect("gunzip response body");
    out
}

/// 当前 Unix 时间戳（秒）
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 读取并校验服务端隧道应答（`[0x10,0xff] || 32B ACK MAC`）
async fn expect_tunnel_ack(
    stream: &mut ClientStream,
    password: &str,
    timestamp: u64,
    host: &str,
    port: u16,
) {
    let mut ack = [0u8; 2 + MAC_LEN];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut ack))
        .await
        .expect("ack timeout")
        .expect("read ack");

    assert_eq!(&ack[..2], &TUNNEL_ACK, "隧道应答魔数不匹配");
    let expected = ack_mac(password, timestamp, port, host);
    assert_eq!(&ack[2..], &expected, "ACK MAC 校验失败");
}

/// 启动一个回显用的上游 TCP 服务，返回其端口。
async fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = listener.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// 收集本机候选 IP：主机名解析（覆盖各网卡地址）+ localhost。
fn local_candidate_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let mut push = |host: String| {
        if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0u16)) {
            for addr in addrs {
                if !ips.contains(&addr.ip()) {
                    ips.push(addr.ip());
                }
            }
        }
    };
    if let Ok(name) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        push(name);
    }
    push("localhost".to_string());
    ips
}

/// 启动一个 UDP 回显目标，返回 `(地址, 端口)`。
///
/// 回环 / 内网地址会被 relay 的 SSRF 规则拦截，因此只在未被禁止的本机地址上
/// 绑定（优先公网 / 全球单播地址），找不到则 panic。
async fn spawn_udp_echo() -> (IpAddr, u16) {
    let mut candidates = local_candidate_ips();
    // 默认路由出口地址（UDP connect 只选路，不实际发包）
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                candidates.push(addr.ip());
            }
        }
    }
    let allowed: Vec<IpAddr> = candidates
        .into_iter()
        .filter(|ip| !is_forbidden_ip(*ip))
        .collect();
    for ip in allowed {
        if let Ok(socket) = tokio::net::UdpSocket::bind((ip, 0)).await {
            let port = socket.local_addr().expect("udp echo addr").port();
            let socket = Arc::new(socket);
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, from)) => {
                            if socket.send_to(&buf[..n], from).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            return (ip, port);
        }
    }
    panic!("本机不存在未被 SSRF 规则禁止的地址，无法搭建 UDP echo 目标");
}

/// 编码并发送一个非 mux UDP 隧道的认证首包（`port = 0` 标记）+ 首个 FLAG_UDP 帧。
///
/// 服务端在收到首个 FLAG_UDP 帧之前不会回 ACK，因此认证与首帧一起发送。
async fn open_udp_tunnel(
    stream: &mut ClientStream,
    stream_id: u32,
    host: &str,
    port: u16,
    dgram: &[u8],
) {
    let ts = unix_now();
    let packet = encode_packet_ext(host, 0, PASSWORD, ts, EXT_UDP);
    stream.write_all(&packet).await.expect("write udp auth");

    let payload = encode_udp_packet(stream_id, host, port, dgram).expect("encode udp packet");
    let mut frame = Vec::new();
    append_frame(&mut frame, &payload, 0, FLAG_UDP);
    stream.write_all(&frame).await.expect("write udp frame");

    expect_tunnel_ack(stream, PASSWORD, ts, host, 0).await;
    let mut cap = [0u8; 1];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut cap))
        .await
        .expect("cap timeout")
        .expect("read cap");
    assert_eq!(cap[0], 0x01, "udp.enabled=true 时能力位应为 CAP_UDP");
}

/// 读取一个与请求 `(stream_id, host, port)` 匹配的 FLAG_UDP 回包帧，返回 dgram。
async fn read_udp_reply(stream: &mut ClientStream, stream_id: u32, host: &str, port: u16) -> Vec<u8> {
    let mut payload = Vec::new();
    for _ in 0..64 {
        let flag = tokio::time::timeout(IO_TIMEOUT, read_frame(stream, &mut payload))
            .await
            .expect("udp reply timeout")
            .expect("read udp reply frame");
        if flag != FLAG_UDP {
            continue;
        }
        if let Some((sid, rhost, rport, dgram)) = parse_udp_packet(&payload) {
            assert_eq!(sid, stream_id, "回包 stream_id 应与请求一致");
            assert_eq!(rhost, host, "回包目标应与请求一致");
            assert_eq!(rport, port, "回包端口应为目标端口");
            return dgram.to_vec();
        }
    }
    panic!("no udp reply");
}

fn http_get(path: &str) -> Vec<u8> {
    format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", path).into_bytes()
}

// -----------------------------------------------------------------------------
// 静态站点分支
// -----------------------------------------------------------------------------

#[tokio::test]
async fn http_get_serves_index_with_gzip() {
    let h = Harness::start().await;
    let mut stream = h.connect().await;

    let raw = send_and_read(&mut stream, &http_get("/")).await;
    let (head, body) = split_response(&raw);

    assert!(head.starts_with("HTTP/1.1 200 OK"), "head={head}");
    assert!(head.contains("Content-Encoding: gzip"), "head={head}");
    assert_eq!(gunzip(body).await, INDEX_BODY);

    h.stop().await;
}

#[tokio::test]
async fn http_get_missing_file_returns_404() {
    let h = Harness::start().await;
    let mut stream = h.connect().await;

    let raw = send_and_read(&mut stream, &http_get("/nope.html")).await;
    let (head, _) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 404"), "head={head}");

    h.stop().await;
}

#[tokio::test]
async fn http_path_traversal_returns_403() {
    let h = Harness::start().await;
    let mut stream = h.connect().await;

    let raw = send_and_read(&mut stream, &http_get("/../Cargo.toml")).await;
    let (head, _) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 403"), "head={head}");

    h.stop().await;
}

#[tokio::test]
async fn http_head_returns_no_body() {
    let h = Harness::start().await;
    let mut stream = h.connect().await;

    let request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let raw = send_and_read(&mut stream, request).await;
    let (head, body) = split_response(&raw);

    assert!(head.starts_with("HTTP/1.1 200"), "head={head}");
    assert!(body.is_empty(), "HEAD 响应不应有 body");

    h.stop().await;
}

#[tokio::test]
async fn rate_limit_drops_connection_after_threshold() {
    // max_requests = 2：第 2 次请求即触发封禁，连接被直接断开
    let h = Harness::start_with_rate_limit(2).await;

    let mut first = h.connect().await;
    let raw = send_and_read(&mut first, &http_get("/")).await;
    let (head, _) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "head={head}");

    let mut second = h.connect().await;
    second
        .write_all(&http_get("/"))
        .await
        .expect("write request");

    // 服务端直接丢弃连接（不发送 close_notify），读到 EOF 或 UnexpectedEof 都算被限流
    let mut buf = [0u8; 64];
    match tokio::time::timeout(IO_TIMEOUT, second.read(&mut buf))
        .await
        .expect("read timeout")
    {
        Ok(0) => {}
        Ok(n) => panic!(
            "触发限流后不应收到数据，实际收到 {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(_) => {}
    }

    h.stop().await;
}

// -----------------------------------------------------------------------------
// 私有协议分支
// -----------------------------------------------------------------------------

#[tokio::test]
async fn private_protocol_opens_tunnel_and_echoes() {
    let h = Harness::start().await;
    let echo_port = spawn_echo_upstream().await;
    let mut stream = h.connect().await;

    let ts = unix_now();
    let packet = encode_packet("127.0.0.1", echo_port, PASSWORD, ts);
    stream.write_all(&packet).await.expect("write packet");
    stream.flush().await.expect("flush");

    expect_tunnel_ack(&mut stream, PASSWORD, ts, "127.0.0.1", echo_port).await;

    // 隧道内为分帧数据：上行编码后发送，下行为分帧 + padding
    let plain: &[u8] = b"ping-through-tunnel";
    let mut framed = Vec::new();
    encode_chunk(plain, true, &mut framed);
    stream
        .write_all(&framed)
        .await
        .expect("write framed payload");

    let mut echoed = Vec::new();
    let mut payload = Vec::new();
    while echoed.len() < plain.len() {
        tokio::time::timeout(IO_TIMEOUT, read_frame(&mut stream, &mut payload))
            .await
            .expect("echo timeout")
            .expect("read echo frame");
        echoed.extend_from_slice(&payload);
    }
    assert_eq!(echoed.as_slice(), plain);

    drop(stream);
    h.stop().await;
}

#[tokio::test]
async fn udp_ext_negotiation_appends_capability_byte() {
    let h = Harness::start().await;
    let echo_port = spawn_echo_upstream().await;
    let mut stream = h.connect().await;

    let ts = unix_now();
    // 新格式首包：MAC 之后追加 1 字节扩展位（bit0 = 请求 UDP）
    let packet = encode_packet_ext("127.0.0.1", echo_port, PASSWORD, ts, EXT_UDP);
    stream.write_all(&packet).await.expect("write packet");
    stream.flush().await.expect("flush");

    expect_tunnel_ack(&mut stream, PASSWORD, ts, "127.0.0.1", echo_port).await;

    // 客户端携带扩展位 → 服务端在 ACK MAC 之后追加 1 字节能力位
    // （服务端 udp.enabled=false（默认），能力位为 0x00 = 不支持）
    let mut cap = [0u8; 1];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut cap))
        .await
        .expect("capability byte timeout")
        .expect("read capability byte");
    assert_eq!(cap[0], 0x00, "udp 未启用时能力位应为 0x00");

    // 能力字节已被消费，后续隧道数据不受影响
    let plain: &[u8] = b"after-cap-echo";
    let mut framed = Vec::new();
    encode_chunk(plain, true, &mut framed);
    stream
        .write_all(&framed)
        .await
        .expect("write framed payload");

    let mut echoed = Vec::new();
    let mut payload = Vec::new();
    while echoed.len() < plain.len() {
        tokio::time::timeout(IO_TIMEOUT, read_frame(&mut stream, &mut payload))
            .await
            .expect("echo timeout")
            .expect("read echo frame");
        echoed.extend_from_slice(&payload);
    }
    assert_eq!(echoed.as_slice(), plain);

    drop(stream);
    h.stop().await;
}

#[tokio::test]
async fn old_client_receives_no_capability_byte() {
    let h = Harness::start().await;
    let echo_port = spawn_echo_upstream().await;
    let mut stream = h.connect().await;

    // 旧格式首包（无扩展位）；上游可达才能确保 ACK 被发出
    let ts = unix_now();
    let packet = encode_packet("127.0.0.1", echo_port, PASSWORD, ts);
    stream.write_all(&packet).await.expect("write packet");
    stream.flush().await.expect("flush");

    expect_tunnel_ack(&mut stream, PASSWORD, ts, "127.0.0.1", echo_port).await;

    // 旧客户端不得收到能力字节：短窗口内应无数据（超时 / EOF 均视为未多发）
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
        Err(_) => {}    // 超时：服务端未多发
        Ok(Ok(0)) => {} // 连接关闭：同样未多发
        Ok(Ok(n)) => panic!("旧客户端不应收到能力字节，实际收到 {n} 字节"),
        Ok(Err(e)) => panic!("读取 ACK 后续字节出错: {e}"),
    }

    drop(stream);
    h.stop().await;
}

#[tokio::test]
async fn private_protocol_wrong_password_falls_back_to_static() {
    let h = Harness::start().await;
    let mut stream = h.connect().await;

    let packet = encode_packet("127.0.0.1", 1, "wrong-password", unix_now());
    stream.write_all(&packet).await.expect("write packet");

    // 回落到静态站点：首包不是 HTTP，解析失败 → 400
    let raw = read_to_eof(&mut stream).await;
    let (head, _) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 400"), "head={head}");

    h.stop().await;
}

#[tokio::test]
async fn private_protocol_expired_timestamp_falls_back_to_static() {
    let h = Harness::start().await;
    let mut stream = h.connect().await;

    // 时间戳超出允许窗口，即使 MAC 正确也应被拒绝
    let stale_ts = unix_now() - 600;
    let packet = encode_packet("127.0.0.1", 1, PASSWORD, stale_ts);
    stream.write_all(&packet).await.expect("write packet");

    let raw = read_to_eof(&mut stream).await;
    let (head, _) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 400"), "head={head}");

    h.stop().await;
}

#[tokio::test]
async fn mux_connection_carries_multiple_streams() {
    let h = Harness::start().await;
    let echo_port = spawn_echo_upstream().await;
    let mut stream = h.connect().await;

    // hostLen = 0：mux 连接
    let ts = unix_now();
    let packet = encode_packet("", 0, PASSWORD, ts);
    stream.write_all(&packet).await.expect("write mux packet");

    expect_tunnel_ack(&mut stream, PASSWORD, ts, "", 0).await;

    // 在同一条 TLS 连接上开两条流
    stream
        .write_all(&encode_open(1, "127.0.0.1", echo_port))
        .await
        .expect("open stream 1");
    stream
        .write_all(&encode_open(2, "127.0.0.1", echo_port))
        .await
        .expect("open stream 2");
    stream
        .write_all(&encode_data(1, b"stream-one"))
        .await
        .expect("send stream 1");
    stream
        .write_all(&encode_data(2, b"stream-two"))
        .await
        .expect("send stream 2");

    let (mut got1, mut got2) = (Vec::new(), Vec::new());
    let mut payload = Vec::new();
    while got1.len() < b"stream-one".len() || got2.len() < b"stream-two".len() {
        let (flag, sid) = tokio::time::timeout(IO_TIMEOUT, read_mux_frame(&mut stream, &mut payload))
            .await
            .expect("mux frame timeout")
            .expect("read mux frame");
        if flag != 0 {
            // 只收集 DATA 帧（服务端下行不会发 OPEN）
            continue;
        }
        match sid {
            1 => got1.extend_from_slice(&payload),
            2 => got2.extend_from_slice(&payload),
            _ => {}
        }
    }

    assert_eq!(got1.as_slice(), b"stream-one");
    assert_eq!(got2.as_slice(), b"stream-two");

    drop(stream);
    h.stop().await;
}

// -----------------------------------------------------------------------------
// UDP relay
// -----------------------------------------------------------------------------

/// UDP over TLS 往返：认证（port=0）+ FLAG_UDP 帧 → 本地 UDP 回显目标 → 回包封帧。
#[tokio::test]
async fn udp_tunnel_relays_datagrams_both_ways() {
    let h = Harness::start_with_udp(true).await;
    let (echo_ip, echo_port) = spawn_udp_echo().await;
    let mut stream = h.connect().await;

    open_udp_tunnel(&mut stream, 0x1234, &echo_ip.to_string(), echo_port, b"hello-over-udp").await;

    // 回包：同 stream_id 的 FLAG_UDP 帧
    let mut got = None;
    let mut payload = Vec::new();
    for _ in 0..64 {
        let flag = tokio::time::timeout(IO_TIMEOUT, read_frame(&mut stream, &mut payload))
            .await
            .expect("udp reply timeout")
            .expect("read udp reply frame");
        if flag != FLAG_UDP {
            continue;
        }
        if let Some((sid, host, port, dgram)) = parse_udp_packet(&payload) {
            assert_eq!(sid, 0x1234, "回包 stream_id 应与请求一致");
            assert_eq!(host, echo_ip.to_string());
            assert_eq!(port, echo_port, "回包端口应为目标端口");
            got = Some(dgram.to_vec());
            break;
        }
    }
    assert_eq!(got.expect("no udp reply"), b"hello-over-udp");

    drop(stream);
    h.stop().await;
}

/// 会话空闲超时回收（`udp.timeout`）：空闲超过超时时间后会话被回收，
/// 隧道继续可用——同 stream_id 的后续数据报触发新建会话并正常往返。
#[tokio::test]
async fn udp_session_idle_timeout_reclaims_and_still_relays() {
    let h = Harness::start_with_options(
        DEFAULT_MAX_REQUESTS,
        Some(UdpSettings {
            timeout: Duration::from_millis(300),
            rate_limit: 100,
        }),
    )
    .await;
    let (echo_ip, echo_port) = spawn_udp_echo().await;
    let mut stream = h.connect().await;

    open_udp_tunnel(&mut stream, 1, &echo_ip.to_string(), echo_port, b"first").await;
    let got = read_udp_reply(&mut stream, 1, &echo_ip.to_string(), echo_port).await;
    assert_eq!(got, b"first", "回收前会话应正常往返");

    // 空闲超过 timeout（300ms）：会话被回收
    tokio::time::sleep(Duration::from_millis(800)).await;

    // 回收后继续转发：同 stream_id 触发新建会话，仍正常往返
    let payload = encode_udp_packet(1, &echo_ip.to_string(), echo_port, b"second").expect("encode");
    let mut frame = Vec::new();
    append_frame(&mut frame, &payload, 0, FLAG_UDP);
    stream.write_all(&frame).await.expect("write second frame");

    let got = read_udp_reply(&mut stream, 1, &echo_ip.to_string(), echo_port).await;
    assert_eq!(got, b"second", "回收后应按需新建会话并继续转发");

    drop(stream);
    h.stop().await;
}

/// SSRF：目标 127.0.0.1 的 UDP 数据报被丢弃——既无转发也无回包。
#[tokio::test]
async fn udp_ssrf_targets_are_dropped() {
    let h = Harness::start_with_udp(true).await;
    let mut stream = h.connect().await;

    // 本地 UDP 探针：验证报文确实未被转发
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind probe");
    let probe_port = probe.local_addr().expect("probe addr").port();

    open_udp_tunnel(&mut stream, 7, "127.0.0.1", probe_port, b"ssrf").await;

    // 无转发：探针收不到任何报文
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(400), probe.recv_from(&mut buf))
            .await
            .is_err(),
        "SSRF 目标不应收到任何 UDP 报文"
    );

    // 无回包：隧道上不应出现 FLAG_UDP 帧
    let mut payload = Vec::new();
    assert!(
        tokio::time::timeout(Duration::from_millis(400), read_frame(&mut stream, &mut payload))
            .await
            .is_err(),
        "SSRF 目标不应有任何封帧回包"
    );

    drop(stream);
    h.stop().await;
}

/// `udp.enabled=false`（默认）时：port=0 的 UDP 隧道认证被安全拒绝，连接被关闭。
#[tokio::test]
async fn udp_disabled_rejects_udp_tunnel() {
    let h = Harness::start().await; // udp.enabled 默认 false
    let mut stream = h.connect().await;

    let ts = unix_now();
    let packet = encode_packet_ext("127.0.0.1", 0, PASSWORD, ts, EXT_UDP);
    stream.write_all(&packet).await.expect("write auth");

    // 客户端随后发出 FLAG_UDP 帧（服务端不会处理，且连接即将被关闭）
    let payload = encode_udp_packet(1, "127.0.0.1", 53312, b"nope").expect("encode");
    let mut frame = Vec::new();
    append_frame(&mut frame, &payload, 0, FLAG_UDP);
    stream.write_all(&frame).await.expect("write udp frame");

    // 服务端不回 ACK，直接关闭连接：读端 EOF / TLS 错误 / 超时
    let mut buf = [0u8; 8];
    match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        Err(_) => {}           // 超时：无数据
        Ok(Ok(0)) => {}        // EOF：已关闭
        Ok(Ok(n)) => panic!("udp 关闭后不应有数据，收到 {n} 字节"),
        Ok(Err(_)) => {}       // TLS 错误（如 unexpected EOF）：同样视为拒绝
    }

    drop(stream);
    h.stop().await;
}

/// 能力协商：`udp.enabled=true` + 客户端 ext 首包 → TCP 隧道 ACK 能力字节为 0x01。
#[tokio::test]
async fn udp_enabled_ack_carries_capability_bit() {
    let h = Harness::start_with_udp(true).await;
    let echo_port = spawn_echo_upstream().await;
    let mut stream = h.connect().await;

    let ts = unix_now();
    let packet = encode_packet_ext("127.0.0.1", echo_port, PASSWORD, ts, EXT_UDP);
    stream.write_all(&packet).await.expect("write packet");

    expect_tunnel_ack(&mut stream, PASSWORD, ts, "127.0.0.1", echo_port).await;
    let mut cap = [0u8; 1];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut cap))
        .await
        .expect("cap timeout")
        .expect("read cap");
    assert_eq!(cap[0], 0x01, "udp.enabled=true 时能力位应为 CAP_UDP");

    // TCP 路径完全不受影响：回显仍正常
    let plain: &[u8] = b"tcp-still-works";
    let mut framed = Vec::new();
    encode_chunk(plain, true, &mut framed);
    stream.write_all(&framed).await.expect("write framed payload");

    let mut echoed = Vec::new();
    let mut payload = Vec::new();
    while echoed.len() < plain.len() {
        tokio::time::timeout(IO_TIMEOUT, read_frame(&mut stream, &mut payload))
            .await
            .expect("echo timeout")
            .expect("read echo frame");
        echoed.extend_from_slice(&payload);
    }
    assert_eq!(echoed.as_slice(), plain);

    drop(stream);
    h.stop().await;
}

/// mux UDP 流（FLAG_UDP = 6）：payload 与非 mux 一致，NAT 按 payload stream_id 维护。
#[tokio::test]
async fn mux_udp_stream_relays_datagrams() {
    let h = Harness::start_with_udp(true).await;
    let (echo_ip, echo_port) = spawn_udp_echo().await;
    let mut stream = h.connect().await;

    // mux 认证：host 为空 + port=0
    let ts = unix_now();
    let packet = encode_packet_ext("", 0, PASSWORD, ts, EXT_UDP);
    stream.write_all(&packet).await.expect("write mux auth");
    expect_tunnel_ack(&mut stream, PASSWORD, ts, "", 0).await;
    let mut cap = [0u8; 1];
    stream.read_exact(&mut cap).await.expect("read cap");
    assert_eq!(cap[0], 0x01);

    // mux UDP 帧：flag=6、sid=9，payload = UDP 报文编码（stream_id=9）
    let udp_payload =
        encode_udp_packet(9, &echo_ip.to_string(), echo_port, b"mux-udp").expect("encode");
    let mut frame = Vec::new();
    append_mux_frame(&mut frame, MUX_FLAG_UDP, 9, &udp_payload, 0);
    stream.write_all(&frame).await.expect("write mux udp frame");

    // 回包：flag=6、sid=9
    let mut got = None;
    let mut payload = Vec::new();
    for _ in 0..64 {
        let (flag, sid) =
            tokio::time::timeout(IO_TIMEOUT, read_mux_frame(&mut stream, &mut payload))
                .await
                .expect("mux udp reply timeout")
                .expect("read mux udp reply frame");
        if flag != MUX_FLAG_UDP {
            continue;
        }
        if let Some((stream_id, _, _, dgram)) = parse_udp_packet(&payload) {
            assert_eq!(sid, 9, "回包 sid 应原样回显");
            assert_eq!(stream_id, 9, "回包 stream_id 应与请求一致");
            got = Some(dgram.to_vec());
            break;
        }
    }
    assert_eq!(got.expect("no mux udp reply"), b"mux-udp");

    drop(stream);
    h.stop().await;
}

/// mux FLAG_UDP_CLOSE(=7)：客户端回收 UDP 会话 → 服务端按 sid 摘除 NAT 表项，
/// 不回任何帧（尤其不得落入兜底分支回 RST），连接保持可用。
#[tokio::test]
async fn mux_udp_close_frame_reclaims_session_without_breaking_connection() {
    let h = Harness::start_with_udp(true).await;
    let (echo_ip, echo_port) = spawn_udp_echo().await;
    let mut stream = h.connect().await;

    // mux 认证：host 为空 + port=0，带 UDP 扩展位
    let ts = unix_now();
    let packet = encode_packet_ext("", 0, PASSWORD, ts, EXT_UDP);
    stream.write_all(&packet).await.expect("write mux auth");
    expect_tunnel_ack(&mut stream, PASSWORD, ts, "", 0).await;
    let mut cap = [0u8; 1];
    stream.read_exact(&mut cap).await.expect("read cap");
    assert_eq!(cap[0], 0x01);

    // FLAG_UDP_CLOSE(=7)：未知 sid 的会话回收请求，服务端不得回任何帧
    stream
        .write_all(&encode_ctl(MUX_FLAG_UDP_CLOSE, 42))
        .await
        .expect("write udp close");

    let mut payload = Vec::new();
    match tokio::time::timeout(
        Duration::from_millis(400),
        read_mux_frame(&mut stream, &mut payload),
    )
    .await
    {
        Err(_) => {} // 超时：未回任何帧（正确行为）
        Ok(Ok((flag, sid))) => panic!("FLAG_UDP_CLOSE 不应触发回帧，实际 flag={flag} sid={sid}"),
        Ok(Err(e)) => panic!("FLAG_UDP_CLOSE 后连接被关闭: {e}"),
    }

    // 连接仍可用：同一 mux 连接上的 UDP 转发照常工作
    let udp_payload =
        encode_udp_packet(9, &echo_ip.to_string(), echo_port, b"after-close").expect("encode");
    let mut frame = Vec::new();
    append_mux_frame(&mut frame, MUX_FLAG_UDP, 9, &udp_payload, 0);
    stream.write_all(&frame).await.expect("write mux udp frame");

    let mut got = None;
    for _ in 0..64 {
        let (flag, sid) =
            tokio::time::timeout(IO_TIMEOUT, read_mux_frame(&mut stream, &mut payload))
                .await
                .expect("mux udp reply timeout")
                .expect("read mux udp reply frame");
        if flag != MUX_FLAG_UDP {
            continue;
        }
        if let Some((stream_id, _, _, dgram)) = parse_udp_packet(&payload) {
            assert_eq!(sid, 9, "回包 sid 应原样回显");
            assert_eq!(stream_id, 9, "回包 stream_id 应与请求一致");
            got = Some(dgram.to_vec());
            break;
        }
    }
    assert_eq!(got.expect("no mux udp reply after close frame"), b"after-close");

    drop(stream);
    h.stop().await;
}

// -----------------------------------------------------------------------------
// 跨端 e2e：完全按客户端（crates/gui）实现构造流量
// -----------------------------------------------------------------------------
//
// 以下编码逐字段复刻客户端实现，锁定双端契约（任一端格式漂移都会在此暴露）：
// - 认证首包：`gui/src/core/proxy/connect.rs::create_protocol_header`
//   （MAGIC || ver=2 || ts u64 BE || port u16 BE || hostLen u8 || host || MAC || EXT_UDP）
// - MAC 域：`connect.rs::compute_mac` = HMAC-SHA256(password, prefix || ts BE || port BE || host)
//   （REQ = "ssl-proxy-v2"，ACK = "ssl-proxy-v2-ack"；port=0 时两端行为一致）
// - UDP 包编码：`gui/src/core/proxy/framing.rs::encode_udp_packet`
//   （stream_id u32 BE || atyp || addr || port u16 BE || dgram_len u16 BE || dgram）
// - UDP 帧封装：`gui/src/core/proxy/framing.rs::append_udp_frame`
//   （flag=2 || len u16 BE || padLen u8 || payload || pad）
// - 回包解析：`gui/src/core/proxy/framing.rs::parse_udp_packet`

/// 客户端 REQ MAC 域前缀（connect.rs `REQ_PREFIX`）
const CLI_REQ_PREFIX: &[u8] = b"ssl-proxy-v2";
/// 客户端 ACK MAC 域前缀（connect.rs `ACK_PREFIX`）
const CLI_ACK_PREFIX: &[u8] = b"ssl-proxy-v2-ack";
/// 客户端首包扩展位（connect.rs `EXT_UDP`）
const CLI_EXT_UDP: u8 = 0x01;
/// 服务端 ACK 能力位（connect.rs `CAP_UDP`）
const CLI_CAP_UDP: u8 = 0x01;

/// 复刻客户端 `compute_mac`：HMAC-SHA256(password, prefix || ts BE || port BE || host)
fn cli_mac(password: &str, prefix: &[u8], timestamp: u64, port: u16, host: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(password.as_bytes()).expect("hmac key");
    mac.update(prefix);
    mac.update(&timestamp.to_be_bytes());
    mac.update(&port.to_be_bytes());
    mac.update(host.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// 复刻客户端 `create_protocol_header(host, port, password)`：
/// MAC 之后固定追加 1 字节 [`CLI_EXT_UDP`] 扩展位
fn cli_auth_packet(host: &str, port: u16, password: &str, timestamp: u64) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut buf = Vec::with_capacity(14 + host_bytes.len() + 32 + 1);
    buf.extend_from_slice(&[0x10, 0xff]); // MAGIC
    buf.push(2); // VERSION
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.push(host_bytes.len() as u8);
    buf.extend_from_slice(host_bytes);
    buf.extend_from_slice(&cli_mac(password, CLI_REQ_PREFIX, timestamp, port, host));
    buf.push(CLI_EXT_UDP);
    buf
}

/// 复刻客户端 `encode_udp_packet`：IPv4 → atyp=1(4B)、IPv6 → atyp=4(16B)、
/// 域名 → atyp=3(1B len + N)，随后 port u16 BE、dgram_len u16 BE、dgram
fn cli_udp_packet(stream_id: u32, host: &str, port: u16, dgram: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&stream_id.to_be_bytes());
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        pkt.push(1);
        pkt.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        pkt.push(4);
        pkt.extend_from_slice(&v6.octets());
    } else {
        let hb = host.as_bytes();
        pkt.push(3);
        pkt.push(hb.len() as u8);
        pkt.extend_from_slice(hb);
    }
    pkt.extend_from_slice(&port.to_be_bytes());
    pkt.extend_from_slice(&(dgram.len() as u16).to_be_bytes());
    pkt.extend_from_slice(dgram);
    pkt
}

/// 复刻客户端 `append_udp_frame` 的帧封装：flag(1)=2 || len(2B BE) || padLen(1)
/// || payload || pad。客户端小报文 padLen 随机 0..=256，此处用固定非零填充
/// 验证服务端确实按 padLen 跳过填充字节。
fn cli_udp_frame(pkt: &[u8], pad_len: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + pkt.len() + pad_len as usize);
    out.push(2); // FLAG_UDP
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.push(pad_len);
    out.extend_from_slice(pkt);
    out.resize(out.len() + pad_len as usize, 0xA5);
    out
}

/// 复刻客户端 `parse_udp_packet`：返回 `(stream_id, host, port, dgram)`
fn cli_parse_udp_packet(payload: &[u8]) -> Option<(u32, String, u16, Vec<u8>)> {
    if payload.len() < 9 {
        return None;
    }
    let stream_id = u32::from_be_bytes(payload[0..4].try_into().ok()?);
    let atyp = payload[4];
    let rest = &payload[5..];
    let (host, addr_len) = match atyp {
        1 => {
            if rest.len() < 4 {
                return None;
            }
            (
                std::net::Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]).to_string(),
                4,
            )
        }
        3 => {
            let n = *rest.first()? as usize;
            if rest.len() < 1 + n {
                return None;
            }
            (String::from_utf8_lossy(&rest[1..1 + n]).to_string(), 1 + n)
        }
        4 => {
            if rest.len() < 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            (std::net::Ipv6Addr::from(octets).to_string(), 16)
        }
        _ => return None,
    };
    let tail = &rest[addr_len..];
    if tail.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([tail[0], tail[1]]);
    let dgram_len = u16::from_be_bytes([tail[2], tail[3]]) as usize;
    Some((stream_id, host, port, tail[4..4 + dgram_len].to_vec()))
}

/// 跨端 e2e（核心）：完全按客户端实现构造非 mux UDP 隧道流量。
///
/// 客户端时序（`udp_relay.rs::create_session` + `connect.rs::connect_proxy`）：
/// 1. 认证首包：目标 host + **port=0**（UDP 隧道标记，host 仅参与 MAC）+ EXT_UDP；
/// 2. 读 ACK（magic + 32B MAC，按 ts / port=0 / host 校验）→ 读 1 字节能力位；
/// 3. ACK 后才发客户端格式 FLAG_UDP 帧（非 mux stream_id 固定为 1）；
/// 4. 断言回包为同 stream_id 的 FLAG_UDP 帧且内容正确。
#[tokio::test]
async fn udp_non_mux_client_format_roundtrip() {
    let h = Harness::start_with_udp(true).await;
    let (echo_ip, echo_port) = spawn_udp_echo().await;
    let mut stream = h.connect().await;

    // Step 1: 客户端格式认证首包（port=0 标记 UDP 隧道）
    let host = echo_ip.to_string();
    let ts = unix_now();
    stream
        .write_all(&cli_auth_packet(&host, 0, PASSWORD, ts))
        .await
        .expect("write auth");

    // Step 2: ACK MAC 必须按 port=0 + 目标 host 计算（双端一致），随后 1 字节能力位
    let mut ack = [0u8; 2 + MAC_LEN];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut ack))
        .await
        .expect("ack timeout")
        .expect("read ack");
    assert_eq!(&ack[..2], &TUNNEL_ACK, "隧道应答魔数不匹配");
    let expected = cli_mac(PASSWORD, CLI_ACK_PREFIX, ts, 0, &host);
    assert_eq!(&ack[2..], &expected, "ACK MAC 应按 port=0 + 目标 host 计算");
    let mut cap = [0u8; 1];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut cap))
        .await
        .expect("cap timeout")
        .expect("read cap");
    assert_eq!(cap[0], CLI_CAP_UDP, "udp.enabled=true 时能力位应为 CAP_UDP");

    // Step 3: ACK 后发送客户端格式 FLAG_UDP 帧（stream_id=1，含非零 padding）
    let dgram = b"client-format-udp";
    let pkt = cli_udp_packet(1, &host, echo_port, dgram);
    stream.write_all(&cli_udp_frame(&pkt, 13)).await.expect("write udp frame");

    // Step 4: 回包应为同 stream_id 的 FLAG_UDP 帧，目标与内容正确
    let mut got = None;
    let mut payload = Vec::new();
    for _ in 0..64 {
        let flag = tokio::time::timeout(IO_TIMEOUT, read_frame(&mut stream, &mut payload))
            .await
            .expect("udp reply timeout")
            .expect("read udp reply frame");
        if flag != FLAG_UDP {
            continue;
        }
        if let Some((sid, rhost, rport, d)) = cli_parse_udp_packet(&payload) {
            assert_eq!(sid, 1, "非 mux 客户端 stream_id 固定为 1");
            assert_eq!(rhost, host, "回包目标应与请求一致");
            assert_eq!(rport, echo_port, "回包端口应为 echo 目标端口");
            got = Some(d);
            break;
        }
    }
    assert_eq!(got.expect("no udp reply"), dgram);

    drop(stream);
    h.stop().await;
}

// -----------------------------------------------------------------------------
// TLS 层
// -----------------------------------------------------------------------------

#[tokio::test]
async fn tls_handshake_uses_configured_certificate() {
    let h = Harness::start().await;
    // connect() 使用信任该证书的 RootCertStore，握手成功即说明服务端证书正确
    let mut stream = h.connect().await;
    let raw = send_and_read(&mut stream, &http_get("/")).await;
    assert!(raw.starts_with(b"HTTP/1.1 200"), "raw={:?}", String::from_utf8_lossy(&raw));
    h.stop().await;
}

#[tokio::test]
async fn self_signed_config_loads_without_files() {
    // 不提供证书文件时应能生成自签证书
    let cfg = load_tls_config(None, None, Some("example.com"));
    assert!(cfg.is_ok(), "self-signed config should build");
}
