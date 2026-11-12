//! 端到端集成测试：真实 TLS 连接 → 首包识别 → 协议分流（静态站点 / 私有协议隧道）。
//!
//! 每个用例都会完整装配 `StaticSourcesService` + `ForwardService` + `ProxyService` + `SocketService`，
//! 用临时自签证书在随机端口上启动，再用 rustls 客户端发起真实 TLS 请求。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
use ssl_proxy_svr::services::framing::{encode_chunk, read_frame};
use ssl_proxy_svr::services::mux::{encode_data, encode_open, read_frame as read_mux_frame};
use ssl_proxy_svr::services::proxy_service::ProxyService;
use ssl_proxy_svr::services::socket_service::{load_tls_config, SocketService};
use ssl_proxy_svr::services::static_sources_service::StaticSourcesService;
use ssl_proxy_svr::utils::protocol::{ack_mac, encode_packet, MAC_LEN, TUNNEL_ACK};

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
        Self::start_with_rate_limit(DEFAULT_MAX_REQUESTS).await
    }

    async fn start_with_rate_limit(max_requests: u32) -> Self {
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
        let proxy = Arc::new(ProxyService::new(
            PASSWORD.to_string(),
            forward.clone(),
            true,
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
