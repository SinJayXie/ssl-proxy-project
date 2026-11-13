//! TLS 入口服务：监听端口、握手、读首包、按协议分流。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

use crate::config::{FIRST_PACKET_TIMEOUT_SECS, ServerConfig as ServerCfg};
use crate::core::service::Service;
use crate::services::forward_service::ForwardService;
use crate::services::initial_stream::InitialThenStream;
use crate::services::proxy_service::ProxyService;
use crate::utils::protocol::check_is_http_protocol;

const FIRST_PACKET_BUF: usize = 8 * 1024;

pub struct SocketService {
    server_cfg: ServerCfg,
    tls_cfg: Arc<ServerConfig>,
    forward: Arc<ForwardService>,
    proxy: Arc<ProxyService>,
    shutdown_tx: watch::Sender<bool>,
    active: Arc<AtomicUsize>,
}

impl SocketService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_cfg: ServerCfg,
        tls_cfg: Arc<ServerConfig>,
        forward: Arc<ForwardService>,
        proxy: Arc<ProxyService>,
        shutdown_tx: watch::Sender<bool>,
        active: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            server_cfg,
            tls_cfg,
            forward,
            proxy,
            shutdown_tx,
            active,
        }
    }
}

#[async_trait]
impl Service for SocketService {
    fn name(&self) -> &str {
        "SocketService"
    }

    async fn start(&self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.server_cfg.listen, self.server_cfg.port)
            .parse()
            .with_context(|| {
                format!(
                    "invalid listen address {}:{}",
                    self.server_cfg.listen, self.server_cfg.port
                )
            })?;

        // 绑定监听端口（使用 std 默认 backlog，跨工具链兼容）
        let std_listener = std::net::TcpListener::bind(addr)
            .with_context(|| format!("bind {} failed", addr))?;
        std_listener
            .set_nonblocking(true)
            .context("set TcpListener non-blocking")?;

        let listener = TcpListener::from_std(std_listener)?;
        let acceptor = TlsAcceptor::from(self.tls_cfg.clone());

        tracing::info!("[Socket] TLS listening on {}", addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let active = self.active.clone();
        let forward = self.forward.clone();
        let proxy = self.proxy.clone();

        tokio::spawn(
            async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                tracing::info!("[Socket] shutdown signal received, stop accept");
                                break;
                            }
                        }
                        accept = listener.accept() => {
                            match accept {
                                Ok((tcp, peer)) => {
                                    // TCP_NODELAY：禁用 Nagle，缩短小包延迟
                                    if let Err(e) = tcp.set_nodelay(true) {
                                        tracing::debug!("set_nodelay failed: {}", e);
                                    }
                                    let acceptor = acceptor.clone();
                                    let forward = forward.clone();
                                    let proxy = proxy.clone();
                                    let active = active.clone();
                                    active.fetch_add(1, Ordering::Relaxed);
                                    tokio::spawn(async move {
                                        let _guard = ActiveGuard::new(active);
                                        if let Err(e) =
                                            handle_connection(acceptor, tcp, peer, forward, proxy).await
                                        {
                                            tracing::debug!("[Socket] conn end: {}", e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("[Socket] accept error: {}", e);
                                    // 短暂退避，避免空转
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                }
                            }
                        }
                    }
                }
            }
            .instrument(tracing::info_span!("socket.accept")),
        );

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        // 等待所有活跃任务退出（最多 5s）
        for _ in 0..50 {
            if self.active.load(Ordering::Relaxed) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }
}

/// 自动减少计数
struct ActiveGuard(Arc<AtomicUsize>);
impl ActiveGuard {
    fn new(c: Arc<AtomicUsize>) -> Self {
        Self(c)
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

type ServerTlsStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

async fn handle_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    forward: Arc<ForwardService>,
    proxy: Arc<ProxyService>,
) -> Result<()> {
    // TLS 握手
    let tls_stream = match acceptor.accept(tcp).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("[Socket] tls handshake failed from {}: {}", peer, e);
            return Ok(());
        }
    };
    let peer_ip = peer.ip().to_string();

    // 读首包（带超时）
    let (initial, mut tls_stream) = read_first_packet(tls_stream).await?;
    let Some(initial) = initial else {
        // 客户端在超时前没有发数据，直接关闭
        let _ = tls_stream.shutdown().await;
        return Ok(());
    };

    if check_is_http_protocol(&initial) {
        tracing::debug!("[Forward] dispatch HTTP from {}", peer_ip);
        let wrapped = InitialThenStream::new(initial.clone(), tls_stream);
        forward.handle(wrapped, initial, &peer_ip).await;
    } else {
        tracing::debug!("[Proxy] dispatch proxy auth from {}", peer_ip);
        proxy.authenticate(tls_stream, initial, &peer_ip).await;
    }
    Ok(())
}

async fn read_first_packet(
    mut tls_stream: ServerTlsStream,
) -> Result<(Option<Bytes>, ServerTlsStream)> {
    let mut buf = vec![0u8; FIRST_PACKET_BUF];
    let n = match timeout(
        Duration::from_secs(FIRST_PACKET_TIMEOUT_SECS),
        tls_stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(0)) => return Ok((None, tls_stream)),
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!("[Socket] read first packet error: {}", e);
            return Ok((None, tls_stream));
        }
        Err(_) => {
            tracing::debug!("[Socket] first packet read timeout");
            return Ok((None, tls_stream));
        }
    };
    buf.truncate(n);
    Ok((Some(Bytes::from(buf)), tls_stream))
}

/// 加载 PEM 证书 + 私钥，构建 rustls ServerConfig
///
/// 当 `cert_path` / `key_path` 同时为 `None` 时，启动期内生成一张自签证书，
/// SAN 由 `sni` 指定（缺省为 `localhost` / `127.0.0.1`）。
#[allow(dead_code)]
pub fn load_tls_config(
    cert_path: Option<&std::path::Path>,
    key_path: Option<&std::path::Path>,
    sni: Option<&str>,
) -> Result<Arc<ServerConfig>> {
    load_tls_config_with_alpn(cert_path, key_path, sni, false)
}

/// 同上；`enable_h2 = true` 时额外广告 `h2`（真实站点回落需要）。
pub fn load_tls_config_with_alpn(
    cert_path: Option<&std::path::Path>,
    key_path: Option<&std::path::Path>,
    sni: Option<&str>,
    enable_h2: bool,
) -> Result<Arc<ServerConfig>> {
    let (certs, key) = match (cert_path, key_path) {
        (Some(c), Some(k)) => load_cert_key_from_file(c, k)?,
        _ => {
            tracing::warn!("[TLS] No cert/key provided, using self-signed cert");
            generate_self_signed(sni)?
        }
    };

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls ServerConfig")?;

    // ALPN 伪装：与回落服务保持一致。只有启用真实站点回落（支持 h2）时才广告 h2。
    cfg.alpn_protocols = if enable_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };

    // TLS session resumption：TLS 1.3 用 ticket，TLS 1.2 用内存 session cache。
    // 只影响重连性能，不改变认证与重放模型。
    cfg.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()
        .context("create TLS 1.3 ticketer")?;
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(256);

    Ok(Arc::new(cfg))
}

fn load_cert_key_from_file(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rustls_pemfile::certs;
    use std::io::BufReader;

    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("open cert {:?}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse certs PEM")?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {:?}", cert_path);
    }

    let key_file =
        std::fs::File::open(key_path).with_context(|| format!("open key {:?}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    // 兼容 PKCS#8 / PKCS#1(RSA) / SEC1(EC) 三种私钥 PEM 格式
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .context("parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", key_path))?;

    Ok((certs, key))
}

/// 启动期内生成一张 ECDSA P-256 自签证书，
/// SAN 为 `sni`（若配置）+ `localhost` + `127.0.0.1`，仅供本地开发/测试使用。
fn generate_self_signed(
    sni: Option<&str>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut names: Vec<String> = Vec::with_capacity(3);
    if let Some(name) = sni {
        names.push(name.to_string());
    }
    names.push("localhost".to_string());
    names.push("127.0.0.1".to_string());

    let CertifiedKey { cert, key_pair: signing_key } =
        generate_simple_self_signed(names.clone())
            .with_context(|| format!("generate self-signed cert for {:?}", names))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(signing_key.serialize_der());

    tracing::info!("[TLS] self-signed cert generated (SAN: {})", names.join(", "));
    Ok((vec![cert_der], PrivateKeyDer::Pkcs8(key_der)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_advertises_h2_only_when_enabled() {
        let h1 = load_tls_config(None, None, Some("example.com")).expect("h1 config");
        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let h2 = load_tls_config_with_alpn(None, None, Some("example.com"), true)
            .expect("h2 config");
        assert_eq!(
            h2.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
