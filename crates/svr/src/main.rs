//! ssl-proxy-svr
//!
//! 基于 tokio + rustls 重写的 TLS 代理服务，对外只暴露一个 TLS 端口。
//! - 命中私有协议 → 透明 TCP 隧道；
//! - 其他流量 → 静态伪装站点（`html/` 目录）。
//!
//! ## 启动
//!
//! ```bash
//! # 命令行模式
//! ssl-proxy-svr --cert ./certs/server.crt --key ./certs/server.key --html ./html
//!
//! # 配置文件模式
//! ssl-proxy-svr --config ./config.example.yaml
//! ```

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::watch;

mod config;
mod core;
mod error;
mod libs;
mod services;
mod utils;

use crate::config::{load_yaml, AppConfig, Cli};
use crate::core::logger::{init, RotatingFileWriter};
use crate::core::service::ServiceRegister;
use crate::libs::rate_limit::RateLimitConfig;
use crate::services::forward_service::ForwardService;
use crate::services::proxy_service::ProxyService;
use crate::services::socket_service::{load_tls_config, SocketService};
use crate::services::static_sources_service::StaticSourcesService;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    // 1. 解析 CLI
    let cli = Cli::parse();

    // 2. 加载 YAML
    let yaml_cfg = load_yaml(cli.config.as_ref())
        .with_context(|| format!("failed to load yaml config from {:?}", cli.config))?;

    // 3. 合并
    let app_cfg = AppConfig::merge(yaml_cfg, cli)?;

    // 4. 初始化日志（轮转文件 + 控制台）
    let writer = RotatingFileWriter::new(app_cfg.log.dir.clone(), app_cfg.log.max_size)
        .context("init rotating file writer")?;
    init(writer, &app_cfg.log.level);

    tracing::info!(
        "ssl-proxy-svr starting (listen={}:{}, log_dir={:?}, log_level={})",
        app_cfg.server.listen,
        app_cfg.server.port,
        app_cfg.log.dir,
        app_cfg.log.level
    );

    // 5. 加载 TLS（缺省自动生成自签证书）
    let tls_cfg = load_tls_config(
        app_cfg.tls.cert.as_deref(),
        app_cfg.tls.key.as_deref(),
        app_cfg.tls.sni.as_deref(),
    )
    .context("load TLS cert/key")?;

    // 6. 构造服务
    let static_sources = Arc::new(StaticSourcesService::new(
        app_cfg.static_sources.html.clone(),
        app_cfg.static_sources.index.clone(),
    ));
    if let Err(e) = static_sources.validate() {
        tracing::error!("{}", e);
        return Err(e);
    }

    let forward = Arc::new(ForwardService::new(
        static_sources.clone(),
        RateLimitConfig {
            max_requests: app_cfg.rate_limit.max_requests,
            rate_time: app_cfg.rate_limit.rate_time,
            black_time: app_cfg.rate_limit.black_time,
        },
    ));

    let proxy = Arc::new(ProxyService::new(
        app_cfg.server.password.clone(),
        forward.clone(),
        app_cfg.server.mux,
    ));

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let active = Arc::new(AtomicUsize::new(0));

    let socket = Arc::new(SocketService::new(
        app_cfg.server.clone(),
        tls_cfg,
        forward.clone(),
        proxy.clone(),
        shutdown_tx,
        active,
    ));

    // 7. 启动
    let register = ServiceRegister::new()
        .add(static_sources.clone())
        .add(forward.clone())
        .add(proxy.clone())
        .add(socket.clone());

    if let Err(e) = register.start_all().await {
        tracing::error!("start services failed: {:#}", e);
        return Err(e);
    }

    // 8. 等待 Ctrl+C
    wait_for_signal().await;
    tracing::info!("shutting down...");

    if let Err(e) = register.stop_all().await {
        tracing::warn!("stop services: {:#}", e);
    }

    tracing::info!("bye");
    Ok(())
}

async fn wait_for_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[allow(dead_code)]
fn _unused_path(p: &PathBuf) -> &PathBuf {
    p
}
