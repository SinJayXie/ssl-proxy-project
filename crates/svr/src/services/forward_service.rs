//! 转发服务：协议识别后，所有"非代理协议"的连接都会进入这里。
//!
//! 它本身不做协议解析，而是先做 IP 限流，再把请求转交给 [`StaticSourcesService`] 处理。
//!
//! 等价于 Node.js 中的 `ForwardService`：内部"模拟"了一个 HTTP Server，捕获到
//! connection 后立即 emit 已读取的 `data`。在 Rust 中我们直接把 TLS 流喂给静态服务即可。

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::service::Service;
use crate::libs::rate_limit::{RateLimit, RateLimitConfig};
use crate::services::initial_stream::InitialThenStream;
use crate::services::static_sources_service::StaticSourcesService;

pub struct ForwardService {
    rate_limit: RateLimit,
    static_sources: Arc<StaticSourcesService>,
}

impl ForwardService {
    pub fn new(
        static_sources: Arc<StaticSourcesService>,
        rate_limit_cfg: RateLimitConfig,
    ) -> Self {
        Self {
            rate_limit: RateLimit::new(rate_limit_cfg),
            static_sources,
        }
    }

    /// 处理一条"伪装"连接：
    /// 1. 限流检查；
    /// 2. 失败：直接关闭；
    /// 3. 成功：交给 `StaticSourcesService`。
    pub async fn handle<S>(&self, stream: InitialThenStream<S>, initial: Bytes, peer_ip: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.rate_limit.record(peer_ip) {
            tracing::info!("[Forward] rate-limited peer={}, drop connection", peer_ip);
            return;
        }
        self.static_sources.handle(stream, initial).await;
    }
}

#[async_trait]
impl Service for ForwardService {
    fn name(&self) -> &str {
        "ForwardService"
    }

    async fn start(&self) -> Result<()> {
        let cfg = self.rate_limit.config();
        tracing::info!(
            "[Forward] ready (rate_limit max={}, window={:?}, black={:?})",
            cfg.max_requests,
            cfg.rate_time,
            cfg.black_time,
        );
        Ok(())
    }
}
