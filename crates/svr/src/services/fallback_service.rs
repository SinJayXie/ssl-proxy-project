//! 真实站点回落（reverse proxy fallback）。
//!
//! 未通过私有协议认证的 TLS 流量不再一律返回静态站点，而是回源到配置的真实
//! 站点；同时支持 HTTP/1.1 与 HTTP/2，使回落流量的 ALPN、响应头、内容与真实
//! 站点一致，降低主动探测的“假站点”特征。
//!
//! 安全约束：
//! - 目标固定来自配置，用户请求的 Host/SNI 不参与选路，避免开放代理/SSRF；
//! - 只转发普通请求，剥离 hop-by-hop 头；
//! - 上游请求带超时，失败返回 502。

use std::convert::Infallible;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};

use super::initial_stream::InitialThenStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// 回源请求体上限，避免回落通道被用来向真实站点打大流量
const MAX_FALLBACK_BODY: u64 = 8 * 1024 * 1024;

/// 真实站点回落服务
#[derive(Clone)]
pub struct FallbackService {
    target: Uri,
    client: Client<HttpsConnector<HttpConnector>, BoxBody>,
    timeout: Duration,
}

impl FallbackService {
    pub fn new(target: &str, timeout: Duration) -> Result<Self> {
        let target: Uri = target
            .parse()
            .with_context(|| format!("parse fallback url {:?}", target))?;
        if target.scheme().is_none() || target.authority().is_none() {
            anyhow::bail!("fallback url must be absolute, e.g. https://example.com");
        }

        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .context("load native root certificates")?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        Ok(Self {
            target,
            client,
            timeout,
        })
    }

    pub fn target(&self) -> &Uri {
        &self.target
    }

    /// 处理一条未通过私有协议认证的 TLS 连接
    pub async fn handle<S>(&self, stream: InitialThenStream<S>, initial: &[u8], peer_ip: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let is_h2 = initial.starts_with(b"PRI * HTTP/2.0");
        let service = {
            let this = self.clone();
            service_fn(move |req| {
                let this = this.clone();
                async move { this.forward(req).await }
            })
        };

        tracing::debug!(
            "[Fallback] proxy {} request from {} -> {}",
            if is_h2 { "h2" } else { "h1" },
            peer_ip,
            self.target
        );

        let io = TokioIo::new(stream);
        let result = if is_h2 {
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
        } else {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
        };

        if let Err(e) = result {
            tracing::debug!("[Fallback] connection end: {}", e);
        }
    }

    async fn forward(&self, req: Request<Incoming>) -> Result<Response<BoxBody>, Infallible> {
        match self.forward_inner(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::warn!("[Fallback] upstream error: {}", e);
                Ok(error_response(StatusCode::BAD_GATEWAY))
            }
        }
    }

    async fn forward_inner(&self, req: Request<Incoming>) -> Result<Response<BoxBody>> {
        let (mut parts, body) = req.into_parts();

        if let Some(len) = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if len > MAX_FALLBACK_BODY {
                return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
            }
        }
        let authority = self
            .target
            .authority()
            .context("fallback target has no authority")?;
        let scheme = self.target.scheme_str().unwrap_or("https");
        let base_path = self.target.path().trim_end_matches('/');
        let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let uri = format!("{scheme}://{authority}{base_path}{path}");
        // 上游统一使用 HTTP/1.1：入站可能是 h2，但 hyper 的 legacy client
        // 不允许把 h2 请求直接发到 h1 连接。
        parts.version = hyper::Version::HTTP_11;
        parts.uri = uri
            .parse()
            .with_context(|| format!("build fallback uri {:?}", uri))?;

        // 剥离 hop-by-hop 头，避免把代理语义传给真实站点
        for name in [
            "connection",
            "proxy-connection",
            "proxy-authorization",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            parts.headers.remove(name);
        }
        parts.headers.insert(
            HOST,
            authority
                .as_str()
                .parse()
                .context("invalid fallback host header")?,
        );

        // 流式限长：chunked / 无 Content-Length 的请求同样受 8MB 上限约束，
        // 超限时 body 立刻报错，hyper 会中止上传，不会继续向真实站点灌流量。
        let body = Limited::new(body, MAX_FALLBACK_BODY as usize);
        let upstream = Request::from_parts(parts, body.boxed());
        let resp = tokio::time::timeout(self.timeout, self.client.request(upstream))
            .await
            .context("fallback upstream timeout")??;

        Ok(resp.map(|b| {
            b.map_err(|e| -> BoxError { Box::new(e) }).boxed()
        }))
    }
}

fn error_response(status: StatusCode) -> Response<BoxBody> {
    let body = Full::new(Bytes::from_static(b"Bad Gateway"))
        .map_err(|never: Infallible| -> BoxError { match never {} })
        .boxed();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(body)
        .expect("static error response is valid")
}
