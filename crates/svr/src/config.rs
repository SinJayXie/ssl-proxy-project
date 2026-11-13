//! 配置模块：支持 YAML 文件 + 命令行参数合并。
//!
//! 合并策略：
//! 1. 读取 YAML（若提供 `--config`）作为基线；
//! 2. 命令行参数覆盖 YAML 中对应字段；
//! 3. 仍未提供则使用内置默认值。

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use rand::Rng;
use serde::Deserialize;

/// 默认 TLS 端口
pub const DEFAULT_PORT: u16 = 1888;
/// 默认监听地址
pub const DEFAULT_LISTEN: &str = "0.0.0.0";
/// 默认日志目录
pub const DEFAULT_LOG_DIR: &str = "./logs";
/// 默认日志级别
pub const DEFAULT_LOG_LEVEL: &str = "info";
/// 单个日志文件最大字节数（5MB）
pub const DEFAULT_LOG_MAX_SIZE: u64 = 5 * 1024 * 1024;
/// 默认限流窗口（秒）
pub const DEFAULT_RATE_TIME_SECS: u64 = 60;
/// 默认黑名单封禁时长（秒）
pub const DEFAULT_BLACK_TIME_SECS: u64 = 600;
/// 默认单窗口最大请求数
pub const DEFAULT_MAX_REQUESTS: u32 = 300;
/// 客户端首包读取超时（秒）
pub const FIRST_PACKET_TIMEOUT_SECS: u64 = 5;
/// 上游 TCP 连接超时（秒）
pub const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 10;
/// UDP 会话空闲超时（秒）
pub const DEFAULT_UDP_TIMEOUT_SECS: u64 = 60;
/// 每会话每秒 UDP 报文数上限
pub const DEFAULT_UDP_RATE_LIMIT: u32 = 100;

// -----------------------------------------------------------------------------
// YAML 结构定义
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct ServerConfigYaml {
    pub listen: Option<String>,
    pub port: Option<u16>,
    /// 代理协议密码，缺省随机生成
    pub password: Option<String>,
    /// 是否接受 mux（多路复用）连接，缺省 true
    pub mux: Option<bool>,
    /// 允许 TCP 隧道连接回环 / 内网目标（默认 false，防 SSRF）
    pub allow_private_targets: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct TlsConfigYaml {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// 自签证书使用的 SNI 域名（仅在未提供 cert/key 时生效）
    pub sni: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct StaticSourcesConfigYaml {
    pub html: Option<PathBuf>,
    pub index: Option<String>,
    /// 真实站点回落地址（绝对 URL，例如 `https://example.com`）
    pub fallback_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct LogConfigYaml {
    pub dir: Option<PathBuf>,
    pub level: Option<String>,
    pub max_size: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct RateLimitConfigYaml {
    pub max_requests: Option<u32>,
    pub rate_time_secs: Option<u64>,
    pub black_time_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct UdpConfigYaml {
    /// 是否启用 UDP relay，默认 false
    pub enabled: Option<bool>,
    /// 会话空闲超时（秒），默认 60
    pub timeout_secs: Option<u64>,
    /// 每会话每秒报文数上限，默认 100
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct AppConfigYaml {
    pub server: ServerConfigYaml,
    pub tls: TlsConfigYaml,
    pub static_sources: StaticSourcesConfigYaml,
    pub log: LogConfigYaml,
    pub rate_limit: RateLimitConfigYaml,
    pub udp: UdpConfigYaml,
}

// -----------------------------------------------------------------------------
// CLI 参数定义
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "ssl-proxy-svr",
    version,
    about = "Lightweight TLS proxy server with HTTP masquerade",
    long_about = "Exposes a single TLS port; traffic matching the private protocol is forwarded to the target host:port, otherwise it is served as a static site.\n\n\
                  When --cert/--key are not provided, a self-signed certificate is generated at startup (SAN: localhost, 127.0.0.1) for local development.\n\
                  In production, supply --cert and --key pointing to a real certificate (PEM format).",
    disable_help_subcommand = true,
    help_template = "{name} {version}\n{usage-heading} {usage}\n\n{all-args}{after-help}",
    after_help = "examples:\n  \
                  ssl-proxy-svr --html ./html\n  \
                  ssl-proxy-svr --cert ./certs/server.crt --key ./certs/server.key --html ./html\n  \
                  ssl-proxy-svr --config ./config.example.yaml\n\n\
                  Default listen: 0.0.0.0:1888. --help / -h prints this help.",
)]
pub struct Cli {
    /// YAML 配置文件路径（若提供，将与命令行参数合并）
    #[arg(short, long, value_name = "FILE", help = "YAML config file path")]
    pub config: Option<PathBuf>,

    /// 监听地址，默认 0.0.0.0
    #[arg(long, value_name = "ADDR", default_value = DEFAULT_LISTEN, help = "listen address (IPv4/IPv6/Unix socket path), default 0.0.0.0")]
    pub listen: Option<String>,

    /// 监听端口，默认 1888
    #[arg(short, long, value_name = "PORT", help = "listen port (1-65535)")]
    pub port: Option<u16>,

    /// 代理协议密码；缺省随机生成
    #[arg(long, value_name = "PWD", help = "password (default random 12 bits)")]
    pub pwd: Option<String>,

    /// 关闭多路复用（mux）支持；默认开启
    #[arg(long, help = "disable multiplexed (mux) connections")]
    pub no_mux: bool,

    /// 允许隧道访问回环 / 内网目标（默认拒绝，防 SSRF）
    #[arg(
        long,
        help = "allow tunneling to loopback/private targets (default: denied, SSRF protection)"
    )]
    pub allow_private_targets: bool,

    /// TLS 证书路径 (PEM)；缺省时自动生成自签证书
    #[arg(long, value_name = "FILE", help = "TLS certificate path (PEM); self-signed cert is generated if not provided")]
    pub cert: Option<PathBuf>,

    /// TLS 私钥路径 (PKCS8 PEM)；缺省时自动生成自签证书
    #[arg(long, value_name = "FILE", help = "TLS private key path (PKCS8 PEM); self-signed cert is generated if not provided")]
    pub key: Option<PathBuf>,

    /// 自签证书使用的 SNI 域名（提供 cert/key 时忽略）
    #[arg(long, value_name = "NAME", help = "SNI/domain name for the self-signed certificate; ignored when --cert/--key are given")]
    pub sni: Option<String>,

    /// 静态伪装站点根目录
    #[arg(long, value_name = "DIR", help = "static site root directory")]
    pub html: Option<PathBuf>,

    /// 真实站点回落地址（绝对 URL，例如 https://example.com）
    #[arg(
        long,
        value_name = "URL",
        help = "reverse-proxy fallback to a real site (absolute URL, enables HTTP/2)"
    )]
    pub fallback_url: Option<String>,

    /// 日志目录
    #[arg(long, value_name = "DIR", help = "log output directory (rotated by size)")]
    pub log_dir: Option<PathBuf>,

    /// 日志级别 (trace|debug|info|warn|error)
    #[arg(long, value_name = "LEVEL", help = "log level: trace|debug|info|warn|error")]
    pub log_level: Option<String>,
}

// -----------------------------------------------------------------------------
// 最终生效配置（合并 CLI + YAML）
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub port: u16,
    pub password: String,
    /// 是否接受 mux 连接
    pub mux: bool,
    /// 是否允许隧道访问回环 / 内网目标
    pub allow_private_targets: bool,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// 缺省 (None, None) 时启动期自动生成自签证书
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// 自签证书使用的 SNI 域名；提供 cert/key 时忽略
    pub sni: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StaticSourcesConfig {
    pub html: Option<PathBuf>,
    pub index: String,
    /// 真实站点回落地址；`None` 时只提供静态站点
    pub fallback_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub dir: PathBuf,
    pub level: String,
    pub max_size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitOptions {
    pub max_requests: u32,
    pub rate_time: Duration,
    pub black_time: Duration,
}

/// UDP relay 配置（`udp` 配置块）
#[derive(Debug, Clone, Copy)]
pub struct UdpConfig {
    /// 是否启用 UDP relay（默认关闭；关闭时 UDP 帧/流被安全拒绝）
    pub enabled: bool,
    /// 会话空闲超时：超时无上下行报文则回收 socket
    pub timeout: Duration,
    /// 每会话每秒报文数上限（令牌桶）
    pub rate_limit: u32,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub static_sources: StaticSourcesConfig,
    pub log: LogConfig,
    pub rate_limit: RateLimitOptions,
    pub udp: UdpConfig,
}

impl AppConfig {
    /// 合并 YAML + CLI，生成最终配置
    pub fn merge(yaml: AppConfigYaml, cli: Cli) -> anyhow::Result<Self> {
        // ---- server ----
        let listen = cli
            .listen
            .or(yaml.server.listen)
            .unwrap_or_else(|| "0.0.0.0".to_string());

        let port = cli
            .port
            .or(yaml.server.port)
            .unwrap_or(DEFAULT_PORT);

        let password = match cli.pwd.or(yaml.server.password) {
            Some(p) if !p.is_empty() => p,
            _ => random_password(12),
        };

        // mux 默认开启；`--no-mux` 或 yaml `mux: false` 可关闭
        let mux = !cli.no_mux && yaml.server.mux.unwrap_or(true);

        // SSRF 防护默认开启；CLI 或 YAML 可显式放行回环 / 内网目标
        let allow_private_targets =
            cli.allow_private_targets || yaml.server.allow_private_targets.unwrap_or(false);

        // ---- tls ----
        // 证书/私钥均缺省时，运行时自动生成自签证书
        let cert = cli.cert.or(yaml.tls.cert);
        let key = cli.key.or(yaml.tls.key);
        if cert.is_none() != key.is_none() {
            anyhow::bail!("--cert and --key must be provided together");
        }
        // 自签证书的 SNI 域名；空白字符串视同未配置
        let sni = cli
            .sni
            .or(yaml.tls.sni)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // ---- static sources ----
        let html = cli.html.or(yaml.static_sources.html);
        let index = yaml
            .static_sources
            .index
            .unwrap_or_else(|| "index.html".to_string());
        let fallback_url = cli
            .fallback_url
            .or(yaml.static_sources.fallback_url)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // ---- log ----
        let log_dir = cli
            .log_dir
            .or(yaml.log.dir)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_DIR));
        let log_level = cli
            .log_level
            .or(yaml.log.level)
            .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string());
        let log_max_size = yaml.log.max_size.unwrap_or(DEFAULT_LOG_MAX_SIZE);

        // ---- rate limit ----
        let max_requests = yaml
            .rate_limit
            .max_requests
            .unwrap_or(DEFAULT_MAX_REQUESTS);
        let rate_time = Duration::from_secs(
            yaml.rate_limit
                .rate_time_secs
                .unwrap_or(DEFAULT_RATE_TIME_SECS),
        );
        let black_time = Duration::from_secs(
            yaml.rate_limit
                .black_time_secs
                .unwrap_or(DEFAULT_BLACK_TIME_SECS),
        );

        // ---- udp ----
        let udp = UdpConfig {
            enabled: yaml.udp.enabled.unwrap_or(false),
            timeout: Duration::from_secs(
                yaml.udp.timeout_secs.unwrap_or(DEFAULT_UDP_TIMEOUT_SECS),
            ),
            rate_limit: yaml.udp.rate_limit.unwrap_or(DEFAULT_UDP_RATE_LIMIT),
        };

        Ok(Self {
            server: ServerConfig {
                listen,
                port,
                password,
                mux,
                allow_private_targets,
            },
            tls: TlsConfig {
                cert: cert.clone(),
                key: key.clone(),
                sni,
            },
            static_sources: StaticSourcesConfig {
                html,
                index,
                fallback_url,
            },
            log: LogConfig {
                dir: log_dir,
                level: log_level,
                max_size: log_max_size,
            },
            rate_limit: RateLimitOptions {
                max_requests,
                rate_time,
                black_time,
            },
            udp,
        })
    }
}

/// 加载 YAML 配置；缺省返回空配置
pub fn load_yaml(path: Option<&PathBuf>) -> anyhow::Result<AppConfigYaml> {
    let Some(path) = path else {
        return Ok(AppConfigYaml::default());
    };
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read config file {:?} failed: {}", path, e))?;
    let cfg: AppConfigYaml = serde_yaml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("parse YAML failed: {}", e))?;
    Ok(cfg)
}

fn random_password(len: usize) -> String {
    const CHARSET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_applied_when_nothing_provided() {
        let cfg = AppConfig::merge(AppConfigYaml::default(), Cli::default()).unwrap();

        assert_eq!(cfg.server.listen, "0.0.0.0");
        assert_eq!(cfg.server.port, DEFAULT_PORT);
        assert_eq!(cfg.server.password.len(), 12, "缺省应生成 12 位随机密码");
        assert!(cfg.server.mux, "mux 默认开启");
        assert!(!cfg.server.allow_private_targets, "SSRF 防护默认开启");

        assert!(cfg.tls.cert.is_none() && cfg.tls.key.is_none());
        assert!(cfg.tls.sni.is_none());

        assert!(cfg.static_sources.html.is_none());
        assert_eq!(cfg.static_sources.index, "index.html");

        assert_eq!(cfg.log.dir, PathBuf::from(DEFAULT_LOG_DIR));
        assert_eq!(cfg.log.level, DEFAULT_LOG_LEVEL);
        assert_eq!(cfg.log.max_size, DEFAULT_LOG_MAX_SIZE);

        assert_eq!(cfg.rate_limit.max_requests, DEFAULT_MAX_REQUESTS);
        assert_eq!(cfg.rate_limit.rate_time, Duration::from_secs(DEFAULT_RATE_TIME_SECS));
        assert_eq!(cfg.rate_limit.black_time, Duration::from_secs(DEFAULT_BLACK_TIME_SECS));

        // UDP 默认关闭
        assert!(!cfg.udp.enabled);
        assert_eq!(cfg.udp.timeout, Duration::from_secs(DEFAULT_UDP_TIMEOUT_SECS));
        assert_eq!(cfg.udp.rate_limit, DEFAULT_UDP_RATE_LIMIT);
    }

    #[test]
    fn yaml_values_are_applied() {
        let yaml = AppConfigYaml {
            server: ServerConfigYaml {
                listen: Some("127.0.0.1".to_string()),
                port: Some(7000),
                password: Some("from-yaml".to_string()),
                mux: None,
                allow_private_targets: None,
            },
            tls: TlsConfigYaml {
                cert: Some(PathBuf::from("certs/a.crt")),
                key: Some(PathBuf::from("certs/a.key")),
                sni: Some("example.com".to_string()),
            },
            static_sources: StaticSourcesConfigYaml {
                html: Some(PathBuf::from("./html")),
                index: Some("main.html".to_string()),
                fallback_url: None,
            },
            log: LogConfigYaml {
                dir: Some(PathBuf::from("./mylogs")),
                level: Some("debug".to_string()),
                max_size: Some(1024),
            },
            rate_limit: RateLimitConfigYaml {
                max_requests: Some(10),
                rate_time_secs: Some(5),
                black_time_secs: Some(30),
            },
            udp: UdpConfigYaml {
                enabled: Some(true),
                timeout_secs: Some(90),
                rate_limit: Some(50),
            },
        };

        let cfg = AppConfig::merge(yaml, Cli::default()).unwrap();

        assert_eq!(cfg.server.listen, "127.0.0.1");
        assert_eq!(cfg.server.port, 7000);
        assert_eq!(cfg.server.password, "from-yaml");
        assert_eq!(cfg.tls.cert, Some(PathBuf::from("certs/a.crt")));
        assert_eq!(cfg.tls.sni.as_deref(), Some("example.com"));
        assert_eq!(cfg.static_sources.html, Some(PathBuf::from("./html")));
        assert_eq!(cfg.static_sources.index, "main.html");
        assert_eq!(cfg.log.dir, PathBuf::from("./mylogs"));
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.log.max_size, 1024);
        assert_eq!(cfg.rate_limit.max_requests, 10);
        assert_eq!(cfg.rate_limit.rate_time, Duration::from_secs(5));
        assert_eq!(cfg.rate_limit.black_time, Duration::from_secs(30));
        assert!(cfg.udp.enabled);
        assert_eq!(cfg.udp.timeout, Duration::from_secs(90));
        assert_eq!(cfg.udp.rate_limit, 50);
    }

    #[test]
    fn cli_overrides_yaml() {
        let yaml = AppConfigYaml {
            server: ServerConfigYaml {
                listen: Some("127.0.0.1".to_string()),
                port: Some(7000),
                password: Some("from-yaml".to_string()),
                mux: None,
                allow_private_targets: None,
            },
            static_sources: StaticSourcesConfigYaml {
                html: Some(PathBuf::from("./yaml-html")),
                index: None,
                fallback_url: None,
            },
            ..Default::default()
        };
        let cli = Cli {
            port: Some(9000),
            pwd: Some("from-cli".to_string()),
            html: Some(PathBuf::from("./cli-html")),
            ..Default::default()
        };

        let cfg = AppConfig::merge(yaml, cli).unwrap();

        assert_eq!(cfg.server.port, 9000);
        assert_eq!(cfg.server.password, "from-cli");
        assert_eq!(cfg.static_sources.html, Some(PathBuf::from("./cli-html")));
        // CLI 未覆盖的字段仍取 YAML
        assert_eq!(cfg.server.listen, "127.0.0.1");
    }

    #[test]
    fn cert_without_key_is_rejected() {
        let cli = Cli {
            cert: Some(PathBuf::from("a.crt")),
            ..Default::default()
        };
        let err = AppConfig::merge(AppConfigYaml::default(), cli).unwrap_err();
        assert!(err.to_string().contains("must be provided together"));
    }

    #[test]
    fn key_without_cert_is_rejected() {
        let cli = Cli {
            key: Some(PathBuf::from("a.key")),
            ..Default::default()
        };
        assert!(AppConfig::merge(AppConfigYaml::default(), cli).is_err());
    }

    #[test]
    fn empty_password_falls_back_to_random() {
        let yaml = AppConfigYaml {
            server: ServerConfigYaml {
                password: Some(String::new()),
                ..Default::default()
            },
            ..Default::default()
        };
        let cfg = AppConfig::merge(yaml, Cli::default()).unwrap();
        assert_eq!(cfg.server.password.len(), 12);
    }

    #[test]
    fn blank_sni_is_treated_as_absent() {
        let cli = Cli {
            sni: Some("   ".to_string()),
            ..Default::default()
        };
        let cfg = AppConfig::merge(AppConfigYaml::default(), cli).unwrap();
        assert!(cfg.tls.sni.is_none());
    }

    #[test]
    fn sni_is_trimmed() {
        let cli = Cli {
            sni: Some("  example.com  ".to_string()),
            ..Default::default()
        };
        let cfg = AppConfig::merge(AppConfigYaml::default(), cli).unwrap();
        assert_eq!(cfg.tls.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn load_yaml_none_returns_empty_config() {
        let cfg = load_yaml(None).unwrap();
        assert!(cfg.server.port.is_none());
    }

    #[test]
    fn load_yaml_parses_kebab_case_keys() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "static-sources:\n  html: ./www\nrate-limit:\n  max-requests: 7\n",
        )
        .unwrap();

        let cfg = load_yaml(Some(&path)).unwrap();
        assert_eq!(cfg.static_sources.html, Some(PathBuf::from("./www")));
        assert_eq!(cfg.rate_limit.max_requests, Some(7));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
