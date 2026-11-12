use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiAppInfo {
    pub socks_port: u16,
    pub proxy_server: String,
    pub connections: usize,
    pub dataflow: DataFlow,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DataFlow {
    pub up: u64,
    pub down: u64,
    pub total: u64,
}

impl DataFlow {
    pub fn new() -> Self {
        Self {
            up: 0,
            down: 0,
            total: 0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    pub host: String,
    pub port: u16,
    pub id: u32,
    pub ip: String,
    #[serde(rename = "connType")]
    pub conn_type: String,
    pub create_time: u64,
    pub geo: GeoInfo,
    pub data: DataFlow,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoInfo {
    pub country: String,
    #[serde(rename = "alpha2Code")]
    pub alpha2_code: String,
    #[serde(rename = "alpha3Code")]
    pub alpha3_code: String,
    pub numeric: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleConfig {
    #[serde(alias = "type")]
    pub rule_type: String,
    pub match_str: String,
    pub mode: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CountryCodeItem {
    pub country: String,
    #[serde(rename = "alpha2Code", alias = "alpha2")]
    pub alpha2_code: String,
    #[serde(rename = "alpha3Code", alias = "alpha3")]
    pub alpha3_code: String,
    pub numeric: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub socks_port: u16,
    pub proxy_server: String,
    pub proxy_port: u16,
    pub proxy_password: String,
    pub directs: Vec<String>,
    pub bind_ips: Vec<String>,
    pub dns_servers: Vec<String>,
    /// Disable TLS certificate and hostname verification for proxy connection.
    /// Enables MITM resistance when disabled — matches the original
    /// `danger_accept_invalid_certs` / `danger_accept_invalid_hostnames` flags.
    pub danger_accept_invalid_certs: bool,
    /// Custom SNI hostname used during the TLS handshake with the proxy server.
    /// When empty, the proxy server hostname is used as the SNI.
    pub sni_name: String,
    /// Multiplex all proxied connections over a shared TLS tunnel (trojan-go style mux).
    /// Enabled by default; falls back to one TLS connection per target when disabled.
    #[serde(default = "default_true")]
    pub mux_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            socks_port: 1080,
            proxy_server: String::new(),
            proxy_port: 443,
            proxy_password: String::new(),
            directs: vec!["PRIVATE".to_string(), "CN".to_string()],
            bind_ips: Vec::new(),
            dns_servers: vec!["8.8.8.8".to_string()],
            danger_accept_invalid_certs: false,
            sni_name: String::new(),
            mux_enabled: true,
        }
    }
}

/// Error sent to frontend via error pool.
/// Only the code is sent; message & fatal are resolved by frontend i18n.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub code: i32,
}

/// Remote version manifest fetched from update server
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateManifest {
    pub version: String,
    pub changelog: Vec<String>,
    pub download_url: String,
}

/// Result returned to frontend after checking for updates
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckUpdateResult {
    pub has_update: bool,
    pub latest_version: String,
    pub current_version: String,
    pub changelog: Vec<String>,
    pub download_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadProgress {
    pub percent: u32,
    pub downloaded: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestRuleResult {
    pub host: String,
    pub resolved_ip: String,
    pub dns_server: String,
    pub country: String,
    pub alpha2_code: String,
    pub matched_rule: String,
    pub mode: String,
    pub elapsed_ms: u64,
}
