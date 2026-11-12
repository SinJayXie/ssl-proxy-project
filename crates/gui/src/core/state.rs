use crate::geo::GeoManager;
use crate::types::{AppConfig, AppError, ConnectionInfo, DataFlow, RuleConfig, UdpMode};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::RwLock;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

pub type Connections = HashMap<u32, ConnectionInfo>;
pub type DnsCache = HashMap<String, String>;

pub struct AppState {
    pub connections: Arc<RwLock<Connections>>,
    pub dns_cache: Arc<RwLock<DnsCache>>,
    pub rules: Arc<RwLock<Vec<RuleConfig>>>,
    pub total_dataflow: Arc<RwLock<DataFlow>>,
    /// Aggregate UDP session traffic (kept separate so `total_dataflow`
    /// keeps meaning exactly what it meant before UDP support).
    pub udp_dataflow: Arc<RwLock<DataFlow>>,
    pub config: Arc<RwLock<AppConfig>>,
    pub connection_id: Arc<RwLock<u32>>,
    pub error_pool: Arc<RwLock<Vec<AppError>>>,
    pub dns_resolver: TokioAsyncResolver,
    /// Directory of the executable (resources: GeoDB.dat)
    pub app_path: PathBuf,
    /// User data directory ($HOME/ssl-proxy-client): settings, rules, log, consent
    pub config_dir: PathBuf,
    pub geo_manager: GeoManager,
}

impl AppState {
    pub fn new(app_path: PathBuf, config_dir: PathBuf) -> Self {
        // Ensure config_dir exists and seed default files if missing
        if let Err(e) = fs::create_dir_all(&config_dir) {
            log::error!("Failed to create config_dir {:?}: {}", config_dir, e);
        }
        Self::ensure_default_config(&config_dir);

        let config = Self::load_config(&config_dir);
        let geo_manager = GeoManager::new(&app_path);

        // Build DNS resolver from config.dns_servers
        let dns_resolver = {
            let mut resolver_config = ResolverConfig::new();
            let servers: Vec<NameServerConfig> = config
                .dns_servers
                .iter()
                .filter_map(|s| {
                    let addr = s.parse::<SocketAddr>().ok().or_else(|| {
                        s.parse::<IpAddr>()
                            .ok()
                            .map(|ip| SocketAddr::new(ip, 53))
                    })?;
                    Some(NameServerConfig::new(addr, Protocol::Udp))
                })
                .collect();
            if servers.is_empty() {
                // Fall back to Google DNS
                resolver_config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                    Protocol::Udp,
                ));
            } else {
                for server in servers {
                    resolver_config.add_name_server(server);
                }
            }
            TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default())
        };

        log::info!("DNS servers: {:?}", config.dns_servers);

        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            dns_cache: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(Self::load_rules(&config_dir))),
            total_dataflow: Arc::new(RwLock::new(DataFlow::new())),
            udp_dataflow: Arc::new(RwLock::new(DataFlow::new())),
            config: Arc::new(RwLock::new(config)),
            connection_id: Arc::new(RwLock::new(0)),
            error_pool: Arc::new(RwLock::new(Vec::new())),
            dns_resolver,
            app_path,
            config_dir,
            geo_manager,
        }
    }

    /// Push an error into the pool. code is the OS error code (e.g. 10048).
    pub async fn push_error(&self, code: i32) {
        let mut pool = self.error_pool.write().await;
        pool.push(AppError { code });
    }

    /// Create default setting.yaml and rules.yaml if they don't exist in config_dir
    fn ensure_default_config(config_dir: &PathBuf) {
        let setting_path = config_dir.join("setting.yaml");
        if !setting_path.exists() {
            let default = AppConfig::default();
            if let Ok(content) = serde_yaml::to_string(&default) {
                if let Err(e) = fs::write(&setting_path, content) {
                    log::error!("Failed to write default setting.yaml: {}", e);
                } else {
                    log::info!("Created default setting.yaml at {:?}", setting_path);
                }
            }
        }

        let rules_path = config_dir.join("rules.yaml");
        if !rules_path.exists() {
            if let Err(e) = fs::write(&rules_path, "[]\n") {
                log::error!("Failed to write default rules.yaml: {}", e);
            } else {
                log::info!("Created default rules.yaml at {:?}", rules_path);
            }
        }
    }

    fn load_config(config_dir: &PathBuf) -> AppConfig {
        let config_path = config_dir.join("setting.yaml");
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                    let mut config = AppConfig::default();
                    if let Some(v) = yaml.get("proxyServer").and_then(|v| v.as_str()) {
                        config.proxy_server = v.trim().to_string();
                    }
                    if let Some(v) = yaml.get("proxyPort").and_then(|v| v.as_u64()) {
                        config.proxy_port = v as u16;
                    }
                    if let Some(v) = yaml.get("proxyPassword").and_then(|v| v.as_str()) {
                        config.proxy_password = v.trim().to_string();
                    }
                    if let Some(v) = yaml.get("socksPort").and_then(|v| v.as_u64()) {
                        config.socks_port = v as u16;
                    }
                    if let Some(v) = yaml.get("directs").and_then(|v| v.as_sequence()) {
                        config.directs = v
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                    }
                    if let Some(v) = yaml.get("bindIps").and_then(|v| v.as_sequence()) {
                        config.bind_ips = v
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                    }
                    if let Some(v) = yaml.get("dnsServers").and_then(|v| v.as_sequence()) {
                        let servers: Vec<String> = v
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                        if !servers.is_empty() {
                            config.dns_servers = servers;
                        }
                    }
                    if let Some(v) = yaml.get("dangerAcceptInvalidCerts").and_then(|v| v.as_bool()) {
                        config.danger_accept_invalid_certs = v;
                    }
                    if let Some(v) = yaml.get("sniName").and_then(|v| v.as_str()) {
                        config.sni_name = v.trim().to_string();
                    }
                    if let Some(v) = yaml.get("muxEnabled").and_then(|v| v.as_bool()) {
                        config.mux_enabled = v;
                    }
                    if let Some(v) = yaml.get("udpMode").and_then(|v| v.as_str()) {
                        config.udp_mode = match v.trim() {
                            "direct" => UdpMode::Direct,
                            "proxy" => UdpMode::Proxy,
                            _ => UdpMode::Off,
                        };
                    }
                    return config;
                }
            }
        }
        AppConfig::default()
    }

    fn load_rules(config_dir: &PathBuf) -> Vec<RuleConfig> {
        let rules_path = config_dir.join("rules.yaml");
        if rules_path.exists() {
            if let Ok(content) = fs::read_to_string(&rules_path) {
                // Handle both old format (type, match) and new format (ruleType, matchStr)
                if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                    if let Some(arr) = yaml.as_sequence() {
                        let rules: Vec<RuleConfig> = arr
                            .iter()
                            .filter_map(|v| {
                                let rule_type = v.get("ruleType")
                                    .or_else(|| v.get("type"))
                                    .and_then(|v| v.as_str())?
                                    .to_string();
                                let match_str = v.get("matchStr")
                                    .or_else(|| v.get("match"))
                                    .and_then(|v| v.as_str())?
                                    .to_string();
                                let mode = v.get("mode").and_then(|v| v.as_str())?.to_string();
                                Some(RuleConfig {
                                    rule_type,
                                    match_str,
                                    mode,
                                })
                            })
                            .collect();
                        log::info!("Loaded {} rules", rules.len());
                        return rules;
                    }
                }
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `muxEnabled` must be read back from `setting.yaml`, otherwise a mux
    /// switch turned off in the UI comes back on after every restart.
    #[test]
    fn load_config_reads_mux_enabled() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-config-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("setting.yaml");

        fs::write(
            &path,
            "socksPort: 1081\nproxyServer: example.com\nmuxEnabled: false\n",
        )
        .unwrap();
        let config = AppState::load_config(&dir);
        assert!(!config.mux_enabled, "muxEnabled: false must be honored");
        assert_eq!(config.socks_port, 1081);

        // Missing key keeps the default (enabled).
        fs::write(&path, "socksPort: 1080\n").unwrap();
        assert!(AppState::load_config(&dir).mux_enabled);

        let _ = fs::remove_dir_all(&dir);
    }

    /// `udpMode` must round-trip through `setting.yaml`; unknown values fall
    /// back to `off` (which keeps old configs — without the key — working).
    #[test]
    fn load_config_reads_udp_mode() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-udp-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("setting.yaml");

        fs::write(&path, "udpMode: proxy\n").unwrap();
        assert_eq!(AppState::load_config(&dir).udp_mode, UdpMode::Proxy);

        fs::write(&path, "udpMode: direct\n").unwrap();
        assert_eq!(AppState::load_config(&dir).udp_mode, UdpMode::Direct);

        fs::write(&path, "udpMode: nonsense\n").unwrap();
        assert_eq!(AppState::load_config(&dir).udp_mode, UdpMode::Off);

        // Missing key keeps the default (off).
        fs::write(&path, "socksPort: 1080\n").unwrap();
        assert_eq!(AppState::load_config(&dir).udp_mode, UdpMode::Off);

        let _ = fs::remove_dir_all(&dir);
    }
}
