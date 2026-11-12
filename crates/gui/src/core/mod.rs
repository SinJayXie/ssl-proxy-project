pub mod dns;
pub mod geo;
pub mod geo_sdk;
pub mod proxy;
pub mod state;
pub mod stats;
pub mod types;

use crate::core::state::AppState;
use crate::core::types::{
    ApiAppInfo, AppConfig, AppError, CheckUpdateResult, ConnectionInfo, CountryCodeItem, DataFlow,
    DownloadProgress, RuleConfig, TestRuleResult, UpdateManifest,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;

/// Set on the process spawned by [`Core::restart_process`]. `main` uses it to
/// wait for the previous instance to release the single-instance mutex instead
/// of treating the launch as a second instance.
pub const RELAUNCH_ENV: &str = "SSL_PROXY_GUI_RELAUNCH";

/// Thin facade over `AppState` used by the GPUI layer.
///
/// Reads are synchronous snapshots (`try_read`) so they never block the UI
/// thread. Writes and network work run on a dedicated tokio runtime.
pub struct Core {
    pub state: Arc<AppState>,
    runtime: Arc<Runtime>,
}

impl Core {
    pub fn new(app_path: PathBuf, config_dir: PathBuf) -> Self {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ssl-proxy-io")
                .build()
                .expect("build tokio runtime"),
        );

        // `AppState::new` creates a `TokioAsyncResolver`, which needs a tokio
        // runtime context, so enter before constructing it.
        let state = {
            let _guard = runtime.enter();
            Arc::new(AppState::new(app_path, config_dir))
        };

        Self { state, runtime }
    }

    pub fn handle(&self) -> Handle {
        self.runtime.handle().clone()
    }

    // ---------- Lifecycle ----------

    pub fn consent_exists(&self) -> bool {
        self.state.config_dir.join("consent.dat").exists()
    }

    pub fn start_proxy(&self) {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            crate::core::proxy::start_socks5_server(state).await;
        });
    }

    pub fn save_consent(&self) -> std::io::Result<()> {
        std::fs::write(self.state.config_dir.join("consent.dat"), "1")?;
        log::info!("Consent saved, starting proxy...");
        self.start_proxy();
        Ok(())
    }

    /// Restart the current executable. The caller is responsible for quitting
    /// the current process afterwards.
    ///
    /// The new process is spawned directly instead of going through
    /// `cmd /C ... start`, because Rust quotes the whole command line with
    /// `\"` escapes that cmd does not understand — `start` then receives a
    /// broken path ("打开路径失败"). The child is flagged with [`RELAUNCH_ENV`]
    /// so `main` waits for this process to release the single-instance mutex.
    pub fn restart_process(&self) -> std::io::Result<()> {
        let exe = std::env::current_exe()?;

        let mut command = std::process::Command::new(&exe);
        command.env(RELAUNCH_ENV, "1");

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;

            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        }

        command.spawn()?;
        log::info!("Relaunching {:?}", exe);
        Ok(())
    }

    // ---------- Synchronous snapshots (UI polling) ----------

    pub fn snapshot_connections(&self) -> Option<Vec<ConnectionInfo>> {
        self.state
            .connections
            .try_read()
            .ok()
            .map(|map| map.values().cloned().collect())
    }

    pub fn snapshot_config(&self) -> Option<AppConfig> {
        self.state.config.try_read().ok().map(|cfg| cfg.clone())
    }

    pub fn snapshot_rules(&self) -> Option<Vec<RuleConfig>> {
        self.state.rules.try_read().ok().map(|rules| rules.clone())
    }

    pub fn snapshot_dataflow(&self) -> Option<DataFlow> {
        self.state
            .total_dataflow
            .try_read()
            .ok()
            .map(|flow| flow.clone())
    }

    /// Aggregate UDP relay traffic (kept separate from `snapshot_dataflow`)
    pub fn snapshot_udp_dataflow(&self) -> Option<DataFlow> {
        self.state
            .udp_dataflow
            .try_read()
            .ok()
            .map(|flow| flow.clone())
    }

    pub fn snapshot_app_info(&self) -> Option<ApiAppInfo> {
        let config = self.snapshot_config()?;
        let connections = self.snapshot_connections()?;
        let dataflow = self.snapshot_dataflow()?;

        Some(ApiAppInfo {
            socks_port: config.socks_port,
            proxy_server: if config.proxy_server.is_empty() {
                String::new()
            } else {
                format!("{}:{}", config.proxy_server, config.proxy_port)
            },
            connections: connections.len(),
            dataflow,
        })
    }

    pub fn geo_countries(&self) -> Vec<CountryCodeItem> {
        self.state.geo_manager.get_all_country_codes()
    }

    /// Last 5000 characters of `app.log`.
    pub fn read_logs(&self) -> String {
        let path = self.state.config_dir.join("app.log");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return "No logs yet".to_string();
        };

        let mut start = content.len().saturating_sub(5000);
        while start < content.len() && !content.is_char_boundary(start) {
            start += 1;
        }
        content[start..].to_string()
    }

    // ---------- Asynchronous actions ----------

    pub fn take_errors(&self) -> JoinHandle<Vec<AppError>> {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            let mut pool = state.error_pool.write().await;
            std::mem::take(&mut *pool)
        })
    }

    pub fn kill_connection(&self, id: u32) -> JoinHandle<bool> {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            state.connections.write().await.remove(&id);
            true
        })
    }

    pub fn add_rule(&self, rule: RuleConfig) -> JoinHandle<bool> {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            let mut rules = state.rules.write().await;
            rules.push(rule);
            save_rules_to_file(&rules, &state.config_dir);
            true
        })
    }

    pub fn save_rule(&self, id: usize, rule: RuleConfig) -> JoinHandle<bool> {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            let mut rules = state.rules.write().await;
            if id < rules.len() {
                rules[id] = rule;
                save_rules_to_file(&rules, &state.config_dir);
                true
            } else {
                false
            }
        })
    }

    pub fn delete_rule(&self, id: usize) -> JoinHandle<bool> {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            let mut rules = state.rules.write().await;
            if id < rules.len() {
                rules.remove(id);
                save_rules_to_file(&rules, &state.config_dir);
                true
            } else {
                false
            }
        })
    }

    pub fn save_config(&self, config: AppConfig) -> JoinHandle<Result<bool, String>> {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            let path = state.config_dir.join("setting.yaml");
            let content = serde_yaml::to_string(&config).map_err(|err| err.to_string())?;
            std::fs::write(&path, content).map_err(|err| err.to_string())?;
            *state.config.write().await = config;
            log::info!("Config saved to {:?}", path);
            Ok(true)
        })
    }

    pub fn test_rule(&self, host: String) -> JoinHandle<Result<TestRuleResult, String>> {
        let state = self.state.clone();
        self.runtime.spawn(async move { run_test_rule(state, host).await })
    }

    pub fn check_update(&self) -> JoinHandle<Result<CheckUpdateResult, String>> {
        self.runtime.spawn(async move { run_check_update().await })
    }

    pub fn download_update(
        &self,
        url: String,
        progress: tokio::sync::mpsc::UnboundedSender<DownloadProgress>,
    ) -> JoinHandle<Result<(), String>> {
        self.runtime.spawn(async move { run_download_update(url, progress).await })
    }
}

fn save_rules_to_file(rules: &[RuleConfig], config_dir: &Path) {
    let path = config_dir.join("rules.yaml");
    match serde_yaml::to_string(rules) {
        Ok(content) => {
            if let Err(err) = std::fs::write(&path, content) {
                log::error!("Failed to save rules.yaml: {}", err);
            } else {
                log::info!("Rules saved to {:?}", path);
            }
        }
        Err(err) => log::error!("Failed to serialize rules: {}", err),
    }
}

async fn run_test_rule(state: Arc<AppState>, host: String) -> Result<TestRuleResult, String> {
    let start = std::time::Instant::now();
    let host = host.trim();

    let is_ip = host.split('.').all(|part| part.parse::<u8>().is_ok())
        && host.split('.').count() == 4;

    let dns_server_display = {
        let config = state.config.read().await;
        if config.dns_servers.is_empty() {
            "8.8.8.8:53 (fallback)".to_string()
        } else {
            config
                .dns_servers
                .iter()
                .map(|server| format!("{}:53", server))
                .collect::<Vec<_>>()
                .join(", ")
        }
    };

    let (resolved_ip, geo_code, country) = if is_ip {
        let (alpha2, country) = state
            .geo_manager
            .get_country_by_ip(host)
            .map(|item| (item.alpha2_code, item.country))
            .unwrap_or_else(|| ("UNK".to_string(), "Unknown".to_string()));
        (host.to_string(), alpha2, country)
    } else {
        match crate::core::dns::lookup(&state, host).await {
            Ok(ip) => {
                let (alpha2, country) = state
                    .geo_manager
                    .get_country_by_ip(&ip)
                    .map(|item| (item.alpha2_code, item.country))
                    .unwrap_or_else(|| ("UNK".to_string(), "Unknown".to_string()));
                (ip, alpha2, country)
            }
            Err(err) => {
                return Ok(TestRuleResult {
                    host: host.to_string(),
                    resolved_ip: format!("DNS failed: {}", err),
                    dns_server: dns_server_display,
                    country: "Unknown".to_string(),
                    alpha2_code: "UNK".to_string(),
                    matched_rule: "N/A".to_string(),
                    mode: "DNS_ERROR".to_string(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                });
            }
        }
    };

    let rules = state.rules.read().await;
    let (matched_rule, mode) = if let Some(mode) =
        crate::core::proxy::connect::match_rules(host, &geo_code, &rules)
    {
        let index = rules.iter().position(|rule| match rule.rule_type.as_str() {
            "HOST" => crate::core::proxy::connect::match_host(host, &rule.match_str),
            "GEO" => rule.match_str.eq_ignore_ascii_case(&geo_code),
            _ => false,
        });

        let description = if let Some(index) = index {
            let rule = &rules[index];
            format!("{}: {} → {}", rule.rule_type, rule.match_str, rule.mode)
        } else {
            "Matched".to_string()
        };
        (description, mode)
    } else {
        let config = state.config.read().await;
        let mode = if config.proxy_server.is_empty() {
            "DIRECT"
        } else if geo_code == "PRIVATE"
            || config
                .directs
                .iter()
                .any(|region| region.eq_ignore_ascii_case(&geo_code))
        {
            "DIRECT"
        } else {
            "PROXY"
        };
        (
            format!("fallback (config.directs: {:?})", config.directs),
            mode.to_string(),
        )
    };

    Ok(TestRuleResult {
        host: host.to_string(),
        resolved_ip,
        dns_server: dns_server_display,
        country,
        alpha2_code: geo_code,
        matched_rule,
        mode,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

async fn run_check_update() -> Result<CheckUpdateResult, String> {
    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
    const UPDATE_URL: &str = "https://hk.dishuyl.cn/ssl-proxy/version.json";

    log::info!("Checking for updates...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|err| {
            log::error!("Failed to build HTTP client: {}", err);
            err.to_string()
        })?;

    let manifest: UpdateManifest = client
        .get(UPDATE_URL)
        .send()
        .await
        .map_err(|err| {
            log::error!("Update check request failed: {}", err);
            err.to_string()
        })?
        .json()
        .await
        .map_err(|err| {
            log::error!("Failed to parse update manifest: {}", err);
            err.to_string()
        })?;

    log::info!(
        "Proxy current version: {}, Latest version: {}",
        CURRENT_VERSION,
        manifest.version
    );

    Ok(CheckUpdateResult {
        has_update: manifest.version.as_str() != CURRENT_VERSION,
        latest_version: manifest.version,
        current_version: CURRENT_VERSION.to_string(),
        changelog: manifest.changelog,
        download_url: manifest.download_url,
    })
}

async fn run_download_update(
    url: String,
    progress: tokio::sync::mpsc::UnboundedSender<DownloadProgress>,
) -> Result<(), String> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    log::info!("Downloading update from {}", url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|err| {
            log::error!("Failed to build HTTP client: {}", err);
            err.to_string()
        })?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|err| {
            log::error!("Download request failed: {}", err);
            err.to_string()
        })?;

    let total = response.content_length().unwrap_or(0);

    let temp_dir = std::env::temp_dir();
    let file_name = url.split('/').last().unwrap_or("update.exe");
    let destination = temp_dir.join(file_name);

    let mut file = tokio::fs::File::create(&destination)
        .await
        .map_err(|err| {
            log::error!("Failed to create download file: {}", err);
            err.to_string()
        })?;

    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| {
            log::error!("Download chunk error: {}", err);
            err.to_string()
        })?;
        file.write_all(&chunk).await.map_err(|err| {
            log::error!("Failed to write chunk: {}", err);
            err.to_string()
        })?;
        downloaded += chunk.len() as u64;

        let percent = if total > 0 {
            ((downloaded as f64 / total as f64) * 100.0) as u32
        } else {
            0
        };

        let _ = progress.send(DownloadProgress {
            percent,
            downloaded,
            total,
        });
    }

    file.flush().await.map_err(|err| {
        log::error!("Failed to flush file: {}", err);
        err.to_string()
    })?;

    log::info!("Download complete: {:?}", destination);

    let installer_path = destination.clone();
    tokio::task::spawn_blocking(move || {
        #[cfg(target_os = "windows")]
        {
            match std::process::Command::new("explorer.exe")
                .arg(&installer_path)
                .spawn()
            {
                Ok(_) => log::info!("Installer launched via explorer"),
                Err(err) => log::error!("Failed to launch installer: {}", err),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            match std::process::Command::new(&installer_path).spawn() {
                Ok(_) => log::info!("Installer launched"),
                Err(err) => log::error!("Failed to launch installer: {}", err),
            }
        }
    })
    .await
    .map_err(|err| {
        log::error!("spawn_blocking panicked: {}", err);
        err.to_string()
    })?;

    std::process::exit(0);
}
