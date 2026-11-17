pub mod diagnostics;
pub mod dns;
pub mod geo;
pub mod geo_sdk;
pub mod proc;
pub mod proxy;
pub mod state;
pub mod stats;
pub mod tun;
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

        let core = Self { state, runtime };
        // 崩溃恢复：先撤销上次异常退出残留的路由，再按当前配置决定是否启用 TUN。
        // 同时清理历次遗留的 TUN 虚拟网卡（旧版本停用时不卸载设备）。
        let tun_device_name = core
            .snapshot_config()
            .map(|cfg| cfg.tun.device_name)
            .unwrap_or_else(|| crate::core::tun::config::TunConfig::default().device_name);
        crate::core::tun::runner::recover_on_startup(
            &core.state.config_dir,
            &tun_device_name,
        );
        core.apply_tun();
        core
    }

    pub fn handle(&self) -> Handle {
        self.runtime.handle().clone()
    }



    /// 按当前配置对齐 TUN 状态（启动时 / 保存配置后调用）。
    pub fn apply_tun(&self) {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            crate::core::tun::runner::apply(state).await;
        });
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
    /// 应用退出前调用：停止 TUN 并回滚路由/网卡/快照（幂等）。
    /// 所有退出路径（托盘、UI 退出按钮、更新安装后）都必须先走这里。
    pub fn shutdown(&self) {
        crate::core::tun::runner::stop_before_exit(&self.state.config_dir);
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
        // 重启前先回滚 TUN 路由/网卡，避免半开状态遗留。
        crate::core::tun::runner::stop_before_exit(&self.state.config_dir);
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

    /// Last `max_bytes` bytes of `app.log`, trimmed to a UTF-8 char boundary.
    ///
    /// 通过 seek 只读取文件尾部（而非整个文件读入内存），
    /// 避免日志变大时每次刷新都产生内存尖峰。
    pub fn read_logs_tail(&self, max_bytes: usize) -> String {
        use std::io::{Read, Seek, SeekFrom};
        let path = self.state.config_dir.join("app.log");
        let Ok(mut file) = std::fs::File::open(&path) else {
            return "No logs yet".to_string();
        };
        let len = match file.metadata() {
            Ok(meta) => meta.len(),
            Err(_) => return "No logs yet".to_string(),
        };
        let start = len.saturating_sub(max_bytes as u64);
        if file.seek(SeekFrom::Start(start)).is_err() {
            return "No logs yet".to_string();
        }
        let mut bytes = Vec::with_capacity((len - start) as usize);
        if file.read_to_end(&mut bytes).is_err() {
            return "No logs yet".to_string();
        }
        tail_utf8(&bytes, max_bytes)
    }

    /// Last 5000 bytes of `app.log`.
    #[allow(dead_code)] // 保留给后续小窗口日志展示，当前日志页统一读 2 MB 尾部。
    pub fn read_logs(&self) -> String {
        self.read_logs_tail(5000)
    }

    /// Write `content` under `<config_dir>/exports` and return the full path.
    pub fn export_text(&self, kind: &str, content: &str) -> std::io::Result<PathBuf> {
        write_export(&self.state.config_dir, kind, content)
    }

    /// 在后台运行全部诊断检查（日志页的“诊断包”用）。
    pub fn run_diagnostics(
        &self,
    ) -> tokio::task::JoinHandle<Vec<crate::core::diagnostics::CheckResult>> {
        let state = self.state.clone();
        let config = self.snapshot_config().unwrap_or_default();
        self.runtime
            .spawn(async move { crate::core::diagnostics::run_with(state, config).await })
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
            // TUN 状态跟随配置（enable 开/关）。
            crate::core::tun::runner::apply(state.clone()).await;
            Ok(true)
        })
    }

    /// 清空 fake-ip 映射（内存 + 持久化文件），返回清理的条数。
    pub fn clear_fakeip(&self) -> JoinHandle<Result<usize, String>> {
        let state = self.state.clone();
        self.runtime
            .spawn(async move { crate::core::tun::runner::clear_fakeip(&state) })
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
        sha256: String,
        signature: String,
        progress: tokio::sync::mpsc::UnboundedSender<DownloadProgress>,
    ) -> JoinHandle<Result<(), String>> {
        self.runtime
            .spawn(async move { run_download_update(url, sha256, signature, progress).await })
    }
}

/// Write `content` to `<dir>/exports/<kind>-<yyyyMMdd-HHmmss>.txt` (UTC, no BOM).
pub(crate) fn write_export(dir: &Path, kind: &str, content: &str) -> std::io::Result<PathBuf> {
    let exports = dir.join("exports");
    std::fs::create_dir_all(&exports)?;
    let path = exports.join(format!("{}-{}.txt", kind, timestamp_utc()));
    std::fs::write(&path, content.as_bytes())?;
    Ok(path)
}

/// Current UTC time formatted as `yyyyMMdd-HHmmss`.
fn timestamp_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format_timestamp_utc(secs)
}

/// Format seconds since the Unix epoch as `yyyyMMdd-HHmmss` (proleptic Gregorian).
fn format_timestamp_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let time = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        year,
        month,
        day,
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Days since 1970-01-01 → (year, month, day), after Howard Hinnant's
/// `civil_from_days` (no external date crate needed).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Decode the last `max_bytes` of `bytes`, skipping a partially cut leading
/// character so the result never starts mid-codepoint.
fn tail_utf8(bytes: &[u8], max_bytes: usize) -> String {
    let mut start = bytes.len().saturating_sub(max_bytes);
    while start < bytes.len() && (bytes[start] & 0xC0) == 0x80 {
        start += 1;
    }
    String::from_utf8_lossy(&bytes[start..]).into_owned()
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

/// 更新清单按平台区分：Windows 是 NSIS 安装包，macOS 是 DMG。
#[cfg(windows)]
const UPDATE_MANIFEST_URL: &str = "https://hk.dishuyl.cn/ssl-proxy/version.json";
#[cfg(target_os = "macos")]
const UPDATE_MANIFEST_URL: &str = "https://hk.dishuyl.cn/ssl-proxy/version-mac.json";
#[cfg(not(any(windows, target_os = "macos")))]
const UPDATE_MANIFEST_URL: &str = "https://hk.dishuyl.cn/ssl-proxy/version.json";

async fn run_check_update() -> Result<CheckUpdateResult, String> {
    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

    log::info!("Checking for updates...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|err| {
            log::error!("Failed to build HTTP client: {}", err);
            err.to_string()
        })?;

    let manifest: UpdateManifest = client
        .get(UPDATE_MANIFEST_URL)
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

    let has_update = is_newer_version(CURRENT_VERSION, &manifest.version);
    if has_update && (manifest.sha256.trim().is_empty() || manifest.signature.trim().is_empty()) {
        log::warn!(
            "Update manifest {} has no sha256/signature; the installer will be refused",
            manifest.version
        );
    }

    Ok(CheckUpdateResult {
        has_update,
        latest_version: manifest.version,
        current_version: CURRENT_VERSION.to_string(),
        changelog: manifest.changelog,
        download_url: manifest.download_url,
        sha256: manifest.sha256,
        signature: manifest.signature,
    })
}

async fn run_download_update(
    url: String,
    expected_sha256: String,
    expected_signature: String,
    progress: tokio::sync::mpsc::UnboundedSender<DownloadProgress>,
) -> Result<(), String> {
    use futures_util::StreamExt;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    // 执行安装包前的边界校验：只允许 https 下载，且清单必须给出合法 SHA-256。
    let url = validate_download_url(&url)?;
    let expected_sha256 = expected_sha256.trim().to_ascii_lowercase();
    if !is_sha256_hex(&expected_sha256) {
        log::error!("Update manifest has no valid sha256, refusing to run the installer");
        return Err(
            "update manifest is missing a valid sha256; refusing to run the installer".to_string(),
        );
    }

    log::info!("Downloading update from {}", url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|err| {
            log::error!("Failed to build HTTP client: {}", err);
            err.to_string()
        })?;

    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|err| {
            log::error!("Download request failed: {}", err);
            err.to_string()
        })?;

    let total = response.content_length().unwrap_or(0);

    let temp_dir = std::env::temp_dir();
    let destination = temp_dir.join(safe_download_file_name(url.path()));

    let mut file = tokio::fs::File::create(&destination)
        .await
        .map_err(|err| {
            log::error!("Failed to create download file: {}", err);
            err.to_string()
        })?;

    let mut downloaded: u64 = 0;
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| {
            log::error!("Download chunk error: {}", err);
            err.to_string()
        })?;
        hasher.update(&chunk);
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
    drop(file);

    // 完整性校验：哈希不匹配时删除文件，绝不执行
    let actual_sha256 = format!("{:x}", hasher.finalize());
    if actual_sha256 != expected_sha256 {
        let _ = tokio::fs::remove_file(&destination).await;
        log::error!(
            "Update package integrity check failed: expected {}, got {}",
            expected_sha256,
            actual_sha256
        );
        return Err(
            "update package integrity check failed (sha256 mismatch); installer was not executed"
                .to_string(),
        );
    }

    log::info!(
        "Download complete and verified (sha256={}): {:?}",
        actual_sha256,
        destination
    );

    // 发布者签名校验：公钥内置在客户端，私钥只在发布端；失败则不执行安装包
    let package = tokio::fs::read(&destination).await.map_err(|err| {
        log::error!("Failed to read downloaded package: {}", err);
        err.to_string()
    })?;
    if let Err(err) = verify_update_signature(&package, expected_signature.trim()) {
        let _ = tokio::fs::remove_file(&destination).await;
        log::error!("Update package signature check failed: {}", err);
        return Err(
            "update package signature check failed; installer was not executed".to_string(),
        );
    }
    log::info!("Update package signature verified");

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
        #[cfg(target_os = "macos")]
        {
            // DMG 不能直接执行，交给系统挂载，Finder 会弹出拖入 Applications 的窗口。
            match std::process::Command::new("open").arg(&installer_path).spawn() {
                Ok(_) => log::info!("DMG opened via open"),
                Err(err) => log::error!("Failed to open dmg: {}", err),
            }
        }
        #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
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

    // 启动安装包前先关停 TUN（回滚路由/网卡），进程随后退出。
    crate::core::tun::runner::stop_before_exit(&crate::platform::paths::config_dir());
    std::process::exit(0);
}

/// 校验下载地址：必须是带主机名的 https 绝对 URL，避免明文下载可执行安装包。
fn validate_download_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw)
        .map_err(|err| format!("invalid update download url {:?}: {}", raw, err))?;
    if url.scheme() != "https" {
        return Err(format!(
            "update download url must use https (got {:?})",
            url.scheme()
        ));
    }
    if url.host_str().is_none() {
        return Err("update download url has no host".to_string());
    }
    Ok(url)
}

/// SHA-256 必须是 64 位十六进制
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 从 URL 路径取安全的临时文件名（不含路径分隔符，拒绝 `.` / `..`）
fn safe_download_file_name(path: &str) -> String {
    let raw = path.rsplit('/').next().unwrap_or("update.exe");
    let name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() || name == "." || name == ".." {
        "update.exe".to_string()
    } else {
        name
    }
}

/// 客户端内置的更新签名公钥（Ed25519，64 位十六进制）
const UPDATE_PUBKEY_HEX: &str = include_str!("../../assets/update_pubkey.hex");

/// 清单版本是否比当前版本新；拒绝降级，无法解析时退回字符串比较（兼容旧清单）
fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(cur), Some(new)) => {
            if new < cur {
                log::warn!(
                    "Update manifest version {} is older than current {}, downgrade refused",
                    latest,
                    current
                );
            }
            new > cur
        }
        _ => current != latest,
    }
}

/// 解析 `major.minor.patch`（忽略 `-pre` / `+build` 后缀），失败返回 `None`
fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let core = value.trim().split(|c| c == '-' || c == '+').next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// 校验安装包 Ed25519 签名（公钥内置，私钥只在发布端）
fn verify_update_signature(data: &[u8], signature_hex: &str) -> Result<(), String> {
    let public_key = decode_hex(UPDATE_PUBKEY_HEX.trim())?;
    if public_key.len() != 32 {
        return Err("embedded update public key is invalid".to_string());
    }
    verify_ed25519(&public_key, data, signature_hex)
}

fn verify_ed25519(public_key: &[u8], data: &[u8], signature_hex: &str) -> Result<(), String> {
    let signature = decode_hex(signature_hex)?;
    if signature.len() != 64 {
        return Err("update signature must be 64 bytes (128 hex chars)".to_string());
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(data, &signature)
        .map_err(|_| "signature mismatch".to_string())
}

/// 十六进制解码（长度必须是偶数）
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?}", byte as char)),
    }
}

#[cfg(test)]
mod update_security_tests {
    use super::{
        decode_hex, is_newer_version, is_sha256_hex, parse_version, safe_download_file_name,
        validate_download_url, verify_ed25519, UPDATE_PUBKEY_HEX,
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn download_url_must_be_https() {
        assert!(validate_download_url("https://example.com/a/Setup.exe").is_ok());
        assert!(validate_download_url("http://example.com/a/Setup.exe").is_err());
        assert!(validate_download_url("file:///c:/Setup.exe").is_err());
        assert!(validate_download_url("not a url").is_err());
        assert!(validate_download_url("https:").is_err());
    }

    #[test]
    fn sha256_requires_64_hex_chars() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        let mixed_case = format!(
            "{}{}",
            "0123456789abcdef".repeat(2),
            "0123456789ABCDEF".repeat(2)
        );
        assert!(is_sha256_hex(&mixed_case));
        assert!(!is_sha256_hex(""));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&"g".repeat(64)));
    }

    #[test]
    fn download_file_name_is_sanitized() {
        assert_eq!(
            safe_download_file_name("/ssl-proxy/win/SSLProxyClient_2.5.0_x64-setup.exe"),
            "SSLProxyClient_2.5.0_x64-setup.exe"
        );
        assert_eq!(safe_download_file_name("/a/../../x"), "x");
        assert_eq!(safe_download_file_name("/a/.."), "update.exe");
        assert_eq!(safe_download_file_name("/"), "update.exe");
        assert_eq!(safe_download_file_name("/a/b:c*d.exe"), "b_c_d.exe");
    }

    #[test]
    fn version_ordering_rejects_downgrade() {
        assert!(is_newer_version("2.5.0", "2.6.0"));
        assert!(is_newer_version("2.5.0", "2.5.1"));
        assert!(!is_newer_version("2.5.0", "2.5.0"));
        assert!(!is_newer_version("2.5.0", "2.4.9"), "降级包必须被拒绝");
        assert!(!is_newer_version("2.5.0", "2.5.0+build.7"));
        assert_eq!(parse_version("2.5.0-beta.1"), Some((2, 5, 0)));
        assert_eq!(parse_version(" 10.20.30 "), Some((10, 20, 30)));
        assert_eq!(parse_version("2.5"), None);
        assert_eq!(parse_version("v2.5.0"), None);
    }

    #[test]
    fn hex_decode_rejects_invalid_input() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert!(decode_hex("abc").is_err(), "奇数长度必须拒绝");
        assert!(decode_hex("zz").is_err(), "非十六进制字符必须拒绝");
    }

    #[test]
    fn embedded_public_key_is_valid() {
        let key = decode_hex(UPDATE_PUBKEY_HEX.trim()).expect("embedded public key is hex");
        assert_eq!(key.len(), 32, "Ed25519 公钥必须是 32 字节");
    }

    #[test]
    fn ed25519_signature_roundtrip() {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate test key");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load test key");
        let public_key = key_pair.public_key().as_ref();
        let data = b"installer bytes";
        let signature = hex(key_pair.sign(data).as_ref());

        assert!(verify_ed25519(public_key, data, &signature).is_ok());
        assert!(
            verify_ed25519(public_key, b"tampered bytes", &signature).is_err(),
            "篡改内容必须校验失败"
        );
        assert!(verify_ed25519(public_key, data, "").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::{format_timestamp_utc, tail_utf8, write_export};

    #[test]
    fn timestamp_formats_known_epochs() {
        assert_eq!(format_timestamp_utc(946_684_800), "20000101-000000");
        assert_eq!(format_timestamp_utc(0), "19700101-000000");
        assert_eq!(format_timestamp_utc(1_700_000_000), "20231114-221320");
    }

    #[test]
    fn write_export_creates_timestamped_file() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-test-{}", std::process::id()));
        let path = write_export(&dir, "logs", "hello log").expect("write export");

        assert!(path.starts_with(dir.join("exports")), "unexpected path: {path:?}");
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string();
        assert!(name.starts_with("logs-"), "unexpected file name: {name}");
        assert!(name.ends_with(".txt"), "unexpected file name: {name}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello log");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_keeps_small_file_intact() {
        assert_eq!(tail_utf8(b"short log", 5000), "short log");
        assert_eq!(tail_utf8(b"", 5000), "");
    }

    #[test]
    fn tail_keeps_only_last_bytes() {
        let content = "x".repeat(100);
        assert_eq!(tail_utf8(content.as_bytes(), 10), "xxxxxxxxxx");
    }

    #[test]
    fn tail_does_not_split_multibyte_chars() {
        let content = "2024-01-01 日志内容 日本語";
        // Cut lands inside "日"; the partial char is dropped, leaving "本語".
        let tail = tail_utf8(content.as_bytes(), 7);

        assert!(std::str::from_utf8(tail.as_bytes()).is_ok());
        assert!(!tail.contains('\u{FFFD}'), "no replacement chars: {tail:?}");
        assert_eq!(tail, "本語");
    }
}
