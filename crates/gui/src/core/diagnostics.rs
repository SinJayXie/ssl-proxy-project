//! Built-in diagnostics: local proxy, upstream, DNS, route table and TUN state.
//!
//! Each check is independent and returns a [`CheckResult`] whose `name` is an
//! i18n key. `detail` is English free text so it can go straight into logs and
//! exported diagnostic reports.

// UI wiring lands in a later task; the public surface is exercised by tests.
#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::state::AppState;
use crate::core::types::AppConfig;
use crate::core::Core;

/// Per-check budget; each check also applies its own shorter connect timeout.
const CHECK_TIMEOUT: Duration = Duration::from_secs(3);
const PORT_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const UPSTREAM_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_PROBE_DOMAIN: &str = "www.gstatic.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    /// i18n key, e.g. `"DIAG_CHECK_PROXY_PORT"`.
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

/// Run all checks in order, each bounded by [`CHECK_TIMEOUT`].
pub async fn run(core: &Core) -> Vec<CheckResult> {
    run_with(
        core.state.clone(),
        core.snapshot_config().unwrap_or_default(),
    )
    .await
}

/// 与 [`run`] 等价，但直接接收已取出的状态和配置（后台任务用，避免再碰 `Core`）。
pub async fn run_with(state: Arc<AppState>, config: AppConfig) -> Vec<CheckResult> {
    let tun_prefix = tun_prefix_from_range(&config.tun.fake_ip_range);

    let mut results = Vec::with_capacity(5);
    results.push(with_timeout(
        "DIAG_CHECK_PROXY_PORT",
        check_proxy_port(&config),
    )
    .await);
    results.push(with_timeout(
        "DIAG_CHECK_UPSTREAM",
        check_upstream(&config),
    )
    .await);
    results.push(with_timeout("DIAG_CHECK_DNS", check_dns(&state)).await);
    results.push(with_timeout("DIAG_CHECK_ROUTE", check_route(&tun_prefix)).await);
    results.push(with_timeout("DIAG_CHECK_TUN", check_tun()).await);
    results
}

async fn with_timeout<F>(name: &'static str, check: F) -> CheckResult
where
    F: Future<Output = CheckResult>,
{
    match timeout(CHECK_TIMEOUT, check).await {
        Ok(result) => result,
        Err(_) => result(
            name,
            CheckStatus::Fail,
            format!("check timed out after {}s", CHECK_TIMEOUT.as_secs()),
        ),
    }
}

async fn check_proxy_port(config: &AppConfig) -> CheckResult {
    const NAME: &str = "DIAG_CHECK_PROXY_PORT";
    let port = config.socks_port;
    let outcome = timeout(
        PORT_PROBE_TIMEOUT,
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await;

    match outcome {
        Ok(Ok(_)) => result(
            NAME,
            CheckStatus::Pass,
            format!("local proxy is listening on 127.0.0.1:{port}"),
        ),
        Ok(Err(_)) | Err(_) => result(
            NAME,
            CheckStatus::Fail,
            "local proxy is not accepting connections".to_string(),
        ),
    }
}

async fn check_upstream(config: &AppConfig) -> CheckResult {
    const NAME: &str = "DIAG_CHECK_UPSTREAM";
    if config.proxy_server.trim().is_empty() {
        return result(NAME, CheckStatus::Info, "no upstream configured".to_string());
    }

    let target = format!("{}:{}", config.proxy_server.trim(), config.proxy_port);
    match timeout(UPSTREAM_PROBE_TIMEOUT, TcpStream::connect(&target)).await {
        Ok(Ok(_)) => result(
            NAME,
            CheckStatus::Pass,
            format!("upstream {target} is reachable"),
        ),
        Ok(Err(err)) => result(
            NAME,
            CheckStatus::Fail,
            format!("cannot reach upstream {target}: {err}"),
        ),
        Err(_) => result(
            NAME,
            CheckStatus::Fail,
            format!("cannot reach upstream {target}: connect timed out"),
        ),
    }
}

async fn check_dns(state: &Arc<AppState>) -> CheckResult {
    const NAME: &str = "DIAG_CHECK_DNS";
    let started = Instant::now();
    let outcome = crate::core::dns::lookup(state, DNS_PROBE_DOMAIN).await;
    let elapsed_ms = started.elapsed().as_millis();

    match outcome {
        Ok(ip) => result(
            NAME,
            CheckStatus::Pass,
            format!("resolved {DNS_PROBE_DOMAIN} -> {ip} in {elapsed_ms} ms"),
        ),
        Err(err) => result(
            NAME,
            CheckStatus::Fail,
            format!("DNS lookup for {DNS_PROBE_DOMAIN} failed: {err}"),
        ),
    }
}

#[cfg(target_os = "windows")]
async fn check_route(tun_prefix: &str) -> CheckResult {
    const NAME: &str = "DIAG_CHECK_ROUTE";
    let output = std::process::Command::new("route")
        .args(["print", "-4"])
        .output();

    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return result(
                NAME,
                CheckStatus::Warn,
                format!("route print -4 exited with {}", output.status),
            );
        }
        Err(err) => {
            return result(
                NAME,
                CheckStatus::Warn,
                format!("failed to run route print -4: {err}"),
            );
        }
    };

    // Route output uses the OEM code page on Windows; lossy decoding keeps the
    // ASCII address columns intact for parsing.
    let text = String::from_utf8_lossy(&output.stdout);
    let summary = parse_route_output(&text, tun_prefix);
    let detail = format!(
        "default_routes={} has_tun_route={} tun_prefix={:?}",
        summary.default_routes, summary.has_tun_route, tun_prefix
    );

    if summary.default_routes == 0 {
        return result(
            NAME,
            CheckStatus::Warn,
            format!("{detail}; no IPv4 default route found"),
        );
    }
    if !summary.has_tun_route {
        return result(
            NAME,
            CheckStatus::Warn,
            format!("{detail}; no TUN route found"),
        );
    }
    result(NAME, CheckStatus::Pass, detail)
}

#[cfg(not(target_os = "windows"))]
async fn check_route(_tun_prefix: &str) -> CheckResult {
    result(
        "DIAG_CHECK_ROUTE",
        CheckStatus::Info,
        "route table check is Windows-only".to_string(),
    )
}

async fn check_tun() -> CheckResult {
    const NAME: &str = "DIAG_CHECK_TUN";
    match crate::core::tun::runner::status() {
        None => result(NAME, CheckStatus::Info, "TUN is not running".to_string()),
        Some(status) => {
            let detail = format!(
                "device={} if_index={} route_scope={} fakeip={} tcp_pending={} tcp_active={} udp_active={} queued={}",
                status.device_name,
                status.if_index,
                status.route_scope.as_str(),
                status.fakeip_count,
                status.tcp_pending,
                status.tcp_active,
                status.udp_active,
                status.queued
            );
            let state = if status.fakeip_count == 0 {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            };
            result(NAME, state, detail)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSummary {
    pub default_routes: usize,
    pub has_tun_route: bool,
}

/// Parse `route print -4` output: count IPv4 default routes (`0.0.0.0 0.0.0.0`)
/// and detect a TUN route via the fake-ip prefix or the interface name.
pub fn parse_route_output(output: &str, tun_prefix: &str) -> RouteSummary {
    let mut summary = RouteSummary {
        default_routes: 0,
        has_tun_route: false,
    };

    for line in output.lines() {
        let line = line.trim();
        let mut fields = line.split_whitespace();
        if fields.next() == Some("0.0.0.0") && fields.next() == Some("0.0.0.0") {
            summary.default_routes += 1;
        }
        if !summary.has_tun_route {
            summary.has_tun_route = (!tun_prefix.is_empty() && line.contains(tun_prefix))
                || line.contains("SSLProxy");
        }
    }

    summary
}

/// One `NAME: STATUS - detail` line per check.
pub fn format_report(results: &[CheckResult]) -> String {
    results
        .iter()
        .map(|item| format!("{}: {} - {}", item.name, item.status.as_str(), item.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 完整 IPv4 路由表文本（非 Windows 返回 "n/a"）。
pub fn route_table_text() -> String {
    #[cfg(target_os = "windows")]
    {
        match std::process::Command::new("route")
            .args(["print", "-4"])
            .output()
        {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).into_owned()
            }
            Ok(output) => format!("route print -4 exited with {}", output.status),
            Err(err) => format!("failed to run route print -4: {err}"),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        "n/a".to_string()
    }
}

/// Counters as `(pass, warn, fail, info)`.
pub fn summarize(results: &[CheckResult]) -> (usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0);
    for item in results {
        match item.status {
            CheckStatus::Pass => counts.0 += 1,
            CheckStatus::Warn => counts.1 += 1,
            CheckStatus::Fail => counts.2 += 1,
            CheckStatus::Info => counts.3 += 1,
        }
    }
    counts
}

/// Derive the `route print` prefix (e.g. `"198.18."`) from `tun.fake_ip_range`.
fn tun_prefix_from_range(range: &str) -> String {
    let address = range.split('/').next().unwrap_or_default();
    let mut octets = address.split('.');
    match (octets.next(), octets.next()) {
        (Some(first), Some(second)) if !first.is_empty() && !second.is_empty() => {
            format!("{first}.{second}.")
        }
        _ => String::new(),
    }
}

fn result(name: &'static str, status: CheckStatus, detail: String) -> CheckResult {
    CheckResult {
        name,
        status,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_route_output() -> String {
        r#"
===========================================================================
Interface List
 12...00 15 5d 01 02 03 ......Ethernet
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        198.18.0.0      255.255.0.0         On-link          198.18.0.1      0
      192.168.1.0    255.255.255.0         On-link      192.168.1.10    281
          0.0.0.0          0.0.0.0         On-link          198.18.0.1      0
"#
        .to_string()
    }

    #[test]
    fn route_output_detects_default_routes_and_tun_prefix() {
        let summary = parse_route_output(&sample_route_output(), "198.18.");
        assert_eq!(summary.default_routes, 2);
        assert!(summary.has_tun_route);
        assert_eq!(tun_prefix_from_range("198.18.0.1/16"), "198.18.");
    }

    #[test]
    fn route_output_without_tun_route() {
        let summary = parse_route_output(&sample_route_output(), "10.0.");
        assert_eq!(summary.default_routes, 2);
        assert!(!summary.has_tun_route, "no fake-ip route in sample output");
    }

    #[test]
    fn route_output_recognizes_interface_name() {
        let output = " 14...00 15 5d 01 02 04 ......SSLProxy\n";
        let summary = parse_route_output(output, "198.18.");
        assert!(summary.has_tun_route);
        assert_eq!(summary.default_routes, 0);
    }

    #[test]
    fn summarize_counts_mixed_statuses() {
        let results = vec![
            result("A", CheckStatus::Pass, "ok".to_string()),
            result("B", CheckStatus::Warn, "meh".to_string()),
            result("C", CheckStatus::Fail, "bad".to_string()),
            result("D", CheckStatus::Info, "fyi".to_string()),
            result("E", CheckStatus::Pass, "ok".to_string()),
        ];
        assert_eq!(summarize(&results), (2, 1, 1, 1));
    }

    #[test]
    fn format_report_contains_name_and_status() {
        let results = vec![
            result("DIAG_CHECK_PROXY_PORT", CheckStatus::Pass, "ok".to_string()),
            result("DIAG_CHECK_DNS", CheckStatus::Fail, "boom".to_string()),
        ];
        let report = format_report(&results);
        assert!(report.contains("DIAG_CHECK_PROXY_PORT: PASS - ok"));
        assert!(report.contains("DIAG_CHECK_DNS: FAIL - boom"));
        assert_eq!(report.lines().count(), 2);
    }
}
