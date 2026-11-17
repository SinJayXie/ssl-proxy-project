use crate::ui::{i18n, theme};
use gpui_kit::base::v_flex;
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::ActiveTheme as _;
use gpui_kit::*;

struct Entry {
    version: &'static str,
    date: &'static str,
    changes: &'static [&'static str],
}

const CHANGELOG: &[Entry] = &[
    Entry {
        version: "2.7.2",
        date: "2026-11-17",
        changes: &[
            "Dashboard: a TUN card shows the current state and lets you toggle TUN without opening Settings (applies immediately)",
            "TUN: heartbeat, fake-ip saver, egress monitor and the event pump now exit together with TUN, so no heartbeat lines appear after disabling and toggling no longer accumulates background tasks",
            "TUN: the adapter is reopened when it already exists and uses a stable GUID derived from its name, so toggling TUN no longer creates SSLProxy 2, SSLProxy 3, ...",
            "TUN: leftover adapters (SSLProxy, SSLProxy-1 ... -4, suffixed SSLProxy 2, 3 ... and the early SSLProxy Tunnel Tunnel form) are removed on startup; only wintun devices are touched",
        ],
    },
    Entry {
        version: "2.7.1",
        date: "2026-11-17",
        changes: &[
            "TUN: disabling TUN now fully tears down the data plane (stack thread, socket threads and wintun session) instead of leaving the adapter connected forever",
            "TUN: the virtual adapter is uninstalled when TUN is disabled, when startup fails midway and when a duplicate start is rolled back",
        ],
    },
    Entry {
        version: "2.7.0",
        date: "2026-11-17",
        changes: &[
            "Performance: DNS lookups no longer serialize concurrent connections (the cache lock is never held across a resolver await), and entries expire after 5 minutes",
            "Performance: direct connections dial the already-resolved IP instead of re-resolving the domain through the system resolver - first connections to a new host no longer take seconds",
            "Performance: idle connections skip the stats write lock; copy buffers grew from 8 KB to 64 KB; connection IDs are allocated atomically",
            "Connections: TUN direct connections now appear in the connections page with geo info, latency and traffic stats (previously only proxy connections were listed)",
            "TUN: TUN settings apply immediately on change (switches, route scope and text fields on Enter/blur) - no Save button and no app restart needed",
            "TUN: route commands no longer flash console windows when enabling/disabling TUN or running diagnostics",
            "Security: rate-limit and blacklist tables are swept periodically instead of growing without bound; app.log rotates at 10 MB and the log viewer reads only the tail; crash.log is capped; fake-ip pool prefixes are validated (8-32)",
        ],
    },
    Entry {
        version: "2.6.2",
        date: "2026-11-17",
        changes: &[
            "Logs: filter by level, keyword search, export the filtered lines, and generate a one-click diagnostics bundle",
            "New Diagnostics page: local proxy port, upstream reachability, DNS resolution, IPv4 route table and TUN self-check, with a copyable report",
            "Connections: search, sort by time / traffic / latency / host, PROXY vs DIRECT filter and per-process filter",
            "Connections: process names are captured on Windows via the TCP/UDP owner tables",
            "Compliance: the installer ships THIRD-PARTY-NOTICES.md and the Wintun GPLv2 license; the About page opens a third-party notices dialog",
            "Compliance: cargo-deny and cargo-audit run in CI with a permissive-license allow-list",
            "UI: hover highlights now follow the rounded corners of cards in Connections, Rules and Rule Tester",
            "Fixes: log reading keeps up to 2 MB without splitting UTF-8; the diagnostics bundle redacts credentials",
        ],
    },
    Entry {
        version: "2.6.1",
        date: "2026-11-17",
        changes: &[
            "TUN: the adapter address is assigned through IP Helper with duplicate-address detection off, so the interface is usable immediately (fixes direct-connection timeouts on some Windows 10 hosts)",
            "TUN: adapter creation retries up to 5 times, 500 ms apart, and falls back to name-1 ... name-4 when the configured name is taken",
            "TUN: all-traffic mode installs two /1 routes and leaves the system default route untouched",
            "TUN: new route scope option (global / fake-ip), plus configurable UDP idle timeout (default 60 s) and max connections (default 256)",
            "TUN: auto route is honoured; turning it off installs no routes at all",
            "TUN: the TUN settings panel is Windows-only, and other platforms never start it",
            "Connections: groups are collapsed by default and rendered by a virtualised list whose scrollbar stays visible at the right edge",
            "Logs: client log output is English only, and the periodic UI heartbeat line is gone",
            "UI: hover highlights follow the rounded corners of cards in Connections, Rules and Rule Tester",
        ],
    },
    Entry {
        version: "2.6.0",
        date: "2026-11-16",
        changes: &[
            "TUN (Windows): WinTun adapter with a userland smoltcp stack, fake-IP DNS hijack on :53 and one routing engine shared by TCP and UDP",
            "TUN: fail-closed startup with route rollback, a crash-recovery snapshot and cleanup on every exit path",
            "TUN: fake-IP mappings persist across restarts in fakeip.json and can be cleared from Settings",
            "TUN: strict route forces private / loopback targets DIRECT and requires a DNS hijack list",
            "TUN: UDP proxying through the TLS tunnel, including QUIC / HTTP3",
            "Settings: new TUN panel with enable, strict-route and auto-route switches plus tunable parameters",
            "Fixes: adapter index conversion, smoltcp AnyIP, socket-recycle panic; the installer now ships wintun.dll",
        ],
    },
    Entry {
        version: "2.5.2",
        date: "2026-11-13",
        changes: &[
            "Appearance: acrylic (blurred) window background on Windows 10/11 and macOS, switchable in Settings",
            "Appearance: background opacity slider (30-100%); sidebar, title bar and cards fade along with it so the blur shows through",
            "Appearance: dialogs and modal overlays stay fully opaque while acrylic is enabled",
            "Settings: the footer action bar no longer paints its own background",
        ],
    },
    Entry {
        version: "2.5.1",
        date: "2026-11-13",
        changes: &[
            "Updates: installers are verified with SHA-256 and an Ed25519 signature before running; unsigned or tampered packages are refused",
            "Updates: downgrade packages are rejected and the manifest download URL must use HTTPS",
            "Server: SSRF protection also blocks NAT64, 6to4, Teredo, site-local and IPv4-compatible IPv6 targets",
            "Server: repeated protocol authentication failures are rate-limited per IP; normal HTTP visitors are not counted",
            "Server: the real-site fallback caps request bodies at 8 MB even for chunked uploads",
            "Protocol v3: every handshake carries a random nonce plus a server-side replay cache",
            "Anti-fingerprinting: the first TLS records are padded on both sides and ALPN offers h2 + http/1.1",
            "Server: optional real-site reverse-proxy fallback with HTTP/2 and TLS session resumption",
            "Updates: mandatory prompt for new versions with an hourly re-check",
        ],
    },
    Entry {
        version: "2.5.0",
        date: "2026-11-13",
        changes: &[
            "Updates: when a new version is found the prompt is mandatory and cannot be dismissed; the client also re-checks hourly",
            "Anti-fingerprinting: the first TLS records are padded on both sides, so handshakes no longer start with an unusually small packet",
            "Client: TLS now offers h2 and http/1.1 via ALPN, matching a normal browser handshake",
            "Server: optional real-site reverse-proxy fallback with HTTP/2, so unauthenticated probes see a real website",
            "Server: TLS session resumption reduces reconnect latency",
        ],
    },
    Entry {
        version: "2.4.0",
        date: "2026-11-13",
        changes: &[
            "Protocol v3: every handshake carries a random nonce and the server keeps a replay cache, so captured handshakes can no longer be reused",
            "Security: servers reject loopback / private / cloud-metadata targets for both TCP and UDP (opt-in with allow-private-targets)",
            "DNS: a failed local lookup now falls back to the proxy instead of dropping the connection",
            "SOCKS5: IPv6 targets, robust fragmented handshake parsing and standards-compliant replies",
            "HTTP proxy: request bodies, keep-alive connections and WebSocket upgrades now work; IPv6 CONNECT targets are supported",
            "Direct connections now honour half-close, so protocols that shut down one direction keep receiving data",
            "Mux: per-stream 256 KB flow-control window keeps one slow stream from blocking the shared tunnel",
            "Mux: stale shared tunnels are retried with a fresh connection instead of failing the first request",
            "Server: mux streams are cleaned up on disconnect and idle sessions close after 90 seconds",
        ],
    },
    Entry {
        version: "2.3.5",
        date: "2026-11-13",
        changes: &[
            "Connections: show a TCP / UDP transport badge on every connection group and row",
            "Connections: UDP sessions show PROXY / DIRECT separately from the transport badge",
        ],
    },
    Entry {
        version: "2.3.4",
        date: "2026-11-13",
        changes: &[
            "Dashboard: the 7-day traffic chart is now an interactive bar chart with a value axis and dashed grid lines",
            "Dashboard: hover a bar to see that day's upload, download and total traffic",
            "Dashboard: show the 7-day total next to the chart title",
            "Connections: show a TCP / UDP badge for every connection group and row",
            "Title bar: display the application version next to the product name",
        ],
    },
    Entry {
        version: "2.3.3",
        date: "2026-11-13",
        changes: &[
            "UDP: SOCKS5 UDP ASSOCIATE relay with Off / Direct / Proxy modes (default Off)",
            "UDP over the TLS tunnel: datagrams are framed by the client and forwarded by the server, with and without mux",
            "UDP: per-target session reuse, idle timeout, capability negotiation and automatic fallback to direct when the server has no UDP support",
            "Server: UDP relay is opt-in via udp.enabled, with per-session rate limiting, idle timeout and private-network blocking",
            "Connections: UDP sessions are listed with their own traffic counters",
        ],
    },
    Entry {
        version: "2.3.2",
        date: "2026-11-12",
        changes: &[
            "Fix: the multiplexing switch was not saved on restart and came back enabled",
            "Fix: \"Save and restart\" showed an open-path error and the app did not relaunch",
            "Restart: the new process is spawned directly and waits for the previous instance to exit, so paths with spaces work",
            "Single instance: ignore a stale error code so the running window is detected reliably",
        ],
    },
    Entry {
        version: "2.3.0",
        date: "2026-11-12",
        changes: &[
            "Protocol v2: HMAC-SHA256 authentication with timestamp and mutual ACK verification",
            "TLS: ALPN advertises http/1.1 so the port looks like a regular HTTPS site",
            "Anti-fingerprint: frame padding masks TLS-in-TLS record lengths and the tiny first packet",
            "Multiplexing: many target connections share one TLS tunnel (trojan-go style), tunable in Settings",
            "Multiplexing can be switched off in Settings to fall back to one TLS connection per target",
        ],
    },
    Entry {
        version: "2.2.1",
        date: "2026-11-12",
        changes: &[
            "Installer: in-place upgrade over the previous version, reusing its install directory and uninstall entry",
            "Installer / EXE: embed app icon and version metadata, optional UPX compression",
            "Tray: fix Show Window and Exit menu items, menu labels follow the UI language",
            "Fix dark / light theme toggle in the title bar",
            "Update check: restore the update dialog and add an \"already up to date\" notice",
            "Build: reduce the executable size by ~42% (fat LTO, abort on panic, size-tuned dependencies)",
        ],
    },
    Entry {
        version: "2.1.6",
        date: "2026-08-04",
        changes: &["Add single-instance mutex: activate existing window when another instance is launched"],
    },
    Entry {
        version: "2.1.5",
        date: "2026-07-01",
        changes: &["GEO: integrated geo-loader-rs SDK, load country codes from country_codes.yaml"],
    },
    Entry {
        version: "2.1.4",
        date: "2026-06-17",
        changes: &["Rules: HOST rules now take priority over GEO rules"],
    },
    Entry {
        version: "2.1.3",
        date: "2026-06-12",
        changes: &[
            "Connections: add group close & optimize styles",
            "TestRule: add rule directly from test result",
            "Rules: optimize styles",
        ],
    },
    Entry {
        version: "2.1.2",
        date: "2026-06-12",
        changes: &[
            "Add quit app button on Dashboard page",
            "Add check for updates button on Dashboard",
            "Update GeoDB.dat geo IP database structure and improve query speed",
        ],
    },
    Entry {
        version: "2.1.1",
        date: "2026-06-11",
        changes: &["Update GeoDB.dat geo IP database"],
    },
    Entry {
        version: "2.1.0",
        date: "2026-06-11",
        changes: &[
            "TestRule: show the DNS server used for resolution (config.dns_servers or fallback)",
            "Fix trust-dns-resolver 0.23 API breakage: parse IP/SocketAddr, use add_name_server()",
            "i18n: add TEST_RESULT_DNS key in 5 languages",
        ],
    },
    Entry {
        version: "2.0.3",
        date: "2026-06-11",
        changes: &[
            "Config files switched from JSON to YAML format",
            "Build: copy resources/ files to output directory automatically",
            "Add imperative showAlert / showConfirm modal composable",
            "Add delete rule confirmation dialog",
            "Fix save_rule IPC parameter key mismatch",
            "Fix error pool check after first consent",
            "i18n: add DELETE_RULE_TITLE, DELETE_RULE_PROMPT, CONFIRM keys",
            "Modal: add backdrop click to close support",
        ],
    },
    Entry {
        version: "2.0.2",
        date: "2026-06-10",
        changes: &[
            "Add bind IPs support per-IP listener binding",
            "Add form validation for settings (ports, IPs, proxy)",
            "Add revert button for unsaved settings changes",
            "Add show/hide password toggle",
            "Add first-run consent modal with disclaimer",
            "Add changelog panel",
            "Dark mode via View Transition API",
            "Refactor Rust backend modules",
            "Simplify About page",
        ],
    },
    Entry {
        version: "2.0.1",
        date: "2026-05-20",
        changes: &[
            "Initial release",
            "SOCKS5 proxy with optional upstream proxy",
            "Geo-based direct/proxy routing rule engine",
            "Connection monitoring and management",
            "Real-time log viewer",
            "Multi-language support (EN / 中文 / 繁體中文 / 日本語 / 한국어)",
            "System tray integration",
            "Dark / light theme support",
        ],
    },
];

pub struct ChangelogPage;

impl ChangelogPage {
    pub fn new() -> Self {
        Self
    }
}

impl Render for ChangelogPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mut entries = v_flex().gap_6();

        for entry in CHANGELOG {
            let mut changes = v_flex().gap_1();
            for change in entry.changes {
                changes = changes.child(
                    div()
                        .text_sm()
                        .text_color(theme::text_muted(cx))
                        .child(format!("• {change}")),
                );
            }

            entries = entries.child(
                v_flex()
                    .gap_1()
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(cx.theme().primary)
                                    .child(format!("v{}", entry.version)),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme::text_muted(cx))
                                    .child(entry.date),
                            ),
                    )
                    .child(changes),
            );
        }

        v_flex()
            .size_full()
            .gap_4()
            .child(
                div()
                    .pr_6()
                    .text_size(px(20.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(i18n::t("CHANGELOG")),
            )
            .child(
                div()
                    .id("changelog-scroll")
                    .flex_1()
                    .min_h_0()
                    .pr_6()
                    .overflow_y_scrollbar()
                    .child(entries),
            )
    }
}

use gpui_kit::base::h_flex;
