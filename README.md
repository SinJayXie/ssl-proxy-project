# SSL Proxy

[English](README.md) | [简体中文](README.zh-CN.md)

![Rust](https://img.shields.io/badge/Rust-1.85%2B%20%C2%B7%20edition%202024-000000)
![License](https://img.shields.io/badge/license-MIT-blue)
![Client](https://img.shields.io/badge/client-Windows%2010%2F11-0078D4)
![Server](https://img.shields.io/badge/server-Windows%20%7C%20Linux%20%7C%20macOS-555)

A two-part Rust proxy suite: a native Windows desktop client built with GPUI and a TLS proxy server, talking to each other over a private protocol that is designed to look like ordinary HTTPS traffic.

- Client: `crates/gui` (package `ssl-proxy-gui`, installed as `ssl-proxy-client.exe`) — version **2.5.2**
- Server: `crates/svr` (`ssl-proxy-svr`) — version **1.5.1**
- Update signer: `crates/update-signer` — Ed25519 manifest signing tool
- License: [MIT](LICENSE)

## Table of contents

- [Highlights](#highlights)
- [Features](#features)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Project layout](#project-layout)
- [Requirements](#requirements)
- [Build](#build)
- [Tests](#tests)
- [Packaging](#packaging)
- [Client data directory](#client-data-directory)
- [Server configuration](#server-configuration)
- [Update pipeline and signing](#update-pipeline-and-signing)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Highlights

- **One local port, three protocols.** SOCKS5 and HTTP / HTTPS (CONNECT) are detected from the first byte on the same port, so a single `127.0.0.1:1080` entry works for browsers, shells and apps.
- **One remote TLS port that looks like a website.** The server serves a masquerade static site (or reverse-proxies a real one) to anything that fails authentication.
- **Private protocol v3.** HMAC-SHA256 authentication, per-handshake nonce with a server-side replay cache, mutual tunnel acknowledgement, frame padding and optional multiplexing.
- **Native desktop client.** GPUI + gpui-kit UI with dashboard, interactive 7-day traffic chart, connection list, rule editor, rule tester, live logs, tray integration and instant theme / language switching.
- **Verified updates.** Installers are checked against SHA-256 **and** an Ed25519 signature before they are allowed to run; downgrades and non-HTTPS manifests are rejected.
- **UDP relay.** Optional SOCKS5 UDP ASSOCIATE with `off` / `direct` / `proxy` modes; the server side is opt-in and rate-limited.

## Features

### Client

**Local proxy**

- SOCKS5 (including IPv6 targets and UDP ASSOCIATE) and HTTP / HTTPS CONNECT on one listener
- HTTP request bodies, keep-alive connections and WebSocket upgrades are forwarded correctly
- Direct connections honour half-close, so one-way protocols keep receiving data
- DNS: custom resolvers, with a fallback to the tunnel when the local lookup fails

**Tunnel and anti-fingerprinting**

- HMAC-SHA256 authentication with timestamp validation and mutual acknowledgement
- Protocol v3 handshake nonce plus a server-side replay cache
- Browser-like ALPN (`h2`, `http/1.1`) and padding of the first TLS records, so a handshake no longer starts with an unusually small packet
- Frame padding masks TLS-in-TLS record lengths
- Optional multiplexing (mux) sharing one TLS tunnel, with a per-stream 256 KB flow-control window and automatic retry of stale tunnels

**Routing**

- HOST and GEO rules, evaluated before the `directs` region fallback
- Rule editor with HOST / GEO groups, plus a rule tester that shows DNS resolution, GeoIP country and the matching mode
- GeoIP database `assets/GeoDB.dat` (shipped next to the executable by the installer)

**UDP**

- `off` — UDP is rejected entirely (UDP ASSOCIATE replies *command not supported*)
- `direct` — every datagram goes out locally, even if a proxy rule matches
- `proxy` — follows the rule chain; requires `udp.enabled: true` on the server and matching versions (capability negotiation falls back to direct with a log warning)

**UI**

| Page | What it shows |
| --- | --- |
| Dashboard | Connection count, live throughput, 7-day interactive bar chart with hover details and totals, update check |
| Connections | Connection groups with TCP / UDP transport badges, PROXY / DIRECT mode, GeoIP, latency, per-group traffic and disconnect |
| Logs | Live log stream |
| Rules | HOST / GEO rule groups, add / edit / delete |
| Rule tester | Target host and port → resolved IP, DNS server, GeoIP country, matched rule and final mode with elapsed time |
| Settings | Proxy server, port, password, SNI, certificate verification, bind IPs, DNS servers, direct regions, mux, UDP mode; **Save** restarts the app automatically |
| Changelog / About | In-app changelog and version information |

**Desktop integration**

- System tray (show window / exit) with labels following the UI language
- Single instance: launching again activates the existing window
- Dark / light theme and English / Chinese UI, persisted in `ui.json`
- First-run disclaimer stored in `consent.dat`
- Update check on demand and hourly, with a mandatory prompt for new versions

### Server

- One TLS port with protocol detection: authenticated private protocol → upstream forward, everything else → masquerade site
- Optional real-site reverse proxy (`static-sources.fallback-url`) with HTTP/1.1, HTTP/2 and TLS session resumption
- Protocol v3 replay protection and per-IP rate limiting of repeated authentication failures (normal HTTP visitors are not counted)
- Multiplexed sessions with stream cleanup on disconnect and idle session expiry
- Opt-in UDP relay (`udp.enabled`) with per-session token-bucket rate limiting and idle timeouts
- SSRF guard for TCP and UDP targets: loopback, private, link-local, cloud metadata, NAT64, 6to4, Teredo, site-local and IPv4-compatible IPv6 addresses are rejected unless `allow-private-targets: true`
- Zero-config self-signed certificate (SAN `localhost`, `127.0.0.1`) when no certificate is configured
- Rate limiting with blacklist, rotating size-capped logs, graceful shutdown on Ctrl+C / SIGTERM

## Quick start

### 1. Install the client

Run `SSLProxyClient_2.5.2_x64-setup.exe` (from `dist/client`, or the download URL in `version.json`). It installs to `%LOCALAPPDATA%\SSLProxyClient`, ships `GeoDB.dat` next to the executable and upgrades older versions in place. Accept the first-run disclaimer.

### 2. Point applications at the local proxy

The client listens on `127.0.0.1:1080` by default and accepts SOCKS5, HTTP and HTTPS (CONNECT) on the same port. Configure it as the proxy in your browser, system settings or individual apps.

### 3. Configure the upstream

Open **Settings** and fill in the proxy server address, port and password (it must match the server). The same page holds SNI, TLS verification, bind addresses, DNS servers, direct regions, mux and UDP mode. Leaving the proxy server empty runs the client in direct mode. **Save** restarts the app automatically.

### 4. Start the server

```bash
ssl-proxy-svr --config ./config.yaml
```

The default listen address is `0.0.0.0:1888`. When no certificate is configured, a self-signed one is generated at startup.

A minimal `config.yaml`:

```yaml
server:
  listen: "0.0.0.0"
  port: 1888
  password: "your-strong-password"   # must match the client's proxy password
  mux: true
  allow-private-targets: false

static-sources:
  html: "./html"
```

## How it works

```text
App ──▶ 127.0.0.1:1080 (SOCKS5 / HTTP / HTTPS CONNECT / UDP ASSOCIATE)
          │ first byte decides SOCKS5 vs HTTP
          ├─ rule match (HOST / GEO, then directs) ──▶ direct connection
          └─ TLS tunnel ──▶ ssl-proxy-svr ──▶ target
                             │
                             ├─ authenticated private protocol → forward (TCP / mux / UDP)
                             └─ anything else → masquerade site or real-site fallback
```

- **Client:** the first byte decides SOCKS5 vs HTTP; HOST / GEO rules (then `directs`) decide direct vs proxied. Proxied traffic is framed inside TLS with HMAC-SHA256 authentication, length padding and optional multiplexing. UDP datagrams use separate frames, with per-target session reuse and capability negotiation.
- **Server:** one TLS port. Authenticated private-protocol traffic is forwarded (optionally multiplexed, optionally carrying UDP frames); everything else is served by the masquerade site, or reverse-proxied to `fallback-url`.

See [crates/svr/docs/ARCHITECTURE.md](crates/svr/docs/ARCHITECTURE.md) for the handshake, frame layout and mux design.

## Project layout

```text
.
├─ crates/
│  ├─ gui/                  Windows client (GPUI + gpui-kit)
│  │  ├─ src/core/          proxy core, geo, stats, state, tun (design stub)
│  │  ├─ src/ui/            shell, pages, components, theme, i18n
│  │  ├─ src/platform/      tray, single instance, logging, paths
│  │  ├─ installer/         NSIS installer script
│  │  ├─ assets/            GeoDB.dat, icons, i18n, update public key, wintun
│  │  └─ specs/             client specs and checklists
│  ├─ svr/                  TLS proxy server (tokio + rustls + hyper)
│  │  ├─ src/services/      socket / forward / proxy / mux / UDP / fallback / static
│  │  ├─ src/libs/          rate limit, replay guard
│  │  ├─ src/utils/         protocol frames, SSRF checks
│  │  ├─ tests/e2e.rs       end-to-end tests
│  │  └─ docs/              architecture and configuration reference
│  └─ update-signer/        Ed25519 signing / verification tool for releases
├─ docs/                    design notes (UDP, TUN)
├─ scripts/
│  ├─ build.ps1             One-step build + packaging (Windows)
│  ├─ build.sh              One-step build + packaging (Linux / macOS; MSYS delegates to build.ps1)
│  └─ build-svr-musl.sh     Static Linux (musl) server build inside WSL
├─ dist/                    Release artifacts (client / server)
└─ Cargo.toml               Workspace and shared release profile
```

## Requirements

- Rust 1.85+ (edition 2024)
- Client: Windows 10 / 11 (the GPUI client is Windows-only)
- Packaging: NSIS (`makensis`); UPX optional
- Server: Windows / Linux / macOS; `x86_64-unknown-linux-musl` toolchain + `musl-gcc` for static Linux builds

## Build

```bash
# Whole workspace
cargo build --release --workspace

# Development
cargo run -p ssl-proxy-gui
cargo run -p ssl-proxy-svr -- --config crates/svr/config.example.yaml
```

During development the client falls back to `crates/gui/assets` when `GeoDB.dat` is not next to the executable.

Release profile notes (`Cargo.toml`): fat LTO, `codegen-units = 1`, `panic = "abort"`, stripped binaries, and `-Os` for cold-path dependencies (image / regex / YAML codecs). In debug builds the GPUI / gpui-kit crates are compiled with `opt-level = 3` to avoid UI stutter.

## Tests

```bash
cargo test -p ssl-proxy-gui    # unit tests, including update signature verification
cargo test -p ssl-proxy-svr    # unit tests plus crates/svr/tests/e2e.rs
```

The server end-to-end suite covers handshake and authentication, masquerade / fallback behaviour, mux, UDP relay, SSRF blocking and rate limiting.

## Packaging

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
# Client only / server only / skip UPX
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipServer
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipClient
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -NoUpx
# Override the download URL prefix written to version.json
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -DownloadBase "https://example.com/ssl-proxy/win"
```

Linux / macOS:

```bash
./scripts/build.sh   # The GUI is Windows-only, so only the server is built here
```

Static Linux server (from WSL):

```bash
wsl -d Ubuntu-22.04 -e bash /mnt/e/myProjects/ssl-proxy-project/scripts/build-svr-musl.sh
```

Artifacts:

- `dist/client/SSLProxyClient_<gui-version>_x64-setup.exe` (also rewrites `version.json` with the new SHA-256 and Ed25519 signature)
- `dist/server/ssl-proxy-svr-<platform>-<svr-version>.zip` (binary, `config.yaml`, `certs/`, `logs/`)
- `dist/server/ssl-proxy-svr-linux-musl-<svr-version>.tar.gz` (static Linux build)

The installer upgrades in place: it reuses the install directory from the registry and stops a running `ssl-proxy-client.exe` before replacing files.

## Client data directory

Defaults to `%USERPROFILE%\ssl-proxy-client` (shared with the legacy Tauri client):

| File | Purpose |
| --- | --- |
| `setting.yaml` | Proxy, TLS/SNI, bind addresses, DNS, direct regions, mux, UDP mode (camelCase) |
| `rules.yaml` | HOST / GEO routing rules |
| `consent.dat` | First-run disclaimer acknowledgement |
| `app.log` | Runtime log |
| `stats.json` | Traffic statistics |
| `ui.json` | Language and theme preferences |

Debug environment variables:

- `SSL_PROXY_GUI_CONFIG_DIR`: override the data directory
- `SSL_PROXY_GUI_MULTI_INSTANCE`: skip the single-instance mutex for parallel debugging
- `SSL_PROXY_GUI_RELAUNCH`: set automatically by "Save and restart"; the new process waits for the previous one to release the mutex

## Server configuration

The server loads YAML through `--config <FILE>` (kebab-case keys). Priority: **command line > YAML > built-in defaults**.

```yaml
server:
  listen: "0.0.0.0"
  port: 1888
  password: "your-strong-password"   # must match the client's proxy password
  mux: true                          # false rejects multiplexed sessions
  allow-private-targets: false       # SSRF guard: loopback/private targets are rejected by default

tls:
  cert: "./certs/server.crt"         # optional; self-signed when omitted
  key: "./certs/server.key"
  sni: "example.com"                 # SAN for the generated self-signed cert

static-sources:
  html: "./html"                     # masquerade site, 404 when missing
  index: "index.html"
  # fallback-url: "https://example.com"  # reverse-proxy a real site and enable HTTP/2

log:
  dir: "./logs"
  level: "info"                      # trace | debug | info | warn | error
  max-size: 5242880                  # bytes per file before rotation

rate-limit:
  max-requests: 300
  rate-time-secs: 60
  black-time-secs: 600

udp:
  enabled: false                     # UDP relay is opt-in
  timeout-secs: 60                   # idle timeout per UDP session
  rate-limit: 100                    # datagrams per second per session
```

Common command-line flags (they override the YAML values):

| Flag | Description |
| --- | --- |
| `-c, --config <FILE>` | YAML configuration file |
| `-l, --listen <ADDR>` | Listen address, default `0.0.0.0` |
| `-p, --port <PORT>` | Listen port, default `1888` |
| `--pwd <PWD>` | Password; a random one is generated when omitted |
| `--no-mux` | Reject multiplexed sessions |
| `--allow-private-targets` | Allow loopback / private targets (TCP and UDP) |
| `--cert` / `--key` | PEM certificate and PKCS#8 private key |
| `--sni <NAME>` | SAN for the generated self-signed certificate |
| `--html <DIR>` | Static masquerade site root |
| `--fallback-url <URL>` | Reverse-proxy an unauthenticated probe to a real site |
| `--log-dir` / `--log-level` | Rotating log directory and level |

- [Architecture](crates/svr/docs/ARCHITECTURE.md)
- [Configuration reference](crates/svr/docs/CONFIGURATION.md)

## Update pipeline and signing

1. `scripts/build.ps1` builds the workspace, packages the NSIS installer and computes its SHA-256.
2. The installer is signed with Ed25519 by `crates/update-signer` (`sign <key> <file>`), using `.secrets/update-signing-key.der` or the path in `SSL_PROXY_UPDATE_KEY`.
3. `version.json` in the project root is rewritten with `version`, `changelog`, `downloadUrl`, `sha256` and `signature` (UTF-8 without BOM).
4. Upload `version.json` and the installer to `https://hk.dishuyl.cn/ssl-proxy/`.

The client embeds the matching public key (`crates/gui/assets/update_pubkey.hex`) and refuses installers whose hash or signature does not verify, as well as downgrades or manifests served over plain HTTP. `scripts/build.ps1` fails early when the private key is missing, because new clients would reject the result.

Version sources:

- `version` in `crates/gui/Cargo.toml` drives the exe metadata, installer name and the in-app version
- `version` in `crates/svr/Cargo.toml` drives the server archive name
- The in-app changelog lives in `crates/gui/src/ui/pages/changelog.rs` and must be updated together with `version.json`

## Security notes

- **Authentication:** HMAC-SHA256 over the password, timestamp window and mutual tunnel ACK; protocol v3 adds a random nonce and a replay cache. Repeated failures are rate-limited per IP.
- **Blast radius:** the server rejects SSRF targets (loopback, private, link-local, cloud metadata and their IPv6 translations) unless explicitly enabled. The real-site fallback caps request bodies at 8 MB, including chunked uploads.
- **Traffic shape:** ALPN, first-record padding and per-frame padding reduce TLS-in-TLS fingerprints; the masquerade site answers probes that do not authenticate.
- **Updates:** SHA-256 + Ed25519 signature verification, HTTPS-only manifest URL, downgrade rejection, mandatory prompt.
- **Secrets:** `setting.yaml` stores the proxy password in plain text in the user profile; the signing key lives in `.secrets/` and must never be committed.

## Troubleshooting

- **Port already in use (10048)**: change the local port in Settings, or stop the process occupying it.
- **`GeoDB.dat` not found**: keep it next to the executable; the installer ships it, and development builds fall back to `crates/gui/assets`.
- **Mux connections fail**: turn mux off in Settings when the server runs with `mux: false`, or when a middlebox drops long-lived tunnels.
- **Update check fails**: the client needs access to `https://hk.dishuyl.cn/ssl-proxy/version.json`.
- **Update refused**: the package failed SHA-256 / signature verification, is a downgrade, or the manifest was not served over HTTPS. Rebuild and re-sign rather than bypassing the check.
- **Settings not applied**: settings take effect after the automatic restart; if the restart fails, start the client again manually.
- **UDP forwarding not working**: enable `udp.enabled: true` on the server and select `proxy` mode; old servers or disabled UDP fall back to direct with a log warning.
- **Private targets rejected**: the default SSRF guard blocks loopback / private destinations; use `allow-private-targets: true` only for intentional intranet proxying.
- **Fallback site shows an error**: check that `fallback-url` is reachable from the server and uses HTTPS.

## Documentation

| Document | Content |
| --- | --- |
| [crates/svr/docs/ARCHITECTURE.md](crates/svr/docs/ARCHITECTURE.md) | Service layout, request flow, protocol v3 handshake, framing, mux |
| [crates/svr/docs/CONFIGURATION.md](crates/svr/docs/CONFIGURATION.md) | Every configuration key, merge priority and defaults |
| [docs/udp-design.md](docs/udp-design.md) | UDP relay design: frames, sessions, negotiation and fallbacks |
| [docs/tun-design.md](docs/tun-design.md) | Windows TUN research (design study, not implemented) |
| `crates/gui/specs/gpui-refactor/` | Client specs and acceptance checklists |

## Roadmap

- TUN mode on Windows (Wintun + auto-route + fake-IP DNS) — design study only, see [docs/tun-design.md](docs/tun-design.md)
- Further UDP session reuse and diagnostics

## Contributing

Issues and pull requests are welcome. Keep `Cargo.toml`, `version.json` and the in-app changelog in sync, and run `cargo test` before opening a PR. UI changes should follow the existing GPUI page structure (`crates/gui/src/ui/pages`) and use gpui-kit components where possible.

## License

[MIT](LICENSE)
