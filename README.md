# SSL Proxy

[English](README.md) | [简体中文](README.zh-CN.md)

A two-part Rust proxy suite: a Windows desktop client built with GPUI and a TLS proxy server, communicating over a private protocol.

- Client: `crates/gui` (package `ssl-proxy-gui`, installed as `ssl-proxy-client.exe`) — current version **2.3.2**
- Server: `crates/svr` (`ssl-proxy-svr`) — current version **1.2.0**
- License: [MIT](LICENSE)

## Features

### Client

- One listener auto-detects the protocol and serves SOCKS5 and HTTP / HTTPS (CONNECT) proxies
- Upstream over a TLS tunnel: HMAC-SHA256 authentication, frame padding against fingerprinting, optional multiplexing (mux)
- Rule routing: HOST / GEO rules first, then a fallback to the direct regions in `directs`
- GeoIP lookup (`assets/GeoDB.dat`)
- Dashboard, 7-day traffic statistics, connection list with group disconnect, live logs
- System tray, single instance (a second launch activates the existing window), dark / light theme, English / Chinese UI
- Online update check; saved settings apply after an automatic restart

### Server

- One TLS port with protocol detection: private protocol → upstream forward, anything else → masquerade site
- Zero-config self-signed certificate, password authentication, rate limiting with blacklist, rotating logs
- Multiplexed sessions

## Quick start

### 1. Install the client

Run `SSLProxyClient_2.3.2_x64-setup.exe` (from `dist/client` or the download URL in `version.json`). It installs to `%LOCALAPPDATA%\SSLProxyClient`, ships `GeoDB.dat` next to the executable and upgrades older versions in place. Accept the first-run disclaimer.

### 2. Point applications at the local proxy

The client listens on `127.0.0.1:1080` by default and accepts SOCKS5, HTTP and HTTPS (CONNECT) on the same port. Configure it as the proxy in your browser, system settings or individual apps.

### 3. Configure the upstream

Open **Settings** and fill in the proxy server address, port and password (it must match the server). The same page holds SNI, TLS verification, bind addresses, DNS servers, direct regions and the mux switch. Leaving the proxy server empty runs the client in direct mode. **Save** restarts the app automatically.

### 4. Start the server

```bash
ssl-proxy-svr --config ./config.yaml
```

The default listen address is `0.0.0.0:1888`. When no certificate is configured, a self-signed one is generated at startup.

## How it works

```text
App ──▶ 127.0.0.1:1080 (SOCKS5 / HTTP / HTTPS)
          │ protocol sniff on the first byte
          ├─ rule match (HOST / GEO) ──▶ direct connection
          └─ TLS tunnel ──▶ ssl-proxy-svr ──▶ target
```

- Client: the first byte decides SOCKS5 vs HTTP; HOST / GEO rules (then `directs`) decide direct vs proxied. Proxied traffic is framed inside TLS with HMAC-SHA256 authentication, length padding and optional multiplexing.
- Server: one TLS port; authenticated private-protocol traffic is forwarded (optionally multiplexed), everything else is served by the masquerade site.

See [crates/svr/docs/ARCHITECTURE.md](crates/svr/docs/ARCHITECTURE.md) for the protocol and frame layout.

## Layout

```text
.
├─ crates/
│  ├─ gui/              Windows client (GPUI + gpui-kit, installer script, assets and specs)
│  └─ svr/              TLS proxy server (tokio + rustls)
├─ scripts/
│  ├─ build.ps1         One-step build + packaging (Windows)
│  └─ build.sh          One-step build + packaging (Linux / macOS; MSYS delegates to build.ps1)
├─ dist/                Release artifacts (client / server)
└─ Cargo.toml           Workspace and shared release profile
```

## Requirements

- Rust 1.85+ (edition 2024)
- Client: Windows 10 / 11 (the GPUI client is Windows-only)
- Packaging: NSIS (`makensis`); UPX optional
- Server: Windows / Linux / macOS

## Build

```bash
# Whole workspace
cargo build --release --workspace

# Development
cargo run -p ssl-proxy-gui
cargo run -p ssl-proxy-svr -- --config crates/svr/config.example.yaml
```

During development the client falls back to `crates/gui/assets` when `GeoDB.dat` is not next to the executable.

## Tests

```bash
cargo test -p ssl-proxy-gui
cargo test -p ssl-proxy-svr
```

## Packaging

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
# Client only / server only / skip UPX
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipServer
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipClient
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -NoUpx
```

Linux / macOS:

```bash
./scripts/build.sh   # The GUI is Windows-only, so only the server is built here
```

Artifacts:

- `dist/client/SSLProxyClient_<gui-version>_x64-setup.exe`
- `dist/server/ssl-proxy-svr-<platform>-<svr-version>.zip` (binary, `config.yaml`, `certs/`, `logs/`)

The installer upgrades in place: it reuses the install directory from the registry and stops a running `ssl-proxy-client.exe` before replacing files.

## Client data directory

Defaults to `%USERPROFILE%\ssl-proxy-client` (shared with the legacy Tauri client):

| File | Purpose |
| --- | --- |
| `setting.yaml` | Proxy, TLS/SNI, bind addresses, DNS, direct regions, mux switch (camelCase) |
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

tls:
  cert: "./certs/server.crt"         # optional; self-signed when omitted
  key: "./certs/server.key"

static-sources:
  html: "./html"                     # masquerade site, 404 when missing

rate-limit:
  max-requests: 300
  rate-time-secs: 60
  black-time-secs: 600
```

- [Architecture](crates/svr/docs/ARCHITECTURE.md)
- [Configuration reference](crates/svr/docs/CONFIGURATION.md)

## Troubleshooting

- **Port already in use (10048)**: change the local port in Settings, or stop the process occupying it.
- **`GeoDB.dat` not found**: keep it next to the executable; the installer ships it, and development builds fall back to `crates/gui/assets`.
- **Mux connections fail**: turn mux off in Settings when the server runs with `mux: false`, or when a middlebox drops long-lived tunnels.
- **Update check fails**: the client needs access to `https://hk.dishuyl.cn/ssl-proxy/version.json`.
- **Settings not applied**: settings take effect after the automatic restart; if the restart fails, start the client again manually.

## Versioning and updates

- `version` in `crates/gui/Cargo.toml` drives the exe metadata, installer name and the in-app version
- `crates/gui/version.json` is the online update manifest (`version` / `changelog` / `downloadUrl`); upload it to `https://hk.dishuyl.cn/ssl-proxy/version.json` when releasing
- The in-app changelog lives in `crates/gui/src/ui/pages/changelog.rs` and must be updated together with `version.json`

## More documentation

- Client specs and checklists: `crates/gui/specs/gpui-refactor/`

## Contributing

Issues and pull requests are welcome. Keep `Cargo.toml`, `version.json` and the in-app changelog in sync, and run `cargo test` before opening a PR.

## License

[MIT](LICENSE)
