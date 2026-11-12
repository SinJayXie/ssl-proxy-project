# SSL Proxy

[English](README.md) | [简体中文](README.zh-CN.md)

A two-part Rust proxy suite: a Windows desktop client built with GPUI and a TLS proxy server, talking to each other over a private protocol.

- Client: `crates/gui` (package `ssl-proxy-gui`, installed as `ssl-proxy-client.exe`), current version **2.3.2**
- Server: `crates/svr` (`ssl-proxy-svr`), current version **1.2.0**

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
- Client: Windows 10 / 11; NSIS (`makensis`) to build the installer, UPX optional
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
- `dist/server/ssl-proxy-svr-<platform>-<svr-version>.zip`

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

The server loads YAML through `--config <FILE>` (kebab-case keys). Priority: **command line > YAML > built-in defaults**. See `crates/svr/config.example.yaml`.

- [Server README](crates/svr/README.md)
- [Architecture](crates/svr/docs/ARCHITECTURE.md)
- [Configuration reference](crates/svr/docs/CONFIGURATION.md)

## Versioning and updates

- `version` in `crates/gui/Cargo.toml` drives the exe metadata, installer name and the in-app version
- `crates/gui/version.json` is the online update manifest (`version` / `changelog` / `downloadUrl`); upload it to `https://hk.dishuyl.cn/ssl-proxy/version.json` when releasing
- The in-app changelog lives in `crates/gui/src/ui/pages/changelog.rs` and must be updated together with `version.json`

## More documentation

- Client refactor and architecture notes: [REFACTOR.md](crates/gui/REFACTOR.md)
- Client specs and checklists: `crates/gui/specs/`
- mux protocol spec: `.trae/specs/implement-mux-protocol/`

## License

MIT
