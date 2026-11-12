# SSL Proxy

[English](#english) | [简体中文](#简体中文)

---

## English

A two-part Rust proxy suite: a Windows desktop client built with GPUI and a TLS proxy server, talking to each other over a private protocol.

- Client: `crates/gui` (package `ssl-proxy-gui`, installed as `ssl-proxy-client.exe`), current version **2.3.2**
- Server: `crates/svr` (`ssl-proxy-svr`), current version **1.2.0**

### Features

#### Client

- One listener auto-detects the protocol and serves SOCKS5 and HTTP / HTTPS (CONNECT) proxies
- Upstream over a TLS tunnel: HMAC-SHA256 authentication, frame padding against fingerprinting, optional multiplexing (mux)
- Rule routing: HOST / GEO rules first, then a fallback to the direct regions in `directs`
- GeoIP lookup (`assets/GeoDB.dat`)
- Dashboard, 7-day traffic statistics, connection list with group disconnect, live logs
- System tray, single instance (a second launch activates the existing window), dark / light theme, English / Chinese UI
- Online update check; saved settings apply after an automatic restart

#### Server

- One TLS port with protocol detection: private protocol → upstream forward, anything else → masquerade site
- Zero-config self-signed certificate, password authentication, rate limiting with blacklist, rotating logs
- Multiplexed sessions

### Layout

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

### Requirements

- Rust 1.85+ (edition 2024)
- Client: Windows 10 / 11; NSIS (`makensis`) to build the installer, UPX optional
- Server: Windows / Linux / macOS

### Build

```bash
# Whole workspace
cargo build --release --workspace

# Development
cargo run -p ssl-proxy-gui
cargo run -p ssl-proxy-svr -- --config crates/svr/config.example.yaml
```

During development the client falls back to `crates/gui/assets` when `GeoDB.dat` is not next to the executable.

### Packaging

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

### Client data directory

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

### Server configuration

The server loads YAML through `--config <FILE>` (kebab-case keys). Priority: **command line > YAML > built-in defaults**. See `crates/svr/config.example.yaml`.

- [Server README](crates/svr/README.md)
- [Architecture](crates/svr/docs/ARCHITECTURE.md)
- [Configuration reference](crates/svr/docs/CONFIGURATION.md)

### Versioning and updates

- `version` in `crates/gui/Cargo.toml` drives the exe metadata, installer name and the in-app version
- `crates/gui/version.json` is the online update manifest (`version` / `changelog` / `downloadUrl`); upload it to `https://hk.dishuyl.cn/ssl-proxy/version.json` when releasing
- The in-app changelog lives in `crates/gui/src/ui/pages/changelog.rs` and must be updated together with `version.json`

### More documentation

- Client refactor and architecture notes: [REFACTOR.md](crates/gui/REFACTOR.md)
- Client specs and checklists: `crates/gui/specs/`
- mux protocol spec: `.trae/specs/implement-mux-protocol/`

### License

MIT

---

## 简体中文

基于 Rust 的双端代理方案：一个 Windows 桌面客户端（GPUI）加一个 TLS 代理服务端，客户端与服务端通过私有协议通信。

- 客户端：`crates/gui`（包名 `ssl-proxy-gui`，安装后为 `ssl-proxy-client.exe`），当前版本 **2.3.2**
- 服务端：`crates/svr`（`ssl-proxy-svr`），当前版本 **1.2.0**

### 功能

#### 客户端

- 单端口协议自动识别，同时支持 SOCKS5 与 HTTP / HTTPS（CONNECT）代理
- 上游代理走 TLS 隧道：HMAC-SHA256 认证、帧填充抗指纹，可选多路复用（mux）
- 规则路由：HOST / GEO 规则优先，未命中时按 `directs` 直连地区回退
- GeoIP 地理识别（`assets/GeoDB.dat`）
- 运行概览、近 7 天流量统计、连接列表与按组断开、实时日志
- 系统托盘、单实例（重复启动唤起已有窗口）、深色 / 浅色主题、中英双语
- 在线检查更新，保存设置后自动重启生效

#### 服务端

- 单 TLS 端口按协议识别：私有协议 → 上游转发，其余流量 → 伪装站点
- 自签证书零配置启动，密码认证，限流与黑名单，日志自动轮转
- 支持多路复用会话

### 目录结构

```text
.
├─ crates/
│  ├─ gui/              Windows 客户端（GPUI + gpui-kit，安装包脚本、资源与规格文档）
│  └─ svr/              TLS 代理服务端（tokio + rustls）
├─ scripts/
│  ├─ build.ps1         一键构建 + 打包（Windows）
│  └─ build.sh          一键构建 + 打包（Linux / macOS 及 MSYS 委托 build.ps1）
├─ dist/                发布产物（client / server）
└─ Cargo.toml           workspace 与统一 release profile
```

### 环境要求

- Rust 1.85+（edition 2024）
- 客户端：Windows 10 / 11；打安装包需要 NSIS（`makensis`），UPX 可选
- 服务端：Windows / Linux / macOS

### 构建

```bash
# 整个 workspace
cargo build --release --workspace

# 开发运行
cargo run -p ssl-proxy-gui
cargo run -p ssl-proxy-svr -- --config crates/svr/config.example.yaml
```

客户端开发期若可执行文件旁没有 `GeoDB.dat`，会自动回退到 `crates/gui/assets`。

### 打包

Windows：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
# 只打客户端 / 只打服务端 / 跳过 UPX
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipServer
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipClient
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -NoUpx
```

Linux / macOS：

```bash
./scripts/build.sh   # GUI 仅支持 Windows，此时只构建服务端
```

产物：

- `dist/client/SSLProxyClient_<gui版本>_x64-setup.exe`
- `dist/server/ssl-proxy-svr-<平台>-<svr版本>.zip`

安装包会覆盖升级旧版本：复用注册表中的安装目录，停止正在运行的 `ssl-proxy-client.exe` 后原地替换。

### 客户端数据目录

默认 `%USERPROFILE%\ssl-proxy-client`（与旧版 Tauri 客户端共用）：

| 文件 | 说明 |
| --- | --- |
| `setting.yaml` | 代理、TLS/SNI、绑定地址、DNS、直连地区、mux 开关（camelCase） |
| `rules.yaml` | HOST / GEO 路由规则 |
| `consent.dat` | 首次使用免责声明确认标记 |
| `app.log` | 运行日志 |
| `stats.json` | 流量统计 |
| `ui.json` | 语言与主题偏好 |

调试用环境变量：

- `SSL_PROXY_GUI_CONFIG_DIR`：覆盖数据目录
- `SSL_PROXY_GUI_MULTI_INSTANCE`：跳过单实例互斥体，便于并行调试
- `SSL_PROXY_GUI_RELAUNCH`：由「保存并重启」自动设置，新进程据此等待旧进程释放互斥体

### 服务端配置

服务端通过 `--config <FILE>` 加载 YAML（字段 kebab-case），优先级：**命令行参数 > YAML > 内置默认值**。示例见 `crates/svr/config.example.yaml`。

- [服务端说明](crates/svr/README.md)
- [架构设计](crates/svr/docs/ARCHITECTURE.md)
- [配置项说明](crates/svr/docs/CONFIGURATION.md)

### 版本与更新

- `crates/gui/Cargo.toml` 的 `version` 同时决定 exe 元数据、安装包命名与应用内版本号
- `crates/gui/version.json` 是在线更新清单（`version` / `changelog` / `downloadUrl`），发版时需上传到 `https://hk.dishuyl.cn/ssl-proxy/version.json`
- 应用内「更新日志」页面由 `crates/gui/src/ui/pages/changelog.rs` 维护，发版时与 `version.json` 同步补充

### 更多文档

- 客户端重构与架构笔记：[REFACTOR.md](crates/gui/REFACTOR.md)
- 客户端规格与验收清单：`crates/gui/specs/`
- mux 协议实现规格：`.trae/specs/implement-mux-protocol/`

### License

MIT
