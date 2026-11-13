# SSL Proxy

[English](README.md) | [简体中文](README.zh-CN.md)

![Rust](https://img.shields.io/badge/Rust-1.85%2B%20%C2%B7%20edition%202024-000000)
![License](https://img.shields.io/badge/license-MIT-blue)
![Client](https://img.shields.io/badge/client-Windows%2010%2F11-0078D4)
![Server](https://img.shields.io/badge/server-Windows%20%7C%20Linux%20%7C%20macOS-555)

基于 Rust 的双端代理方案：一个原生 Windows 桌面客户端（GPUI）加一个 TLS 代理服务端，两者通过私有协议通信，对外表现得和普通 HTTPS 流量一致。

- 客户端：`crates/gui`（包名 `ssl-proxy-gui`，安装后为 `ssl-proxy-client.exe`），版本 **2.5.2**
- 服务端：`crates/svr`（`ssl-proxy-svr`），版本 **1.5.1**
- 更新签名工具：`crates/update-signer`，负责发布清单的 Ed25519 签名
- 许可证：[MIT](LICENSE)

## 目录

- [核心亮点](#核心亮点)
- [功能](#功能)
- [快速开始](#快速开始)
- [工作原理](#工作原理)
- [目录结构](#目录结构)
- [环境要求](#环境要求)
- [构建](#构建)
- [测试](#测试)
- [打包](#打包)
- [客户端数据目录](#客户端数据目录)
- [服务端配置](#服务端配置)
- [发布与签名流程](#发布与签名流程)
- [安全设计](#安全设计)
- [常见问题](#常见问题)
- [文档](#文档)
- [后续规划](#后续规划)
- [贡献](#贡献)
- [License](#license)

## 核心亮点

- **本地单端口三协议**：同一端口按首字节识别 SOCKS5 与 HTTP / HTTPS（CONNECT），浏览器、终端和各类应用共用一个 `127.0.0.1:1080`。
- **远端单端口像网站**：认证失败的流量由伪装站点（或真实站点反代）应答，不做代理时端口看起来就是个 HTTPS 网站。
- **私有协议 v3**：HMAC-SHA256 认证、每次握手随机 nonce 配合服务端重放缓存、隧道双向确认、帧填充与可选多路复用。
- **原生桌面客户端**：GPUI + gpui-kit，运行概览、7 天交互式流量图、连接列表、规则编辑、规则测试器、实时日志、系统托盘，主题与语言即时切换。
- **安全更新**：安装包在运行前同时校验 SHA-256 与 Ed25519 签名，拒绝降级包与非 HTTPS 清单。
- **UDP 转发**：SOCKS5 UDP ASSOCIATE 支持 `off` / `direct` / `proxy` 三种模式，服务端默认关闭、按会话限速。

## 功能

### 客户端

**本地代理**

- 单端口同时支持 SOCKS5（含 IPv6 目标与 UDP ASSOCIATE）与 HTTP / HTTPS CONNECT
- 正确转发 HTTP 请求体、keep-alive 连接与 WebSocket 升级
- 直连连接支持半关闭，单向 shutdown 的协议仍能继续收数据
- DNS 可自定义解析服务器；本地解析失败时自动回退到隧道

**隧道与抗指纹**

- HMAC-SHA256 认证 + 时间戳校验 + 隧道双向确认
- 协议 v3 在每次握手中携带随机 nonce，服务端维护重放缓存
- 浏览器式 ALPN（`h2`、`http/1.1`）与首条 TLS record 填充，握手不再呈现异常小包特征
- 帧级填充掩盖 TLS-in-TLS 的 record 长度
- 可选多路复用（mux），共享一条 TLS 隧道；每流 256 KB 流控窗口，陈旧隧道自动重连重试

**路由**

- HOST / GEO 规则优先，未命中时按 `directs` 直连地区回退
- 规则编辑器按 HOST / GEO 分组，并可增删改
- 规则测试器展示目标域名解析出的 IP、DNS 服务器、GeoIP 国家、命中规则、最终模式与耗时
- GeoIP 数据库 `assets/GeoDB.dat`（安装包会放到 exe 同目录）

**UDP**

- `off`：完全不转发 UDP，SOCKS5 UDP ASSOCIATE 回复「命令不支持」
- `direct`：所有 UDP 一律本机直连，命中代理规则也强制直连
- `proxy`：按规则链决定直连或经隧道转发；需要服务端 `udp.enabled: true` 且两端版本配套（通过能力字节协商，旧服务端自动降级为直连并写日志）

**界面**

| 页面 | 内容 |
| --- | --- |
| 运行概览 | 连接数、实时速率、7 天交互式柱状图（悬停查看上下行与总量）、版本更新检查 |
| 连接列表 | 按连接分组展示 TCP / UDP 传输标记、PROXY / DIRECT 模式、GeoIP、延迟、分组流量，并支持按组断开 |
| 日志 | 实时日志流 |
| 规则 | HOST / GEO 规则分组，新增 / 编辑 / 删除 |
| 规则测试 | 输入目标与端口，输出解析 IP、DNS、GeoIP 国家、命中规则与最终模式 |
| 系统设置 | 代理地址、端口、认证密钥、SNI、证书校验、绑定地址、DNS、直连地区、mux、UDP 模式；**保存**后自动重启生效 |
| 更新日志 / 关于 | 应用内更新日志与版本信息 |

**桌面集成**

- 系统托盘（显示窗口 / 退出），菜单文案跟随界面语言
- 单实例：重复启动会唤起已有窗口
- 深色 / 浅色主题、中英双语，偏好持久化在 `ui.json`
- 首次启动的免责声明确认记录在 `consent.dat`
- 更新检查支持手动触发与每小时轮询，新版本提示为强制弹窗

### 服务端

- 单 TLS 端口按协议识别：通过认证的私有协议 → 上游转发，其余流量 → 伪装站点
- 可选真实站点回落（`static-sources.fallback-url`），支持 HTTP/1.1、HTTP/2 与 TLS session resumption
- 协议 v3 重放防护；同一 IP 反复认证失败会触发限流，正常 HTTP 访问不计入
- 多路复用会话，断开时清理流，空闲会话自动回收
- UDP relay 默认关闭，开启后每会话令牌桶限速并有空闲超时
- TCP / UDP 共用 SSRF 防护：默认拒绝回环、内网、链路本地、云元数据以及 NAT64、6to4、Teredo、site-local、IPv4-compatible IPv6 目标（`allow-private-targets: true` 可放开）
- 未配置证书时零配置生成自签证书（SAN `localhost`、`127.0.0.1`）
- 限流与黑名单、按大小自动轮转日志、Ctrl+C / SIGTERM 优雅关闭

## 快速开始

### 1. 安装客户端

运行 `SSLProxyClient_2.5.2_x64-setup.exe`（来自 `dist/client`，或 `version.json` 中的下载地址）。安装到 `%LOCALAPPDATA%\SSLProxyClient`，`GeoDB.dat` 会放在 exe 同目录，旧版本原地覆盖升级。首次启动需确认免责声明。

### 2. 让应用走本地代理

客户端默认监听 `127.0.0.1:1080`，同一端口同时支持 SOCKS5、HTTP 与 HTTPS（CONNECT）。在浏览器、系统设置或单个应用中把它配置为代理即可。

### 3. 配置上游

打开「系统设置」，填写代理服务器地址、端口和认证密钥（需与服务端一致）。同一页面还可以配置 SNI、证书校验、绑定地址、DNS、直连地区、mux 与 UDP 模式。代理服务器留空则全部直连。点击**保存**后应用会自动重启。

### 4. 启动服务端

```bash
ssl-proxy-svr --config ./config.yaml
```

默认监听 `0.0.0.0:1888`；未配置证书时启动阶段会自动生成自签证书。

最小可用 `config.yaml`：

```yaml
server:
  listen: "0.0.0.0"
  port: 1888
  password: "your-strong-password"   # 必须与客户端的认证密钥一致
  mux: true
  allow-private-targets: false

static-sources:
  html: "./html"
```

## 工作原理

```text
应用 ──▶ 127.0.0.1:1080（SOCKS5 / HTTP / HTTPS CONNECT / UDP ASSOCIATE）
          │ 首字节区分 SOCKS5 与 HTTP
          ├─ 规则匹配（HOST / GEO，再回退 directs）──▶ 直连
          └─ TLS 隧道 ──▶ ssl-proxy-svr ──▶ 目标
                            │
                            ├─ 通过认证的私有协议 → 转发（TCP / mux / UDP）
                            └─ 其余流量 → 伪装站点或真实站点回落
```

- **客户端**：首字节决定 SOCKS5 还是 HTTP；HOST / GEO 规则（再回退到 `directs`）决定直连或代理。代理流量在 TLS 内封装为私有协议帧，带 HMAC-SHA256 认证、长度填充与可选多路复用；UDP 使用独立帧，按目标复用会话并做能力协商。
- **服务端**：单 TLS 端口。通过认证的私有协议流量被转发（可选择复用，也可承载 UDP 帧），其余请求返回伪装站点，或按 `fallback-url` 反代真实站点。

握手细节、帧格式与 mux 设计见 [crates/svr/docs/ARCHITECTURE.md](crates/svr/docs/ARCHITECTURE.md)。

## 目录结构

```text
.
├─ crates/
│  ├─ gui/                  Windows 客户端（GPUI + gpui-kit）
│  │  ├─ src/core/          代理核心、GeoIP、统计、状态、tun（仅设计占位）
│  │  ├─ src/ui/            外壳、页面、组件、主题、i18n
│  │  ├─ src/platform/      托盘、单实例、日志、路径
│  │  ├─ installer/         NSIS 安装包脚本
│  │  ├─ assets/            GeoDB.dat、图标、i18n、更新公钥、wintun
│  │  └─ specs/             客户端规格与验收清单
│  ├─ svr/                  TLS 代理服务端（tokio + rustls + hyper）
│  │  ├─ src/services/      socket / forward / proxy / mux / UDP / fallback / static
│  │  ├─ src/libs/          限流、重放防护
│  │  ├─ src/utils/         协议帧、SSRF 校验
│  │  ├─ tests/e2e.rs       端到端测试
│  │  └─ docs/              架构与配置文档
│  └─ update-signer/        发布清单的 Ed25519 签名 / 校验工具
├─ docs/                    设计文档（UDP、TUN）
├─ scripts/
│  ├─ build.ps1             一键构建 + 打包（Windows）
│  ├─ build.sh              一键构建 + 打包（Linux / macOS；MSYS 委托 build.ps1）
│  └─ build-svr-musl.sh     WSL 内构建静态链接（musl）服务端
├─ dist/                    发布产物（client / server）
└─ Cargo.toml               workspace 与统一 release profile
```

## 环境要求

- Rust 1.85+（edition 2024）
- 客户端：Windows 10 / 11（GPUI 客户端仅支持 Windows）
- 打包：NSIS（`makensis`）；UPX 可选
- 服务端：Windows / Linux / macOS；静态 Linux 构建需要 `x86_64-unknown-linux-musl` 工具链与 `musl-gcc`

## 构建

```bash
# 整个 workspace
cargo build --release --workspace

# 开发运行
cargo run -p ssl-proxy-gui
cargo run -p ssl-proxy-svr -- --config crates/svr/config.example.yaml
```

客户端开发期若可执行文件旁没有 `GeoDB.dat`，会自动回退到 `crates/gui/assets`。

Release 配置（根 `Cargo.toml`）：fat LTO、`codegen-units = 1`、`panic = "abort"`、strip，并对图片 / 正则 / YAML 等冷路径依赖使用 `-Os`。Debug 构建下 GPUI / gpui-kit 相关 crate 使用 `opt-level = 3`，避免界面卡顿。

## 测试

```bash
cargo test -p ssl-proxy-gui    # 单元测试，含更新签名校验
cargo test -p ssl-proxy-svr    # 单元测试 + crates/svr/tests/e2e.rs
```

服务端端到端测试覆盖握手与认证、伪装 / 回落行为、mux、UDP relay、SSRF 拦截与限流。

## 打包

Windows：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
# 只打客户端 / 只打服务端 / 跳过 UPX
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipServer
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipClient
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -NoUpx
# 自定义 version.json 中的下载地址前缀
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -DownloadBase "https://example.com/ssl-proxy/win"
```

Linux / macOS：

```bash
./scripts/build.sh   # GUI 仅支持 Windows，此时只构建服务端
```

静态 Linux 服务端（WSL 内）：

```bash
wsl -d Ubuntu-22.04 -e bash /mnt/e/myProjects/ssl-proxy-project/scripts/build-svr-musl.sh
```

产物：

- `dist/client/SSLProxyClient_<gui版本>_x64-setup.exe`（同时用新的 SHA-256 与 Ed25519 签名重写 `version.json`）
- `dist/server/ssl-proxy-svr-<平台>-<svr版本>.zip`（可执行文件、`config.yaml`、`certs/`、`logs/`）
- `dist/server/ssl-proxy-svr-linux-musl-<svr版本>.tar.gz`（静态 Linux 构建）

安装包会覆盖升级旧版本：复用注册表中的安装目录，停止正在运行的 `ssl-proxy-client.exe` 后原地替换。

## 客户端数据目录

默认 `%USERPROFILE%\ssl-proxy-client`（与旧版 Tauri 客户端共用）：

| 文件 | 说明 |
| --- | --- |
| `setting.yaml` | 代理、TLS/SNI、绑定地址、DNS、直连地区、mux、UDP 模式（camelCase） |
| `rules.yaml` | HOST / GEO 路由规则 |
| `consent.dat` | 首次使用免责声明确认标记 |
| `app.log` | 运行日志 |
| `stats.json` | 流量统计 |
| `ui.json` | 语言与主题偏好 |

调试用环境变量：

- `SSL_PROXY_GUI_CONFIG_DIR`：覆盖数据目录
- `SSL_PROXY_GUI_MULTI_INSTANCE`：跳过单实例互斥体，便于并行调试
- `SSL_PROXY_GUI_RELAUNCH`：由「保存并重启」自动设置，新进程据此等待旧进程释放互斥体

## 服务端配置

服务端通过 `--config <FILE>` 加载 YAML（字段 kebab-case），优先级：**命令行参数 > YAML > 内置默认值**。

```yaml
server:
  listen: "0.0.0.0"
  port: 1888
  password: "your-strong-password"   # 必须与客户端的认证密钥一致
  mux: true                          # false 时拒绝多路复用会话
  allow-private-targets: false       # 默认拒绝回环/内网目标（SSRF 防护）

tls:
  cert: "./certs/server.crt"         # 可选；缺省时自动生成自签证书
  key: "./certs/server.key"
  sni: "example.com"                 # 自签证书的 SAN

static-sources:
  html: "./html"                     # 伪装站点，缺省时统一返回 404
  index: "index.html"
  # fallback-url: "https://example.com"  # 真实站点回落并启用 HTTP/2

log:
  dir: "./logs"
  level: "info"                      # trace | debug | info | warn | error
  max-size: 5242880                  # 单文件字节数，超限轮转

rate-limit:
  max-requests: 300
  rate-time-secs: 60
  black-time-secs: 600

udp:
  enabled: false                     # UDP relay 默认关闭
  timeout-secs: 60                   # UDP 会话空闲回收时间
  rate-limit: 100                    # 每会话每秒报文上限
```

常用命令行参数（优先于 YAML）：

| 参数 | 说明 |
| --- | --- |
| `-c, --config <FILE>` | YAML 配置文件 |
| `-l, --listen <ADDR>` | 监听地址，默认 `0.0.0.0` |
| `-p, --port <PORT>` | 监听端口，默认 `1888` |
| `--pwd <PWD>` | 密码；缺省时随机生成 |
| `--no-mux` | 拒绝多路复用会话 |
| `--allow-private-targets` | 允许回环 / 内网目标（TCP 与 UDP） |
| `--cert` / `--key` | PEM 证书与 PKCS#8 私钥 |
| `--sni <NAME>` | 自签证书的 SAN |
| `--html <DIR>` | 伪装站点根目录 |
| `--fallback-url <URL>` | 未认证流量反代到真实站点 |
| `--log-dir` / `--log-level` | 日志目录与级别 |

- [架构设计](crates/svr/docs/ARCHITECTURE.md)
- [配置项说明](crates/svr/docs/CONFIGURATION.md)

## 发布与签名流程

1. `scripts/build.ps1` 构建 workspace、打 NSIS 安装包并计算 SHA-256。
2. 由 `crates/update-signer`（`sign <key> <file>`）用 Ed25519 对安装包签名，私钥取 `.secrets/update-signing-key.der` 或 `SSL_PROXY_UPDATE_KEY` 指定的路径。
3. 项目根目录的 `version.json` 被重写，包含 `version`、`changelog`、`downloadUrl`、`sha256`、`signature`（无 BOM 的 UTF-8）。
4. 把 `version.json` 与安装包上传到 `https://hk.dishuyl.cn/ssl-proxy/`。

客户端内置对应公钥（`crates/gui/assets/update_pubkey.hex`），会拒绝哈希或签名不匹配的安装包，也会拒绝降级版本与非 HTTPS 清单。私钥缺失时 `scripts/build.ps1` 会直接失败，因为新版客户端不会执行未签名更新。

版本来源：

- `crates/gui/Cargo.toml` 的 `version` 决定 exe 元数据、安装包命名与应用内版本号
- `crates/svr/Cargo.toml` 的 `version` 决定服务端发布包命名
- 应用内「更新日志」由 `crates/gui/src/ui/pages/changelog.rs` 维护，发版时与 `version.json` 同步补充

## 安全设计

- **认证**：基于密码的 HMAC-SHA256、时间戳窗口与隧道双向确认；协议 v3 增加随机 nonce 与服务端重放缓存；同一 IP 的连续失败会被限流。
- **影响面**：服务端默认拒绝 SSRF 目标（回环、内网、链路本地、云元数据及其 IPv6 转换形式），需显式开启才允许；真实站点回落对请求体（含 chunked 上传）限制 8 MB。
- **流量特征**：ALPN、首条 record 填充与逐帧填充降低 TLS-in-TLS 指纹；未认证探测由伪装站点应答。
- **更新**：SHA-256 + Ed25519 双重校验、清单仅限 HTTPS、拒绝降级、强制提示。
- **密钥**：`setting.yaml` 以明文保存代理密码；签名私钥位于 `.secrets/`，禁止提交到仓库。

## 常见问题

- **端口被占用（10048）**：在设置中更换本地端口，或结束占用该端口的进程。
- **找不到 `GeoDB.dat`**：保持它与 exe 同目录；安装包会自带，开发期会自动回退到 `crates/gui/assets`。
- **mux 连接失败**：服务端配置为 `mux: false`，或中间设备会断开长连接时，在设置中关闭 mux。
- **检查更新失败**：客户端需要能访问 `https://hk.dishuyl.cn/ssl-proxy/version.json`。
- **更新被拒绝**：安装包未通过 SHA-256 / 签名校验、属于降级版本，或清单不是 HTTPS。应重新构建并签名，而不是绕过校验。
- **设置未生效**：设置需要应用自动重启后生效；若重启失败，手动再启动一次客户端即可。
- **UDP 转发不生效**：服务端需 `udp.enabled: true`，客户端选 `proxy` 模式；旧服务端或未开启时会自动降级为直连并在日志提示。
- **内网目标被拒绝**：默认 SSRF 防护会拦截回环 / 内网目标，仅在确有内网代理需求时开启 `allow-private-targets`。
- **回落站点报错**：确认服务端能访问 `fallback-url` 且该地址使用 HTTPS。

## 文档

| 文档 | 内容 |
| --- | --- |
| [crates/svr/docs/ARCHITECTURE.md](crates/svr/docs/ARCHITECTURE.md) | 服务分层、请求流程、协议 v3 握手、分帧、mux |
| [crates/svr/docs/CONFIGURATION.md](crates/svr/docs/CONFIGURATION.md) | 全部配置项、合并优先级与默认值 |
| [docs/udp-design.md](docs/udp-design.md) | UDP relay 设计：帧格式、会话、协商与降级 |
| [docs/tun-design.md](docs/tun-design.md) | Windows TUN 方案研究（仅设计，未实施） |
| `crates/gui/specs/gpui-refactor/` | 客户端规格与验收清单 |

## 后续规划

- Windows TUN 模式（Wintun + 自动路由 + fake-IP DNS）——目前仅为方案研究，见 [docs/tun-design.md](docs/tun-design.md)
- UDP 会话复用与诊断能力的进一步完善

## 贡献

欢迎提交 Issue 和 Pull Request。改动版本时请同步 `Cargo.toml`、`version.json` 与应用内更新日志，并在提交前运行 `cargo test`。界面改动请沿用现有 GPUI 页面结构（`crates/gui/src/ui/pages`），优先复用 gpui-kit 组件。

## License

[MIT](LICENSE)
