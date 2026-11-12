# SSL Proxy

[English](README.md) | [简体中文](README.zh-CN.md)

基于 Rust 的双端代理方案：一个 Windows 桌面客户端（GPUI）加一个 TLS 代理服务端，客户端与服务端通过私有协议通信。

- 客户端：`crates/gui`（包名 `ssl-proxy-gui`，安装后为 `ssl-proxy-client.exe`），当前版本 **2.3.2**
- 服务端：`crates/svr`（`ssl-proxy-svr`），当前版本 **1.2.0**
- 许可证：[MIT](LICENSE)

## 功能

### 客户端

- 单端口协议自动识别，同时支持 SOCKS5 与 HTTP / HTTPS（CONNECT）代理
- 上游代理走 TLS 隧道：HMAC-SHA256 认证、帧填充抗指纹，可选多路复用（mux）
- 规则路由：HOST / GEO 规则优先，未命中时按 `directs` 直连地区回退
- GeoIP 地理识别（`assets/GeoDB.dat`）
- 运行概览、近 7 天流量统计、连接列表与按组断开、实时日志
- 系统托盘、单实例（重复启动唤起已有窗口）、深色 / 浅色主题、中英双语
- 在线检查更新，保存设置后自动重启生效

### 服务端

- 单 TLS 端口按协议识别：私有协议 → 上游转发，其余流量 → 伪装站点
- 自签证书零配置启动，密码认证，限流与黑名单，日志自动轮转
- 支持多路复用会话

## 快速开始

### 1. 安装客户端

运行 `SSLProxyClient_2.3.2_x64-setup.exe`（来自 `dist/client`，或 `version.json` 中的下载地址）。安装到 `%LOCALAPPDATA%\SSLProxyClient`，`GeoDB.dat` 会放在 exe 同目录，旧版本原地覆盖升级。首次启动需确认免责声明。

### 2. 让应用走本地代理

客户端默认监听 `127.0.0.1:1080`，同一端口同时支持 SOCKS5、HTTP 与 HTTPS（CONNECT）。在浏览器、系统设置或单个应用中把它配置为代理即可。

### 3. 配置上游

打开「系统设置」，填写代理服务器地址、端口和认证密钥（需与服务端一致）。同一页面还可以配置 SNI、证书校验、绑定地址、DNS、直连地区与 mux 开关。代理服务器留空则全部直连。点击**保存**后应用会自动重启。

### 4. 启动服务端

```bash
ssl-proxy-svr --config ./config.yaml
```

默认监听 `0.0.0.0:1888`；未配置证书时启动阶段会自动生成自签证书。

## 工作原理

```text
应用 ──▶ 127.0.0.1:1080（SOCKS5 / HTTP / HTTPS）
          │ 首字节识别协议
          ├─ 规则匹配（HOST / GEO）──▶ 直连
          └─ TLS 隧道 ──▶ ssl-proxy-svr ──▶ 目标
```

- 客户端：首字节区分 SOCKS5 与 HTTP；先匹配 HOST / GEO 规则（再回退到 `directs`）决定直连或代理。代理流量在 TLS 内封装为私有协议帧，带 HMAC-SHA256 认证、长度填充与可选多路复用。
- 服务端：单 TLS 端口；通过认证的私有协议流量被转发（可选择复用），其余请求返回伪装站点。

协议帧格式与实现细节见 [crates/svr/docs/ARCHITECTURE.md](crates/svr/docs/ARCHITECTURE.md)。

## 目录结构

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

## 环境要求

- Rust 1.85+（edition 2024）
- 客户端：Windows 10 / 11（GPUI 客户端仅支持 Windows）
- 打包：NSIS（`makensis`）；UPX 可选
- 服务端：Windows / Linux / macOS

## 构建

```bash
# 整个 workspace
cargo build --release --workspace

# 开发运行
cargo run -p ssl-proxy-gui
cargo run -p ssl-proxy-svr -- --config crates/svr/config.example.yaml
```

客户端开发期若可执行文件旁没有 `GeoDB.dat`，会自动回退到 `crates/gui/assets`。

## 测试

```bash
cargo test -p ssl-proxy-gui
cargo test -p ssl-proxy-svr
```

## 打包

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
- `dist/server/ssl-proxy-svr-<平台>-<svr版本>.zip`（可执行文件、`config.yaml`、`certs/`、`logs/`）

安装包会覆盖升级旧版本：复用注册表中的安装目录，停止正在运行的 `ssl-proxy-client.exe` 后原地替换。

## 客户端数据目录

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

## 服务端配置

服务端通过 `--config <FILE>` 加载 YAML（字段 kebab-case），优先级：**命令行参数 > YAML > 内置默认值**。

```yaml
server:
  listen: "0.0.0.0"
  port: 1888
  password: "your-strong-password"   # 必须与客户端的认证密钥一致
  mux: true                          # false 时拒绝多路复用会话

tls:
  cert: "./certs/server.crt"         # 可选；缺省时自动生成自签证书
  key: "./certs/server.key"

static-sources:
  html: "./html"                     # 伪装站点，缺省时统一返回 404

rate-limit:
  max-requests: 300
  rate-time-secs: 60
  black-time-secs: 600
```

- [架构设计](crates/svr/docs/ARCHITECTURE.md)
- [配置项说明](crates/svr/docs/CONFIGURATION.md)

## 常见问题

- **端口被占用（10048）**：在设置中更换本地端口，或结束占用该端口的进程。
- **找不到 `GeoDB.dat`**：保持它与 exe 同目录；安装包会自带，开发期会自动回退到 `crates/gui/assets`。
- **mux 连接失败**：服务端配置为 `mux: false`，或中间设备会断开长连接时，在设置中关闭 mux。
- **检查更新失败**：客户端需要能访问 `https://hk.dishuyl.cn/ssl-proxy/version.json`。
- **设置未生效**：设置需要应用自动重启后生效；若重启失败，手动再启动一次客户端即可。
- **UDP 转发不生效**：UDP 转发默认关闭。客户端设置中的「UDP 转发」三种模式：`off` 完全不转发 UDP（SOCKS5 UDP ASSOCIATE 回复不支持）；`direct` 所有 UDP 一律本机直连（命中代理规则也强制直连）；`proxy` 按规则链决定直连或经服务端转发。走 `proxy` 模式需要服务端 `udp.enabled: true`（默认 `false`）且两端版本配套（客户端会通过能力字节协商，旧服务端 / 未启用时自动降级为直连并在日志中提示）。

## 版本与更新

- `crates/gui/Cargo.toml` 的 `version` 同时决定 exe 元数据、安装包命名与应用内版本号
- `crates/gui/version.json` 是在线更新清单（`version` / `changelog` / `downloadUrl`），发版时需上传到 `https://hk.dishuyl.cn/ssl-proxy/version.json`
- 应用内「更新日志」页面由 `crates/gui/src/ui/pages/changelog.rs` 维护，发版时与 `version.json` 同步补充

## 更多文档

- 客户端规格与验收清单：`crates/gui/specs/gpui-refactor/`

## 贡献

欢迎提交 Issue 和 Pull Request。改动版本时请同步 `Cargo.toml`、`version.json` 与应用内更新日志，并在提交前运行 `cargo test`。

## License

[MIT](LICENSE)
