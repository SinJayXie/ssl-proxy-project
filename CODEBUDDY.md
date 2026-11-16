# CODEBUDDY.md This file provides guidance to CodeBuddy when working with code in this repository.

## 常用命令

工作区有三个 crate：`gui`、`svr`、`update-signer`；`default-members` 为 `gui` 和 `svr`。所有 `[profile.*]` 只能写在根目录 `Cargo.toml`（成员 crate 的 profile 会被 Cargo 忽略）。

**构建**
- `cargo build --release --workspace` — 全量发布构建。release 配置：fat LTO、`codegen-units=1`、`panic="abort"`、`strip=true`，冷路径依赖（图像/正则/YAML/DNS）用 `-Os`。
- `cargo run -p ssl-proxy-gui` — 启动客户端（开发模式，`GeoDB.dat` 缺失时回退到 `crates/gui/assets`）。
- `cargo run -p ssl-proxy-svr -- --config crates/svr/config.example.yaml` — 启动服务端。
- `powershell -ExecutionPolicy Bypass -File scripts\build.ps1` — Windows 一键构建 + NSIS 打包；可选 `-SkipServer` / `-SkipClient` / `-NoUpx` / `-DownloadBase "..."`。缺少私钥会提前失败。
- `./scripts/build.sh` — Linux/macOS 打包（仅服务端；macOS 另打包客户端 `.app`）。
- `wsl -d Ubuntu-22.04 -e bash /mnt/e/myProjects/ssl-proxy-project/scripts/build-svr-musl.sh` — 静态 Linux（musl）服务端。

**测试**
- `cargo test -p ssl-proxy-gui` — 客户端单测（含更新签名校验，测试集中于 `core/mod.rs` 的 `update_security_tests`）。
- `cargo test -p ssl-proxy-svr` — 服务端单测 + `tests/e2e.rs` 端到端套件（握手、认证、伪装/回落、mux、UDP、SSRF、限流）。
- `cargo test -p ssl-proxy-svr --test e2e <测试名> -- --exact` — 运行单个端到端测试。
- `cargo test -p ssl-proxy-gui <模块路径::测试名> -- --exact` — 运行单个客户端单测，如 `update_security_tests::download_url_must_be_https`。
- `cargo test --workspace` — 全工作区测试。

**代码检查**
- `cargo fmt --all -- --check` — 格式检查；`cargo clippy --workspace --all-targets -- -D warnings` — 静态检查。仓库未提供自定义 clippy/rustfmt 配置，使用工具默认规则。

**发布签名工具**（仅发布流程，不随产品分发）
- `cargo run -p update-signer -- keygen <private-key.der> <public-key.hex>` — 生成 Ed25519 密钥对。
- `cargo run -p update-signer -- sign <private-key.der> <file>` — 输出签名 hex。
- `cargo run -p update-signer -- verify <public-key.hex> <file> <signature-hex>` — 发布前自检。
  客户端内置公钥 `crates/gui/assets/update_pubkey.hex`；私钥位于 `.secrets/`（已 gitignore）。

## 架构

**整体形态**：两部分 Rust 程序通过私有协议 v3 通信。客户端 `ssl-proxy-gui`（GPUI 桌面应用，v2.5.2）在本机开一个代理端口；服务端 `ssl-proxy-svr`（v1.5.1）在远端用单个 TLS 端口既承载认证后的私有协议转发，又对未认证探测返回伪装站点。客户端面向 Windows/macOS，服务端面向 Windows/Linux/macOS。

**客户端分层**。`crates/gui/src/main.rs` → `core::Core`（`core/mod.rs`）是 GPUI 与代理核心之间的门面：`Core` 持有 `Arc<AppState>` 和专用多线程 tokio runtime。UI 通过 `snapshot_*` 方法用 `try_read()` 取同步快照，绝不阻塞 UI 线程；写操作和网络任务通过 `handle().spawn()` 投递到该 runtime。`AppState`（`core/state.rs`）集中持有配置、规则、连接表、流量统计、错误池、GeoIP 管理器与 DNS resolver。`types.rs` 定义 `AppConfig` / `RuleConfig` / UDP 模式等数据结构。保存配置/规则后会调用 `restart_process()` 自动重启进程使其生效。

**客户端数据流（核心）**：`core/proxy/mod.rs::start_socks5_server` 在每个 `bind_ips` 上绑定 TCP listener（默认 `127.0.0.1:1080`）；`handle_client()` 读取首字节做协议探测——`0x05` 走 SOCKS5，其余走 HTTP/HTTPS。分流决策在 `core/proxy/connect.rs`：`match_host` 支持 `*.domain` 通配，`match_rules` 返回字符串 `"PROXY"` / `"DIRECT"`，HOST 规则优先于 GEO；未命中规则时回退到 `config.directs` 与 `PRIVATE` 地区，无上游代理则全部 DIRECT。PROXY 路径进入 TLS 隧道：`connect.rs` 实现 HMAC-SHA256（`compute_mac`）、v3 nonce 与时间窗、`framing.rs` 帧封装、`tunnel.rs` 双向转发与统计、`mux.rs` 单隧道多流复用（per-stream 256KB 流控、陈旧隧道重试）。UDP 由 `udp_relay.rs` 处理 SOCKS5 UDP ASSOCIATE，模式为 `off`（默认拒绝）/ `direct` / `proxy`（跟随规则链），带 `UdpRouteDecision` 局部抽象、会话表与空闲回收；注意 UDP 数据在独立 UDP socket 上，不复用 1080 端口。DNS 解析在 `core/dns.rs`：先查缓存再走 `trust-dns-resolver`，解析失败且有上游时按“地区未知”交给服务端解析。GeoIP 由 `core/geo.rs` + `geo_sdk/` 读取 `GeoDB.dat`。UI 页面在 `src/ui/pages`，含仪表盘、连接列表、实时日志、规则编辑/测试、设置、更新日志；i18n 与主题持久化到 `ui.json`。

**服务端分层**：入口在 `crates/svr/src/main.rs` / `config.rs`（配置优先级：命令行 > YAML > 内置默认，YAML 用 kebab-case）。单个 TLS 端口由 `services/` 下各模块协作：读首包判断是否为认证私有协议——是则进入 `proxy_service`（HMAC 校验 + `replay_guard` 防重放）、`mux_service` / `mux`、`udp_relay_service` 转发；否则交给 `forward_service` 按限流结果反代真实站点或返回 `static_sources_service` 的伪装站点。`fallback_service` 反代时 Host/SNI 不参与选路，避免成为开放代理。`utils/protocol.rs` 定义帧布局与 MAC 计算，`utils/ssrf.rs` 的 `is_forbidden_ip` / `resolve_target` 拦截 loopback、私网、链路本地、云元数据、NAT64/6to4/Teredo 等目标（返回 SocketAddr 消除 DNS rebinding 窗口），除非 `allow-private-targets: true`。`libs/` 提供限流与重放保护。服务端不做改动即可支撑客户端新增的入口类型。

**安全不变量**：认证 = HMAC-SHA256 + 时间戳窗口 + 双向 ACK + v3 nonce + 服务端 replay cache；更新 = 下载只允许 HTTPS、清单必须给合法 SHA-256、Ed25519 签名校验（公钥内置）、拒绝降级、强制提示。改这两处需格外谨慎，`core/mod.rs` 的 `update_security_tests` 与 `svr` 的 e2e 套件是回归防线。

**配置与数据目录**：客户端默认 `%USERPROFILE%\ssl-proxy-client`，含 `setting.yaml`（camelCase，由 `AppConfig` 的 serde rename 决定）、`rules.yaml`、`consent.dat`（首次运行免责声明，接受后才启动代理）、`app.log`、`stats.json`、`ui.json`。调试环境变量：`SSL_PROXY_GUI_CONFIG_DIR`、`SSL_PROXY_GUI_MULTI_INSTANCE`、`SSL_PROXY_GUI_RELAUNCH`。服务端配置是独立的 kebab-case 体系，不要与客户端混淆。

**TUN 现状（重要）**：已在 `tun` 分支实现（`c906034`/`e46f00c` 及后续阶段 C 提交），`core/tun/` 含 config/route/dns/lifecycle/device/netinfo/netstack/outbound/routes/runner/recovery 模块；依赖 `wintun 0.4`+`smoltcp 0.11`+`trust-dns-proto 0.23`，`assets/wintun/wintun.dll` 由 build.rs 复制到 exe 旁。分流决策统一在 `core/proxy/route.rs`（TCP/UDP/TUN 共用）。strict-route 已实现：`routes::effective_excludes` 按 `strict_route` 决定是否把私网段写成路由例外，`outbound::decide_for_tun` 用 `route::must_direct_ip` 保证私网/本地目标强制 DIRECT（防 SSRF），`TunConfig::validate` 要求严格模式必须配置 dns-hijack；默认仍为 `strict_route=false`（兼容模式）。设置页已有独立 TUN 卡片（`ui/pages/settings.rs` 的 `TunInputs` + `tun_card`），可开关并配置设备名/MTU/strict-route/DNS 劫持/排除网段，保存后自动 apply 并重启进程。**尚未实现**：Windows Service（SYSTEM 权限与守护）。设计研究见 `tun.md` 第 12 节与 `docs/tun-design.md`，关键结论如下：

- 路线：优先“Rust 控制面 + 外部 sing-tun 数据面”，再考虑纯 Rust（`tun-rs` + `netstack-smoltcp` + Wintun + Windows Service）。真正复杂的是 TCP 状态机、UDP NAT、DNS 劫持与路由恢复，不是规则匹配。
- 分流：把 `connect.rs` 的字符串决策抽象为 `RouteDecision { Direct, Proxy, Reject }` + `Outbound` trait；DIRECT 必须新建原生 socket 走物理网卡（绑定 `IP_UNICAST_IF`/`IPV6_UNICAST_IF`），PROXY 才进入 TLS 隧道；出站 socket 不得被 TUN 二次捕获。
- 路由：auto-route 指向 TUN，同时**必须**把代理服务器 IP 写例外/绑定物理出口，否则隧道自环；接口探测不得返回 TUN 自身，失败用无效值 fail-closed；退出/崩溃须原子化撤销路由与 DNS。
- DNS（最高优先级）：TUN 与 DNS 必须成对上线。`any:53` 表示任意 IP 的 53，TCP/UDP 两条路径都劫持；fake-ip 查不到域名时拒绝连接而非按 IP 直连；代理节点域名用独立 nameserver 解析，避免“用代理解析代理域名”环路。
- 权限：无管理员/Service 能力时强制关闭 TUN（fail-closed），不得半开残留路由。
- 验证清单见 `tun.md` 第 9 节：直连绕过、代理出口 IP、DNS 泄漏、TUN 自环、权限失败、策略切换、协议边界、崩溃恢复。

参考文档：`README.md`（快速开始、打包、配置参考）、`crates/svr/docs/ARCHITECTURE.md`（握手/帧/mux）、`crates/svr/docs/CONFIGURATION.md`、`docs/udp-design.md`。
