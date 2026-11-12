# SSL Proxy Client · GPUI 重构方案

> 目标工程：`ssl-proxy-gui`（GPUI + gpui-kit）
> 参照工程：`ssl-proxy-client-tauri`（Tauri 2 + Vue 3 + WebView）
> 原则：**Rust 代理核心原样搬迁，只替换 UI 层；视觉、交互、配置格式保持与现有客户端一致。**

---

## 0. 结论先行

| 项目 | 结论 |
| --- | --- |
| 代理核心 | `state / types / dns / geo / geo_sdk / proxy` 全部直接复制，不改协议、不改配置格式 |
| 配置兼容 | 继续读写 `$HOME/ssl-proxy-client/{setting.yaml, rules.yaml, app.log, consent.dat}` |
| UI 技术 | GPUI + gpui-kit 0.9.1，不使用 WebView |
| 窗口 | 900×650、最小 800×600、TitleBar 34px、允许最大化（标题栏控件随原生窗口） |
| 主题 | 复用现有 SCSS token 数值，映射到 gpui-kit 主题 + 自有 `Palette` |
| 语言 | 首版 `en + zhCn`，key 与 vue-i18n 完全一致，结构可继续扩展日/韩 |
| 组件 | `TitleBar / Sidebar / Button / Input / NumberInput / Combobox / Select / Switch / Dialog / AlertDialog / Progress / List / Scrollable / Empty / Badge / Tag / DescriptionList / Notification / Clipboard` |
| 托盘 | 通过 `tray-icon` + 独立线程实现；关闭窗口 = 隐藏到托盘，托盘菜单可显示窗口 / 退出 |

---

## 1. 现状盘点

### 1.1 Tauri 端分层

```
Vue 3 (WebView)
  └── BaseApi.ts ── invoke ──► commands.rs（22 个命令）
                                 └── Arc<AppState>（tokio::sync::RwLock）
                                       ├── proxy/（SOCKS5 + HTTP/HTTPS，TLS，按规则 DIRECT/PROXY）
                                       ├── dns.rs（trust-dns-resolver + 缓存）
                                       ├── geo.rs + geo_sdk/（GeoDB.dat 查询）
                                       └── single_instance.rs（Windows 互斥体 + FindWindowW 激活）
```

### 1.2 核心文件职责

| 文件 | 职责 | 是否含 Tauri 依赖 |
| --- | --- | --- |
| [state.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/state.rs) | `AppState`：连接表、DNS 缓存、规则、流量、配置、错误池、GeoManager | 否 |
| [types.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/types.rs) | 全部 DTO（`ConnectionInfo / AppConfig / RuleConfig / ...`） | 否 |
| [dns.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/dns.rs) | 带缓存的异步 DNS | 否 |
| [geo.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/geo.rs) | GeoDB 包装 | 否 |
| `geo_sdk/*` | GeoDB 解析 + 国家码表 | 否 |
| `proxy/mod.rs` | 监听端口、首字节协议探测（0x05 → SOCKS5，其余 → HTTP） | 否 |
| `proxy/socks5.rs` | SOCKS5 握手与请求解析 | 否 |
| `proxy/http.rs` | CONNECT 隧道 + 普通 HTTP 正向代理 | 否 |
| `proxy/connect.rs` | 规则匹配、DIRECT/PROXY 建连、协议头、连接登记 | 否 |
| `proxy/tunnel.rs` | 双向转发 + 流量统计（500ms 落库） | 否 |
| [single_instance.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/single_instance.rs) | Windows 单实例与窗口激活 | 否（仅 `windows` crate） |
| [commands.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/commands.rs) | IPC 命令实现 | **是**（`#[tauri::command]`、`State`、`Emitter`） |
| [lib.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/lib.rs) | 启动、日志 Tee、错误码、托盘、关闭隐藏、启动代理 | **是** |

> 结论：除 `commands.rs` 与 `lib.rs` 外，其余文件可以 **0 修改复制**。

### 1.3 窗口与全局行为

来自 [tauri.conf.json](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/tauri.conf.json)：

- 900×650，最小 800×600，居中，`resizable:false`，`maximizable:false`，`decorations:false`
- 自绘标题栏 32px：应用名 + 主题切换 + 最小化 + 关闭
- 关闭 = `window.hide()` 隐藏到托盘；`quit_app` 才真正退出
- 启动时检查 `consent.dat`，未同意不启动代理
- `GeoDB.dat` 必须位于 exe 同目录，缺失则 push error code 2

### 1.4 前端页面（8 页 + 3 个全局弹窗）

| 页面 | Vue 文件 | 数据/API | 刷新 |
| --- | --- | --- | --- |
| 仪表盘 | `AppComponent.vue` | `get_app_info` | 2s 轮询 |
| 连接 | `ConnectionsComponent.vue` | `get_connections / kill_connection / add_rule` | 1s 轮询 |
| 日志 | `LogsComponent.vue` | `get_logs` | 手动 |
| 规则 | `RulesComponent.vue` | `get_rules / add_rule / save_rule / delete_rule / get_geo` | 事件驱动 |
| 规则测试 | `TestRuleComponent.vue` | `test_rule / add_rule / get_rules` | 手动 |
| 设置 | `SettingsComponent.vue` | `get_config / save_config / restart_app / get_geo` | 无 |
| 更新日志 | `ChangelogComponent.vue` | 静态数组 | 无 |
| 关于 | `AboutComponent.vue` | 版本常量 | 无 |
| 免责声明 | `Layout.vue` | `check_consent / save_consent / get_error_pool / quit_app` | 启动 |
| 错误池 | `Layout.vue` | `get_error_pool` | 启动 + 同意后 500ms |
| 更新提示 | `Layout.vue` | `check_update / download_update` + 事件 `update-download-progress` | 1h 节流 |

---

## 2. 目标架构

### 2.1 分层

```
┌──────────────────────────────────────────────────────────────┐
│ GPUI 主线程（UI / 渲染）                                      │
│   AppShell (Entity)                                          │
│     ├─ TitleBar + 自绘侧边栏（160px）                          │
│     ├─ Page Entities（Dashboard / Connections / ...）          │
│     ├─ Dialog / AlertDialog / Notification（Root 统一承载）     │
│     └─ 轮询 Task：Timer + Core::snapshot()（只读、零等待）       │
└───────────────┬──────────────────────────────────────────────┘
                │ 写操作 / 网络请求：runtime.spawn(...)
                ▼
┌──────────────────────────────────────────────────────────────┐
│ Core（无 GPUI 依赖，可单元测试）                                │
│   Arc<AppState>（沿用 tokio::sync::RwLock）                     │
│   Arc<tokio::runtime::Runtime>（专用于代理/DNS/TLS/HTTP）       │
└───────────────┬──────────────────────────────────────────────┘
                ▼
   proxy / dns / geo  （原样搬迁，tokio 生态）
```

**硬性约束：**

1. `src/core/**` 不允许 `use gpui*`，也不允许引用 `src/ui/**`。
2. `src/ui/**` 不直接碰 `TcpListener / reqwest / trust-dns`，只调用 `Core`。
3. 所有 `tokio::sync::RwLock` 的**读**走 `try_read()` 快照，绝不在 UI 线程 `blocking_read`。
4. 所有**写/网络**走 `runtime.spawn` 返回 `JoinHandle`，UI 在前台任务里 await 后 `cx.notify()`。
5. 不在 `render()` 里 spawn 任务或无条件 `cx.notify()`。

### 2.2 目录规划

```
ssl-proxy-gui/
├── Cargo.toml
├── build.rs                      # 可选：复制 GeoDB.dat / 设置 exe 图标
├── assets/
│   ├── GeoDB.dat                 # 从 ssl-proxy-client-tauri/src-tauri/resources 复制
│   ├── app-icon.png              # 托盘/exe 图标（复用现有 app-icon.png）
│   └── icons/                    # 仅自定义图标需要；默认使用 gpui-kit Lucide
├── themes/
│   ├── ssl-proxy-light.json
│   └── ssl-proxy-dark.json
└── src/
    ├── main.rs                   # 入口：单实例 → 日志 → Core → 托盘 → GPUI
    ├── core/
    │   ├── mod.rs                # Core 门面（原 commands.rs 改造）
    │   ├── state.rs              # 直接复制
    │   ├── types.rs              # 直接复制
    │   ├── dns.rs                # 直接复制
    │   ├── geo.rs                # 直接复制
    │   ├── geo_sdk/              # 直接复制（5 个文件）
    │   └── proxy/                # 直接复制（5 个文件）
    ├── platform/
    │   ├── mod.rs
    │   ├── paths.rs              # app_path / config_dir
    │   ├── logging.rs            # TeeWriter + env_logger
    │   ├── window.rs             # FindWindowW + ShowWindow（隐藏/唤回）
    │   ├── tray.rs               # tray-icon 托盘线程（Windows）
    │   └── single_instance.rs    # 直接复制
    ├── ui/
    │   ├── mod.rs
    │   ├── app.rs                # AppShell：标题栏 + 侧边栏 + 页面路由
    │   ├── theme.rs              # Palette + ThemeMode + 主题应用
    │   ├── i18n.rs               # 首版 en + zhCn，key 与 vue-i18n 完全一致
    │   ├── prefs.rs              # ui.json（语言/主题/上次检查更新时间）
    │   ├── components/
    │   │   ├── modal.rs          # Dialog / AlertDialog 封装
    │   │   ├── toggle.rs         # Switch 封装
    │   │   ├── multiselect.rs    # Combobox 封装（多选 + 搜索）
    │   │   ├── stat_card.rs
    │   │   ├── rule_dialog.rs    # 新增/编辑规则
    │   │   └── update_dialog.rs
    │   └── pages/
    │       ├── dashboard.rs
    │       ├── connections.rs
    │       ├── logs.rs
    │       ├── rules.rs
    │       ├── test_rule.rs
    │       ├── settings.rs
    │       ├── changelog.rs
    │       └── about.rs
```

### 2.3 文件映射

| Tauri 源文件 | GUI 目标 | 改动 |
| --- | --- | --- |
| `src-tauri/src/state.rs` | `src/core/state.rs` | 无 |
| `src-tauri/src/types.rs` | `src/core/types.rs` | 无（保留 serde） |
| `src-tauri/src/dns.rs` | `src/core/dns.rs` | 无 |
| `src-tauri/src/geo.rs` | `src/core/geo.rs` | 无 |
| `src-tauri/src/geo_sdk/**` | `src/core/geo_sdk/**` | 无 |
| `src-tauri/src/proxy/**` | `src/core/proxy/**` | 无 |
| `src-tauri/src/single_instance.rs` | `src/platform/single_instance.rs` | 无 |
| `src-tauri/src/lib.rs`（托盘 + 关闭隐藏） | `src/platform/tray.rs` + `src/platform/window.rs` | `tray-icon` 独立线程 + Win32 `ShowWindow` |
| `src-tauri/src/commands.rs` | `src/core/mod.rs` | 去掉 Tauri 宏/`State`；拆成快照 + 异步动作 |
| `src-tauri/src/lib.rs` | `src/main.rs` + `platform/*` + `ui/app.rs` | 重写启动/托盘/关闭策略 |
| `src-tauri/src/main.rs` | `src/main.rs` | `windows_subsystem` 保留 |
| `src-tauri/resources/GeoDB.dat` | `assets/GeoDB.dat` | 打包/开发期路径需处理 |
| `src-tauri/country_codes.yaml` | 不需要 | `country_codes.rs` 已编译进二进制 |

---

## 3. Cargo.toml

```toml
[package]
name = "ssl-proxy-gui"
version = "2.1.6"          # 与 Tauri 版一致，用于版本检查
edition = "2024"

[dependencies]
gpui-kit = "0.9.1"

# ---- 代理核心（与 Tauri 版一致）----
tokio = { version = "1", features = ["full"] }
tokio-native-tls = "0.3"
native-tls = "0.2"
trust-dns-resolver = "0.23"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
log = "0.4"
env_logger = "0.11"
once_cell = "1.19"
regex = "1"
crc32fast = "1"
flate2 = "1.0"
reqwest = { version = "0.12", default-features = false, features = ["native-tls", "json", "stream"] }
futures-util = "0.3"
thiserror = "2"

[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
    "Win32_System_Threading",
    "Win32_UI_WindowsAndMessaging",
    "Win32_Foundation",
    "Win32_Security",
] }
tray-icon = "0.26"                       # 实际使用版本
image = { version = "0.25", default-features = false, features = ["png"] }

# ---- Debug 下让框架依赖带优化，避免 UI 卡顿（官方推荐）----
[profile.dev.package]
gpui-pre = { opt-level = 3 }
gpui-component = { opt-level = 3 }
gpui-kit = { opt-level = 3 }
gpui-kit-assets = { opt-level = 3 }
gpui-pre-platform = { opt-level = 3 }
rustybuzz = { opt-level = 3 }
taffy = { opt-level = 3 }
ttf-parser = { opt-level = 3 }

[profile.release]
opt-level = 3          # 原版为 "z"，GPUI 下会明显拖慢首帧与滚动
lto = "thin"
codegen-units = 1
strip = true
# panic = "abort"      # 建议先移除，便于定位渲染/任务 panic
```

> 说明：gpui-kit 0.9.1 要求 Rust 1.92+、Windows 使用 **MSVC** 工具链并安装 C++ Desktop workload。

---

## 4. 核心层迁移

### 4.1 直接复制清单

```powershell
# 在 ssl-proxy-gui 根目录执行（示例）
New-Item -ItemType Directory -Force src\core, src\platform, assets
Copy-Item ..\ssl-proxy-client-tauri\src-tauri\src\state.rs       src\core\
Copy-Item ..\ssl-proxy-client-tauri\src-tauri\src\types.rs       src\core\
Copy-Item ..\ssl-proxy-client-tauri\src-tauri\src\dns.rs         src\core\
Copy-Item ..\ssl-proxy-client-tauri\src-tauri\src\geo.rs         src\core\
Copy-Item -Recurse ..\ssl-proxy-client-tauri\src-tauri\src\geo_sdk src\core\
Copy-Item -Recurse ..\ssl-proxy-client-tauri\src-tauri\src\proxy   src\core\
Copy-Item ..\ssl-proxy-client-tauri\src-tauri\src\single_instance.rs src\platform\
Copy-Item ..\ssl-proxy-client-tauri\src-tauri\resources\GeoDB.dat assets\
```

复制后只需把 `crate::state` / `crate::types` / `crate::dns` / `crate::geo` 等路径随模块移动保持不变（全部位于 `core` 内，`crate::core::state` 可继续用 `crate::core::` 前缀）。

### 4.2 `commands.rs` → `Core` 门面

原来的 `#[tauri::command]` + `State<'_, Arc<AppState>>` 全部去掉，改为 `&self`。**方法体逻辑一行不改**。

```rust
// src/core/mod.rs
pub mod dns;
pub mod geo;
pub mod geo_sdk;
pub mod proxy;
pub mod state;
pub mod types;

use crate::core::state::AppState;
use crate::core::types::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;

pub struct Core {
    pub state: Arc<AppState>,
    runtime: Arc<Runtime>,          // 必须由 Core 持有，保证代理任务存活
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
        // 关键：AppState::new 内部会创建 TokioAsyncResolver，
        // 它需要 tokio 运行时上下文，必须先 enter。
        let state = {
            let _guard = runtime.enter();
            Arc::new(AppState::new(app_path, config_dir))
        };
        Self { state, runtime }
    }

    pub fn handle(&self) -> Handle { self.runtime.handle().clone() }

    // ---------- 启动 / 生命周期 ----------

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
        self.start_proxy();
        Ok(())
    }

    /// 原 restart_app：重启自身进程
    pub fn restart_process(&self) -> std::io::Result<()> {
        let exe = std::env::current_exe()?;
        std::process::Command::new(exe).spawn()?;
        Ok(())
    }

    // ---------- 同步快照（UI 轮询专用，零等待）----------

    pub fn snapshot_connections(&self) -> Option<Vec<ConnectionInfo>> {
        self.state.connections.try_read().ok()
            .map(|m| m.values().cloned().collect())
    }

    pub fn snapshot_config(&self) -> Option<AppConfig> {
        self.state.config.try_read().ok().map(|c| c.clone())
    }

    pub fn snapshot_rules(&self) -> Option<Vec<RuleConfig>> {
        self.state.rules.try_read().ok().map(|r| r.clone())
    }

    pub fn snapshot_dataflow(&self) -> Option<DataFlow> {
        self.state.total_dataflow.try_read().ok().map(|d| d.clone())
    }

    pub fn snapshot_app_info(&self) -> Option<ApiAppInfo> {
        let config = self.snapshot_config()?;
        let conns = self.snapshot_connections()?;
        let dataflow = self.snapshot_dataflow()?;
        Some(ApiAppInfo {
            socks_port: config.socks_port,
            proxy_server: if config.proxy_server.is_empty() {
                String::new()          // 由 UI 用 i18n(NOT_CONFIGURED) 渲染
            } else {
                format!("{}:{}", config.proxy_server, config.proxy_port)
            },
            connections: conns.len(),
            dataflow,
        })
    }

    pub fn geo_countries(&self) -> Vec<CountryCodeItem> {
        self.state.geo_manager.get_all_country_codes()
    }

    // ---------- 异步动作（UI await JoinHandle）----------

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

    pub fn save_rule(&self, id: usize, rule: RuleConfig) -> JoinHandle<bool> { /* 同上 */ }

    pub fn delete_rule(&self, id: usize) -> JoinHandle<bool> { /* 同上 */ }

    pub fn save_config(&self, config: AppConfig) -> JoinHandle<Result<bool, String>> {
        let state = self.state.clone();
        self.runtime.spawn(async move {
            let path = state.config_dir.join("setting.yaml");
            let content = serde_yaml::to_string(&config).map_err(|e| e.to_string())?;
            std::fs::write(&path, content).map_err(|e| e.to_string())?;
            *state.config.write().await = config;
            Ok(true)
        })
    }

    pub fn test_rule(&self, host: String) -> JoinHandle<Result<TestRuleResult, String>> {
        // 逻辑与 commands::test_rule 完全一致
        // 注意：内部会调用 dns::lookup，必须在 tokio runtime 上执行
        let state = self.state.clone();
        self.runtime.spawn(async move { run_test_rule(state, host).await })
    }

    pub fn check_update(&self) -> JoinHandle<Result<CheckUpdateResult, String>> {
        // 逻辑与 commands::check_update 完全一致（reqwest 需要 reactor）
        self.runtime.spawn(async move { run_check_update().await })
    }

    pub fn download_update(
        &self,
        url: String,
        progress: tokio::sync::mpsc::UnboundedSender<DownloadProgress>,
    ) -> JoinHandle<Result<(), String>> {
        self.runtime.spawn(async move { run_download_update(url, progress).await })
    }
}

// 原 commands.rs 中的私有工具函数原样保留
fn save_rules_to_file(rules: &[RuleConfig], config_dir: &Path) { /* 复制 */ }
```

**复制后保持“零改动”的办法：** 在 `main.rs` 里把模块重新导出到 crate 根，原文件中的 `crate::state::` 等路径即可继续解析：

```rust
mod core;
pub(crate) use crate::core::{dns, geo, geo_sdk, proxy, state, types};
```

这样 `state.rs / types.rs / dns.rs / geo.rs / geo_sdk / proxy` **一行都不用改**。新代码（`Core`、UI）统一使用 `crate::core::*` 即可。

> 模块名虽然叫 `core`，但引用时务必写 `crate::core::...`，避免与 Rust 内置的 `core` crate 混淆。

如果不采用重导出，也可以做一次性全局替换（二选一）：

| 原路径 | 新路径 |
| --- | --- |
| `crate::state::` | `crate::core::state::` |
| `crate::types::` | `crate::core::types::` |
| `crate::dns::` | `crate::core::dns::` |
| `crate::geo::` | `crate::core::geo::` |
| `crate::geo_sdk::` | `crate::core::geo_sdk::` |
| `crate::proxy::` | `crate::core::proxy::` |
| `crate::single_instance::` | `crate::platform::single_instance::` |

**改造要点：**

| 原命令 | 新归属 | 说明 |
| --- | --- | --- |
| `get_connections / get_app_info / get_rules / get_config` | 同步 `snapshot_*` | UI 轮询用 `try_read`，不阻塞 UI |
| `kill_connection / add_rule / save_rule / delete_rule / save_config` | `runtime.spawn` | 返回 `JoinHandle` |
| `get_geo` | 同步 `geo_countries()` | 纯内存，调用一次缓存到 UI |
| `test_rule / check_update / download_update` | `runtime.spawn` | 依赖 DNS/reqwest reactor |
| `get_error_pool` | `take_errors()` | 保持“取走即清空”语义 |
| `check_consent / save_consent` | 同步 | `save_consent` 内 `start_proxy()` |
| `min_size / close_app` | **删除** | 改由 `Window`/`TitleBar` 处理 |
| `restart_app` | `restart_process()` + `cx.quit()` | 先拉起新进程再退出 |
| `quit_app` | `cx.quit()` | UI 直接调用 |
| `download_update` 的 `app.emit` | `mpsc::UnboundedSender<DownloadProgress>` | 见 §7.10 |

**唯一需要留意的逻辑差异：** 原 `get_app_info` 在未配置代理时返回英文 `"Not configured"`。建议改为返回空串，由 UI 用 i18n key 渲染（多语言一致）。其余 DTO 与行为保持不变。

**给 `types.rs` 补的 derive：** `ApiAppInfo`、`DataFlow`、`AppConfig`、`RuleConfig`、`ConnectionInfo` 增加 `#[derive(Default, PartialEq)]`，供 UI 初始值与轮询差异比较使用（不影响序列化）。

### 4.3 启动流程迁移

原 [lib.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-client-tauri/src-tauri/src/lib.rs) 的启动顺序保持不变：

```
单实例互斥体
  → 计算 app_path / config_dir
  → 创建 config_dir + 默认 setting.yaml / rules.yaml
  → 初始化 TeeWriter 日志（stdout + app.log）
  → AppState::new（加载配置/规则/GeoDB/DNS resolver）
  → 检查 GeoDB.dat 是否存在（缺失 push_error(2)）
  → consent 存在则启动代理
  → 启动托盘线程（Windows）
  → 打开窗口（关闭请求 → 隐藏到托盘）
```

`TeeWriter`、`get_app_path`、`get_config_dir` 原样搬到 `platform/logging.rs` 与 `platform/paths.rs`。

**开发期 GeoDB 路径兜底**（避免每次手工 copy）：

```rust
pub fn resolve_app_path() -> PathBuf {
    let exe_dir = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));

    if exe_dir.join("GeoDB.dat").exists() {
        exe_dir
    } else {
        // cargo run 时从工程根目录读
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }
}
```

### 4.4 `main.rs` 骨架

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;
mod platform;
mod ui;

// 让直接复制过来的核心文件继续使用 crate::state / crate::proxy 等路径
pub(crate) use crate::core::{dns, geo, geo_sdk, proxy, state, types};

use crate::core::Core;
use gpui_kit::component::{Theme, ThemeMode, TitleBar};
use gpui_kit::*;
use std::sync::Arc;

fn main() {
    // 1. 单实例（Windows）
    #[cfg(windows)]
    let _mutex_guard = match platform::single_instance::try_acquire() {
        Some(handle) => handle,
        None => return, // 已激活旧窗口
    };

    // 2. 路径 + 日志（与原版一致）
    let app_path = platform::paths::resolve_app_path();
    let config_dir = platform::paths::config_dir();
    platform::logging::init(&config_dir);
    log::info!("SSL Proxy Client (GPUI) starting...");
    log::info!("App path: {:?}, config dir: {:?}", app_path, config_dir);

    // 3. 核心
    let core = Arc::new(Core::new(app_path, config_dir));

    // 4. GeoDB 缺失错误（与原版一致，code 2）
    if !core.state.app_path.join("GeoDB.dat").exists() {
        log::error!("Required file not found: GeoDB.dat");
        let handle = core.handle();
        handle.spawn({
            let state = core.state.clone();
            async move { state.push_error(2).await; }
        });
    }

    // 5. 已同意则启动代理
    if core.consent_exists() {
        core.start_proxy();
    } else {
        log::info!("Consent not yet given, proxy will start after user agrees");
    }

    // 6. GPUI
    let prefs = ui::prefs::Prefs::load(&core.state.config_dir);
    let initial_mode = prefs.theme_mode();

    application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            gpui_kit::init(cx);
            Theme::change(initial_mode, None, cx);
            ui::i18n::set_language(prefs.lang);

            // 托盘：独立线程，菜单“显示窗口 / 退出”
            #[cfg(windows)]
            platform::tray::spawn(cx);

            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(900.), px(650.)),
                    cx,
                ))),
                window_min_size: Some(size(px(800.), px(600.))),
                is_resizable: true,   // 允许最大化（已确认）
                ..TitleBar::window_options()
            };

            let shell_core = core.clone();
            let (window_handle, _shell) = open_window(options, cx, move |window, cx| {
                // 单实例激活 / 托盘唤回均依赖窗口标题，必须与原版一致
                window.set_window_title("SSL Proxy Client");

                // 关闭 = 隐藏到托盘，不退出进程
                window.on_window_should_close(cx, |_, _| {
                    platform::window::hide_main_window();
                    false
                });

                cx.new(|cx| ui::AppShell::new(shell_core.clone(), window, cx))
            })
            .expect("failed to open main window");

            let _ = window_handle;
        });
}
```

> `WindowOptions` 的最小尺寸字段在不同 gpui-pre 快照中命名可能不同。若当前版本没有 `window_min_size`，可暂时省略，后续在 `platform/window.rs` 里通过 HWND 设置最小跟踪尺寸（`WM_GETMINMAXINFO`）。

---

## 5. UI 骨架

### 5.1 `AppShell`

```rust
// src/ui/app.rs
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page { App, Connections, Logs, Rules, TestRule, Settings, Changelog, About }

pub struct AppShell {
    core: Arc<Core>,
    page: Page,
    dashboard: Entity<DashboardPage>,
    connections: Entity<ConnectionsPage>,
    logs: Entity<LogsPage>,
    rules: Entity<RulesPage>,
    test_rule: Entity<TestRulePage>,
    settings: Entity<SettingsPage>,
    _subs: Vec<Subscription>,
}

impl AppShell {
    pub fn new(core: Arc<Core>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let dashboard = cx.new(|cx| DashboardPage::new(core.clone(), cx));
        let connections = cx.new(|cx| ConnectionsPage::new(core.clone(), cx));
        let logs = cx.new(|cx| LogsPage::new(core.clone(), window, cx));
        let rules = cx.new(|cx| RulesPage::new(core.clone(), window, cx));
        let test_rule = cx.new(|cx| TestRulePage::new(core.clone(), window, cx));
        let settings = cx.new(|cx| SettingsPage::new(core.clone(), window, cx));

        Self { core, page: Page::App, dashboard, connections, logs, rules,
               test_rule, settings, _subs: vec![] }
    }

    fn nav_item(
        &self,
        id: &'static str,
        icon: IconName,
        label: String,
        page: Page,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let active = self.page == page;
        let weak = cx.weak_entity();
        h_flex()
            .id(id)
            .h(px(36.))
            .px_3()
            .gap_2()
            .cursor_pointer()
            .border_l_2()
            .border_color(if active { cx.theme().primary } else { transparent_black() })
            .bg(if active { cx.theme().accent } else { transparent_black() })
            .text_color(if active { cx.theme().primary } else { cx.theme().muted_foreground })
            .hover(|s| s.bg(cx.theme().accent).text_color(cx.theme().foreground))
            .child(Icon::new(icon).size_4())
            .child(Label::new(label).text_sm())
            .on_click(move |_, _, cx| {
                let _ = weak.update(cx, |this, cx| {
                    this.page = page;
                    cx.notify();
                });
            })
    }
}

impl Render for AppShell {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(
                TitleBar::new()
                    // gpui-kit 默认 34px，已确认沿用，并保留原生最大化/最小化/关闭
                    .child(h_flex().gap_2().child("SSL Proxy Client"))
                    .child(
                        h_flex().ml_auto().gap_2().child(
                            Button::new("theme")
                                .ghost()
                                .xsmall()
                                .icon(IconName::Sun)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.toggle_theme(window, cx)
                                })),
                        ),
                    ),
            )
            .child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.sidebar(cx))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .p_3()          // $spacing-md
                            .overflow_hidden()
                            .child(match self.page {
                                Page::App => self.dashboard.clone().into_any_element(),
                                Page::Connections => self.connections.clone().into_any_element(),
                                Page::Logs => self.logs.clone().into_any_element(),
                                Page::Rules => self.rules.clone().into_any_element(),
                                Page::TestRule => self.test_rule.clone().into_any_element(),
                                Page::Settings => self.settings.clone().into_any_element(),
                                Page::Changelog => ChangelogPage::new().into_any_element(),
                                Page::About => AboutPage::new().into_any_element(),
                            }),
                    ),
            )
    }
}
```

侧边栏宽度 160px，背景 `bg-secondary`，右侧 1px 边框。可选用 gpui-kit `Sidebar`；若需要 1:1 还原 2px 左侧强调条/36px 行高，建议保留上面的自绘导航列（仍是 gpui-kit 的 `Icon / Label / Hoverable` 组合）。

### 5.2 页面生命周期与轮询

原版 `<KeepAlive>` 保证切换页面不销毁、定时器持续跑。GPUI 中页面是常驻 `Entity`，天然等价。

```rust
pub struct DashboardPage {
    core: Arc<Core>,
    info: ApiAppInfo,
    _poll: Task<()>,
}

impl DashboardPage {
    pub fn new(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        let info = core.snapshot_app_info().unwrap_or_default();
        let poll = cx.spawn(async move |this, cx| {
            loop {
                Timer::after(Duration::from_secs(2)).await;
                let snapshot = core.snapshot_app_info();
                let updated = this.update(cx, |page, cx| {
                    if let Some(info) = snapshot {
                        if page.info != info {
                            page.info = info;
                            cx.notify();
                        }
                    }
                });
                if updated.is_err() {
                    break; // 页面已销毁
                }
            }
        });
        Self { core, info, _poll: poll }
    }
}
```

要点：

- `Timer` 用 gpui-kit 重导出的 GPUI 定时器（底层 smol）；若当前版本未导出，加 `smol = "2"` 并 `use smol::Timer;`。
- 任务 handle 必须存进页面结构体，不能 `detach` 后无人持有。
- **只有数据变化才 `cx.notify()`**，避免每 2 秒无意义重绘。
- 连接页 1s、仪表盘 2s；日志页无轮询；规则页事件驱动；更新检查 1h 节流（时间戳存 `ui.json`）。

---

## 6. 视觉对齐

### 6.1 设计 token 映射

| SCSS token | 亮色 | 暗色 | GPUI 使用方式 |
| --- | --- | --- | --- |
| `--color-bg-primary` | `#f5f5f5` | `#1a1a1a` | `cx.theme().background` |
| `--color-bg-secondary` | `#ffffff` | `#242424` | `cx.theme().sidebar` / 自定义 `palette.bg_secondary` |
| `--color-bg-tertiary` | `#e8e8e8` | `#2d2d2d` | `palette.bg_tertiary` |
| `--color-bg-hover` | `#eeeeee` | `#333333` | `.hover(|s| s.bg(...))` |
| `--color-bg-active` | `#e0e0e0` | `#3a3a3a` | `.active(...)` |
| `--color-bg-card` | `#ffffff` | `#2a2a2a` | `palette.card` |
| `--color-bg-input` | `#eeeeee` | `#333333` | Input 主题 token |
| `--color-text-primary` | `#1a1a1a` | `rgba(255,255,255,.9)` | `cx.theme().foreground` |
| `--color-text-secondary` | `#666666` | `rgba(255,255,255,.55)` | `cx.theme().muted_foreground` |
| `--color-text-muted` | `#999999` | `rgba(255,255,255,.35)` | `palette.text_muted` |
| `--color-border` | `#e0e0e0` | `#3a3a3a` | `cx.theme().border` |
| `--color-border-light` | `#f0f0f0` | `#333333` | `palette.border_light` |
| `--color-accent` | `#3b82f6` | `#60a5fa` | `cx.theme().primary` |
| `--color-accent-hover` | `#2563eb` | `#3b82f6` | `cx.theme().primary_hover` |
| `--color-danger` | `#ef4444` | `#f87171` | `cx.theme().danger` |
| `--color-success` | `#22c55e` | `#4ade80` | `cx.theme().success` |
| `--color-warning` | `#f59e0b` | `#fbbf24` | `cx.theme().warning` |
| `--color-bg-overlay` | `rgba(0,0,0,.3)` | `rgba(0,0,0,.5)` | Dialog 遮罩（主题 token） |

### 6.2 尺寸

| 项 | 值 | GPUI |
| --- | --- | --- |
| 窗口 | 900×650，min 800×600，允许缩放/最大化 | `WindowOptions`（`is_resizable: true`） |
| 标题栏 | 34px（gpui-kit 默认） | `TitleBar` |
| 侧边栏 | 160px | `.w(px(160.))` |
| 主区内边距 | 12px | `.p_3()` |
| 按钮高 | 32px / 小号 26px | `Button` 默认 / `.small()` |
| 输入高 | 32px | `Input` 默认 |
| 字号 | 11/12/13/14/16/20/24 | `.text_xs/.text_sm/.text_base/.text_lg/.text_xl/.text_2xl` |
| 间距 | 4/8/12/16/24 | `gap_1/gap_2/gap_3/gap_4/gap_6`，`p_*` 同理 |
| 圆角 | 4/8/12/16 | `.rounded(px(4.))` 等 |
| 卡片边框 | 1px `border-light` | `.border_1().border_color(...)` |

### 6.3 主题实现

两条路径同时用：

1. **gpui-kit 组件外观**：在启动时加载 `themes/ssl-proxy-light.json` / `ssl-proxy-dark.json`（`ThemeRegistry::watch_dir` 或 `Theme::apply_config`），把 `background / foreground / border / primary / muted / sidebar` 等 token 覆盖为上面的数值。
2. **业务自定义颜色**：`ui/theme.rs` 定义 `Palette`（卡片图标底色、日志级别色、延迟色、协议徽章色），通过 GPUI `Global` 暴露：

```rust
// src/ui/theme.rs
use gpui_kit::{hsla, rgba, App, Global, Hsla, Rgba};

#[derive(Clone)]
pub struct Palette {
    pub bg_secondary: Hsla,
    pub bg_tertiary: Hsla,
    pub card: Hsla,
    pub card_hover: Hsla,
    pub border_light: Hsla,
    pub text_muted: Hsla,
    pub log_info: Hsla,
    pub log_warn: Hsla,
    pub log_error: Hsla,
    pub log_debug: Hsla,
    pub lat_good: Hsla,
    pub lat_warn: Hsla,
    pub lat_bad: Hsla,
}

impl Global for Palette {}

impl Palette {
    pub fn light() -> Self {
        Self {
            bg_secondary: rgb(0xffffff).into(),
            bg_tertiary: rgb(0xe8e8e8).into(),
            card: rgb(0xffffff).into(),
            card_hover: rgb(0xf8f8f8).into(),
            border_light: rgb(0xf0f0f0).into(),
            text_muted: rgb(0x999999).into(),
            log_info: rgb(0x3b82f6).into(),
            log_warn: rgb(0xf59e0b).into(),
            log_error: rgb(0xef4444).into(),
            log_debug: rgb(0x6b7280).into(),
            lat_good: rgb(0x22c55e).into(),
            lat_warn: rgb(0xf59e0b).into(),
            lat_bad: rgb(0xef4444).into(),
        }
    }

    pub fn dark() -> Self { /* 对应暗色数值 */ }

    pub fn current(cx: &App) -> Self {
        match cx.theme().mode {
            gpui_kit::component::ThemeMode::Dark => Self::dark(),
            _ => Self::light(),
        }
    }
}
```

> 主题切换：`Theme::change(ThemeMode::Light | Dark, None, cx)`，切换后所有 `Entity` 需 `cx.notify()` 一次；`Palette` 在 `render` 内按当前模式取值即可。
>
> 导入提示：`ActiveTheme`（`cx.theme()`）与 `ThemeMode` 需从 `gpui_kit::component` 引入；Dialog 相关还需 `WindowExt as _`。具体 re-export 路径以当前 0.9.x 版本为准。

### 6.4 图标映射（mdi → Lucide）

| 原 mdi | Lucide `IconName` |
| --- | --- |
| `view-dashboard-outline` | `LayoutDashboard` |
| `lan-connect` | `Network` |
| `text-box-outline` | `FileText` |
| `filter-variant` | `Filter` |
| `flask-outline` | `FlaskConical` |
| `cog-outline` | `Settings` |
| `history` | `History` |
| `information-outline` | `Info` |
| `shield-alert-outline` | `ShieldAlert` |
| `alert` / `alert-circle-outline` / `close-circle` | `TriangleAlert` / `CircleAlert` / `CircleX` |
| `update` / `refresh` | `RefreshCw` |
| `proxy-outline` | `Globe` 或 `Waypoints` |
| `white-balance-sunny` / `moon-waning-crescent` | `Sun` / `Moon` |
| `eye-outline` / `eye-off-outline` | `Eye` / `EyeOff` |
| `plus` / `close` / `check` / `delete-outline` / `pencil-outline` | `Plus` / `X` / `Check` / `Trash2` / `Pencil` |
| `chevron-down` | `ChevronDown` |

若 `IconName` 中不存在某个图标，用 `Icon::data(include_bytes!("../../assets/icons/xxx.svg"))` 内嵌，不要引入图标字体。

---

## 7. 逐页重构

### 7.1 仪表盘（Dashboard）

- 结构：标题行（标题 + Check Update + Exit）→ 2 列统计卡（SOCKS Port / Proxy Server / Connections）+ 跨 2 列流量卡。
- 组件：`Button`（`primary` / `ghost`）、自定义 `StatCard`（`v_flex` + 40×40 圆角图标底 + 11px 大写 label）、`Tag` 显示运行状态。
- 数据：`Core::snapshot_app_info()`，2s；`bytesToSize()` 移植为 Rust `format_bytes(u64)`。
- 交互：Check Update 走 `Core::check_update()`，绕过 1h 节流；Exit → `cx.quit()`。
- i18n：`APP_INFO, SOCKS_PORT, PROXY_SERVER, CONNECTIONS, DATAFLOW, CHECK_UPDATE, CHECKING_UPDATE, QUIT_APP`。
- 图标底色：`rgba(59,130,246,.1)` / `rgba(139,92,246,.1)` / `rgba(34,197,94,.1)` / `rgba(245,158,11,.1)`。

### 7.2 连接（Connections）

- 结构：标题 + 总数 `Badge` → 按 host 分组的折叠卡 → 展开连接行 → Add Rule 弹窗（380px）。
- 组件：`List`（delegate，按 host 分组 + section header）或自绘 `v_flex` + `Collapsible`；`Badge` 显示 PROXY/DIRECT；`Button` 断开；`AlertDialog` 确认整组断开；`Empty` 空态。
- 数据：1s `snapshot_connections()`；`kill_connection(id)`；`add_rule`。
- 行内容：`host:port`、IP、国家（`alpha2Code`）、延迟（`<100` 绿 / `<300` 黄 / 其余红，0 值忽略）、上下行流量。
- 分组断开：`AlertDialog`（`DISCONNECT_GROUP_PROMPT {host} {count}`）→ 并发 `kill_connection`。
- Add Rule 预填 `{ ruleType: "HOST", matchStr: "*." + host, mode: "DIRECT" }`；保存后调用 shell 的 `refresh_rules()` 并 `cx.notify()`（修正原版不刷新列表的问题）。

### 7.3 日志（Logs）

- 结构：标题 + 刷新按钮 → 日志列表 / 空态。
- 组件：`Scrollable`（或 `List` 虚拟化）+ 行元素；每行 3px 左侧色条（INFO `#3b82f6`、WARN `#f59e0b`、ERROR `#ef4444`、DEBUG `#6b7280`）。
- 数据：`get_logs`（读 `app.log` 末 5000 字符，逻辑不变；建议在 `Core` 中提供同步 `read_logs()`）。
- 解析：正则 `^\[(\S+)\s+(INFO|WARN|ERROR|DEBUG)\]\s*(.*)$`，保留原格式。
- 交互：加载后滚动到底部；点击整行复制 → `cx.write_to_clipboard(ClipboardItem::new_string(format!("[{} {}] {}", time, level, msg)))`；无定时器。
- 字体：时间/级别用 `Consolas`（`.font_family("Consolas")`），正文用主题字体。

### 7.4 规则（Rules）

- 结构：标题 + 规则总数 + Add → HOST / GEO 两个默认展开分组 → 规则行 → 新增/编辑弹窗（380px）。
- 组件：`Accordion`/`Collapsible` 分组；`Select`（ruleType / mode）；GEO 用 `Combobox`（可搜索单选，源数据来自 `geo_countries()`）；HOST 用 `Input`；删除用 `AlertDialog`；重复校验保留 `ruleType + matchStr`。
- 数据：启动时 `snapshot_rules()`；增删改后 await `JoinHandle` 再刷新；`save_rule` 的 `id` 仍是**数组下标**（保持后端语义）。
- i18n：`RULES, ADD_RULE, EDIT_RULE, TYPE, MATCH, MODE, SELECT_RULE_TYPE, SELECT_COUNTRY, SELECT_MODE, SAVE, CLOSE, DELETE_RULE_TITLE, DELETE_RULE_PROMPT, DUPLICATE_RULE_TITLE, DUPLICATE_RULE, NO_MATCH`。
- 行布局：模式固定宽 80px；编辑/删除按钮 `ghost` / `danger` 图标按钮。

### 7.5 规则测试（Test Rule）

- 结构：标题 → 输入框 + Test 按钮 → 结果卡（Host / IP / DNS / Country / Rule / Mode / Time）→ Add to Rules 弹窗。
- 组件：`Input`（Enter 提交）+ `Button`；结果用 `DescriptionList`；模式用 `Tag`（DIRECT 绿、PROXY 蓝、ERROR 红）；左侧 3px 色条。
- 数据：`Core::test_rule(host)`（await JoinHandle）；计时 `elapsed_ms` 由后端返回，与原版一致。
- Add to Rules：HOST（match = 输入）与 GEO（`alpha2Code` 匹配 `^[A-Z]{2}$` 时可用），加入前 `snapshot_rules()` 查重。

### 7.6 设置（Settings）

- 结构（顺序与现版一致）：
  1. TLS Verify Skip → `Switch`
  2. SNI Name → `Input`
  3. Local Proxy Port → `NumberInput` 或 `Input`
  4. Proxy Server → `Input`
  5. Proxy Port → `NumberInput`
  6. Proxy Password → `Input` + `.masked(true).mask_toggle()`
  7. Bind IPs → 可增删的行列表
  8. DNS Servers → 可增删的行列表
  9. Direct Regions → `Combobox.multiple(true).searchable(true)`，选项来自 `geo_countries()`
  10. 底部 sticky 操作条：Language `Select` + Revert + Save
- 校验（原样保留）：
  - 端口 1–65535
  - `proxyServer` 与 `proxyPassword` 必须同时有值
  - IP 正则 `^(\d{1,3}\.){3}\d{1,3}$`，逐行标红
  - `hasChanges` 深比较，Revert 还原快照
- 保存：`save_config` → 成功后 `AlertDialog` 提示“需重启生效” → `restart_process()` + `cx.quit()`。
- 表单布局：`Form` + `Field`，标签横向、宽 120px；主体 `max_w(px(560.))`（原版 70% 宽）。若希望更贴近桌面设置页语义，可改用 gpui-kit 的 `Settings / SettingPage / SettingGroup / SettingItem / SettingField`（`gpui_kit::component::setting`）。

### 7.7 更新日志（Changelog）

- 静态数据：把 `ChangelogComponent.vue` 中的 11 条 `{version, date, changes[]}` **原样**搬成 Rust `const CHANGELOG: &[Entry]`。
- 组件：`Scrollable` + 版本号（16px/600/accent）+ 日期（11px muted）+ 列表（行高 1.8）。
- 无 API、无交互。

### 7.8 关于（About）

- 结构：居中 Logo（`Icon::new(IconName::Globe).size(px(72.))`，accent、透明度 .85）→ 标题 24px/700 → 版本 `Tag`（`env!("CARGO_PKG_VERSION")`）→ 描述 → MIT License 胶囊 → 免责声明卡（`max_h(px(160.))` 滚动）→ 版权年份。
- 文案复用 `ABOUT_DESC / DISCLAIMER_*`。

### 7.9 全局弹窗

| 弹窗 | 原实现 | GPUI |
| --- | --- | --- |
| 免责声明（480px） | `Modal.vue` + 滚动到底才可同意 | `window.open_dialog` + `Scrollable` + `on_scroll` 判断 `max_scroll_top - scroll_top < 10` 置 `can_agree`；`footer` 两个按钮 |
| 错误池（400px） | 致命码 `{1,2,3,10048}` | `AlertDialog`；标题 `ERR_TITLE`，每项 `ERR_{code}` + `ERR_FATAL/ERR_WARNING` 标签；致命时只保留“退出” |
| 更新提示（420px） | `Progress` + changelog | `Dialog`；下载中显示 `Progress::new("dl").value(percent)`，取消/稍后按钮隐藏 |
| 删除/断开确认 | `showConfirm` | `window.open_alert_dialog`，`CANCEL` + `danger` 确认 |
| 规则编辑（380px） | `Modal.vue` | `window.open_dialog` + `content(\|content,..\| ...)`；持久输入状态在打开前创建并传入 |

Dialog 代码形态（API 见 gpui-kit 文档）：

```rust
// 注意：builder 可能重复执行，元素不能复用，必须在闭包里重新构造
window.open_dialog(cx, move |dialog, _, _| {
    dialog
        .w(px(480.))
        .title(i18n::t("DISCLAIMER_TITLE"))
        .child(consent_body(can_agree))   // 每次调用都新建元素
        .footer(|_, _, _, _| vec![
            Button::new("consent-disagree")
                .danger()
                .label(i18n::t("CONSENT_DISAGREE"))
                .on_click(|_, _, cx| cx.quit()),
            Button::new("consent-agree")
                .primary()
                .disabled(!can_agree)
                .label(i18n::t("CONSENT_AGREE"))
                .on_click(move |_, window, cx| {
                    window.close_dialog(cx);
                    // core.save_consent()
                }),
        ])
});
```

### 7.10 下载更新进度

原版通过 Tauri 事件 `update-download-progress` 推送。GPUI 改为 channel：

```rust
let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DownloadProgress>();
let task = core.download_update(url, tx);

cx.spawn(async move |this, cx| {
    while let Some(p) = rx.recv().await {
        let _ = this.update(cx, |view, cx| {
            view.progress = p.percent.min(100);
            cx.notify();
        });
    }
    let _ = task.await;
});
```

保持原行为：下载完成后启动安装包、`std::process::exit(0)`。若希望用户看到 100%，可拆成 `download_update`（返回文件路径）与 `launch_installer`（退出）两步。

---

## 8. i18n 与本地偏好

### 8.1 语言

- 首版只做 **2 种语言：`en / zhCn`**，默认 `en`；`zhTw / ja / ko` 保留结构位，后续按同一套 key 补齐即可。
- **key 保持与 `src/i18n/*.ts` 完全一致**，包括 `ERR_{code}`。
- 迁移方式：把 `en.ts` 与 `zh-cn.ts` 转成 `assets/i18n/{en,zh-cn}.yml`，启动时用已有的 `serde_yaml` 载入 `HashMap<String, String>`；`t(key)` 走全局 `Language`。
- 带插值的 key（如 `DISCONNECT_GROUP_PROMPT`）改为 `t_with(key, &[("host", host), ("count", n)])`，占位符语法统一成 `{host}`。
- 切换语言：`GlobalLanguage` + 所有页面 `cx.notify()`；设置页与免责声明弹窗都可切换。
- 语言枚举预留 `ZhTw / Ja / Ko`，加载不到对应 yml 时回退到 `en`，避免后续加语言时改 UI 代码。

### 8.2 `ui.json`（替代 localStorage）

```json
{
  "lang": "zhCn",
  "theme": "dark",
  "lastUpdateCheck": 1760000000000
}
```

- 路径：`$HOME/ssl-proxy-client/ui.json`
- 读取：启动时一次；写入：语言/主题切换、更新检查后。
- 不放入 `setting.yaml`，避免污染代理配置格式。

---

## 9. 资源与打包

| 项 | 做法 |
| --- | --- |
| `GeoDB.dat` | 运行时读 exe 同目录；开发期回退到 `CARGO_MANIFEST_DIR`；安装包必须包含 |
| 图标 | 默认 `gpui_kit::assets::Assets`（Lucide）；exe 图标用 `embed-resource`/`winres` |
| 窗口图标 | Windows 上如 `WindowOptions` 不支持，用 `platform/window.rs` 调 Win32 `WM_SETICON`（可选） |
| 子系统 | `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` |
| 安装包 | NSIS/WiX（`currentUser` 安装模式），安装后 `GeoDB.dat` 与 exe 同级 |
| 版本号 | `Cargo.toml` 的 `version` 必须与 `version.json` 发布版本一致（`check_update` 用 `CARGO_PKG_VERSION`） |

---

## 10. 与原版行为差异（预期内）

| 项 | 原版 | GPUI 版 | 处理 |
| --- | --- | --- | --- |
| 页面切换动画 | 0.15s 位移+淡入 | 默认瞬时 | 可选 `with_animation` 淡入；不影响功能 |
| 模态遮罩 | `backdrop-filter: blur(4px)` | GPUI 无 CSS 模糊 | 用半透明遮罩，必要时预渲染模糊背景 |
| 主题切换动画 | View Transition 300ms + blur | 无 | 直接切换，或对根节点做透明度动画 |
| 日志复制 | `navigator.clipboard` | `cx.write_to_clipboard` | 等价 |
| 更新检查节流 | `localStorage` | `ui.json` | 等价 |
| 语言持久化 | `localStorage.lang` | `ui.json.lang` | 等价 |
| 关闭窗口 | 隐藏到托盘 | `tray-icon` + Win32 `ShowWindow(SW_HIDE)` | 已确认保留托盘 |
| 窗口最大化 | 禁用 | `TitleBar` 原生控件，允许最大化 | 已确认允许 |
| 首版语言 | 5 种 | en + zhCn | 已确认，其余后续补齐 |

---

## 11. 风险与技术方案

### 11.1 系统托盘（已决策：保留）

gpui-kit 没有托盘组件，采用 **`tray-icon` + 独立线程**，不干扰 GPUI 的渲染线程。

```rust
// src/platform/tray.rs
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};

pub fn spawn(cx: &mut gpui_kit::App) {
    let app = cx.to_async();

    std::thread::Builder::new()
        .name("ssl-proxy-tray".into())
        .spawn(move || {
            let menu = Menu::new();
            let show = MenuItem::new("Show Window", true, None);
            let exit = MenuItem::new("Exit", true, None);
            menu.append(&show).ok();
            menu.append(&exit).ok();

            let _tray = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("SSL Proxy Client")
                .with_icon(load_icon())
                .build()
                .expect("create tray icon");

            // 阻塞接收托盘菜单事件；窗口显示/隐藏走 Win32，不跨线程碰 GPUI 状态
            while let Ok(event) = MenuEvent::receiver().recv() {
                match event.id.0.as_str() {
                    "show" => crate::platform::window::show_main_window(),
                    "exit" => {
                        let _ = app.update(|cx| cx.quit());
                        break;
                    }
                    _ => {}
                }
            }
        })
        .expect("spawn tray thread");
}

fn load_icon() -> Icon {
    let rgba = image::load_from_memory(include_bytes!("../../assets/app-icon.png"))
        .expect("decode app icon")
        .to_rgba8();
    let (w, h) = rgba.dimensions();
    Icon::from_rgba(rgba.into_raw(), w, h).expect("build tray icon")
}
```

```rust
// src/platform/window.rs
use windows::core::w;
use windows::Win32::UI::WindowsAndMessaging::*;

pub fn hide_main_window() {
    unsafe {
        if let Ok(hwnd) = FindWindowW(None, w!("SSL Proxy Client")) {
            let _ = ShowWindow(hwnd, SW_HIDE);
        }
    }
}

pub fn show_main_window() {
    unsafe {
        if let Ok(hwnd) = FindWindowW(None, w!("SSL Proxy Client")) {
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = SetForegroundWindow(hwnd);
        }
    }
}
```

**风险与兜底：**

- `tray-icon` 在 Windows 上自建消息窗口；若当前版本不自带消息泵，需要在托盘线程补一个 `GetMessageW` 循环。
- 托盘线程**只做 Win32 窗口显隐**，只有“退出”通过 `AsyncApp::update` 回主线程 `cx.quit()`，避免跨线程访问 GPUI 状态。
- 一定要持有 `_tray` 直到线程结束，`TrayIcon` drop 会移除托盘图标。
- 若托盘创建失败（图标解码/系统限制），降级为“关闭即退出”，并写 `log::error!`，不能 panic。
- `platform/mod.rs` 中按平台导出：`#[cfg(windows)] pub mod tray; #[cfg(windows)] pub mod window;`，非 Windows 提供空实现，保证可编译。

### 11.2 标题栏（已决策）

- 采用 gpui-kit `TitleBar`，默认 **34px**，保留 Windows 原生的 **最小化 / 最大化 / 关闭** 控件。
- `WindowOptions.is_resizable = true`，因此最大化可用；这是相对原版（`resizable:false`、`maximizable:false`）的**有意差异**。
- 主题切换按钮放在 `TitleBar` 左侧内容区（`ml_auto` 推到右侧、紧邻系统按钮）。

### 11.3 窗口隐藏 / 唤回（已决策）

- 关闭请求：`window.on_window_should_close` 返回 `false` + `platform::window::hide_main_window()`，进程继续运行。
- 托盘“显示窗口”：`FindWindowW` → `ShowWindow(SW_RESTORE/SW_SHOW)` → `SetForegroundWindow`。
- 托盘“退出”：`AsyncApp::update(|cx| cx.quit())`。
- 单实例第二次启动：继续复用 `single_instance.rs` 的 `activate_existing_window()`（同样按窗口标题查找），无需改动。
- 若 `SW_SHOW` 后 GPUI 未立即重绘，可通过 `window_handle.update(cx, |_, window, _| window.activate_window())` 主动激活一次；正常情况 Win32 的 `WM_PAINT` 会触发重绘。

### 11.4 其他

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| `opt-level = "z"` + `panic = "abort"` | 渲染掉帧、崩溃无回溯 | release 改 `opt-level = 3`、去掉 `panic="abort"` |
| 国家列表 250 项 | Combobox 展开卡顿 | 必须用 `searchable(true)`；列表虚拟化由组件负责 |
| 连接列表高频变化 | 1s 全量重绘 | 只在数据差异时 `notify`；用 `List` 虚拟化 |
| 单实例激活 | `FindWindowW` 按标题查找 | 窗口标题必须严格为 `SSL Proxy Client` |
| DNS/HTTP 任务误放 UI 线程 | UI 卡死 | 所有网络调用只经 `Core::runtime` |
| `try_read` 失败 | 该帧数据未更新 | 保留上一次快照，下一 tick 再取，不阻塞 |
| GeoDB 缺失 | Geo 查询不可用 | 保留错误码 2 + 错误池弹窗 |

---

## 12. 实施阶段

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| P0 | 复制核心；`Core` 门面；`platform/*`；`main.rs` 打开空窗口 | `cargo run` 出现 900×650 窗口；日志写入 `app.log`；单实例生效 |
| P1 | 主题 token + `TitleBar` + 自绘侧边栏 + Dashboard + **托盘/关闭隐藏** | 与 Vue 版并排对比颜色/尺寸一致；关闭后进程存活，托盘可显示/退出；2s 数据刷新 |
| P2 | Connections + Rules + Rule Dialog | 1s 刷新、断开、增删改规则、`rules.yaml` 落盘 |
| P3 | Settings + Test Rule | 配置保存/重启、校验、规则测试与加规则 |
| P4 | Logs + Changelog + About + 免责声明/错误池/更新弹窗 | 首次启动流程、错误码弹窗、更新下载进度 |
| P5 | 打包、性能与视觉打磨 | 安装包可运行；60fps；切换页面无卡顿 |

### 验收清单

- [ ] 第二次启动会激活已有窗口，不产生第二个进程
- [ ] 首次启动显示免责声明，未滚动到底不能同意；拒绝则退出
- [ ] 同意后 SOCKS5/HTTP 代理在配置端口监听，浏览器可正常上网
- [ ] 连接列表 1s 刷新，单条/整组断开生效
- [ ] 规则增删改后立即影响路由（HOST 优先于 GEO）
- [ ] 设置保存后重启，`setting.yaml` 与内存配置一致
- [ ] 日志页显示 `app.log` 尾部 5000 字符并可点击复制
- [ ] 更新检查 1h 节流、下载进度可见、安装包可拉起
- [ ] 亮/暗主题与中/英语言切换即时生效，重启后保持
- [ ] Geo 国家/地区查询结果与 Tauri 版一致
- [ ] 点击关闭窗口后进程不退出，托盘图标存在；托盘“显示窗口”可唤回；托盘“退出”正常结束进程
- [ ] 窗口可最大化/还原，标题栏三键行为正常

---

## 13. 编码约定

1. `core` 与 `ui` 单向依赖；禁止反向引用。
2. 页面结构体统一实现 `Render`，状态字段私有，变更后 `cx.notify()`。
3. 所有 `Task` / `Subscription` 必须由结构体持有，禁止裸 `cx.spawn(...)` 丢弃。
4. `render` 中只做取值与布局，不做 I/O、不 spawn、不无条件 notify。
5. 颜色/间距/字号一律走 `cx.theme()` 或 `Palette`，禁止散落魔法数值。
6. 新增文案必须同时补齐 `en` 与 `zh-cn` 两个语言文件（其余语言可选），key 与 Vue 版保持同名。
7. 涉及配置/规则的写操作后，必须刷新对应页面并同步 `rulesRefresh` 等跨页信号（可用 `AppShell` 上的 `Entity` 事件或 `Subscription` 实现，替代原 `provide/inject`）。

---

## 14. 实施记录（P0–P4）

### 14.1 已落地

| 模块 | 状态 | 说明 |
| --- | --- | --- |
| 核心搬运 | 完成 | `state/types/dns/geo/geo_sdk/proxy` 复制到 `src/core` |
| Core 门面 | 完成 | 快照 + `runtime.spawn` 动作，`tokio` 运行时由 `Core` 持有 |
| 平台层 | 完成 | 路径、TeeWriter 日志、单实例、Win32 隐藏/唤回 |
| 托盘 | 完成 | `tray-icon 0.26` + 独立线程 + 消息泵 |
| 外壳 | 完成 | `TitleBar` + 160px 导航 + 8 个页面 |
| 主题 | 完成 | SCSS token 映射到 gpui-kit 主题 + `Palette` |
| 页面 | 完成 | 仪表盘、连接、日志、规则、规则测试、设置、更新日志、关于 |
| 全局弹窗 | 完成 | 免责声明（滚动门控）、错误池、更新提示均以居中卡片覆盖层实现 |
| i18n | 完成 | `en / zhCn`，JSON 由原 TS 文件生成，key 完全一致 |
| 构建 | 完成 | `build.rs` 把 `GeoDB.dat` 复制到 `target/<profile>` |

### 14.2 与设计稿的差异

1. **免责声明/错误/更新不是 Dialog**：改为 `AppShell` 内的居中卡片覆盖层。原因：滚动门控需要稳定的 `ScrollHandle` 与轮询状态，Dialog builder 会重复执行，容易丢状态。
2. **Bind IPs / DNS Servers 使用多行 Textarea**：每行一个，替代动态行列表；校验与存储格式不变。
3. **Direct Regions 使用 `Combobox` 多选**：与原 MultiSelect 等价。
4. **语言首版仅 en/zhCn**（已确认）。
5. **托盘退出**：托盘线程只设置原子标志，主线程 250ms 轮询后 `cx.quit()`，避免跨线程访问 GPUI 状态。
6. **图标资源使用 `AllAssets`**：默认 `Assets` 只含子集，`list-filter / flask-conical / clock / activity / arrow-up-down` 会缺失。
7. **规则弹窗按类型切换 MATCH 控件**：HOST 显示输入框，GEO 显示可搜索国家下拉；Dialog builder 会在选择变化后重建。
8. **重启应用延迟拉起**：`restart_process` 通过 `cmd /C timeout 1 & start` 延迟 1s 启动新进程，避免旧进程尚未释放单实例互斥体导致新进程直接退出。
9. **主题直接通过 `Theme::update` 覆盖 token**：未落地 `themes/*.json` 文件，避免额外主题注册流程；`ui/theme.rs` 是唯一颜色来源。

### 14.3 核心修复

`proxy/http.rs` 的 HTTP 正向代理在重建请求时，原实现把请求行后的 `\r\n` 也拼进了 headers，导致目标服务器返回 400。已改为 `strip_prefix(b"\r\n")` 后再拼接，SOCKS5 / HTTPS CONNECT / HTTP 正向代理均验证通过。

### 14.4 开发/测试开关

| 环境变量 | 作用 |
| --- | --- |
| `SSL_PROXY_GUI_CONFIG_DIR` | 覆盖配置目录（避免污染正在运行的 Tauri 客户端） |
| `SSL_PROXY_GUI_MULTI_INSTANCE` | 跳过单实例互斥体，便于并行调试 |
| `SSL_PROXY_GUI_PAGE` | 启动页：`connections / logs / rules / test / settings / changelog / about` |

> 本机全局 `cargo` 把 crates-io 指向了阿里云镜像，但该镜像索引缺少 gpui-kit 0.9.x。
> 因此工程内 `.cargo/config.toml` 改用 rsproxy sparse 索引；如团队镜像已更新，可删除该文件恢复全局配置。

### 14.5 已执行的验证

- `cargo check` / `cargo build` / `cargo build --release` 通过。
- 启动后窗口标题 `SSL Proxy Client`、外框 914×658（客户区 900×650）。
- 托盘隐藏窗口 `tray_icon_app` 创建成功；发送 `WM_CLOSE` 后进程存活且窗口隐藏。
- 隔离配置目录 + `socksPort: 18080` 启动后端口监听成功。
- 通过该代理访问 `http://example.com`：SOCKS5 返回 200，HTTP 正向代理修复后返回 200。
- 8 个页面分别作为启动页运行 3s，进程均存活且无 panic。
- 更新检查请求成功（日志：当前版本与远端版本均为 2.1.6）。
- 发布产物：`target/release/ssl-proxy-gui.exe`（约 29.6 MB），`GeoDB.dat` 已随构建复制到同目录。

---

## 15. MDI 图标接入

### 15.1 方案

gpui-kit 自带 Lucide，但原 Vue 版使用的是 **Material Design Icons（MDI）**。为了视觉一致，工程内嵌了一份 MDI SVG，并与 gpui-kit 的 Lucide 资源组合：

```
assets/mdi/*.svg                       # 从 @iconify-json/mdi 生成
src/ui/assets.rs
  ├── MdiAssets  (rust-embed, mdi/**/*.svg)
  └── AppAssets  (先查 MDI，再回退 gpui_kit::assets::AllAssets)
```

`main.rs` 注册：

```rust
gpui_kit::application()
    .with_assets(ui::assets::AppAssets)
```

组件内部（Checkbox、Select 等）仍使用 Lucide 路径，`AppAssets` 会自动回退到 `AllAssets`，两者互不冲突。

### 15.2 生成图标

数据源：`ssl-proxy-client-tauri/node_modules/@iconify-json/mdi/icons.json`（无需联网）。

```powershell
cd ssl-proxy-gui
node scripts/gen-mdi-icons.mjs
```

脚本会把 `scripts/gen-mdi-icons.mjs` 里列出的图标写成完整的 `<svg>` 到 `assets/mdi/`。
新增图标时：把名字加入数组 → 重新运行脚本 → `cargo build`。

当前已生成 53 个（覆盖 Vue 版全部 `i-mdi:*` 用法 + `chevron-right`）。

### 15.3 使用方式

`Icon::new` 只接受实现了 `IconNamed` 的类型，字符串路径要用 `.path()`：

```rust
use crate::ui::assets::mdi;

Icon::default().path(mdi("history"))        // assets/mdi/history.svg
Icon::default().path(mdi("proxy-outline"))
```

`mdi(name)` 只是拼出 `mdi/<name>.svg`，实际字节由 `MdiAssets` 在编译期嵌入。

### 15.4 已替换的图标

| 位置 | MDI |
| --- | --- |
| 侧边栏 | `view-dashboard-outline` / `lan-connect` / `text-box-outline` / `filter-variant` / `flask-outline` / `cog-outline` / `history` / `information-outline` |
| 仪表盘卡片 | `serial-port` / `virtual-private-network` / `link` / `swap-calls` |
| 主题切换 | `white-balance-sunny` / `moon-waning-crescent` |
| 连接页 | `chevron-down` / `chevron-right` / `plus` / `close-circle` / `close` / `lan-disconnect` |
| 规则页 | `chevron-down` / `chevron-right` / `pencil-outline` / `delete-outline` |
| 日志页 | `text-box-outline` / `refresh` |
| 免责声明 | `shield-alert-outline` |
| 错误池 | `alert` / `alert-circle-outline` / `close-circle` |
| 更新提示 | `update` |
| 关于页 | `proxy-outline` |

> 验证：8 个页面分别启动运行，`app.log` 中无 `Unable to find icon`，无 panic。

---

## 16. Vue 页面细节对齐记录

| 页面 | 对齐内容 |
| --- | --- |
| Dashboard | 2 列统计卡 + 跨 2 列流量卡；卡片横向 40×40 图标 + 11px 大写标签 + 14px 值；Check Update/Exit 按钮与 MDI 图标；流量卡 up/down/total 三色 |
| Connections | 标题计数徽标；分组卡 web 图标、host + 国家、PROXY/DIRECT 徽标、平均延迟、上下行汇总、组内数量；28×28 操作按钮（pencil-ruler / lan-disconnect）、旋转 chevron；行内 ip:port、上下行、延迟、24×24 关闭按钮；空态 48px 图标 |
| Rules | HOST/GEO 分组（web/earth 图标、计数徽标、旋转 chevron）；行内 regex/flag 图标、GEO 显示 `Country (CODE)`、file-document 图标 + 模式徽标、26×26 编辑/删除按钮；弹窗按类型切换 MATCH 控件 |
| Test Rule | 标题/表单/结果卡尺寸与颜色；左侧 3px DIRECT/PROXY/ERROR 色条；100px 标签列；`MODE_*` 徽标；仅 DIRECT/PROXY 显示 HOST/GEO 加规则按钮 |
| Settings | 已改为分组卡片布局（见 §17）；字段校验、SNI 动态 placeholder、Bind/DNS 动态行、Direct Regions 可搜索多选、保存确认弹窗保持一致 |

## 17. Settings 布局重设计

目标：一眼看清配置分区，降低表单认知负担。

- 页面头：`系统设置` 20px 标题 + 11px「保存后重启」副标题
- 四张分组卡片（`theme::card` 背景、1px `border_light`、8px 圆角、16px 内边距），每张卡带 13px 分组标题与 11px 说明：
  1. **代理**：2×2 两列——本地代理端口 / 代理服务器地址；代理端口 / 认证密钥（带 mask 切换）
  2. **TLS / SNI**：开关行（标题 + 状态说明，右侧 Switch）+ SNI 输入（下方提示）
  3. **网络**：绑定 IP 与 DNS 服务器并排两列，各自「标签 + 提示 + 动态行 + ADD」
  4. **路由**：直连地区多选 Combobox
- 校验错误：卡片列表末尾的 danger 边框提示条（alert 图标 + 文案）
- 底部操作栏：左侧语言切换，右侧「取消更改 / 保存」；仅在有改动时显示取消更改
- 滚动区 `settings-scroll` 只包裹卡片内容，底部操作栏固定不随滚动
- 相关 helper：`section()` 卡片容器、`field()` 表单字段（flex_1 + 可选 hint）、`field_label()`

验证：`cargo check` / `cargo build` / `cargo build --release` 均通过；`SSL_PROXY_GUI_PAGE=settings` 启动烟测无 panic，代理正常监听 127.0.0.1:1080。

## 18. macOS 风格视觉重构

仅调整视觉层（`theme.rs` + 各页面容器样式），业务逻辑、事件与数据流均未改动。

### 18.1 设计 token

| 项 | 浅色 | 深色 |
| --- | --- | --- |
| 窗口内容背景 | `#f5f5f7` | `#1e1e1e` |
| 侧边栏 / 标题栏 | `#ececee` | `#252527` |
| 卡片 | `#ffffff` | `#2c2c2e` |
| 强调色 | `#007aff` | `#0a84ff` |
| 成功 / 警告 / 危险 | `#34c759` / `#ff9f0a` / `#ff3b30` | `#30d158` / `#ffd60a` / `#ff453a` |
| 边框（常规 / 浅） | `#d9d9de` / `#e8e8ec` | `#3a3a3c` |
| 控件圆角 / 卡片圆角 | 7px / 10px | 同左 |

- 字体：`Segoe UI`（中文由 DirectWrite 系统回退到雅黑），基准字号 13px；等宽 `Consolas`
- 滚动条：透明轨道 + 半透明滑块（macOS overlay 观感）
- 选择色 `selection` 使用强调色 18% 透明度

### 18.2 框架层（`app.rs`）

- 标题栏：与侧边栏同色、去掉底部分隔线，左侧应用图标 + 12px 半粗标题
- 侧边栏：176px，条目 30px 高、13px 文字，圆角 7px 选中胶囊（`sidebar_accent`），选中项图标使用强调色，取消左侧竖条
- 内容区：内边距 20px（原 12px），页面之间呼吸感更接近 macOS
- Dashboard 统计卡 / 流量卡、Connections 分组卡、Rules 分组卡、Test Rule 结果卡、Settings 分组卡、About 免责声明卡：统一 10px 圆角 + `shadow_xs` 轻投影 + 浅边框
- 弹窗卡片（免责声明 / 错误 / 更新）：14px 圆角 + `shadow_lg`
- 页面标题统一 20px 半粗；统计卡图标底色由强调色/成功色/警告色派生，不再硬编码

### 18.3 验证

`cargo check` / `cargo build` / `cargo build --release` 通过；Dashboard 与 Settings 冒烟启动无 panic，代理正常监听 `127.0.0.1:1080`。

## 19. Dashboard 持久化统计与图表

### 19.1 布局修复

原「连接管理」统计卡右侧用 `div().flex_1()` 占位，视觉上多出一段空白。现改为 2×2 四卡：

1. 本地端口（SOCKS_PORT）
2. 代理服务器（PROXY_SERVER）
3. 当前连接（CONNECTIONS）+ 历史峰值提示
4. 累计流量（DASH_TOTAL_TRAFFIC）+ 今日上行/下行提示

下方依次为「近 7 天流量」柱状图与本次运行流量卡。

### 19.2 持久化统计（`core/stats.rs`）

- 文件：`$config_dir/stats.json`
- 结构：`total_up` / `total_down` / `peak_connections` / `days[{date, up, down}]`，每日桶保留 30 天
- 采集：Dashboard 每 2s 轮询 `snapshot_app_info()`，按 `total_dataflow` 差值累加；代理在进程内重启导致计数回退时使用 `saturating_sub`，不会出现负数或重复计数
- 落盘：每 30s 写一次；首次启动自动创建
- 日期：Windows 使用 `GetLocalTime` 取本地日期（随系统时区），其他平台回退 UTC；`days_from_civil` / `civil_from_days` 负责日期与天数互转

### 19.3 图表

- 纯 GPUI 元素绘制双色柱状图，不引入图表依赖：每天两根 12px 柱（上行绿 / 下行蓝），按 7 天最大值归一化，最小高度 3px
- 空数据显示「暂无流量记录」；图例在卡片右上角
- 新增 i18n：`DASH_TRAFFIC_7D`、`DASH_TOTAL_TRAFFIC`、`DASH_PEAK`、`DASH_TODAY`、`DASH_UP`、`DASH_DOWN`、`DASH_NO_DATA`

### 19.4 验证

- `cargo test --bin ssl-proxy-gui stats::`：3 个用例通过（日期往返、近 7 天零填充、累计落桶）
- debug / release 构建通过
- 实跑约 40s 后 `stats.json` 已落盘，记录到真实代理流量与峰值连接数


