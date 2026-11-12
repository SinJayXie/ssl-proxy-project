# GPUI 重构规格说明（Spec）

- 状态：已评审通过（P0–P4 已实施，P5 打包/人工验收进行中）
- 工程：`ssl-proxy-gui`
- 参照：`ssl-proxy-client-tauri` v2.1.6（Tauri 2 + Vue 3）
- 设计文档：[REFACTOR.md](../../REFACTOR.md)
- 日期：2026-11-11

---

## 1. 目标

用 **GPUI + gpui-kit 0.9.1** 重写 SSL Proxy Client 的桌面 UI，Rust 代理核心原样复用，达到与 Tauri 版**功能等价、视觉一致、配置互通**，并保留 Windows 托盘行为。

成功的定义：

1. 用户可把 Tauri 版的 `$HOME/ssl-proxy-client` 目录直接给 GPUI 版使用，配置/规则/日志/consent 无需迁移。
2. 8 个页面、3 个全局弹窗、托盘、主题、语言全部可用。
3. 不引入新的代理协议或网络行为；TLS/规则/Geo 语义与 Tauri 版一致。

---

## 2. 范围

### 2.1 In scope

- Windows 10+ 桌面应用（x64，MSVC）。
- 单实例、日志、配置加载、代理启动、托盘、关闭隐藏、重启/退出。
- 仪表盘、连接、日志、规则、规则测试、设置、更新日志、关于。
- 免责声明、错误池、更新提示三个全局弹窗。
- 亮/暗主题，`en / zhCn` 两种语言。
- 更新检查与下载。
- NSIS/安装包资源（`GeoDB.dat`、图标）。

### 2.2 Out of scope（本期不做）

- macOS / Linux 的托盘与安装包适配（代码保留 `cfg`，不验收）。
- `zhTw / ja / ko` 文案（仅保留结构与 key）。
- 自动签名、增量更新、灰度发布。
- 新的代理协议、流量统计口径调整、规则语义变更。
- 视觉改版；只做等价还原。

---

## 3. 已确认决策

| 编号 | 决策 | 影响 |
| --- | --- | --- |
| D-01 | 保留系统托盘，使用 `tray-icon` + 独立线程 | 关闭窗口 = 隐藏；托盘菜单“显示窗口 / 退出” |
| D-02 | 使用 gpui-kit `TitleBar`，默认 34px，允许最大化 | 与原版 32px/禁用最大化存在有意差异 |
| D-03 | 首版仅 `en + zhCn` | 其余语言保留 key 结构与回退逻辑 |
| D-04 | 核心模块复制后不修改，通过 crate 根重导出兼容旧路径 | `crate::state::*` 等继续可用 |
| D-05 | UI 只通过 `Core` 访问核心，不直接持有 tokio I/O | 便于测试与线程安全 |

---

## 4. 功能需求

### FR-1 启动与进程生命周期

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-1.1 | 启动时检查 Windows 单实例互斥体；第二次启动激活已有窗口并退出自身 | 连续双击 exe 只有一个进程 |
| FR-1.2 | 日志同时写 stdout 与 `config_dir/app.log`，格式 `[毫秒 级别] 消息` | 文件内容与格式正确 |
| FR-1.3 | `config_dir` 不存在时创建，并生成默认 `setting.yaml` / `rules.yaml` | 首次启动后文件存在且可解析 |
| FR-1.4 | 启动时加载配置、规则、GeoDB、DNS resolver | 仪表盘显示正确端口/代理地址 |
| FR-1.5 | `GeoDB.dat` 缺失时向错误池 push code 2，不崩溃 | 启动后错误弹窗出现 |
| FR-1.6 | `consent.dat` 存在才自动启动代理；否则等用户同意 | 未同意时端口不监听 |
| FR-1.7 | 同意免责声明后写入 `consent.dat` 并启动代理 | 端口开始监听 |
| FR-1.8 | 关闭主窗口 = 隐藏到托盘，进程存活 | 任务管理器进程仍在 |
| FR-1.9 | 托盘“显示窗口”恢复并前置窗口 | 窗口可见且获得焦点 |
| FR-1.10 | 托盘“退出”结束进程 | 进程与托盘图标消失 |
| FR-1.11 | 设置保存后“重启应用”先拉起新进程再退出 | 新进程接管，配置生效 |
| FR-1.12 | 窗口标题严格为 `SSL Proxy Client` | `FindWindowW` 能找到 |

### FR-2 仪表盘

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-2.1 | 显示 SOCKS 端口、代理服务器、连接数、上下行/总流量 | 与 `get_app_info` 一致 |
| FR-2.2 | 每 2s 刷新，只有数据变化才重绘 | CPU 空载时无明显占用 |
| FR-2.3 | Check Update 按钮强制检查更新（绕过 1h 节流） | 有更新弹窗/无更新提示 |
| FR-2.4 | Exit 按钮退出应用 | 进程结束 |

### FR-3 连接

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-3.1 | 每 1s 刷新连接列表，按 host 分组 | 新连接 1s 内出现 |
| FR-3.2 | 组可折叠/展开，显示组内连接数 | 交互正常 |
| FR-3.3 | 单条断开调用 `kill_connection` | 该行消失 |
| FR-3.4 | 整组断开需确认后并发 kill | 组内连接全部消失 |
| FR-3.5 | 显示 host:port、IP、国家、延迟、上下行 | 字段与后端一致 |
| FR-3.6 | 延迟颜色：<100 绿、<300 黄、其余红；0 不参与计算 | 颜色正确 |
| FR-3.7 | Add Rule 预填 `HOST / *.host / DIRECT`，保存后刷新规则页 | 规则立即可见 |
| FR-3.8 | 无连接时显示 `NO_CONNECTIONS` 空态 | 空态可见 |

### FR-4 日志

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-4.1 | 读取 `app.log` 末 5000 字符 | 内容与文件尾部一致 |
| FR-4.2 | 按 `^\[(\S+)\s+(INFO|WARN|ERROR|DEBUG)\]\s*(.*)$` 解析 | 级别/时间/消息正确 |
| FR-4.3 | 级别色条：INFO 蓝、WARN 橙、ERROR 红、DEBUG 灰 | 颜色正确 |
| FR-4.4 | 加载后滚动到底部；点击行复制原文 | 剪贴板内容正确 |
| FR-4.5 | 无自动轮询；手动刷新按钮生效 | 无后台定时器 |

### FR-5 规则

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-5.1 | 分 HOST / GEO 两组展示，默认展开 | 分组正确 |
| FR-5.2 | 新增/编辑/删除规则，写回 `rules.yaml` | 重启后规则仍存在 |
| FR-5.3 | HOST 匹配用输入框；GEO 用可搜索国家选择器 | 交互正常 |
| FR-5.4 | 重复规则（`ruleType + matchStr`）拒绝并提示 | 出现 `DUPLICATE_RULE` |
| FR-5.5 | 删除需二次确认 | 取消不删除 |
| FR-5.6 | 保存后代理路由立即使用新规则 | 后续连接按新规则分流 |

### FR-6 规则测试

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-6.1 | 输入域名/IP，点击 Test 调用 `test_rule` | 返回结果卡 |
| FR-6.2 | 展示 Host、解析 IP、DNS、国家、命中规则、模式、耗时 | 字段完整 |
| FR-6.3 | 模式颜色：DIRECT 绿、PROXY 蓝、ERROR 红 | 颜色正确 |
| FR-6.4 | Add to Rules 支持 HOST；`alpha2Code` 合法时支持 GEO | 规则写入成功 |
| FR-6.5 | 空输入时按钮禁用 | 不可提交 |

### FR-7 设置

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-7.1 | 读取并编辑：TLS 跳过校验、SNI、SOCKS 端口、代理地址/端口/密码、Bind IPs、DNS Servers、Direct Regions | 字段与 `AppConfig` 一致 |
| FR-7.2 | 端口范围 1–65535；IP 逐行正则校验；server/password 同时有值 | 非法值标红且不可保存 |
| FR-7.3 | 内容变更后才启用 Save；Revert 还原快照 | 按钮状态正确 |
| FR-7.4 | 保存写 `setting.yaml` 并提示重启，确认后重启进程 | 新进程读取新配置 |
| FR-7.5 | 语言切换即时生效并写入 `ui.json` | 重启后保持 |
| FR-7.6 | 密码默认掩码，可切换显示 | 明文只在切换后出现 |

### FR-8 更新日志 / 关于

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-8.1 | 更新日志展示与 Vue 版相同的 11 条记录 | 版本/日期/条目一致 |
| FR-8.2 | 关于页展示 Logo、名称、版本、MIT、免责声明、版权年份 | 文案与版本正确 |

### FR-9 全局弹窗

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-9.1 | 首次启动显示免责声明（480px），滚动到底才可同意 | 未到底按钮禁用 |
| FR-9.2 | 拒绝 = 退出应用 | 进程结束 |
| FR-9.3 | 同意后 500ms 查询错误池 | 有错误则弹窗 |
| FR-9.4 | 错误码 1/2/3/10048 视为致命，只提供“退出” | 弹窗按钮正确 |
| FR-9.5 | 错误文案按 `ERR_{code}` 本地化 | 中英文案正确 |
| FR-9.6 | 发现更新时展示版本对比与 changelog（420px） | 内容正确 |
| FR-9.7 | 下载时显示百分比进度；完成后拉起安装包并退出 | 进度递增、安装器启动 |
| FR-9.8 | 更新检查 1h 节流，时间戳持久化 | 1h 内不重复请求 |

### FR-10 主题 / 语言 / 偏好

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-10.1 | 亮/暗主题切换，颜色与现有 SCSS token 一致 | 并排截图无明显色差 |
| FR-10.2 | 主题写入 `ui.json`，重启保持 | 重启后正确 |
| FR-10.3 | 中/英切换即时生效 | 所有页面文案切换 |
| FR-10.4 | 语言写入 `ui.json`，重启保持 | 重启后正确 |
| FR-10.5 | 缺失翻译回退到 `en` | 不出现空白/panic |

### FR-11 打包与资源

| ID | 需求 | 验收 |
| --- | --- | --- |
| FR-11.1 | exe 与 `GeoDB.dat` 同目录；开发期支持工程根回退 | 两种模式都能加载 Geo |
| FR-11.2 | exe 图标与托盘图标使用现有 `app-icon.png` / `.ico` | 图标正确 |
| FR-11.3 | release 构建无控制台窗口 | 双击不弹黑框 |
| FR-11.4 | 安装包按 currentUser 安装，包含 `GeoDB.dat` | 安装后可直接运行 |

---

## 5. 非功能需求

| ID | 需求 | 判据 |
| --- | --- | --- |
| NFR-1 | UI 线程不阻塞 | 无 `blocking_read`、无同步网络 I/O；1s 轮询不卡顿 |
| NFR-2 | 空闲资源占用 | 仪表盘/连接页可见时空闲 CPU 低于 Tauri 版；隐藏页面可暂停轮询 |
| NFR-3 | 渲染 | 常规操作 60fps；列表滚动不跳变 |
| NFR-4 | 可靠性 | 托盘/图标/GeoDB 异常降级并记录日志，不 panic |
| NFR-5 | 兼容性 | 完全兼容 Tauri 版配置/规则/日志/consent 格式 |
| NFR-6 | 可维护性 | `core` 不依赖 `gpui`；`ui` 不直接做网络 I/O |
| NFR-7 | 安全 | 不改 TLS 校验语义；不新增监听端口；密码不落日志 |
| NFR-8 | 构建 | Rust 1.92+，MSVC；`cargo build --release` 无警告阻断 |

---

## 6. 架构约束

1. `src/core/**` 禁止 `use gpui*`；`src/ui/**` 禁止 `TcpListener/reqwest/trust-dns`。
2. 读取核心状态：`try_read()` 快照；写入/网络：`runtime.spawn` + `JoinHandle`。
3. `Task` / `Subscription` 必须由 View 持有，禁止裸 `cx.spawn(...)` 丢弃。
4. `render()` 中不 spawn、不做 I/O、不无条件 `cx.notify()`。
5. 颜色/尺寸走 `cx.theme()` 或 `Palette`，禁止散落魔法值。
6. 所有 `tokio::sync::RwLock` 写锁内不得跨 `await` 持有（保持原核心行为）。

---

## 7. 数据契约

### 7.1 文件

| 文件 | 位置 | 格式 |
| --- | --- | --- |
| `setting.yaml` | `$HOME/ssl-proxy-client` | camelCase：`socksPort / proxyServer / proxyPort / proxyPassword / directs / bindIps / dnsServers / dangerAcceptInvalidCerts / sniName` |
| `rules.yaml` | 同上 | `[{ ruleType, matchStr, mode }]`，兼容旧 `{ type, match }` |
| `consent.dat` | 同上 | 内容 `1` |
| `app.log` | 同上 | `[<millis> <LEVEL>] <message>` |
| `ui.json` | 同上（新增） | `{ lang, theme, lastUpdateCheck }` |
| `GeoDB.dat` | exe 同目录 | 二进制，不修改 |

### 7.2 Core API 契约

| 类别 | 方法 | 返回 | 线程 |
| --- | --- | --- | --- |
| 快照 | `snapshot_connections / snapshot_config / snapshot_rules / snapshot_dataflow / snapshot_app_info` | `Option<T>` | UI 线程 `try_read` |
| 快照 | `geo_countries()` | `Vec<CountryCodeItem>` | UI 线程 |
| 生命周期 | `consent_exists / save_consent / start_proxy / restart_process` | 同步 | 调用线程 / runtime |
| 动作 | `take_errors / kill_connection / add_rule / save_rule / delete_rule / save_config / test_rule / check_update / download_update` | `JoinHandle<T>` | tokio runtime |
| 日志 | `read_logs()` | `String` | 同步文件读 |

> `test_rule / check_update / download_update` 必须在 tokio runtime 内执行（DNS/reqwest reactor）。

### 7.3 事件替代

| Tauri 事件 | GPUI 方案 |
| --- | --- |
| `update-download-progress` | `tokio::sync::mpsc::UnboundedSender<DownloadProgress>` + UI 任务接收 |
| `provide/inject`（`refreshRules`） | `AppShell` 上的 `Entity` 事件或 `Subscription` |

---

## 8. 验收标准

- AC-01 单实例、日志、默认配置、GeoDB 错误码行为与 Tauri 版一致。
- AC-02 免责声明流程完整（未同意不启动代理；同意后启动）。
- AC-03 8 个页面全部可用，数据与 Tauri 版同源同值。
- AC-04 连接 1s、仪表盘 2s 刷新；日志无轮询；规则事件驱动。
- AC-05 规则增删改落盘并立即影响路由；HOST 优先于 GEO。
- AC-06 设置校验、保存、重启链路完整。
- AC-07 更新检查 1h 节流；下载进度可见；安装器可拉起。
- AC-08 中/英与亮/暗切换即时生效且持久化。
- AC-09 关闭隐藏到托盘；托盘显示/退出正常；窗口可最大化。
- AC-10 安装包在干净 Windows 用户环境可运行，GeoDB 正常加载。
- AC-11 `specs/gpui-refactor/checklist.md` 全部勾选。

---

## 9. 风险

| ID | 风险 | 缓解 |
| --- | --- | --- |
| R-01 | `tray-icon` 与 GPUI 事件循环兼容性 | 独立线程 + 仅 Win32 显隐；失败降级为关闭即退出 |
| R-02 | `TitleBar` 34px/最大化与原版差异 | 已确认接受，记录在案 |
| R-03 | `GeoDB.dat` 开发期路径 | exe 目录优先，`CARGO_MANIFEST_DIR` 回退 |
| R-04 | GPUI Debug 性能差 / `opt-level=z` | 框架依赖 `opt-level=3`；release 用 3 |
| R-05 | Vue i18n → Rust 迁移遗漏 key | 以现有 key 清单为准，缺失回退 `en` |
| R-06 | 下载完成后 `process::exit` 导致进度不可见 | 保持原行为；如需展示 100% 再拆分两步 |

---

## 10. 假设与待确认

1. 发布目标仅 Windows x64。
2. 现有 `version.json` 更新源与版本号规则不变。
3. 托盘图标资源使用仓库现有 `app-icon.png`。
4. 不要求与 Tauri 版同时安装（单实例互斥体名称沿用 `Global\SSLProxyClient_SingleInstance`）。
