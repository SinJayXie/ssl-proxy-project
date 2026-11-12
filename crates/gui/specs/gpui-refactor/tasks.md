# GPUI 重构任务清单（Tasks）

> 每个任务可独立提交、可验证。依赖未完成时不要提前开始。
> 任务编号与阶段对应 `REFACTOR.md` §12；验收项对应 `checklist.md`。

## 实施状态（2026-11-11）

| 阶段 | 状态 | 备注 |
| --- | --- | --- |
| P0 骨架 + 核心搬运 | 完成 | 编译、启动、单实例、日志、代理启动均验证 |
| P1 外壳/主题/托盘/仪表盘 | 完成 | 托盘、关闭隐藏、窗口尺寸已验证 |
| P2 连接/规则 | 完成 | 编译通过；弹窗/增删改待人工交互验收 |
| P3 设置/规则测试 | 完成 | 编译通过；保存/重启链路待人工验收 |
| P4 日志/静态页/全局弹窗/更新 | 完成 | 免责声明滚动门控、错误池、更新卡片已实现 |
| P5 打包/QA | 进行中 | 发布构建与资源复制已完成；NSIS 安装包与剩余人工交互项待完成 |


## 执行顺序总览

```
P0 骨架 ──► P1 外壳/主题/托盘/仪表盘 ──► P2 连接/规则 ──► P3 设置/规则测试
                                              └──► P4 日志/静态页/弹窗/更新
                                                        └──► P5 打包/QA
```

可并行：P2 与 P4 的静态页（Changelog/About）可并行；P3 与 P4 的日志页可并行。

---

## P0 工程骨架与核心搬运

### T0.1 初始化 Cargo 与目录

- 文件：`Cargo.toml`、`src/main.rs`
- 内容：
  - 版本 `2.1.6`、edition `2024`
  - 依赖按 `REFACTOR.md` §3（gpui-kit、tokio、serde、native-tls、reqwest、tray-icon、image 等）
  - `[profile.dev.package]` 框架优化、release `opt-level = 3`
  - 创建 `src/core`、`src/platform`、`src/ui`、`assets`、`themes`
- 完成判据：`cargo metadata` 成功；`cargo build` 能开始编译。
- 依赖：无

### T0.2 复制核心代码

- 源：`../ssl-proxy-client-tauri/src-tauri/src/{state,types,dns,geo,geo_sdk,proxy}`
- 目标：`src/core/`
- 源：`single_instance.rs` → `src/platform/`
- 资源：`resources/GeoDB.dat` → `assets/`；`app-icon.png` → `assets/`
- 内容：`state.rs / types.rs / dns.rs / geo.rs / geo_sdk / proxy` **保持原样**；`types.rs` 仅补 `Default/PartialEq` derive
- 完成判据：`diff` 除上述 derive 外为空。
- 依赖：T0.1

### T0.3 模块树与旧路径兼容

- 文件：`src/core/mod.rs`、`src/main.rs`
- 内容：
  - `core/mod.rs` 声明 `pub mod state/types/dns/geo/geo_sdk/proxy`
  - `main.rs` 添加 `pub(crate) use crate::core::{dns, geo, geo_sdk, proxy, state, types};`
- 完成判据：`cargo check` 能解析所有 `crate::state::*` 等旧路径。
- 依赖：T0.2

### T0.4 平台层：路径与日志

- 文件：`src/platform/{mod,paths,logging}.rs`
- 内容：
  - `config_dir()` = `%USERPROFILE%/ssl-proxy-client`
  - `resolve_app_path()`：exe 同目录优先，回退 `CARGO_MANIFEST_DIR`
  - `TeeWriter` + `env_logger`，格式 `[毫秒 级别] 消息`，写 `app.log`
- 完成判据：启动后 `app.log` 存在且格式正确。
- 依赖：T0.1

### T0.5 Core 门面

- 文件：`src/core/mod.rs`
- 内容：
  - `Core::new`：先建 tokio runtime，`runtime.enter()` 内创建 `AppState`
  - 同步快照：`snapshot_*`、`geo_countries`、`read_logs`
  - 生命周期：`consent_exists / save_consent / start_proxy / restart_process`
  - 动作：`take_errors / kill_connection / add_rule / save_rule / delete_rule / save_config / test_rule / check_update / download_update`
  - 原 `commands.rs` 私有逻辑（`save_rules_to_file`、`run_test_rule`、`run_check_update`、`run_download_update`）完整迁移
- 完成判据：单元测试或临时 `main` 可调用快照/动作；`cargo check` 通过。
- 依赖：T0.3

### T0.6 空窗口启动

- 文件：`src/main.rs`
- 内容：单实例 → 日志 → Core → GeoDB 错误码 → proxy 启动判断 → `gpui_kit::init` → `open_window` 空视图 → 窗口标题
- 完成判据：`cargo run` 出现 900×650 空窗口；日志写入；第二次运行不新开进程。
- 依赖：T0.4、T0.5

### T0.7 P0 验收

- 执行 `checklist.md` A-01～A-05、B-01～B-03、B-06、B-07。
- 依赖：T0.6

---

## P1 外壳、主题、托盘、仪表盘

### T1.1 主题与 Palette

- 文件：`src/ui/theme.rs`、`themes/ssl-proxy-{light,dark}.json`
- 内容：
  - `Palette`（bg/card/border/text_muted/日志色/延迟色）按 SCSS 数值
  - `ThemeMode` 应用与切换；主题 token 覆盖到 gpui-kit
- 完成判据：切换亮/暗后背景、文字、边框、accent 与 `_variables.scss` 一致。
- 依赖：T0.6

### T1.2 i18n 与偏好

- 文件：`src/ui/i18n.rs`、`src/ui/prefs.rs`、`assets/i18n/{en,zh-cn}.yml`
- 内容：
  - 从 `src/i18n/en.ts`、`zh-cn.ts` 转换，key 完全一致
  - `t(key)`、`t_with(key, vars)`
  - `ui.json` 读写：`lang / theme / lastUpdateCheck`
  - 缺失 key 回退 `en`
- 完成判据：切换语言后任意页面文案变化；`ui.json` 正确写入。
- 依赖：T0.6

### T1.3 AppShell 布局

- 文件：`src/ui/app.rs`、`src/ui/mod.rs`
- 内容：`TitleBar`（34px）+ 160px 导航列 + 12px 主区；8 个导航项；页面切换
- 完成判据：8 个入口可点击，当前项高亮，布局尺寸正确。
- 依赖：T1.1、T1.2

### T1.4 窗口隐藏/唤回

- 文件：`src/platform/window.rs`
- 内容：`hide_main_window` / `show_main_window`（`FindWindowW` + `ShowWindow` + `SetForegroundWindow`）
- 完成判据：手动调用可隐藏/显示窗口。
- 依赖：T0.6

### T1.5 托盘

- 文件：`src/platform/tray.rs`
- 内容：`tray-icon` 独立线程；菜单 Show/Exit；图标解码；失败降级 + 日志
- 完成判据：托盘图标出现；两个菜单项可触发；退出走 `AsyncApp::update(cx.quit)`。
- 依赖：T1.4

### T1.6 关闭拦截

- 文件：`src/main.rs`
- 内容：`on_window_should_close` → hide + 返回 false
- 完成判据：点关闭后进程存活，托盘可唤回。
- 依赖：T1.5

### T1.7 仪表盘

- 文件：`src/ui/pages/dashboard.rs`、`src/ui/components/stat_card.rs`
- 内容：4 张卡、2s 轮询、`format_bytes`、Check Update、Exit
- 完成判据：checklist D-01～D-04。
- 依赖：T1.3、T0.5

---

## P2 连接与规则

### T2.1 连接页

- 文件：`src/ui/pages/connections.rs`
- 内容：1s 快照、按 host 分组、折叠、单条/整组断开、延迟颜色、空态
- 完成判据：checklist E-01～E-05、E-07。
- 依赖：T1.3、T0.5

### T2.2 规则编辑弹窗（共享）

- 文件：`src/ui/components/rule_dialog.rs`
- 内容：新增/编辑；HOST 输入、GEO 搜索选择；mode 选择；重复校验；380px Dialog
- 完成判据：从连接页与规则页均可打开并保存。
- 依赖：T1.3、T0.5

### T2.3 规则页

- 文件：`src/ui/pages/rules.rs`
- 内容：HOST/GEO 分组、增删改、删除确认、事件驱动刷新
- 完成判据：checklist G-01～G-06。
- 依赖：T2.2

### T2.4 规则生效验证

- 内容：连接页 Add Rule → 规则页出现 → 新连接按规则分流
- 完成判据：checklist E-06、G-07。
- 依赖：T2.1、T2.3

---

## P3 设置与规则测试

### T3.1 设置页表单

- 文件：`src/ui/pages/settings.rs`
- 内容：全部字段、掩码密码、Bind IPs/DNS 行列表、Direct Regions 多选、校验、dirty/Revert
- 完成判据：checklist I-01～I-07。
- 依赖：T1.3、T0.5

### T3.2 保存与重启

- 内容：`save_config` → 重启确认弹窗 → `restart_process()` + `cx.quit()`
- 完成判据：checklist B-08、I-04。
- 依赖：T3.1

### T3.3 规则测试页

- 文件：`src/ui/pages/test_rule.rs`
- 内容：输入/提交、结果卡、模式颜色、Add to Rules（HOST/GEO）、查重
- 完成判据：checklist H-01～H-06。
- 依赖：T2.2

---

## P4 日志、静态页、弹窗、更新

### T4.1 日志页

- 文件：`src/ui/pages/logs.rs`
- 内容：读取/解析/色条/自动滚底/点击复制/手动刷新
- 完成判据：checklist F-01～F-05。
- 依赖：T1.3、T0.5

### T4.2 更新日志与关于

- 文件：`src/ui/pages/{changelog,about}.rs`
- 内容：11 条静态记录原样迁移；关于页版本/许可/免责声明
- 完成判据：checklist FR-8 对应项。
- 依赖：T1.3

### T4.3 免责声明与错误池

- 文件：`src/ui/app.rs`、`src/ui/components/modal.rs`
- 内容：滚动门控、同意/拒绝、`save_consent`、500ms 后取错误池、致命码仅退出
- 完成判据：checklist K-01～K-04、B-04、B-05。
- 依赖：T1.3、T0.5

### T4.4 更新检查与下载

- 文件：`src/ui/components/update_dialog.rs`
- 内容：1h 节流（`ui.json`）、更新弹窗、`Progress`、mpsc 进度、拉起安装器退出
- 完成判据：checklist K-05～K-07。
- 依赖：T4.3

### T4.5 文案补全与回归

- 内容：逐页核对 `en/zh-cn` key，补齐遗漏；检查回退
- 完成判据：checklist J-03～J-05。
- 依赖：T2、T3、T4.1～T4.4

---

## P5 打包与 QA

### T5.1 打包

- 内容：`GeoDB.dat` 随包、exe/托盘图标、GUI 子系统、NSIS currentUser、版本号
- 完成判据：checklist L-01、L-05。
- 依赖：P4

### T5.2 兼容性回归

- 内容：用 Tauri 版留下的配置目录启动；旧格式规则加载
- 完成判据：checklist L-02、L-03。
- 依赖：T5.1

### T5.3 性能与稳定性

- 内容：长时间运行、200+ 连接滚动、页面切换、断网恢复
- 完成判据：checklist M-01～M-05。
- 依赖：T5.2

### T5.4 全量验收

- 内容：完整执行 `checklist.md`，记录结果与遗留问题
- 完成判据：除明确标注“本期不做”的项外全部勾选。
- 依赖：T5.3

---

## Definition of Done

一个任务完成必须同时满足：

1. 代码通过 `cargo check` / `cargo build`；
2. 不破坏既有核心文件（`git diff` 可审查）；
3. 对应 `checklist.md` 条目可复现通过；
4. 无新增 `unwrap()` 于 UI 事件路径（除启动初始化）；
5. 新增文案同时存在于 `en` 与 `zh-cn`；
6. 无裸 `cx.spawn(...)` 丢弃、无 `render` 内 spawn。

---

## 建议提交粒度

| 阶段 | 建议 commit |
| --- | --- |
| P0 | `chore: scaffold gpui app and port proxy core` |
| P1 | `feat: add gpui shell, theme, tray and dashboard` |
| P2 | `feat: add connections and rules pages` |
| P3 | `feat: add settings and rule test pages` |
| P4 | `feat: add logs, dialogs and updater` |
| P5 | `chore: packaging and qa fixes` |
