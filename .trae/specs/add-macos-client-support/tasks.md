# Tasks

- [x] Task 1: 平台基础（依赖 / 目录 / 字体）
  - [x] SubTask 1.1: `crates/gui/Cargo.toml` 增加 `[target.'cfg(unix)'.dependencies] libc = "0.2"`，Windows 依赖保持不动
  - [x] SubTask 1.2: `platform/paths.rs` 的 `config_dir()` 按平台分支：Windows 保持 `%USERPROFILE%\\ssl-proxy-client`，macOS 使用 `$HOME/Library/Application Support/ssl-proxy-client`
  - [x] SubTask 1.3: `ui/theme.rs` 的字体名按平台分支（macOS：正文字体 `SF Pro Text`、等宽 `SF Mono`；Windows 保持 `Segoe UI`/`Consolas`）
  - [x] SubTask 1.4: `cargo check -p ssl-proxy-gui` 通过（Windows 侧无回归）

- [x] Task 2: macOS 单实例与退出策略
  - [x] SubTask 2.1: 新增 `platform/mac.rs`：基于 `libc::flock` 的配置文件锁（锁文件放配置目录，进程退出自动释放）
  - [x] SubTask 2.2: `platform/mod.rs` 增加 `#[cfg(target_os = "macos")] pub mod mac;`
  - [x] SubTask 2.3: `main.rs` 在 macOS 分支接入单实例守卫；Windows 分支保持现有互斥体逻辑
  - [x] SubTask 2.4: `main.rs` 在 macOS 上设置 `cx.set_quit_mode(QuitMode::LastWindowClosed)`，保证关闭窗口即退出
  - [x] SubTask 2.5: macOS 单实例补齐 `RELAUNCH_ENV` 重试（30 次 × 100ms），避免「保存并重启」时新旧进程抢锁导致重启静默失败

- [x] Task 3: 平台化标题栏
  - [x] SubTask 3.1: `ui/app.rs` 标题栏内容按平台调整：macOS 隐藏版本号副标题、微调图标/文字与右侧按钮间距，避免与红绿灯重叠；Windows 保持现状
  - [x] SubTask 3.2: `main.rs` 构造 `WindowOptions` 时，macOS 覆写 `titlebar.traffic_light_position` 使红绿灯在 34px 标题栏内垂直居中（其余沿用 `TitleBar::window_options()`）
  - [x] SubTask 3.3: 确认 macOS 下不渲染自绘窗口按钮（gpui-component `WindowControls` 已在 macOS 返回空）、双击标题栏与拖拽仍生效（组件内置，无需额外代码）

- [x] Task 4: 更新入口平台化
  - [x] SubTask 4.1: `AppShell::check_updates` 与定时检查任务在非 Windows 上直接返回，不发起请求、不弹窗
  - [x] SubTask 4.2: 仪表盘「检查更新」按钮在非 Windows 上不渲染

- [x] Task 5: .app 打包
  - [x] SubTask 5.1: 新增 `scripts/bundle-macos.sh`：构建 release 二进制，生成 `dist/client/SSLProxyClient.app/Contents/{MacOS,Resources}`，写入 Info.plist，复制 `icons/icon.icns` 与 `crates/gui/assets/GeoDB.dat`，执行 ad-hoc 签名
  - [x] SubTask 5.2: `scripts/build.sh` 的 Darwin 分支改为构建 GUI 并调用打包脚本（Windows 分支不变）
  - [x] SubTask 5.3: README / README.zh-CN 的平台说明补充 macOS 客户端构建方式

- [x] Task 6: 验证
  - [x] SubTask 6.1: 本机（Windows）执行 `cargo check -p ssl-proxy-gui` 与 `cargo build --release -p ssl-proxy-gui`，确认无回归（release 构建 3m04s 通过，`bash -n` 两个脚本语法通过）
  - [ ] SubTask 6.2: 在 macOS 实机执行 `cargo run -p ssl-proxy-gui`，验证：窗口启动、红绿灯布局、双击标题栏、关闭即退出、单实例、配置目录、字体、亚克力 —— **需 macOS 实机，当前 Windows 环境无法执行，留待交付前验证**
  - [ ] SubTask 6.3: 在 macOS 实机执行 `scripts/bundle-macos.sh`，双击 .app 验证启动与 GeoDB.dat 加载 —— **需 macOS 实机，当前环境无法执行**

# Task Dependencies

- Task 2 / Task 3 / Task 4 依赖 Task 1（平台分支与依赖就绪）
- Task 5 依赖 Task 1（目录与字体不影响打包，但可并行准备 Info.plist 内容）
- Task 6 依赖 Task 1-5 全部完成；SubTask 6.2 / 6.3 需要 macOS 实机，Windows 环境只能完成 6.1
