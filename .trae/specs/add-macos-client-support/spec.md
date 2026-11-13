# macOS 客户端支持与原生标题栏适配 Spec

## Why

GUI 客户端目前只在 Windows 上构建和发布：`scripts/build.sh` 在非 Windows 平台直接跳过 GUI，托盘 / 单实例 / 窗口控制等模块整块被 `#[cfg(windows)]` 掉，也没有 `.app` 打包。GPUI 本身有 macOS 后端（gpui-pre-macos），代码里剩下的 Win32 依赖基本都已隔离，因此补齐平台层后即可在 macOS 上交付可运行的客户端。

## What Changes

- 新增 macOS 平台模块：单实例（文件锁）、关闭窗口即退出的策略；Windows 现有行为（互斥体 + 隐藏到托盘）保持不变
- 标题栏按平台适配：macOS 使用系统原生红绿灯，标题栏内容避让红绿灯安全区、红绿灯在 34px 标题栏内垂直居中；Windows 继续使用自定义无缝标题栏
- 主题字体按平台选择：macOS 使用系统字体（SF Pro Text / SF Mono），Windows 保持 Segoe UI / Consolas
- 配置目录按平台：macOS 使用 `~/Library/Application Support/ssl-proxy-client`，Windows 保持 `%USERPROFILE%\ssl-proxy-client`（与 Tauri 版共用）
- macOS 上禁用自动更新：更新清单只提供 Windows 安装包，mac 上跳过定时检查并隐藏「检查更新」入口
- 新增 `scripts/bundle-macos.sh` 产出 `.app`（Info.plist + icon.icns + GeoDB.dat），`scripts/build.sh` 在 Darwin 上构建 GUI 并调用它
- **不包含**：菜单栏托盘常驻、代码签名与公证、按平台拆分更新清单、mac 服务端打包变更

## Impact

- Affected specs: GUI 客户端平台支持
- Affected code:
  - `crates/gui/Cargo.toml`（unix 依赖）
  - `crates/gui/src/main.rs`（单实例接入、退出模式）
  - `crates/gui/src/platform/mod.rs`、新增 `crates/gui/src/platform/mac.rs`
  - `crates/gui/src/platform/paths.rs`（配置目录）
  - `crates/gui/src/ui/theme.rs`（字体）
  - `crates/gui/src/ui/app.rs`（标题栏布局、更新入口）
  - `scripts/build.sh`、新增 `scripts/bundle-macos.sh`
  - `README.md` / `README.zh-CN.md`（平台说明）

## ADDED Requirements

### Requirement: macOS 可编译运行

客户端 SHALL 在 macOS 上通过 `cargo build -p ssl-proxy-gui` 编译，且启动后主窗口、代理核心、设置页可正常使用。

#### Scenario: macOS 首次启动
- **WHEN** 用户在 macOS 上构建并运行客户端
- **THEN** 窗口正常显示，无编译错误，无因 Win32 依赖缺失导致的链接失败
- **AND** 首次启动仍弹出免责声明，确认后代理按配置启动

### Requirement: 原生红绿灯标题栏

macOS 上 SHALL 使用系统原生红绿灯（关闭/最小化/缩放）作为窗口控制，标题栏内容 SHALL 全部位于红绿灯安全区右侧；Windows 的标题栏外观与交互 SHALL 与现状一致。

#### Scenario: macOS 标题栏布局
- **WHEN** 窗口在 macOS 上显示
- **THEN** 左上角为系统红绿灯，应用图标/标题不与其重叠
- **AND** 不渲染自绘的最小化/最大化/关闭按钮
- **AND** 双击标题栏遵循系统偏好（缩放或最小化）
- **AND** 拖拽标题栏可移动窗口

#### Scenario: Windows 标题栏不变
- **WHEN** 窗口在 Windows 上显示
- **THEN** 标题栏高度、图标、版本号、右侧主题切换按钮的位置与当前版本一致

### Requirement: 平台退出策略

macOS 上关闭最后一个窗口 SHALL 退出应用进程；Windows 上关闭窗口 SHALL 继续隐藏到托盘，由托盘菜单退出。

#### Scenario: macOS 关闭窗口
- **WHEN** 用户点击红绿灯关闭按钮
- **THEN** 进程退出，代理监听端口释放（不残留无窗口的后台进程）

#### Scenario: Windows 关闭窗口
- **WHEN** 用户点击窗口关闭按钮
- **THEN** 窗口隐藏到托盘，代理继续运行（与当前版本一致）

### Requirement: macOS 单实例

macOS 上 SHALL 保证同一用户同时只有一个客户端实例；第二个实例检测到已有实例时 SHALL 直接退出，不启动代理、不占用端口。

#### Scenario: 重复启动
- **WHEN** 客户端已在运行时再次启动
- **THEN** 新进程立即退出，原实例不受影响
- **AND** 原实例崩溃后锁自动释放，可再次正常启动

### Requirement: 原生目录与字体

macOS 上配置、日志 SHALL 写入 `~/Library/Application Support/ssl-proxy-client`；界面字体 SHALL 使用 macOS 系统字体而非 Windows 字体名。

#### Scenario: macOS 目录
- **WHEN** 应用在 macOS 上读写配置
- **THEN** `ui.json`、`app.log` 位于 `~/Library/Application Support/ssl-proxy-client`

#### Scenario: 字体
- **WHEN** 界面在 macOS 上渲染
- **THEN** 正文字体为 macOS 系统字体，等宽内容使用 SF Mono/Menlo，不出现 Segoe UI/Consolas

### Requirement: macOS 不提供自动更新

> 后续变更：macOS 更新已改为独立清单 `version-mac.json` + DMG（见文末「后续变更」），本条仅记录本次交付时的状态。

macOS 上 SHALL 跳过定时与启动时的更新检查，并 SHALL 隐藏仪表盘的「检查更新」入口与相关更新弹窗。

#### Scenario: macOS 启动
- **WHEN** 应用在 macOS 上启动并运行超过一小时
- **THEN** 不发起任何版本检查请求，不出现强制更新弹窗

#### Scenario: Windows 更新功能保留
- **WHEN** 应用在 Windows 上运行
- **THEN** 自动检查、强制更新提示与下载安装流程与当前版本一致

### Requirement: .app 打包

仓库 SHALL 提供 `scripts/bundle-macos.sh`，在 macOS 上产出 `dist/client/SSLProxyClient.app`，其中包含 Info.plist、`icon.icns` 与 `GeoDB.dat`。

#### Scenario: 打包产物
- **WHEN** 在 macOS 上执行打包脚本
- **THEN** 生成 `SSLProxyClient.app/Contents/MacOS/ssl-proxy-gui` 与 `Contents/Resources/icon.icns`
- **AND** `GeoDB.dat` 与可执行文件同目录，双击 .app 可启动
- **AND** 脚本执行 ad-hoc 签名（`codesign -s -`），公证留待后续

## MODIFIED Requirements

### Requirement: 窗口背景（亚克力）

窗口背景取值在 macOS 上 SHALL 继续使用 `WindowBackgroundAppearance::Blurred`（NSVisualEffectView），标题栏与红绿灯共存时半透明背景不应遮挡红绿灯。

## REMOVED Requirements

无。

## 后续变更

- macOS 应用内更新已启用：客户端在 macOS 上改为拉取 `version-mac.json`，下载 `.dmg` 后交给系统挂载（`open`），签名与 SHA-256 校验流程与 Windows 一致
- `scripts/bundle-macos.sh` 额外产出 `dist/client/SSLProxyClient_<version>_<arch>.dmg`，并用 `update-signer` 重写 `version-mac.json`
- 上述变更取代「macOS 不提供自动更新」这一条
