# Checklist

## 平台基础
- [x] `crates/gui/Cargo.toml` 中 unix 依赖（libc）已按目标平台声明，Windows 依赖未被移除或降级
- [x] `config_dir()` 在 Windows 仍返回 `%USERPROFILE%\ssl-proxy-client`，在 macOS 返回 `$HOME/Library/Application Support/ssl-proxy-client`
- [x] 主题字体在 Windows 仍为 Segoe UI / Consolas，在 macOS 为系统字体（SF Pro Text / SF Mono）
- [x] `cargo check -p ssl-proxy-gui` 在 Windows 上通过且无新增告警

## 单实例与退出
- [x] macOS 下第二次启动会立即退出，且不绑定 1080 端口（flock `LOCK_NB` 失败即 `return`，早于 Core 初始化）
- [x] macOS 下关闭窗口后进程退出（`QuitMode::LastWindowClosed`）
- [x] Windows 下关闭窗口仍隐藏到托盘，托盘菜单可退出（行为无变化，代码未触碰）
- [x] 锁在进程异常退出后可再次获取（flock 随进程销毁释放，无需手动解锁）
- [x] 「保存并重启」在 macOS 上不会因抢锁失败：`RELAUNCH_ENV` 时重试 30 次 × 100ms

## 标题栏
- [x] macOS 显示系统原生红绿灯，未渲染自绘最小化/最大化/关闭按钮（gpui-component `WindowControls` 在 macOS 返回空，本项目未自绘）
- [x] macOS 标题栏内容不与红绿灯重叠，红绿灯在 34px 高度内垂直居中（组件内置 80px 左侧安全区 + `traffic_light_position = (12, 11)`；视觉细节需实机确认）
- [x] macOS 双击标题栏遵循系统偏好，拖拽标题栏可移动窗口（gpui-component `TitleBar` 内置 `titlebar_double_click` / `start_window_move`）
- [x] Windows 标题栏布局（图标、标题、版本号、主题按钮位置）与改动前一致（版本号仅用 `.when(!macos)` 包裹）

## 更新
> 后续已改为 macOS 走 `version-mac.json` + DMG，Windows 行为不变。
- [x] macOS 启动与运行期间不发起版本检查，不出现强制更新弹窗（`UPDATES_SUPPORTED = cfg!(windows)`，`check_updates` 与 `update_watch` 提前返回）
- [x] macOS 仪表盘不显示「检查更新」按钮（`.when(UPDATES_SUPPORTED, ...)`）
- [x] Windows 的自动检查、强制更新与下载安装流程无变化（常量在 Windows 恒为 true）

## 打包
- [x] `scripts/bundle-macos.sh` 可生成 `dist/client/SSLProxyClient.app`（脚本通过 `bash -n`，版本解析与 Info.plist 展开已实测）
- [x] .app 内含 `Contents/MacOS/ssl-proxy-gui`、`Contents/Resources/icon.icns`、与可执行文件同目录的 `GeoDB.dat` 和 Info.plist（CFBundleIconFile/CFBundleExecutable 正确）
- [x] `scripts/build.sh` 在 Darwin 上会构建 GUI 并调用打包脚本，Windows 分支行为不变
- [x] README / README.zh-CN 已补充 macOS 构建说明
