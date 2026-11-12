# GPUI 重构验收清单（Checklist）

> 逐项可验证；每项都要有明确的观察结果。对应需求见 [spec.md](./spec.md)。
> 环境：Windows 10/11 x64，Rust 1.92+（MSVC），仓库根 `e:\myProjects\ssl-proxy`。

## 0. 自动化烟测记录（2026-11-11）

以下项目已在本机实际执行：

- [x] `cargo check`、`cargo build`、`cargo build --release` 通过（仅剩非阻断 warning）。
- [x] 核心目录无 `gpui` 依赖；UI 目录无 `TcpListener/reqwest/trust-dns` 直接引用。
- [x] 窗口标题 `SSL Proxy Client`，外框 914×658（客户区 900×650）。
- [x] 托盘隐藏窗口 `tray_icon_app` 创建成功。
- [x] 发送 `WM_CLOSE` 后进程存活、窗口隐藏（关闭到托盘）。
- [x] 隔离配置 `socksPort: 18080` 加载成功，代理监听 `127.0.0.1:18080`。
- [x] 经 SOCKS5 与 HTTP 正向代理访问 `http://example.com` 均返回 200。
- [x] 8 个页面分别作为启动页运行 3s，无 panic，且无 `Unable to find icon`（MDI 资源已内嵌）。
- [x] 启动时更新检查请求成功（版本一致）。
- [x] 发布产物可启动：窗口正常、`GeoDB.dat` 同目录、代理端口监听、SOCKS5 返回 200。
- [ ] 安装包与剩余 UI 交互项待人工验收。


## A. 工程结构与编译

- [x] A-01 `ssl-proxy-gui` 目录符合 `REFACTOR.md` §2.2 规划，`src/core`、`src/platform`、`src/ui` 独立存在。
- [x] A-02 `src/core/**` 中搜索不到 `gpui`（`rg -n "gpui" src/core` 无结果）。
- [x] A-03 `src/ui/**` 中无 `TcpListener`、`reqwest`、`trust_dns_resolver` 直接引用。
- [x] A-04 核心文件与 Tauri 源文件 diff 仅包含：`types.rs` 新增 derive、`http.rs` 请求头 CRLF 修复；其余无改动。
- [x] A-05 `cargo build` 通过；无 `warning: unused` 阻断项。
- [x] A-06 `cargo build --release` 通过；产物为 GUI 子系统（无双击黑框）。
- [x] A-07 `Cargo.toml` 版本号为 `2.1.6`，与 `version.json` 规则一致。

## B. 启动与进程生命周期

- [ ] B-01 删除 `$HOME/ssl-proxy-client` 后首次启动，自动创建目录与默认 `setting.yaml`、`rules.yaml`。
- [x] B-02 `app.log` 生成，行格式为 `[<毫秒> INFO] ...`，同时输出到控制台（debug）。
- [ ] B-03 `GeoDB.dat` 缺失时启动不崩溃，错误池出现 code 2，弹窗提示。
- [ ] B-04 未同意免责声明时，`1080`（或配置端口）未监听（`Test-NetConnection 127.0.0.1 -Port 1080` 失败）。
- [x] B-05 同意后端口开始监听，代理可正常访问外网。
- [ ] B-06 第二次启动 exe：不产生第二进程，已有窗口前置。
- [x] B-07 窗口标题为 `SSL Proxy Client`（可用 Spy++/`GetWindowText` 验证）。
- [ ] B-08 设置保存后确认重启：新进程启动，旧进程退出，配置生效。

## C. 托盘与窗口

- [x] C-01 托盘图标可见，tooltip 为 `SSL Proxy Client`。
- [x] C-02 点击关闭按钮：窗口消失，进程仍在，托盘图标仍在。
- [ ] C-03 托盘“显示窗口”：窗口恢复、前置、可交互。
- [ ] C-04 托盘“退出”：进程结束，图标消失。
- [ ] C-05 最小化/最大化/还原按钮行为正常；窗口尺寸不小于 800×600。
- [ ] C-06 托盘创建失败时（临时改坏图标）应用仍能启动并降级为关闭即退出，日志有 error。

## D. 仪表盘

- [ ] D-01 四张卡片字段与 `get_app_info` 一致（端口、代理地址、连接数、流量）。
- [ ] D-02 建立新连接后 2s 内数字变化。
- [ ] D-03 Check Update 按钮触发检查；无更新时提示 `UPDATE_NONE`。
- [ ] D-04 Exit 退出进程。

## E. 连接

- [ ] E-01 产生 HTTP/SOCKS 连接后 1s 内出现在列表并按 host 分组。
- [ ] E-02 组折叠/展开正常，组内数量正确。
- [ ] E-03 单条断开后该连接消失，客户端连接被关闭。
- [ ] E-04 整组断开弹出确认；取消不执行；确认后全部消失。
- [ ] E-05 延迟颜色符合 <100 / <300 / 其他；0 值不显示为绿色。
- [ ] E-06 Add Rule 弹窗预填 `HOST / *.host / DIRECT`；保存后规则页出现该条。
- [ ] E-07 无连接时显示空态文案（中/英）。

## F. 日志

- [ ] F-01 显示内容等于 `app.log` 最后 5000 字符。
- [ ] F-02 级别解析正确（INFO/WARN/ERROR/DEBUG），色条颜色正确。
- [ ] F-03 打开页面后自动滚动到底部。
- [ ] F-04 点击一行后剪贴板内容为 `[time LEVEL] message`。
- [ ] F-05 页面无定时刷新；点击刷新按钮才重新读取。

## G. 规则

- [ ] G-01 HOST / GEO 分组展示，数量正确。
- [ ] G-02 新增 HOST 规则后 `rules.yaml` 立即出现该条。
- [ ] G-03 编辑规则后文件与界面同步。
- [ ] G-04 删除需确认；确认后文件与界面同步。
- [ ] G-05 重复 `ruleType+matchStr` 被拒绝并提示。
- [ ] G-06 GEO 选择器可搜索 250+ 国家，选择结果保存为 alpha2。
- [ ] G-07 新规则立即影响后续连接分流（HOST 优先于 GEO）。

## H. 规则测试

- [ ] H-01 输入域名点击 Test，返回 Host/IP/DNS/Country/Rule/Mode/Time。
- [ ] H-02 输入 IP 时按 IP 查询 Geo，不进行 DNS。
- [ ] H-03 DNS 失败时 Mode 显示 `DNS_ERROR`，不崩溃。
- [ ] H-04 模式颜色正确（DIRECT 绿 / PROXY 蓝 / ERROR 红）。
- [ ] H-05 Add to Rules 的 HOST 项可保存；`alpha2Code` 合法时 GEO 项可用。
- [ ] H-06 空输入时按钮禁用。

## I. 设置

- [ ] I-01 打开设置显示当前 `setting.yaml` 全部字段。
- [ ] I-02 端口 0/65536 被拦截；非法 IP 行标红；server/password 只填一个时不可保存。
- [ ] I-03 修改任意字段后 Save 可用；Revert 恢复初始值。
- [ ] I-04 保存后提示重启；确认后新进程读取新配置。
- [ ] I-05 密码默认掩码，切换后可显示，再切换恢复。
- [ ] I-06 Direct Regions 多选可保存/回显。
- [ ] I-07 Bind IPs、DNS Servers 可增删并保存。
- [ ] I-08 语言切换后所有页面立即变化，`ui.json` 写入。

## J. 主题与语言

- [ ] J-01 亮/暗主题颜色与 `_variables.scss` 数值一致（并排截图抽查背景、文字、边框、accent）。
- [ ] J-02 主题切换后重启保持。
- [ ] J-03 en/zhCn 切换后所有页面、弹窗、错误文案均切换。
- [ ] J-04 缺失 key 时回退英文，不显示 key 原文或空白。
- [ ] J-05 `ui.json` 结构正确且不污染 `setting.yaml`。

## K. 弹窗与更新

- [ ] K-01 首次启动弹免责声明；未滚动到底“同意”禁用。
- [ ] K-02 拒绝后进程退出。
- [ ] K-03 同意后 500ms 内错误池被读取；有错误则弹窗。
- [ ] K-04 错误码 1/2/3/10048 只显示“退出”；其他错误显示“关闭”。
- [ ] K-05 有更新时显示当前版本 → 最新版本与 changelog。
- [ ] K-06 下载进度百分比递增；完成后安装器启动、应用退出。
- [ ] K-07 1 小时内再次启动不重复请求更新；手动 Check Update 可强制请求。

## L. 打包与兼容

- [ ] L-01 安装包安装后 exe 与 `GeoDB.dat` 同级，Geo 查询可用。
- [ ] L-02 复用 Tauri 版已有的 `$HOME/ssl-proxy-client`，配置/规则/consent 全部生效。
- [ ] L-03 Tauri 版写入的旧格式规则（`type/match`）仍能加载。
- [ ] L-04 卸载后用户配置不被误删（或按产品约定处理）。
- [ ] L-05 release 下无控制台窗口、无缺失 DLL。

## M. 性能与稳定性

- [ ] M-01 仪表盘/连接页打开 10 分钟，内存无持续增长。
- [ ] M-02 隐藏到托盘 30 分钟后唤回，UI 正常、数据继续更新。
- [ ] M-03 连接数 200+ 时列表滚动流畅。
- [ ] M-04 连续切换页面 100 次无 panic、无句柄泄漏。
- [ ] M-05 网络断开/恢复后，代理与更新检查不崩溃。

---

## 评审签字

| 角色 | 结论 | 日期 |
| --- | --- | --- |
| 需求/产品 | 待评审 | |
| 开发 | 待评审 | |
| 测试 | 待评审 | |
