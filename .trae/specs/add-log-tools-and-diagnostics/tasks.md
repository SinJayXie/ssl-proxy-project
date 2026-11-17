# Tasks

- [x] Task 1: Core 日志读取与导出基础（`core/mod.rs`）
  - [x] SubTask 1.1: 新增 `read_logs_tail(max_bytes: usize) -> String`，按字节截尾并修正到 UTF-8 边界
  - [x] SubTask 1.2: `read_logs()` 改为调用 `read_logs_tail(5000)`，保持现有行为
  - [x] SubTask 1.3: 新增 `export_text(kind, content)`，创建 `<config_dir>/exports/` 并写入 `<kind>-<yyyyMMdd-HHmmss>.txt`
  - [x] SubTask 1.4: 单测：小文件全量返回、大文件只留尾部、多字节字符不被切断、导出文件路径与内容正确

- [x] Task 2: 诊断数据层（新增 `core/diagnostics.rs`）
  - [x] SubTask 2.1: 定义 `CheckStatus { Pass, Warn, Fail, Info }`、`CheckResult { name, status, detail }`
  - [x] SubTask 2.2: 实现 `run(core)`，异步执行五项检查：本地代理端口、上游连通性、DNS 解析、IPv4 路由表、TUN 自检
  - [x] SubTask 2.3: 路由表检查在 Windows 执行 `route print -4` 并解析默认路由条数与 TUN 网段，其他平台返回 Info
  - [x] SubTask 2.4: 提供 `format_report(&[CheckResult]) -> String` 供诊断包使用
  - [x] SubTask 2.5: 单测覆盖纯逻辑：路由输出解析、状态汇总

- [x] Task 3: TUN 只读状态（`core/tun/runner.rs`、`netstack.rs`）
  - [x] SubTask 3.1: `StackShared` 新增 `fakeip_count()`
  - [x] SubTask 3.2: `runner::status() -> Option<TunStatus>`，返回实际网卡名、if_index、route_scope、fake-ip 数量与 `stats()` 四元组
  - [x] SubTask 3.3: `TunManager` 记录实际网卡名与 if_index，测试覆盖未启用时为 `None`

- [x] Task 4: 日志页增强（`ui/pages/logs.rs`）
  - [x] SubTask 4.1: 顶部工具栏新增级别下拉（ALL/INFO/WARN/ERROR/DEBUG）、搜索输入框
  - [x] SubTask 4.2: 展示时按「级别 + 关键字（大小写不敏感）」过滤，保留原始 entries
  - [x] SubTask 4.3: 新增「导出」按钮：写当前筛选结果到 exports，并显示路径与复制操作
  - [x] SubTask 4.4: 新增「生成诊断包」按钮：收集版本/系统/配置（密码脱敏）/路由表/日志尾部/诊断结果后写文件并显示路径

- [x] Task 5: 诊断页面与导航（`ui/pages/diagnostics.rs`、`ui/app.rs`、`ui/pages/mod.rs`）
  - [x] SubTask 5.1: 新建 `DiagnosticsPage`：运行按钮、运行中状态、结果列表（名称/状态徽标/说明）、复制全部
  - [x] SubTask 5.2: `Page` 枚举与 `NAV_ITEMS` 增加「诊断」，图标 `shield-alert-outline`
  - [x] SubTask 5.3: 首次进入不自动运行；切换页面保留上次结果（App 持有 Entity）

- [x] Task 6: 文案（`assets/i18n/{zh-cn,en}.json`）
  - [x] SubTask 6.1: 日志页：筛选、搜索占位符、导出、诊断包、路径提示、复制成功
  - [x] SubTask 6.2: 诊断页：导航标题、五项检查名与状态、运行/复制

- [x] Task 7: 验证
  - [x] SubTask 7.1: `cargo check -p ssl-proxy-gui`（无 warning）
  - [x] SubTask 7.2: `cargo test -p ssl-proxy-gui`（131 passed）
  - [x] SubTask 7.3: 人工核对：筛选/搜索叠加、导出与诊断包生成路径、诊断五项状态、非 Windows 行为（按代码路径核对）

# Task Dependencies

- Task 2 依赖 Task 1（复用导出与日志读取）
- Task 4 依赖 Task 1、Task 2
- Task 5 依赖 Task 2
- Task 3 与 Task 1/2 无依赖，可并行
- Task 6 依赖 Task 4、Task 5 的文案需求
- Task 7 依赖 Task 1-6
