# 日志工具与内置诊断 Spec

## Why

当前日志页只能看到 `app.log` 最后 5000 个字符，无法按级别筛选、搜索或导出；排障（尤其 TUN / DNS）只能靠翻日志。本批先落地「日志页增强」与「内置诊断」两项，后续再按顺序推进连接列表、TUN 收尾与 UDP。

## What Changes

- 日志页：级别过滤（ALL / INFO / WARN / ERROR / DEBUG）、关键字搜索、导出当前筛选结果、一键生成诊断包
- Core：新增按大小截取的日志读取（默认 2 MB）与导出/诊断文件写入（`<config_dir>/exports/`）
- 新增 `core/diagnostics.rs`：五项内置检查 —— 本地代理端口、上游连通性、DNS 解析、IPv4 路由表、TUN 自检
- 新增「诊断」页面与侧边栏入口：一键运行、逐项展示状态（通过 / 警告 / 失败 / 信息）、复制结果
- TUN 侧暴露只读状态：实际网卡名、ifIndex、路由范围、fake-ip 映射数量、socket 统计
- 新增中英文案（日志筛选、导出、诊断项与状态）

## Impact

- 影响能力：日志查看、故障诊断、TUN 可观测性
- 影响代码：
  - `crates/gui/src/core/mod.rs`（`read_logs_tail`、导出入口）
  - `crates/gui/src/core/diagnostics.rs`（新增）
  - `crates/gui/src/core/tun/runner.rs`、`netstack.rs`（只读状态）
  - `crates/gui/src/ui/pages/logs.rs`、`crates/gui/src/ui/pages/diagnostics.rs`（新增）
  - `crates/gui/src/ui/app.rs`（新增页面与导航项）
  - `crates/gui/src/ui/pages/mod.rs`
  - `crates/gui/assets/i18n/{zh-cn,en}.json`
- 不影响：代理数据面、SOCKS5/HTTP 行为、服务端

## ADDED Requirements

### Requirement: 日志级别过滤与搜索

日志页 SHALL 支持按级别筛选和关键字搜索，二者可叠加，且只影响展示，不修改 `app.log`。

#### Scenario: 只看错误

- **WHEN** 用户在级别下拉中选择 `ERROR`
- **THEN** 列表只展示 ERROR 行，其他级别隐藏

#### Scenario: 关键字搜索

- **WHEN** 用户在搜索框输入 `TUN`
- **THEN** 列表只展示消息包含该关键字的行（大小写不敏感），与级别筛选同时生效

### Requirement: 日志读取与导出

系统 SHALL 支持读取较大的日志尾部，并把当前筛选结果导出为文本文件。

#### Scenario: 导出筛选结果

- **WHEN** 用户点击「导出」
- **THEN** 在 `<config_dir>/exports/logs-<yyyyMMdd-HHmmss>.txt` 写入当前筛选后的行
- **AND** 页面显示导出文件完整路径，并支持点击复制

#### Scenario: 日志过长

- **WHEN** `app.log` 大于 2 MB
- **THEN** 只读取最后 2 MB，并保证不截断 UTF-8 字符

### Requirement: 一键诊断包

系统 SHALL 生成一个包含运行环境、配置（已脱敏）、路由表、日志尾部与诊断结果的文本文件。

#### Scenario: 生成诊断包

- **WHEN** 用户点击「生成诊断包」
- **THEN** 写入 `<config_dir>/exports/diagnostics-<yyyyMMdd-HHmmss>.txt`
- **AND** 文件包含：客户端版本、操作系统与架构、TUN 状态、脱敏后的 `setting.yaml`、IPv4 路由表、最近 2000 行日志、本次五项检查结果
- **AND** 认证密钥（`proxy_password`）以 `***` 替换

### Requirement: 内置诊断

诊断页 SHALL 提供五项检查，每项返回状态（Pass / Warn / Fail / Info）与可读说明，运行过程不得阻塞 UI。

#### Scenario: 本地代理端口

- **WHEN** 运行诊断
- **THEN** 尝试连接 `127.0.0.1:<socks_port>`：可连接为 Pass，否则 Fail 并提示代理未启动

#### Scenario: 上游连通性

- **WHEN** 配置了 `proxy_server:proxy_port`
- **THEN** 3 秒内完成 TCP 连接为 Pass，超时或拒绝为 Fail；未配置上游时为 Info

#### Scenario: DNS 解析

- **WHEN** 运行诊断
- **THEN** 用当前 DNS 配置解析一个固定测试域名，报告解析结果与耗时；失败为 Fail

#### Scenario: 路由表

- **WHEN** 运行诊断（Windows）
- **THEN** 执行 `route print -4`，报告默认路由条数、是否存在 TUN 网段路由；执行失败为 Warn

#### Scenario: TUN 自检

- **WHEN** TUN 未启用
- **THEN** 返回 Info（未启用）；启用时报告实际网卡名、ifIndex、路由范围、fake-ip 数量与 socket 统计，任一异常（如 fake-ip 为 0）为 Warn

## MODIFIED Requirements

### Requirement: 日志页布局

日志页顶部 SHALL 由「标题 + 刷新」扩展为「标题 + 级别下拉 + 搜索框 + 导出 + 生成诊断包 + 刷新」，窄窗口下允许换行；列表保持可滚动、点击行复制。

## REMOVED Requirements

无。

## 后续批次（本 Spec 不包含）

1. 连接列表增强：搜索 / 排序 / 按规则与进程过滤（含进程名采集）
2. TUN 收尾：DNS guard、IPv6 数据面、fake-ip LRU、Windows Service
3. UDP：会话限速、QUIC 统计
