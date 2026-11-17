# 继续移植 meow-rs TUN（Windows）Spec

## Why

2.6.0 的 TUN 数据面已跑通，但与 meow-rs 相比仍缺三块控制面能力：可选的「只路由 fake-ip 段」模式、可配置的连接/UDP 回收上限、以及网卡名冲突时的重试。补齐后行为与 meow-rs 的 Windows 实现基本对齐，也减少长时间运行与多实例场景下的故障。

## What Changes

- `TunConfig` 新增三个字段：
  - `routeScope`：`global`（默认，现状：整机流量进 TUN）或 `fake-ip`（只把 fake-ip 网段路由进 TUN）
  - `udpTimeout`：UDP 会话空闲回收秒数，默认 60
  - `maxConnections`：TUN 内并发 socket 上限，默认 256（0 表示不限）
- 路由生成按 `routeScope` 分流：`global` 保持两条 `/1`；`fake-ip` 只下发 fake-ip 网段的 TUN 路由，不写私网/代理例外。
- 协议栈回收与限流改为读取配置：UDP 空闲 TTL 用 `udpTimeout`，新建 socket 前检查 `maxConnections`。
- 设备层网卡名冲突时按 meow-rs 方式重试 `名称-1` … `名称-4`（最多 5 次，每次间隔 500ms），路由快照与日志使用实际使用的网卡名。
- 设置页 TUN 卡片新增「路由范围」「UDP 空闲超时」「最大连接数」三个控件及中英文文案。

## Impact

- 影响能力：Windows TUN 控制面、路由安装、协议栈资源回收、设置页
- 影响代码：
  - `crates/gui/src/core/tun/config.rs`
  - `crates/gui/src/core/tun/routes.rs`
  - `crates/gui/src/core/tun/netstack.rs`
  - `crates/gui/src/core/tun/device.rs`
  - `crates/gui/src/core/tun/runner.rs`
  - `crates/gui/src/ui/pages/settings.rs`
  - `crates/gui/assets/i18n/{zh-cn,en}.json`
- 不影响：SOCKS5/HTTP 代理路径、服务端、macOS 平台（TUN 已隐藏）

## ADDED Requirements

### Requirement: TUN 路由范围

系统 SHALL 支持 `tun.routeScope` 的两种取值，并按取值生成不同的路由程序。

#### Scenario: global 模式（默认）

- **WHEN** `routeScope = global`
- **THEN** 安装 `0.0.0.0/1` 与 `128.0.0.0/1` 指向 TUN 网关，并按 `strictRoute` 决定是否追加私网例外；退出时对称删除

#### Scenario: fake-ip 模式

- **WHEN** `routeScope = fake-ip`
- **THEN** 只安装 fake-ip 网段（由 `fakeIpRange` 推导 network/prefix）指向 TUN 网关的一条路由，不安装 `/1` 拆分路由与私网例外；退出时删除该路由

### Requirement: TUN 资源上限

系统 SHALL 允许配置 UDP 空闲回收时间与并发 socket 上限。

#### Scenario: UDP 空闲回收

- **WHEN** UDP 会话空闲时间超过 `udpTimeout` 秒
- **THEN** 回收该 socket，后续报文重新建会话

#### Scenario: 连接数上限

- **WHEN** `maxConnections > 0` 且当前 TUN socket 数已达到上限
- **THEN** 新的入站 TCP/UDP 流不再创建 socket（直接丢弃），已有连接不受影响
- **AND WHEN** `maxConnections = 0` 则不限制

### Requirement: TUN 网卡名冲突轮转

系统 SHALL 在按配置名创建网卡失败时尝试带后缀的名称。

#### Scenario: 名称被占用

- **WHEN** 以 `SSLProxy` 创建 TUN 网卡失败（已存在/被占用）
- **THEN** 依次尝试 `SSLProxy-1`、`SSLProxy-2`，成功则使用该名称
- **AND** 路由快照、崩溃恢复、日志均记录实际使用的网卡名
- **AND** 三次都失败时按 fail-closed 回滚并返回错误

## MODIFIED Requirements

### Requirement: TUN 设置面板

面板 SHALL 在原有开关、设备名、MTU、fake-ip 池、DNS 劫持、路由排除、直连 DNS 之外，新增：

- 路由范围选择（global / fake-ip）
- UDP 空闲超时（秒）
- 最大连接数（0 = 不限）

保存后随配置重启生效，沿用现有 TUN 卡片与 i18n 机制。

## REMOVED Requirements

无。
