# Tasks

- [x] Task 1: 扩展 TUN 配置模型（`core/tun/config.rs`）
  - [x] SubTask 1.1: 新增 `TunRouteScope` 枚举（`Global` 默认 / `FakeIp`，serde 值 `global` / `fake-ip`）
  - [x] SubTask 1.2: `TunConfig` 新增 `route_scope`、`udp_timeout: u64`（默认 120）、`max_connections: usize`（默认 0）
  - [x] SubTask 1.3: `validate()` 校验 `udp_timeout` 范围（10..=86400）与 `max_connections`（<= 65535）
  - [x] SubTask 1.4: 补充 serde 反序列化与 validate 单测

- [x] Task 2: 路由程序支持 `route_scope`（`core/tun/routes.rs`）
  - [x] SubTask 2.1: `build_program` 在 `Global` 下保持 `/1` 拆分 + 例外逻辑
  - [x] SubTask 2.2: `FakeIp` 下只生成 fake-ip 网段一条路由（由 `fake_ip_range` 解析 network/prefix），up/down 对称
  - [x] SubTask 2.3: 单测覆盖两种模式（global 两条 `/1`；fake-ip 只有一条且无 `/1`、无私网例外）

- [x] Task 3: 协议栈读取配置上限（`core/tun/netstack.rs`）
  - [x] SubTask 3.1: `reap_closed` 的 UDP 空闲 TTL 改用 `core.cfg.udp_timeout`
  - [x] SubTask 3.2: 新建 TCP/UDP socket 前检查 `cfg.max_connections`（0 = 不限），达到上限直接丢弃
  - [x] SubTask 3.3: 保留现有 1024 告警阈值作为观测，不改为硬上限

- [x] Task 4: 网卡名冲突轮转（`core/tun/device.rs` + `runner.rs`）
  - [x] SubTask 4.1: `open` 内部按 `设备名`、`设备名-1`、`设备名-2` 依次尝试创建适配器
  - [x] SubTask 4.2: 成功时 `TunDevice.name` 使用实际名称，并记录「名称被占用，改用 X」日志
  - [x] SubTask 4.3: `runner::start` 的路由快照与日志改用 `tun_dev.name` 而非 `cfg.device_name`

- [x] Task 5: 设置页与文案（`ui/pages/settings.rs` + i18n）
  - [x] SubTask 5.1: TUN 卡片新增「路由范围」选择控件（复用现有 Select 组件）
  - [x] SubTask 5.2: 新增 UDP 空闲超时、最大连接数输入框，保存时写回 `TunConfig`
  - [x] SubTask 5.3: `zh-cn.json` / `en.json` 增加对应标题、提示与选项文案

- [x] Task 6: 验证
  - [x] SubTask 6.1: `cargo check -p ssl-proxy-gui`
  - [x] SubTask 6.2: `cargo test -p ssl-proxy-gui tun`
  - [x] SubTask 6.3: 核对设置页三项控件可读写、保存后重启生效（代码路径核对：控件初始化 → collect_config 读取 → 保存后重启）

# Task Dependencies

- Task 2 依赖 Task 1（需要 `route_scope` 字段）
- Task 3 依赖 Task 1（需要 `udp_timeout` / `max_connections`）
- Task 5 依赖 Task 1（需要配置字段）
- Task 4 与 Task 1/2/3 无依赖，可并行
- Task 6 依赖 Task 1-5
