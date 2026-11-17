# Checklist

- [x] `TunConfig` 含 `route_scope` / `udp_timeout` / `max_connections`，默认值分别为 `global` / `60` / `256`
- [x] `routeScope` 的 serde 取值为 `global` 与 `fake-ip`，旧配置文件缺少该字段时按 `global` 解析
- [x] `validate()` 拒绝超出范围的 `udp_timeout` 与 `max_connections`
- [x] `routeScope=global` 生成 `0.0.0.0/1` + `128.0.0.0/1` 两条 TUN 路由，down 对称
- [x] `routeScope=fake-ip` 只生成 fake-ip 网段一条 TUN 路由，不含 `/1`、不含私网例外
- [x] UDP 空闲回收使用配置的 `udpTimeout`（默认 60 秒），不再是硬编码值
- [x] `maxConnections > 0` 时达到上限后新的 TCP/UDP 流不再创建 socket；`0` 时不限制
- [x] 网卡名冲突时依次尝试 `名称-1` … `名称-4`（每次间隔 500ms），成功后日志与路由快照使用实际名称
- [x] 五次创建都失败时返回错误并保持 fail-closed（无残留路由）
- [x] `autoRoute=false` 时不安装任何路由，也不写崩溃恢复快照
- [x] 设置页 TUN 卡片含「路由范围 / UDP 空闲超时 / 最大连接数」三项，中英文文案齐全
- [x] `cargo check -p ssl-proxy-gui` 通过
- [x] `cargo test -p ssl-proxy-gui tun` 全部通过（含路由范围、auto-route 开关与配置校验新增单测）
- [x] 非 Windows 平台仍不渲染 TUN 卡片、不启动 TUN（回归）
