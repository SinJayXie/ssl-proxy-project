# Checklist

- [x] `read_logs_tail` 在 2 MB 上限下只返回尾部，且不切断多字节 UTF-8 字符
- [x] `read_logs()` 行为与原先一致（最后 5000 字符）
- [x] 导出文件写入 `<config_dir>/exports/logs-*.txt`，内容等于当前筛选结果
- [x] 日志页支持级别筛选（ALL/INFO/WARN/ERROR/DEBUG）
- [x] 日志页支持关键字搜索，大小写不敏感，且可与级别叠加
- [x] 导出/诊断包完成后页面显示完整路径，可复制
- [x] 诊断包包含版本、系统、TUN 状态、脱敏配置、IPv4 路由表、最近 2000 行日志、诊断结果
- [x] 诊断包中 `proxy_password` 显示为 `***`
- [x] 五项检查均返回 Pass/Warn/Fail/Info 之一与说明文字
- [x] TUN 未启用时「TUN 自检」返回 Info；启用时展示网卡名、ifIndex、route scope、fake-ip 数量与 socket 统计
- [x] 非 Windows 平台上路由表检查不 panic，返回 Info 或 Warn
- [x] 诊断运行期间 UI 不阻塞（诊断在 Core 的 tokio runtime 执行，UI 侧 await JoinHandle）
- [x] 侧边栏新增「诊断」入口，可正常切换并保留上次结果
- [x] 中英文文案齐全（25 个新增 key 均存在）
- [x] `cargo check -p ssl-proxy-gui` 通过（无 warning）
- [x] `cargo test -p ssl-proxy-gui` 全部通过（131 passed）
