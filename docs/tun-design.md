# TUN 模式方案研究：Windows 平台

> 状态：方案研究（未实施）
> 适用版本：gui 2.3.x / svr 1.2.x 之后
> 关联文档：[udp-design.md](./udp-design.md)

---

## 1. 背景

当前产品形态是"本地代理端口"：

```text
应用 ──▶ 127.0.0.1:1080（SOCKS5 / HTTP）
          ├─ 规则匹配 ──▶ 直连
          └─ TLS 隧道（私有协议帧 + UDP 帧）──▶ svr ──▶ 目标
```

不走系统代理的软件（部分游戏、Electron 客户端、命令行工具、UWP 应用）无法被接管。
TUN 模式通过一层 L3 虚拟网卡接管全部 IP 流量，再复用现有分流与隧道，从而解决这个问题。

**核心问题**：TUN 的接入成本、Windows 上的系统集成复杂度，以及是否值得做成产品能力。

---

## 2. 结论摘要

TUN 的代码本身不复杂，复杂的是 Windows 的系统集成与权限模型：

| 阶段 | 范围 | 估算 |
| ---- | ---- | ---- |
| POC | IPv4 TCP、手动路由、管理员运行、无 DNS | 2~4 人日 |
| MVP | 自动路由、DNS（fake-ip / 劫持）、UDP、环路规避、异常清理 | 2~3 周 |
| 产品级 | Service Mode、安装器、VPN/多网卡共存、崩溃恢复 | 1.5~2 个月 |

结论：**值得先做 POC 验证体验，但不建议直接上产品级 TUN**。若目标只是打磨现有代理体验，TUN 的支持成本（断网、杀软、VPN 冲突）高于代码成本。

---

## 3. 竞品实现拆解（Clash for Windows / mihomo / sing-box）

Windows 上的 TUN 基本是同一套答案，CFW 的实现可以拆成 6 件事：

| # | 组成 | 说明 |
| - | ---- | ---- |
| 1 | **Service Mode** | GUI 安装一个以管理员身份运行的 Windows 服务，TUN、路由、DNS 都由服务执行；否则整个 GUI 必须以管理员启动 |
| 2 | **Wintun 驱动** | 把 `wintun.dll` 放到程序目录，创建 L3 虚拟网卡，典型地址 `198.18.0.1/16` |
| 3 | **auto-route** | 自动改系统路由表把默认流量导向虚拟网卡，同时识别物理出口网卡；**代理服务器 IP 必须指回原网关**，否则隧道流量会再次被 TUN 抓走形成环路 |
| 4 | **DNS** | 推荐 `fake-ip` + `dns-hijack`（劫持 `198.18.0.2:53`）；只做 TUN 不做 DNS，系统拿到真实 IP，按域名分流直接失效；浏览器"安全 DNS"会绕过劫持 |
| 5 | **协议栈** | Windows 上使用用户态栈（gvisor）；`system` 栈在 Windows 意义不大。TCP 需要从原始 IP 包还原成流，UDP 还原成数据报 |
| 6 | **收尾** | 防火墙放行、`fake-ip-filter` 放过微软连通性探测域名、退出/崩溃时恢复路由与 DNS |

CFW 参考配置（Windows）：

```yaml
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
  fake-ip-filter:
    - "dns.msftncsi.com"

tun:
  enable: true
  stack: gvisor
  dns-hijack:
    - 198.18.0.2:53
  auto-route: true
  auto-detect-interface: true
```

注意：CFW 已停更，现代实现可对照 mihomo / sing-box，但骨架一致。

---

## 4. 本项目落地方案

### 4.1 技术选型

| 能力 | 选型 | 说明 |
| ---- | ---- | ---- |
| TUN 设备 | `tun-rs` | 跨平台，Windows 走 wintun，支持 async、多地址、MTU、DNS 配置 |
| 用户态协议栈 | `netstack-smoltcp` | 提供 tokio 风格的 `TcpListener` / `TcpStream` / `UdpSocket`，把 TUN 包还原成流/数据报 |
| Windows 系统调用 | `windows` crate（已有） | 路由、接口、DNS、服务管理 |
| 驱动分发 | `wintun.dll` | 预编译签名版允许随软件分发；源码为 GPLv2，随包附 LICENSE 即可，无需自行签名 |

### 4.2 目标架构

```text
应用 ──▶ Wintun 网卡（198.18.0.1/16）
             │  原始 IP 包
             ▼
        netstack-smoltcp（TCP 流 / UDP 五元组）
             │
             ├─ 规则匹配 ──▶ 直连（复用 resolve_and_connect）
             └─ 代理 ──▶ 现有 TLS 隧道 / mux / UDP relay ──▶ svr ──▶ 目标
```

### 4.3 可复用资产

- `core/proxy/connect.rs::resolve_and_connect`：DNS、GEO、规则分流、直连/代理决策
- `core/proxy/tunnel.rs::forward_target_stream`：双向转发与流量统计
- `core/proxy/mux.rs`：mux 流复用
- `core/proxy/udp_relay.rs`：UDP 会话表、空闲回收、统计

TUN 侧只需要把 `TcpStream` 换成 netstack 提供的流，把 UDP 数据报按五元组建立会话，
**服务端不需要任何改动**（单 TLS 端口 + UDP over TLS 已就绪）。

### 4.4 建议新增模块

```text
crates/gui/src/core/tun/
├── mod.rs       # 启停、状态、错误回滚
├── device.rs    # tun-rs 设备创建与事件循环
├── stack.rs     # netstack-smoltcp 对接（accept / recv_from）
├── router.rs    # 路由表、接口 metric、代理服务器 IP 绕行
└── dns.rs       # fake-ip 映射或本地 53 劫持
```

后续产品化再补：

```text
crates/gui/src/platform/service.rs   # Service Mode（Windows 服务 + 命名管道 IPC）
```

### 4.5 配置项（建议）

```yaml
tunMode: "off"      # off | on
tunStack: "smoltcp" # 预留：smoltcp | system
tunAutoRoute: true
tunDnsHijack: true
tunFakeIpRange: "198.18.0.1/16"
```

---

## 5. 关键风险与对策

| 风险 | 影响 | 对策 |
| ---- | ---- | ---- |
| 提权模型变化 | 从"本地代理"变成"系统级 VPN"，用户信任与杀软误报成本上升 | 独立开关 + 明确提示；后续用 Service Mode 降权 |
| 路由/DNS 未恢复导致断网 | 高（用户直接失联） | 进程内 finally 恢复 + 独立 watchdog + 启动时清理残留路由 |
| 隧道流量被 TUN 二次捕获 | 环路，全部流量瘫痪 | 代理服务器 IP 走物理网卡；`auto-detect-interface` 绑定出口网卡 |
| 只做 TUN 不做 DNS | 无法按域名分流，规则体系失效 | 一期就上 fake-ip 或 53 劫持；放行连通性探测域名 |
| IPv6 / 双栈 | Windows IPv6 处理复杂，易出兼容问题 | 一期仅 IPv4，或显式禁用 TUN 下的 IPv6 |
| 性能 | smoltcp 单栈吞吐有限 | 先测速；不达标再评估 GSO / 多队列（仅 Linux）或 WFP 重定向 |
| 企业 VPN / 虚拟机网卡共存 | 路由冲突、间歇性断流 | MVP 阶段加"不接管网段"排除配置 |
| 驱动分发 | 合规风险 | 随包附带 `wintun.dll` 与其 LICENSE，不自签驱动 |

---

## 6. 实施拆分建议

1. **P0（POC）**：`tun-rs + netstack-smoltcp`，仅 IPv4 TCP；手写 `0.0.0.0/1 + 128.0.0.0/1` 路由与代理服务器 IP 绕行；入口直接复用 `resolve_and_connect`。验收标准：浏览器关闭系统代理后能正常上网。
2. **P1（MVP）**：DNS（fake-ip 或 53 劫持）、UDP 会话（复用 `udp_relay`）、自动路由与接口检测、退出/崩溃清理。
3. **P2（产品化）**：Service Mode + 安装器、UI 开关与状态、故障回滚提示、与 VPN 共存、性能验证。

P0 与 P1 可分开发版；P0 只解决"能不能用"，P1 才解决"能不能日常用"。

---

## 7. 待确认问题

1. TUN 下 UDP 是否复用现有 `udp_relay` 的会话键（目标 host:port），还是改成五元组键？后者更贴近 UDP 语义，但需要改会话表结构。
2. 是否需要在 TUN 模式下继续监听本地 SOCKS5/HTTP 端口（共存），还是二选一？
3. 分流维度是否要扩展为"进程级"（需要额外拿 PID/路径，Windows 上成本较高）？
4. Service Mode 的 IPC 采用命名管道还是本地 HTTP，是否需要鉴权？

---

## 8. 参考

- [TUN Device | Clash Knowledge](https://en.clash.wiki/premium/tun-device.html)
- [Clash for Windows 文档 — TUN 模式](https://doc.clashforwindows.app/tun/)
- [Wintun – Layer 3 TUN Driver for Windows](https://www.wintun.net/)
- [sing-box — Tun inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [netstack-smoltcp — crates.io](https://crates.io/crates/netstack-smoltcp)
- [tun-rs — docs.rs](https://docs.rs/tun-rs/latest/tun_rs/)
