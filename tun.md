# TUN 安全分流与 Trojan 出站实现研究

> 研究对象：
>
> - `E:\clash-verge-rev-dev`：Clash Verge Rev 外壳、配置生成与权限护栏
> - `E:\clash-verge-rev-dev\mihomo`：`MetaCubeX/mihomo` 的 `Meta` 分支源码，commit `0455d0d28c4526937380505153e65a843d8612e8`
>
> 迁移目标：`E:\myProjects\ssl-proxy-project`
>
> 结论先行：Clash Verge Rev **不直接创建 TUN 网卡、不直接写系统路由、也不直接实现 Trojan 协议**。它是「配置生成器 + 提权启动器 + 状态护栏」；TUN 网卡、路由、DNS 劫持、规则匹配与 Trojan 出站都由外部 **Mihomo（MetaCubeX/mihomo）内核**完成。Verge 的价值在于把这些能力安全地包装成可配置、可审计、可回退的桌面应用行为。第 12 节基于已切换的 `Meta` 分支源码，实证分析内核侧 TUN 的真实实现与 Rust 移植方案。

---

## 1. 研究边界与证据等级

本文区分三类结论：

| 等级 | 含义 | 来源 |
|---|---|---|
| **A：本仓库实证** | 可在 `clash-verge-rev-dev` 源码中直接定位 | Rust/TypeScript 文件、配置模板、Tauri 命令、构建脚本 |
| **B：内核惯例/机制推导** | 由 Verge 生成的配置字段可推出内核必须完成的行为 | Mihomo/Clash 通用语义、TUN/策略路由/Trojan 协议通用实现 |
| **C：迁移建议** | 面向 `ssl-proxy-project` 的设计取舍 | 结合目标项目现有 SOCKS5/HTTP + TLS 私有协议架构推导 |

Verge 主仓库不包含 Mihomo 内核源码：没有 `go.mod`/`*.go`，没有 `.gitmodules`，没有 `sidecar/` 实体，Tauri 只声明外部二进制 `sidecar/verge-mihomo` 与 `sidecar/verge-mihomo-alpha`。内核从 GitHub Release 动态下载：

- `e:/clash-verge-rev-dev/scripts/prebuild.mjs:162-198`：Mihomo release/alpha 下载 URL 与平台资产名。
- `e:/clash-verge-rev-dev/scripts/prebuild.mjs:274-298`：sidecar 命名与下载链接拼接。
- `e:/clash-verge-rev-dev/src-tauri/tauri.conf.json:17`：`externalBin` 声明外部内核。
- `e:/clash-verge-rev-dev/src-tauri/src/feat/core_upgrade.rs:25-27, 448-465`：应用内升级与版本读取。

后来已在独立目录 `e:/clash-verge-rev-dev/mihomo` 检出 `MetaCubeX/mihomo` 的 `Meta` 分支；本文第 12 节基于该源码分析内核侧 TUN 实现。即便如此，**在 Verge 主仓库里仍然找不到** `CreateUnicastIpAddress`、`route add`、`trojan` 拨号等实现；它们属于 `mihomo` 及其外部依赖 `sing-tun`。

---

## 2. 总体架构：两张数据面，一套规则引擎

Verge 同时支持两条流量入口：

```text
入口 1：系统代理（用户态 socket 代理）
App ──OS proxy──▶ 127.0.0.1:mixed-port ──▶ Mihomo rule engine ──▶ DIRECT / Trojan outbound

入口 2：TUN（网卡层拦截）
App ──IP packet──▶ TUN 虚拟网卡 ──▶ Mihomo user-space stack ──▶ rule engine ──▶ DIRECT / Trojan outbound
```

关键点：

- **系统代理模式**只接管“愿意遵守系统代理设置”的应用；绕过代理的应用、raw socket、部分游戏/工具不会进入代理。
- **TUN 模式**在网络层接管 IP 包，覆盖面更广；但需要管理员/Service 权限创建网卡与改路由。
- 两种模式最终都进入同一个 Mihomo 规则引擎和出站体系；区别只是“包如何进入内核”。

Verge 中 TUN 与系统代理是独立开关：

- `src-tauri/src/config/verge.rs:80,86-101`：`enable_tun_mode`、`enable_system_proxy`、`enable_proxy_guard`、`enable_bypass_check`、`use_default_bypass`、`system_proxy_bypass`。
- `src/components/shared/proxy-control-switches.tsx:149-168,196-234`：UI 开关与 TUN 可用性检查。
- `src/components/home/proxy-tun-card.tsx:137-249`：首页代理/TUN 切换卡。

---

## 3. TUN 安全分流：谁创建网卡，谁决定“直连/代理”

### 3.1 Verge 生成的最小 TUN 配置

默认模板在 `src-tauri/src/config/clash.rs:56-114`；常量在 `src-tauri/src/constants.rs:70-89`。

```yaml
tun:
  enable: false
  stack: mips                  # system / gvisor / mixed / mips
  auto-route: true
  strict-route: false
  auto-detect-interface: true
  dns-hijack:
    - any:53
  mtu: 1500
  # route-exclude-address: []
```

字段含义：

| 字段 | Verge 默认值 | 作用 |
|---|---|---|
| `enable` | `false` | 总开关，由 `enable_tun_mode` 写入运行时配置 |
| `stack` | `mips` | 用户态 TCP/IP 栈；Windows 常用 gvisor/mixed/mips，system 更贴近系统栈 |
| `auto-route` | `true` | 内核自动把全网段路由指向 TUN，实现“全局拦截” |
| `auto-detect-interface` | `true` | 内核探测带默认网关的物理网卡，作为 DIRECT 出口 |
| `route-exclude-address` | `[]` | 排除网段：这些网段不进 TUN，直接按系统原路由走物理网卡 |
| `strict-route` | `false` | 严格路由，配合策略路由降低绕过风险 |
| `dns-hijack` | `any:53` | 劫持 53 端口 DNS 到内核 DNS 模块 |
| `mtu` | `1500` | TUN MTU |
| `auto-redirect` | Linux only | iptables/nftables 重定向，非 root 不可用 |

前端 TUN 参数面板：`src/components/setting/mods/tun-viewer.tsx:42-415`；其中 `36-70,388-411` 做 CIDR 校验，`139-144` 保存后调用 `enhanceProfiles()`。

### 3.2 开启 TUN 时强制修正 DNS

`src-tauri/src/enhance/tun.rs:10-55` 的 `use_tun(config, enable)` 逻辑：

1. 写 `tun.enable`。
2. 如果启用且 DNS 为 fake-ip：
   - 强制 `dns.enable = true`；
   - IPv4 fake-ip 段固定为 `198.18.0.1/16`；
   - IPv6 开启时补 `fake-ip-range6: 2001:2::0/64`。

这是防 DNS 泄漏的关键：TUN 拦截所有流量后，DNS 也必须在内核里被解析并进入规则系统，否则会出现“IP 走代理、域名解析走本地 ISP”的泄漏。

`src-tauri/src/enhance/mod.rs:711-798` 还负责合并 DNS 配置与补齐 IPv6 fake-ip 段，注释关联 #7373（AAAA 解析问题）。

### 3.3 防止订阅脚本覆盖安全字段

`src-tauri/src/enhance/mod.rs:294-493` 定义了 `AuthoritativeFields`。Verge 管理的 `tun`/DNS/控制面字段不允许被订阅的 merge/script 覆盖，并给出 `discarded_note`。

`src-tauri/src/enhance/field.rs:4-19` 中明确列出的强控制字段包括：

```text
mode, redir-port, tproxy-port, mixed-port, socks-port,
port, allow-lan, log-level, ipv6, external-controller,
secret, unified-delay
```

以及默认资源字段：

```text
proxies, proxy-providers, proxy-groups, rule-providers, rules
```

意义：订阅源不可信；如果允许订阅脚本改写 `tun.enable`、`dns-hijack`、`auto-detect-interface`，就能把安全分流降级成透明全局代理或关闭防泄漏。

---

## 4. 权限与启动链：TUN 不是“点一下开关”就行

### 4.1 能力门控（fail-closed）

`src-tauri/src/core/runstate/health.rs:61-102`：

- `tun_capable() = is_admin || service_usable()`
- `tun_should_be_disabled()`：无 Service 且非管理员时为真。
- `startup_tun_should_be_disabled()`：启动时同样检查。

`src-tauri/src/feat/tun.rs:21-86`：

- `reconcile_startup_tun_availability()` / `reconcile_tun_availability()` 在状态不满足时调用 `disable_tun_and_persist()` 或发 `TunModeAutoDisabled` 通知。

`src-tauri/src/core/manager/state.rs:29-44`：

- Windows 非管理员 sidecar 启动时，`sidecar_config_without_tun()` 强制把运行时配置里的 `tun.enable` 改为 `false`。

前端也 fail-closed：`src/hooks/use-system-state.ts:21-38` 的 `isTunModeAvailable = runState.tunCapable`；未知状态按不可用处理。

### 4.2 提权路径

Verge 有两条启动内核路径：

```text
sidecar（管理员）：
  manager/state.rs:162-219 start_core_by_sidecar()
  → -f <runtime.yaml> -ext-ctl-pipe/unix <ipc>

service（SYSTEM）：
  core/service.rs:991-1001 run_core_by_service()
  → IPC start_clash(config_path, core_path, session_token)
  → Windows Service 以 SYSTEM 启动内核
```

服务安装/修复：`src-tauri/src/core/service.rs:606-628,737-787,907-988`；命令入口：`src-tauri/src/cmd/service.rs:84-118`。

服务模式下还有二进制完整性校验：`src-tauri/src/core/service.rs:789-830` 的 `stage_approved_core` 用 SHA-256 钉住内核字节，只允许管理员批准目录中的内核被执行，防止二进制替换攻击。

### 4.3 完整开关调用链

```text
UI 开关 proxy-control-switches.tsx / proxy-tun-card.tsx
  → patchVerge({ enable_tun_mode })                    [cmds.ts:203]
  → patch_verge_config                                  [cmd/verge.rs:17-27]
  → patch_verge + reconcile_tun_availability            [feat/config.rs:17-26]
  → Effect::Tun → ClashConfig + Tray*                    [feat/effects.rs:72]
  → update_config_in_patch                               [feat/executor.rs:47-108]
  → Config::generate() → enhance() → use_tun()          [enhance/mod.rs:858]
  → validate -t -f                                      [core/validate.rs:350-375]
  → write runtime.yaml                                  [config/config.rs:225-229]
  → reload_config(true, path) 或 restart_core           [core/manager/config.rs:386-468]
  → Mihomo 创建 TUN / 写路由 / 劫持 DNS / 应用规则
```

切换 TUN 时还会按 `auto_close_connection` 关闭已有连接，避免旧连接绕过新策略：`src-tauri/src/feat/proxy.rs:19-97`。

---

## 5. 直连为什么走物理网卡，代理为什么进 Trojan

### 5.1 TUN 下“直连走物理网卡”的两种机制

#### 机制 A：路由排除（`route-exclude-address`）

工作在 **IP 层**。内核把排除网段从 TUN 路由中剔除，系统保留原物理网卡路由。

```text
访问 192.168.1.10
  → 命中系统物理网卡路由（192.168.1.0/24 dev Ethernet）
  → 不进入 Mihomo TUN
  → 不经过 Trojan
```

Verge 负责让用户填写 CIDR 并校验格式；真正不写这些路由的是 Mihomo 内核。

适用场景：

- 局域网设备、打印机、NAS、路由器管理页；
- 内网服务发现；
- 不需要被代理审计的私有网段。

风险：排除网段内的域名解析若仍被 TUN DNS 接管，可能出现“域名假 IP、直连路由不通”的不一致，须配合 DNS 规则处理。

#### 机制 B：规则判定 DIRECT（`auto-detect-interface`）

工作在 **连接/规则层**。所有 IP 包先进入 TUN，然后 Mihomo 按 `rules` 判断：

```yaml
rules:
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
```

命中 DIRECT 后，内核使用 `auto-detect-interface` 探测到的物理默认网卡建立 **新的原生 socket**：

```text
App → TUN → Mihomo stack → rule = DIRECT → 物理网卡 socket → 目标
```

注意：这里并不是把原 TUN 包原封不动“转发出去”，而是内核终止用户态连接后重新拨号；所以源 IP 是物理网卡地址，不经过 Trojan 加密隧道。

`auto-detect-interface=true` 是关键：若误把 TUN 自己当成出口，会形成环路；内核必须选择真实物理默认路由网卡。

### 5.2 代理流量如何进入 Trojan

命中 `PROXY` 类规则后：

```text
App → TUN → Mihomo stack → rule = PROXY
  → proxy-group（select/url-test/fallback）
  → 选中 Trojan 节点
  → Trojan 协议封装 → TLS → 远端 Trojan 服务器
  → 远端服务器解密后代替客户端访问目标
```

规则与组的配置关系由 Verge 保证：

```yaml
proxies:
  - name: my-trojan
    type: trojan
    server: example.com
    port: 443
    password: ...
    sni: example.com
    alpn: [h2, http/1.1]
    skip-cert-verify: false
    udp: true

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - my-trojan
      - DIRECT

rules:
  - MATCH,PROXY
```

Verge 侧相关实现：

- 订阅 YAML 原文保留：`src-tauri/src/config/prfitem.rs:258-411`，只浅校验 `proxies` 或 `proxy-providers` 存在。
- Trojan URI 解析：`src/utils/uri-parser/trojan.ts:12-92`，输出 `type: 'trojan'`、server、port、password、sni、alpn、ws/grpc opts 等。
- 类型定义：`src/types/global.d.ts:380-402`。
- seq 增强新增节点自动加入第一个 selector 组：`src-tauri/src/enhance/seq.rs:83-130`。
- 无效 proxy/group/provider 引用清理：`src-tauri/src/enhance/mod.rs:630-709`。
- 节点切换 API：`src-tauri/src/feat/profile.rs:25-61`。
- runtime 生成与热重载：`src-tauri/src/config/config.rs:203-243`、`src-tauri/src/core/manager/config.rs:386-468`。

Trojan 握手、TLS/SNI/ALPN、WS/gRPC framing、UDP over Trojan、健康检查都在外部 Mihomo 内核中，本仓库不可见。

---

## 6. Trojan 协议层：迁移时真正要实现什么

### 6.1 基础 Trojan over TLS

Trojan 的协议设计很简洁：它借用 TLS 作为外层，服务端通过首行认证识别合法客户端。

一次 TCP 连接的典型流程：

```text
1. 客户端向 Trojan 服务器建立 TCP 连接（常见 443）。
2. 在其上做标准 TLS 握手：
   - SNI = 配置中的 sni（通常伪装为普通站点域名）
   - ALPN = h2 / http/1.1（按配置）
   - 校验证书；skip-cert-verify=true 时跳过（不推荐）
3. TLS 连接建立后，客户端立即发送认证行：
   CRLF 风格：
   <password>\r\n
   <command>\r\n
   <address>\r\n
   <CRLF>
4. command：
   - 0x01 CONNECT：建立 TCP 到目标
   - 0x02 UDP ASSOCIATE：请求 UDP 中继
5. address：
   - 0x01 + 4 字节 IPv4
   - 0x03 + 1 字节长度 + 域名
   - 0x04 + 16 字节 IPv6
   - 随后 2 字节大端端口
6. 服务端校验 password；失败时返回伪装站点行为或直接断开。
7. 成功后：
   TCP：TLS 记录中的剩余字节就是目标 TCP 流的双向透传。
   UDP：每个 UDP 包按 Trojan UDP frame 格式封装。
```

Trojan 的“安全性”主要来自：

- TLS 外层使流量看起来像 HTTPS；
- 密码认证防止未授权使用；
- SNI/证书/ALPN 提供伪装一致性；
- 服务端认证失败可回落伪装站点，降低主动探测识别度。

迁移时必须保证：

1. password 通过安全随机源生成且不写日志；
2. TLS 证书校验默认开启；`skip-cert-verify` 只能作为显式高级选项；
3. SNI、ALPN、证书 CN/SAN 逻辑一致；
4. 认证阶段不要暴露“Trojan 特有错误响应”给探测器；
5. 出站拨号与直连拨号使用不同的 socket 生命周期管理，防止串流。

### 6.2 Verge 保留的 Trojan 节点字段

`src/types/global.d.ts:380-402`、`src/utils/uri-parser/trojan.ts:30-89`：

```yaml
name: trojan-node
type: trojan
server: example.com
port: 443
password: secret

# TLS
sni: example.com
alpn: [h2, http/1.1]
skip-cert-verify: false
fingerprint: chrome
client-fingerprint: chrome

# UDP
udp: true

# transport（可选，二选一）
network: ws
ws-opts:
  path: /path
  headers:
    Host: example.com

# 或
network: grpc
grpc-opts:
  grpc-service-name: svc
```

注意 Verge 的 parser 特例：

- URI 的 `?alpn=a,b` 用 `split(',')`，未做 trim；
- `network=ws|grpc` 才会生成对应 `*-opts`；`tcp` 无额外字段；
- `encryption=...` 会被转成 `ss-opts`，不是所有 Trojan 实现都支持；
- schema 有 `reality-opts`，但 Trojan URI parser 未生成。

迁移建议：配置解析要“宽容保存、严格校验”。兼容字段先保留为 opaque mapping，真正拨号前再按当前实现能力校验；避免像 Verge parser 一样静默生成字段不一致。

---

## 7. 安全分流的关键不变量

迁移时建议把下面几条写成架构不变量，而不是散落在 UI 逻辑里。

### 7.1 流量不变量

| 不变量 | 违反后果 | 建议实现 |
|---|---|---|
| DIRECT 流量不得经过 TLS 隧道 | 本机服务绕远路、延迟与隐私风险 | 规则命中 DIRECT 后关闭 TUN 连接，用物理接口新 socket 出站 |
| PROXY 流量不得落到物理网卡 | IP/域名泄漏 | 出站拨号前断言当前 packet 已归属规则并选中 proxy |
| DNS 不得泄漏到本地解析器 | 域名查询暴露 | TUN 下强制 `dns-hijack: any:53`，fake-ip，DNS 规则 |
| TUN 自身流量不得回环进 TUN | 内核卡死 | auto-detect-interface 排除 TUN；strict-route + 路由例外 |
| 私网/链路本地地址不应走 Trojan | 代理服务端 SSRF 风险 | 默认 DIRECT 或拒绝；参考目标项目现有 SSRF guard |
| 配置更新不得改变旧连接的策略 | 新旧策略混用 | 切换 TUN/代理模式时关闭旧连接 |
| 无权限时不得半开 TUN | 路由残留、断网 | fail-closed 能力检测 + 回滚 + 用户通知 |

### 7.2 DNS 防泄漏的三层设计

1. **劫持层**：`dns-hijack: any:53` 把所有 DNS 查询送进内核 DNS 模块。
2. **解析层**：fake-ip 把域名映射成保留地址段，迫使后续连接按域名规则匹配；IPv4 `198.18.0.1/16`，IPv6 `2001:2::0/64`。
3. **出口层**：为不同用途指定不同 DNS：
   - `proxy-server-nameserver`：解析代理节点域名，避免“用代理解析代理域名”形成环路；
   - `direct-nameserver`：解析直连域名；
   - `fallback` + `fallback-filter.geoip`：防 DNS 污染。

上述字段在 `src/components/setting/mods/dns-viewer.tsx:140-274` 中暴露给用户。

### 7.3 路由安全

Verge 中 `strict-route` 默认 `false`，意味着兼容优先；如果目标项目追求“必不泄漏”，迁移时应评估改为 `true` 或实现等价的策略路由。

Windows 上真正健壮的 TUN 路由通常包含：

- 给 TUN 接口配置地址与 MTU；
- 添加高优先级默认路由指向 TUN；
- 为物理默认网关添加例外路由，保证内核自身能连上 Trojan 服务器；
- 为本地/私网/多播/链路本地地址添加例外；
- 用 `GetBestInterface`/路由表 restore 检测物理出口；
- 服务退出/崩溃时恢复原路由。

这些 syscall 不在 Verge 仓库，是 Mihomo 内核的职责；迁移到 Rust 时需要自己实现或引入 sing-tun/wintun 类库。

---

## 8. 从 Clash Verge 迁移到 ssl-proxy-project

### 8.1 目标项目现状

`E:\myProjects\ssl-proxy-project` 已是 Rust 项目：

- 客户端：`crates/gui`，GPUI，包名 `ssl-proxy-gui`；
- 服务端：`crates/svr`；
- 本机入口：`127.0.0.1:1080` 同时支持 SOCKS5、HTTP/HTTPS CONNECT、UDP ASSOCIATE；
- 远端：TLS 端口 + HMAC-SHA256 私有协议 + 伪装站点；
- 现有规则：HOST/GEO，DIRECT/PROXY；
- 现有 UDP 模式：off/direct/proxy；
- 已有 SSRF guard、replay cache、mux 等安全机制。

详见 `E:\myProjects\ssl-proxy-project\README.md:38-158`。

因此迁移不是“引入 Clash”，而是两条路线：

```text
路线 A：复用 Mihomo 内核
  保留 Verge 式 YAML 配置生成 + TUN 参数 + 提权启动
  优点：能力完整、迁移快
  缺点：引入 Go 二进制、配置面复杂、协议要与现有私有协议二选一或双栈

路线 B：自研 Rust TUN 数据面
  在 ssl-proxy-gui 内用 wintun/sing-tun 建网卡
  用户态 TCP/IP 栈解析包，决策 DIRECT/PROXY
  PROXY 走现有 TLS 私有协议或新增 Trojan outbound
  优点：协议统一、可控、可审计
  缺点：工作量大，TCP 状态机/DNS/UDP/路由恢复复杂
```

### 8.2 推荐路线

若目标是把现有客户端升级为“系统级透明代理”，建议分阶段：

#### 阶段 1：保留本地代理入口，补齐路由可视化

- 复用现有 `127.0.0.1:1080`；
- 把规则测试结果、DIRECT/PROXY 决策暴露为统一 `RouteDecision`；
- 为后续 TUN 数据面准备同一决策接口。

```rust
enum RouteDecision {
    Direct { interface: InterfaceId },
    Proxy { outbound: OutboundId },
    Reject,
}
```

#### 阶段 2：实现 SOCKS5/HTTP 层的“TUN 等价”安全不变量

在现有代理入口上先做到：

- HOST/GEO 规则命中 DIRECT 时，使用物理网卡 socket；
- PROXY 时进入 TLS 隧道；
- 域名解析统一走规则引擎，禁止应用侧裸解析造成 DNS 泄漏；
- 切换规则/服务器时关闭旧连接。

这部分不需要 TUN，但能验证策略引擎的正确性。

#### 阶段 3：引入 TUN 设备与用户态栈

Windows 建议组件：

- `wintun`：虚拟网卡；
- `smoltcp` 或 `netstack`（咨询授权）：用户态 TCP/IP；
- Windows NetIO API / `netsh`/`route`：地址、路由、指标；
- Windows Service：SYSTEM 权限管理网卡和路由生命周期。

核心数据流：

```text
TUN reader
  → packet parser
  → TCP state machine / UDP association
  → resolve hostname via safe DNS
  → rule engine
  → DirectConnector(bind physical interface)
      或 TunnelConnector(ssl-proxy/trojan)
```

关键实现约束：

- 必须维护 TCP 状态（SYN/ACK/FIN/RST、seq/ack、窗口、重传），不能简单“收到包就转发”；
- 直连 socket 要显式绑定物理接口，避免再次被 TUN 默认路由捕获；
- tunnel socket 必须加入路由例外，否则会出现“隧道目标也被 TUN 拦截”的死锁；
- UDP 需按五元组维护映射和超时回收；
- 服务/进程退出时必须恢复路由与删除网卡。

#### 阶段 4：Trojan 作为可选 outbound

目标项目当前使用私有协议；若要兼容 Trojan 节点，建议抽象为：

```rust
enum Outbound {
    Direct,
    SslProxy { server, sni, password, tls },
    Trojan { server, port, password, sni, alpn, transport },
}
```

Trojan outbound 实现模块：

```text
crates/gui/src/core/proxy/trojan/
  mod.rs        // Outbound 实现
  config.rs     // TrojanNode + TLS/transport 配置
  handshake.rs  // auth line + command/address
  udp.rs        // UDP over Trojan frame
```

与现有 `SslProxy` outbound 共享：

- TCP connector；
- TLS config/certificate verifier；
- DNS resolver；
- connection tracker；
- mux（若 Trojan 不需要 mux，则禁用）。

### 8.3 最小可迁移配置模型

```yaml
# 基础入口
listen: 127.0.0.1:1080
mode: rule

tun:
  enabled: false
  stack: smoltcp
  name: SSLProxy
  mtu: 1500
  auto_route: true
  strict_route: true
  auto_detect_interface: true
  route_exclude_address:
    - 192.168.0.0/16
    - 10.0.0.0/8
    - 172.16.0.0/12
  dns_hijack: ["any:53"]

dns:
  fake_ip_range: 198.18.0.1/16
  fake_ip_range6: 2001:2::0/64
  proxy_server_nameserver: []
  direct_nameserver: []
  fallback: []

outbounds:
  - name: direct
    type: direct
  - name: ssl-proxy
    type: ssl-proxy
    server: example.com
    port: 1888
    sni: example.com
  - name: trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: ...
    sni: trojan.example.com
    alpn: [h2, http/1.1]
    udp: true

rules:
  - IP-CIDR,127.0.0.0/8,direct,no-resolve
  - IP-CIDR,192.168.0.0/16,direct,no-resolve
  - GEOIP,CN,direct
  - MATCH,trojan
```

### 8.4 不迁移的部分

Verge 中以下内容不建议照搬：

- Tauri/前端配置 UI；GPUI 项目应直接做原生设置页；
- Boa JS 脚本增强：攻击面大，难以审计；
- profile/merge/script 复杂增强链：除非目标项目确实需要订阅生态；
- `proxy-groups` 的 url-test/fallback/load-balance：可简化为单 outbound + 故障切换；
- 符号链接式的“默认 UDP 全代理”：应保留目标项目现有的 off/direct/proxy 显式语义。

---

## 9. 验证清单（迁移时逐项实测）

> 以下不是“添加测试代码的清单”，而是手工/集成验证项；在目标项目中实现后再决定哪些固化为自动化测试。

1. **直连绕过验证**
   - 访问 `192.168.x.x` 管理页，检查连接跟踪：应为 DIRECT，源 IP 为物理网卡。
   - 抓包确认没有到 Trojan 443 的 TLS 握手。

2. **代理泄漏验证**
   - 访问外部 IP，检查远端看到的源 IP 应为 Trojan 服务器出口。
   - 同时抓物理网卡与 TUN，确认目标流量只出现一次且未以明文直出。

3. **DNS 泄漏验证**
   - 在应用内查询域名，确认本地 DNS 服务器没有收到对应 A/AAAA 查询。
   - 检查 fake-ip 段是否正确进入规则引擎。

4. **TUN 自环验证**
   - 断开 Trojan 服务器，客户端应失败但路由表不失效。
   - 确认内核隧道 socket 不被 TUN 再次捕获。

5. **权限失败验证**
   - 非管理员启动，TUN 必须保持关闭且不残留路由/网卡。
   - 服务启动失败后 UI 明确提示，而不是显示“已连接”。

6. **切换策略验证**
   - 从 PROXY 切到 DIRECT，旧连接按配置关闭；新连接不得继承旧出站。
   - 从 DIRECT 切到 PROXY，DNS cache 中的 fake-ip 映射应失效或重新选举。

7. **Trojan 协议验证**
   - password 错误时服务端不得泄露有用差异响应；
   - TLS 证书错误默认拒绝；
   - SNI/ALPN 与证书一致；
   - UDP ASSOCIATE 按帧格式与超时策略转发。

8. **恢复验证**
   - 强杀客户端或服务后，系统默认路由/DNS 恢复原值。
   - 重启机器后无残留 TUN 适配器。

---

## 10. 关键源码索引

| 主题 | 文件 | 关键行 |
|---|---|---|
| TUN 常量 | `e:/clash-verge-rev-dev/src-tauri/src/constants.rs` | 70-89 |
| 默认 TUN 模板 | `e:/clash-verge-rev-dev/src-tauri/src/config/clash.rs` | 56-114,347-355 |
| TUN 开关注入 | `e:/clash-verge-rev-dev/src-tauri/src/enhance/tun.rs` | 10-55 |
| 防订阅覆盖 | `e:/clash-verge-rev-dev/src-tauri/src/enhance/mod.rs` | 294-493,711-798,800-896 |
| TUN 能力检测 | `e:/clash-verge-rev-dev/src-tauri/src/core/runstate/health.rs` | 61-102 |
| TUN 可用性协调 | `e:/clash-verge-rev-dev/src-tauri/src/feat/tun.rs` | 21-86 |
| 非管理员关闭 TUN | `e:/clash-verge-rev-dev/src-tauri/src/core/manager/state.rs` | 29-44 |
| Service 启动与哈希校验 | `e:/clash-verge-rev-dev/src-tauri/src/core/service.rs` | 606-628,789-830,991-1001 |
| 配置生成 | `e:/clash-verge-rev-dev/src-tauri/src/config/config.rs` | 203-243 |
| 配置校验 | `e:/clash-verge-rev-dev/src-tauri/src/core/validate.rs` | 228-251,350-375,419-444 |
| 热重载 | `e:/clash-verge-rev-dev/src-tauri/src/core/manager/config.rs` | 386-468 |
| 系统代理 bypass | `e:/clash-verge-rev-dev/src-tauri/src/core/sysopt.rs` | 262-289,418-529 |
| 切换时断连 | `e:/clash-verge-rev-dev/src-tauri/src/feat/proxy.rs` | 19-97 |
| Trojan URI 解析 | `e:/clash-verge-rev-dev/src/utils/uri-parser/trojan.ts` | 12-92 |
| Trojan 类型 | `e:/clash-verge-rev-dev/src/types/global.d.ts` | 380-402 |
| seq 自动加入组 | `e:/clash-verge-rev-dev/src-tauri/src/enhance/seq.rs` | 83-130 |
| 节点切换 API | `e:/clash-verge-rev-dev/src-tauri/src/feat/profile.rs` | 25-61 |
| 内核下载来源 | `e:/clash-verge-rev-dev/scripts/prebuild.mjs` | 162-198,274-298 |
| 外部二进制声明 | `e:/clash-verge-rev-dev/src-tauri/tauri.conf.json` | 17 |
| 目标项目现状 | `E:/myProjects/ssl-proxy-project/README.md` | 38-158 |

---

## 11. 最终判断

1. **安全分流的本质是策略与出口绑定**：DIRECT 重新走物理网卡原生 socket，PROXY 进入加密 outbound；两者必须在内核内部明确隔离。
2. **DNS 是最大泄漏面**：TUN 模式下必须同时接管 DNS、fake-ip 和代理节点域名解析，不能只做 IP 路由。
3. **权限失败必须 fail-closed**：Verge 的 admin/service 门控与 sidecar 强制禁 TUN 是值得直接迁移的设计。
4. **Trojan 只是 outbound 的一种**：Verge 侧真正可迁移的是配置模型、节点引用校验、选路与热重载；Trojan 拨号需在你自己的 Rust 栈或 Mihomo 内核中实现。
5. **迁移到 ssl-proxy-project 的最优路径**是先抽象 `Outbound` 与 `RouteDecision`，再逐步接入 TUN；不要一开始就复制 Verge 的整套订阅/脚本/规则生态。

---

## 12. Meta 分支源码实证：TUN 内核实现与 Rust 移植设计

> 本章基于 `e:/clash-verge-rev-dev/mihomo` 当前检出的 `Meta` 分支，commit `0455d0d28c4526937380505153e65a843d8612e8`，工作区干净。
>
> 这里纠正前面章节的一个边界：Verge 主仓库确实没有内核源码；但独立检出的 `mihomo` 仓库就是 Verge 使用的 Go 内核源码。下面的分析全部来自该源码。

### 12.1 责任边界：Mihomo 编排，sing-tun 落地

最重要的结论：**Mihomo 本仓库也不直接实现 Wintun 创建、Windows 路由表写入、系统 DNS 设置和 gVisor/MIPS 协议栈**。这些能力来自外部依赖：

```text
go.mod:42  github.com/metacubex/sing-tun v0.4.29
```

因此源码里看到的是三层结构：

| 层 | 归属 | 负责什么 |
|---|---|---|
| 配置/编排层 | Mihomo Go 仓库 | 解析 `tun` 配置、归一默认值、决定热重载、启动 monitor、设置全局 dialer hook、DNS 黑名单、调用 sing-tun |
| 设备/路由/栈层 | `sing-tun` + OS + Wintun | 创建 TUN 网卡、配置 IP/MTU、装路由、`strict-route`、`route-exclude-address`、gVisor/system/mixed/mips stack、接口监控 |
| 业务数据面 | Mihomo Go 仓库 | DNS 53 劫持、metadata 构造、fake-ip 反查、规则匹配、DIRECT/PROXY 出站、loopback 检测、UDP NAT |

所以 Rust 移植不能只看 Mihomo Go 仓库；真正要重写或替换的是 `sing-tun` 那一层。

### 12.2 配置解析与默认值

#### 12.2.1 配置结构

`listener/config/tun.go:12-71` 定义了运行时 `Tun` 结构。核心字段包括：

- `enable`、`device`、`stack`、`dns-mode`、`dns-hijack`
- `auto-route`、`auto-detect-interface`
- `mtu`、`gso`、`gso-max-size`
- `inet4-address`、`inet6-address`
- `strict-route`
- `route-address`、`route-exclude-address`
- `inet4-route-address`、`inet6-route-address`
- `inet4-route-exclude-address`、`inet6-route-exclude-address`
- `include-interface`、`exclude-interface`
- `include-uid*`、`exclude-uid*`、`include-package*`、`exclude-package*`
- `udp-timeout`、`icmp-timeout`、`disable-icmp-forwarding`
- `endpoint-independent-nat`
- `file-descriptor`、`recvmsgx`、`sendmsgx`、`processors-per-channel`

这些字段比 Verge UI 暴露的字段多得多；Rust 首版不必全实现，但至少要能无损保存。

#### 12.2.2 默认值

`config/config.go:545-556` 的默认值：

```go
Tun: RawTun{
    Enable:               false,
    Device:               "",
    Stack:                C.TunMips,
    DNSHijack:            []string{"0.0.0.0:53"},
    AutoRoute:            true,
    AutoDetectInterface:  true,
    Inet6Address:         []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
    RecvMsgX:             true,
    SendMsgX:             false,
    ProcessorsPerChannel: 1,
}
```

Verge 写的是 `any:53`，Mihomo 默认是 `0.0.0.0:53`。在 `listener/sing_tun/server.go:285-295` 中会把 `any` 替换成 `0.0.0.0`，二者语义一致：匹配任意地址的 53 端口。

#### 12.2.3 TUN IPv4 地址来自 fake-ip 池

`config/config.go:1687-1692`：

```go
tunAddressPrefix := dns.FakeIPRange
if !tunAddressPrefix.IsValid() {
    tunAddressPrefix = netip.MustParsePrefix("198.18.0.1/16")
}
tunAddressPrefix = netip.PrefixFrom(tunAddressPrefix.Addr(), 30)
```

然后 `config/config.go:1706` 把它作为 `Inet4Address`。

这意味着：

- TUN 网关是 `198.18.0.1`
- DNS 服务器是网关下一跳 `198.18.0.2`
- 地址前缀是 `/30`

`listener/sing_tun/server.go:298-308` 会为每个 IPv4/IPv6 TUN 地址计算下一跳 `:53`，加入 DNS 劫持集合，并把这些 IP 加入系统 DNS 黑名单。

IPv6 有独立处理：`config/config.go:1680-1684` 在 `ipv6: false` 或 IPv6 不可用时清空 `fake-ip-range6` 和 `inet6-address`。

### 12.3 启动、热重载与清理链路

#### 12.3.1 配置应用顺序

`hub/executor/executor.go:84-123` 中，配置应用顺序是：

```text
updateGeneral
→ updateDNS
→ updateNTP
→ updateListeners
→ updateTun
→ updateIPTables
→ ...
→ resolver.ResetConnection
```

关键约束：**DNS 先于 TUN**。因为 TUN 地址、DNS 劫持和 fake-ip 反查都依赖 DNS 配置。

#### 12.3.2 热重载判定

`listener/listener.go:498-535` 的 `ReCreateTun()`：

1. `tunConf.Sort()` 归一化列表顺序；
2. 加全局锁；
3. 若 `Equal(LastTunConf)`，只调用旧 listener 的 `OnReload()`，不重建网卡；
4. 否则先 `closeTunListener()`；
5. 若 `enable=false` 直接返回；
6. 调用 `sing_tun.New(tunConf, tunnel)` 创建新实例。

`listener/config/tun.go:73-98` 的 `Sort()` 对 CIDR、UID、包名、接口名等全部排序；`Equal()` 做逐字段比较。Rust 移植时必须实现等价逻辑，否则用户只改了列表顺序也会重建网卡，引发断网抖动。

#### 12.3.3 `sing_tun.New()` 做了什么

`listener/sing_tun/server.go:136-556` 是核心入口：

```text
New(options)
  ├─ GSO 默认 65536                                  [145-147]
  ├─ 非 Linux 强制关闭 auto-redirect                 [148-150]
  ├─ 计算/校验设备名，默认 Meta                      [151-165]
  ├─ 合并 route-address / inet*-route-address        [166-178]
  ├─ 合并 route-exclude / inet*-route-exclude        [179-191]
  ├─ MTU 默认 9000                                   [192-195]
  ├─ UDP/ICMP timeout、table/rule index、mark 默认值 [196-227]
  ├─ 校验 dns-mode                                   [277-281]
  ├─ 解析 dns-hijack，并追加 TUN 网关 :53            [283-308]
  ├─ 创建 sing.NewListenerHandler                    [310-325]
  ├─ 失败时 defer l.Close() 回滚                     [332-337]
  ├─ 启动 NetworkUpdateMonitor / DefaultInterfaceMonitor [341-379]
  ├─ 安装 auto-detect-interface 全局 finder（CAS）   [381-390]
  ├─ 构造 tun.Options                                [393-429]
  ├─ Linux auto-redirect / route set 动态规则        [431-479]
  ├─ tunNew() 创建 TUN 设备                          [486]
  ├─ resolver.AddSystemDnsBlacklist                  [492-494]
  ├─ tun.NewStack(...)                               [496-515]
  ├─ tunStack.Start()                                [517-521]
  └─ autoRedirect / routing mark / resolver reset    [523-548]
```

`server.go:393-429` 把 `AutoRoute`、`StrictRoute`、route/exclude、MTU、GSO、include/exclude UID/端口/MAC、InterfaceMonitor 等全部塞进 `tun.Options`。**真正解释这些字段的是 sing-tun。**

#### 12.3.4 Windows 特化

`listener/sing_tun/server_windows.go:12-27`：

- `tun.New(options)` 最多重试 3 次；
- 如果失败耗时小于 1 秒，直接返回错误，避免对“文件已存在”这类瞬时错误无意义重试；
- 如果超过 1 秒，打 warning 后重试。

`server_windows.go:29-36`：

- `tun.TunnelType = InterfaceName`，即设备类型名 `Meta`；
- Windows < 10 时设置 `EnforceBindInterface = true`，规避 `bind: The requested address is not valid in its context`。

默认设备名来自 `server.go:39` 的 `InterfaceName = "Meta"`。

注意：Mihomo 源码里没有管理员提权、Wintun 驱动安装、Windows 路由 metric 设置。这些都是 Verge Service / 安装包 / sing-tun / OS 的职责。

#### 12.3.5 清理

`listener/sing_tun/server.go:677-695` 的 `Close()` 顺序：

1. 移除系统 DNS 黑名单；
2. 还原全局 `DefaultRoutingMark`；
3. 还原全局 `DefaultInterfaceFinder`；
4. 依次关闭 rule callback、tun stack、TUN 接口、auto redirect、接口监控、网络监控。

其中 `l.tunIf.Close()` 触发 sing-tun 删除 TUN 设备并撤销路由。构造中途失败由 `server.go:332-337` 的 `defer l.Close()` 回滚。

Mihomo 只处理正常退出、配置重载和信号退出；SIGKILL/系统崩溃没有进程内补偿清理。Rust 移植时若做成服务，应增加路由快照和崩溃恢复。

### 12.4 数据面：IP 包如何变成规则匹配连接

#### 12.4.1 总体路径

```text
应用层 socket
  → OS 路由表（auto-route 指向 TUN）
  → TUN 虚拟网卡
  → sing-tun stack: gvisor / system / mixed / mips
  ├─ DNS 53 → Mihomo DNS 模块，直接应答，不进规则引擎
  └─ 普通流量 → sing.ListenerHandler
        ├─ TCP → net.Conn + Metadata → Tunnel.HandleTCPConn
        └─ UDP → packet + Metadata → Tunnel.HandleUDPPacket
              → 规则匹配
              → DIRECT / PROXY outbound
              → dialer 绑定物理网卡或 routing mark
```

#### 12.4.2 TCP

`listener/sing/sing.go:126-151`：

- stack 回调给出 `net.Conn` 和 sing metadata；
- 构造 Mihomo `C.Metadata`；
- `inbound.ApplyAdditions()` 注入源/目的地址、inbound name、特殊规则等；
- 调用 `Tunnel.HandleTCPConn()`。

`tunnel/tunnel.go:502-625`：

1. 检查 metadata 合法性；
2. `fixMetadata()` 处理 IPv4-mapped 地址和 host 中的 IP；
3. `preHandleMetadata()` 做 fake-ip / redir-host 反查；
4. 若 fake-ip 映射缺失，尝试 sniffer 补域名；
5. 仍失败则直接放弃连接；
6. 200ms 异步 `Peek(1)`，为 sniffer 和远端握手保留首包；
7. `resolveMetadata()` 执行规则匹配；
8. `proxy.DialContext()` 建立出站；
9. `statistic.NewTCPTracker()` 记录流量；
10. `handleSocket()` 双向 relay。

这里的 `proxy.DialContext()` 就是 DIRECT/PROXY 的分叉点：规则返回 DIRECT 时走 direct outbound；返回 Trojan/其他代理时走对应 outbound。

#### 12.4.3 UDP

`listener/sing/sing.go:153-249` 和 `tunnel/tunnel.go:85-113,413-500`：

- stack 输出的是 packet，不是 stream；
- UDP 按 `packet.Key()` 分发到多个 worker；
- `nat.Table` 保存 SNAT/DNAT 映射；
- `packetSender` 保证单会话包顺序；
- 首次包可能需要解析域名；
- 后续包套用 `originToTarget` 映射；
- 回包通过 `packet.WriteBack()` 写回 TUN stack。

Rust 移植不能简单“一个 UDP 包建一个 socket”，必须维护五元组/NAT 会话和回包映射，否则 DNS、QUIC、游戏流量会错乱。

#### 12.4.4 DNS 在入口短路

`listener/sing_tun/dns.go:21-28`：

```go
func (h *ListenerHandler) ShouldHijackDns(targetAddr netip.AddrPort) bool {
    for _, addrPort := range h.DnsAddrPorts {
        if addrPort == targetAddr || (addrPort.Addr().IsUnspecified() && targetAddr.Port() == 53) {
            return true
        }
    }
    return false
}
```

DNS 判断发生在 stack 进入 tunnel 之前：

- TCP DNS → `resolver.RelayDnsConn()`；
- UDP DNS packet → `relayDnsPacket()` → `resolver.RelayDnsPacket()`；
- UDP PacketConn → 循环读取并逐个 relay；
- DNS 包不会进入规则引擎，也不会被当作普通 TCP/UDP 连接代理。

这是防 DNS 泄漏最重要的一刀：**DNS 一进 TUN 就被内核接管，不经过“是否代理”的规则判断。**

`server.go:298-308` 还会自动把 TUN 网关下一跳的 `:53` 加入劫持集合，因为 sing-tun 会把 TUN 适配器 DNS 设成这个地址。

#### 12.4.5 fake-ip 反查

`tunnel/tunnel.go:289-315`：

- 若 metadata 只有 fake IP、没有 host，用 `resolver.FindHostByIP()` 反查域名；
- 确认是 fake IP 后清空 `DstIP`，标记 `DNSFakeIP`；
- 若 IP 落在 fake-ip 池但查不到映射，直接返回 `fake DNS record missing`；
- 连接因此被放弃，而不是按 IP 直连。

这是 fail-closed：宁可断，也不用真实 IP 绕过域名规则。

### 12.5 安全分流细节

#### 12.5.1 DIRECT 为什么走物理网卡

Mihomo 不是靠“把 TUN 包原路转发出去”实现 DIRECT，而是：

1. 规则命中 DIRECT；
2. direct outbound 调用 dialer 创建新 socket；
3. dialer 查询目的地址应走哪个物理接口；
4. 把 socket 绑定到那个物理接口；
5. 包从物理网卡出去，不再进入 TUN。

`component/dialer/dialer.go:163-185`：

```text
显式 interface
  → DefaultInterface
  → DefaultInterfaceFinder.FindInterfaceName(destination)
  → bindIfaceToDialer
  → DefaultRoutingMark / bindMarkToDialer
```

Windows 绑定实现 `component/dialer/bind_windows.go:20-37`：

- IPv4：`setsockopt(IPPROTO_IP, IP_UNICAST_IF, ifindex)`
- IPv6：`setsockopt(IPPROTO_IPV6, IPV6_UNICAST_IF, ifindex)`

这就是“直连走物理网卡”的真实代码路径。

#### 12.5.2 auto-detect-interface 防自环

`listener/sing_tun/server.go:619-643` 的 `FindInterfaceName()`：

1. 先按目的地址查接口；
2. 再查默认接口 monitor；
3. 若查到 TUN 自己，丢弃；
4. 若为空或 `<nil>`，丢弃；
5. 依次尝试目的地址、`0.0.0.0`、`::`；
6. 全部失败返回 `"<invalid>"`，注释明确是 “to avoid lookback”。

Rust 移植必须保留这个失败语义：宁可返回无效接口让拨号失败，也不能返回 TUN 自己。

#### 12.5.3 loopback detector

`component/loopback/detector.go:27-111`：

- direct outbound 建立连接后，把本地地址登记到 `connMap` / `packetConnMap`；
- 新入站 metadata 的源地址若命中登记表，返回 `ErrReject`；
- UDP 还会检查源 IP 是否为本机/loopback；
- 关闭连接时从表中删除。

它专门防止“代理/直连 socket 发出的包又被 TUN 当作新入站连接接回来”。

#### 12.5.4 route-exclude-address

`server.go:179-191` 合并通用与 IPv4/IPv6 专用排除项；`server.go:411-412` 传给 sing-tun。

重要事实：**Mihomo 不会自动把 Trojan/代理节点服务器 IP 写入排除路由**。若系统默认路由把所有流量导入 TUN，而代理节点域名又解析成公网 IP，隧道出站包可能再次进入 TUN，形成自环。实际部署应：

- 手动把代理服务器 IP/CIDR 写入 `route-exclude-address`；
- 或使用 `proxy-server-nameserver` 保证节点域名解析不被代理污染；
- 或用路由 mark / 物理接口绑定让隧道 socket 直接走物理网卡。

Rust 项目应把“自动排除代理服务器出口 IP”作为增强项实现，这比 Mihomo 更稳。

#### 12.5.5 strict-route

`server.go:408` 只把 `StrictRoute` 填进 `tun.Options`，真正实现仍在 sing-tun/OS 防火墙。

文档 `docs/config.yaml:151` 说明：strict-route 会把所有连接强制路由进 TUN 防泄漏，但设备将无法访问其他局域网设备。

Windows 上 `dns-mode: hijack` 依赖 strict-route（`docs/config.yaml:140`）。Rust 移植时若不支持 strict-route，就不能声称 Windows DNS hijack 是完整安全的。

#### 12.5.6 ICMP

`listener/sing_tun/prepare.go:18-52`：

- ICMP 进入 `PrepareConnection()`；
- 若关闭 ICMP forwarding，或目标是 TUN 自身网段/fake IP，返回 fake ping；
- 否则用 `ping.ConnectDestination()` + `dialer.ICMPControl()` 真实转发；
- `ICMPControl` 同样会绑定物理网卡和 routing mark。

目的：避免 ping TUN 网关、fake IP 或本地地址时产生 ICMP 自环风暴。

#### 12.5.7 网络切换

`server.go:366-374` 的默认接口回调会：

- 打日志；
- `iface.FlushCache()`；
- `resolver.ResetConnection()`。

否则 Wi-Fi/以太网切换后，缓存的默认接口和系统 DNS 会失效，造成流量走旧网卡或 DNS 泄漏。

### 12.6 Rust 移植设计建议

#### 12.6.1 不要复制 Mihomo 的全量结构

`ssl-proxy-project` 已有 SOCKS5/HTTP/TLS 私有协议和规则引擎，不需要复制：

- Clash 订阅/profile 体系；
- proxy-groups；
- rule-providers；
- Boa/JS 脚本；
- gVisor 全量 netstack；
- Android/Linux UID/package/MAC 规则；
- Trojan/VMess/SS 全协议栈。

Rust 版应保留 Mihomo 的**安全不变量和模块边界**，而不是复制代码规模。

#### 12.6.2 推荐模块划分

```text
crates/gui/src/core/tun/
  config.rs        # TunConfig + 默认值 + Sort/Equal + CIDR 校验
  lifecycle.rs     # start/reload/stop 状态机 + 失败回滚
  device.rs        # Wintun/sing-tun/系统 TUN 适配
  stack.rs         # system/gvisor/smoltcp 抽象
  metadata.rs      # src/dst/host/network/inbound/process
  dns_hijack.rs    # 53 入口短路 + fake-ip 反查 + DNS 黑名单
  tunnel.rs        # TCP/UDP 会话、NAT、packet sender
  rule.rs          # RouteDecision + HOST/GEO/IP-CIDR 规则
  route.rs         # 默认接口探测、路由安装、exclude、恢复
  outbound.rs      # Direct / SslProxy / Trojan
  loopback.rs      # 出站 socket 登记与入站拒绝
```

#### 12.6.3 最小 trait 抽象

```rust
trait TunDevice {
    fn name(&self) -> &str;
    fn read_packet(&mut self) -> Result<Vec<u8>>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<()>;
    fn close(self) -> Result<()>;
}

trait PacketStack {
    fn on_tcp(&self, conn: TcpInbound);
    fn on_udp(&self, packet: UdpPacket);
    fn on_icmp(&self, packet: IcmpPacket);
}

enum RouteDecision {
    Direct { interface: InterfaceId },
    Proxy { outbound: OutboundId },
    Reject,
}

trait Outbound {
    fn dial_tcp(&self, meta: &ConnectionMeta) -> Result<TcpUpstream>;
    fn associate_udp(&self, meta: &ConnectionMeta) -> Result<UdpUpstream>;
}
```

#### 12.6.4 三阶段落地

**阶段 A：Rust 控制面 + 现有本地代理**

- 先实现 `TunConfig`、默认值、`Sort/Equal`、CIDR 校验；
- 把现有 `127.0.0.1:1080` 的规则决策抽象成 `RouteDecision`；
- 验证 DIRECT 真走物理网卡，PROXY 真走 TLS 隧道；
- 不碰 TUN 设备。

**阶段 B：Rust 控制面 + 外部 TUN 数据面**

- 保留 `sing-tun` 或一个独立 Go 子进程负责设备/路由/栈；
- Rust 负责配置生成、生命周期、DNS 黑名单、节点/路由策略；
- 这是最快达到 Verge 同等能力的路径。

**阶段 C：纯 Rust 数据面**

Windows 建议组件：

- Wintun 绑定：创建 TUN 网卡；
- `smoltcp` 或系统栈适配：TCP/UDP/IP；
- IP Helper API：枚举接口、读写路由、监听路由变化；
- `windows-sys` setsockopt：`IP_UNICAST_IF` / `IPV6_UNICAST_IF`；
- Windows Service：SYSTEM 权限和崩溃恢复。

纯 Rust 数据面的最大工作量不是规则匹配，而是 TCP 状态机、UDP NAT、DNS 劫持和路由恢复。

#### 12.6.5 Rust 版必须保留的安全不变量

1. DNS 配置先于 TUN 初始化。
2. `any:53` 表示任意 IP 的 53；TCP/UDP 两条路径都要劫持。
3. TUN IPv4 地址从 fake-ip 池切 `/30`；网关下一跳作为 TUN DNS，并加入系统 DNS 黑名单。
4. fake IP 查不到域名时拒绝连接，不按 IP 直连。
5. 接口探测不得返回 TUN 自身、空值或 `<nil>`；失败用确定无效值。
6. DIRECT/PROXY 出站 socket 都要绑定物理接口或 routing mark；loopback 目的不绑定。
7. 自动排除代理节点服务器 IP；不要依赖用户手工填写。
8. `strict-route`、`auto-route`、exclude 的写入和撤销必须与 TUN 生命周期原子化。
9. 全局 finder/mark 单例 CAS，关闭时对称恢复。
10. 热重载先比较 `Equal`，配置未变只刷新全局状态，不重建 TUN。
11. 网络切换时刷新接口缓存、重置 DNS、重算默认出口。
12. 服务崩溃后恢复系统路由和 DNS；不要只依赖进程退出清理。

### 12.7 Meta 分支关键源码索引

| 主题 | 文件 | 关键行 |
|---|---|---|
| sing-tun 依赖版本 | `e:/clash-verge-rev-dev/mihomo/go.mod` | 42 |
| TUN 配置字段 | `e:/clash-verge-rev-dev/mihomo/listener/config/tun.go` | 12-71 |
| 配置排序/比较 | `e:/clash-verge-rev-dev/mihomo/listener/config/tun.go` | 73-251 |
| 默认配置 | `e:/clash-verge-rev-dev/mihomo/config/config.go` | 545-556 |
| IPv6 归一化 | `e:/clash-verge-rev-dev/mihomo/config/config.go` | 1680-1685 |
| fake-ip 派生 TUN 地址 | `e:/clash-verge-rev-dev/mihomo/config/config.go` | 1687-1707 |
| 配置应用顺序 | `e:/clash-verge-rev-dev/mihomo/hub/executor/executor.go` | 84-123 |
| TUN 重建判定 | `e:/clash-verge-rev-dev/mihomo/listener/listener.go` | 498-535 |
| sing-tun New 主流程 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server.go` | 136-556 |
| DNS 劫持列表构造 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server.go` | 277-325 |
| 网络/接口监控 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server.go` | 341-391 |
| tun.Options 透传 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server.go` | 393-429 |
| 创建 stack | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server.go` | 486-521 |
| 接口查找防自环 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server.go` | 614-643 |
| Close 清理 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server.go` | 677-695 |
| DNS 入口短路 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/dns.go` | 21-138 |
| ICMP 处理 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/prepare.go` | 18-52 |
| Windows TUN 重试 | `e:/clash-verge-rev-dev/mihomo/listener/sing_tun/server_windows.go` | 12-36 |
| stack → tunnel 桥接 | `e:/clash-verge-rev-dev/mihomo/listener/sing/sing.go` | 126-250 |
| fake-ip 反查 | `e:/clash-verge-rev-dev/mihomo/tunnel/tunnel.go` | 275-315 |
| TCP 连接处理 | `e:/clash-verge-rev-dev/mihomo/tunnel/tunnel.go` | 502-625 |
| dialer 出口绑定 | `e:/clash-verge-rev-dev/mihomo/component/dialer/dialer.go` | 98-220 |
| Windows setsockopt 绑定 | `e:/clash-verge-rev-dev/mihomo/component/dialer/bind_windows.go` | 15-97 |
| loopback detector | `e:/clash-verge-rev-dev/mihomo/component/loopback/detector.go` | 17-111 |
| 配置文档 | `e:/clash-verge-rev-dev/mihomo/docs/config.yaml` | 133-198 |
