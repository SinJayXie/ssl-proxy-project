# ssl-proxy-svr 架构与设计文档

> 一个基于 tokio + rustls 的轻量级 TLS 代理服务，由 Node.js 版重构而来。
> 对外只暴露**一个 TLS 端口**：命中私有协议的流量走透明 TCP 隧道，其余流量回落为静态伪装站点。

---

## 1. 概述

`ssl-proxy-svr` 的核心能力是"单端口协议分流"：

```
                         ┌─ 私有协议 ──→ 透明 TCP 隧道（转发到目标 host:port）
外部 TLS 客户端 ──→ TLS ─┤
                         └─ 其他(HTTP等) ─→ 静态伪装站点（html/ 目录 + gzip）
```

- 伪装站点让端口"看起来"只是一个普通 HTTPS 网站，隐藏代理行为；
- 私有协议 v2 采用 HMAC-SHA256 + 时间戳双向认证，未通过认证的连接一律回落为静态站点响应；
- 支持零配置启动：不提供证书时自动生成自签证书（SAN: `localhost, 127.0.0.1`）。

### 技术栈

| 领域 | 选型 |
| ---- | ---- |
| 异步运行时 | tokio（multi_thread, 4 worker） |
| TLS | rustls 0.23 + tokio-rustls 0.26（TLS 1.3，不验证客户端证书） |
| 配置 | serde + serde_yaml + clap（YAML 与 CLI 合并） |
| 日志 | tracing + tracing-subscriber（控制台 + 按大小轮转文件） |
| 限流 | dashmap（内存级并发安全限流与黑名单） |
| HTTP 解析 | httparse（零依赖只读解析） |
| 自签证书 | rcgen（ECDSA P-256） |

---

## 2. 目录结构

```
ssl-proxy-svr/
├── Cargo.toml
├── config.example.yaml      # 配置文件示例
├── README.md
└── src/
    ├── main.rs              # 启动入口：配置合并、服务装配、信号处理
    ├── lib.rs               # 库入口（供集成测试 / 嵌入式使用）
    ├── config.rs            # YAML + CLI 配置结构与合并逻辑
    ├── error.rs             # 统一错误类型（AppError）
    ├── core/
    │   ├── service.rs       # Service 抽象 + ServiceRegister 注册表
    │   └── logger.rs        # 轮转文件日志写入器 + tracing 初始化
    ├── libs/
    │   └── rate_limit.rs    # IP 限流 + 黑名单
    ├── services/
    │   ├── socket_service.rs        # TLS 入口：监听、握手、读首包、分流
    │   ├── proxy_service.rs         # 私有协议认证 + 透明 TCP 隧道
    │   ├── forward_service.rs       # 伪装连接入口：限流后转交静态服务
    │   ├── static_sources_service.rs # 静态站点：HTTP/1.1 解析 + gzip 输出
    │   └── initial_stream.rs        # 首包与剩余流的拼接（InitialThenStream）
    └── utils/
        └── protocol.rs     # 私有协议编解码 + HTTP 协议识别 + 校验码
```

---

## 3. 架构设计

### 3.1 服务抽象与注册表

所有业务服务实现 [`Service`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/core/service.rs) 特征：

```rust
#[async_trait]
pub trait Service: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn start(&self) -> Result<()>;   // 启动（绑定端口、初始化资源）
    async fn stop(&self) -> Result<()> { Ok(()) }  // 优雅停止
}
```

[`ServiceRegister`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/core/service.rs) 按注册顺序**顺序启动**、**逆序停止**全部服务，保证依赖先就绪、后释放：

```
StaticSourcesService → ForwardService → ProxyService → SocketService
```

服务之间**通过构造函数注入显式依赖**，不使用全局状态：

- `SocketService` 依赖 `ForwardService`（HTTP 分流）与 `ProxyService`（私有协议分流）；
- `ProxyService` 依赖 `ForwardService`（认证失败时回落）；
- `ForwardService` 依赖 `StaticSourcesService`（真实响应者）与 `RateLimit`。

### 3.2 配置合并策略

[`AppConfig::merge`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/config.rs) 遵循三级优先级：

1. **YAML 文件**（`--config`）作为基线；
2. **命令行参数**覆盖 YAML 对应字段；
3. 仍未提供的字段使用内置默认值。

关键默认值：

| 项 | 默认值 |
| -- | ------ |
| 监听地址 / 端口 | `0.0.0.0:1888` |
| 代理密码 | 随机生成 12 位字母数字 |
| 静态目录 / 首页 | 缺省（此时所有 HTTP 请求统一返回 404）/ `index.html` |
| 日志目录 / 级别 / 单文件上限 | `./logs` / `info` / 5 MB |
| 限流窗口 / 单窗口上限 / 封禁时长 | 60s / 300 次 / 600s |

> 注意：`--cert` 与 `--key` 必须同时提供，只给其一会在启动时报错。

---

## 4. 请求处理流程

一条连接的完整生命周期（见 [`handle_connection`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/services/socket_service.rs)）：

```
TCP accept（set_nodelay 禁 Nagle）
   │
   ▼
TLS 握手（rustls，无客户端证书校验；失败直接断开）
   │
   ▼
读取首包（最多 8KB，超时 5s；无数据则关闭）
   │
   ▼
check_is_http_protocol(首包)？
   ├── 是 ──→ ForwardService.handle（伪装站点分支）
   └── 否 ──→ ProxyService.authenticate（私有协议分支）
```

### 4.1 HTTP 协议识别

[`check_is_http_protocol`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/utils/protocol.rs)：取首行（到 `\r` 为止，最长 2048 字节），若其中存在 `HTTP/1.` 且出现位置 `> 0` 则判定为 HTTP。

- `GET / HTTP/1.1` → HTTP；
- `\x10\xff...`（私有协议）→ 非 HTTP。

### 4.2 伪装站点分支（ForwardService）

```
首包 + 剩余流 封装为 InitialThenStream
   │
   ▼
RateLimit.record(peer_ip) ── 被限流/黑名单 → 直接断开
   │ 通过
   ▼
StaticSourcesService.handle：
   1. httparse 解析请求（失败 → 400）
   2. 无 base 目录 → 404
   3. sanitize_path 防路径穿越（`..`/绝对路径/盘符 → 403）
   4. GET → 200 + gzip 流式输出（Connection: close 定界 body）；HEAD → 仅响应头；文件缺失 → 404
```

[`InitialThenStream`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/services/initial_stream.rs) 把"已读出的首包字节"与"剩余 TLS 流"拼接成一个连续 `AsyncRead`，供后续解析器或管道直接消费。

### 4.3 私有协议分支（ProxyService）

```
ProxyService.authenticate：
   │
   ├── authenticate_protocol(首包, 本地密码, now) 校验失败 → 回落（交给 ForwardService）
   ├── hostLen = 0（mux 连接）→ 回 ACK → mux_service::serve 多路复用分发
   └── hostLen > 0（单流）→ open_tunnel：
         1. 连接目标 host:port（超时 10s，set_nodelay）
         2. 向客户端回写应答 [0x10, 0xFF] || 32B ACK MAC
         3. 分帧双向转发：上行全程分帧 + padding，下行前 16KB 后裸透传
```

---

## 5. 私有协议设计（v2）

### 5.1 首包格式

```text
+----+----+----+---------------+--------+----------+----------+----------+
| 10 | ff | 02 |   timestamp   |  port  | hostLen  |   host   |   mac    |
+----+----+----+---------------+--------+----------+----------+----------+
 1B   1B   1B     8B BE(u64)      2B BE     1B       N byte     32B
```

| 字段 | 长度 | 说明 |
| ---- | ---- | ---- |
| 魔数 | 2B | 固定 `0x10 0xFF` |
| version | 1B | 固定 `0x02`（v1 已废弃，硬切不兼容） |
| timestamp | 8B | Unix 秒级时间戳，大端序 |
| port | 2B | 目标端口，大端序 |
| hostLen | 1B | 目标主机名长度（N，不能为 0） |
| host | N B | 目标主机名（UTF-8） |
| mac | 32B | `HMAC-SHA256(password, "ssl-proxy-v2" || timestamp || port || host)` |

### 5.2 认证与重放防护

1. **密码不过线**：客户端只发送 HMAC，服务端用本地密码重算并做常量时间比对（`verify_slice`）；
2. **时间窗**：`|now - timestamp| <= 120s`，超出直接拒绝，窗口外无法重放；
3. **防篡改**：timestamp / port / host 均参与签名，任一字段被改都会导致 MAC 校验失败；
4. 校验失败一律回落为 HTTP 伪装响应，不返回任何协议特征。

### 5.3 隧道应答（双向认证）

认证通过后服务端回写：

```text
+----+----+--------------------------------------+
| 10 | ff |              ack mac                 |
+----+----+--------------------------------------+
 1B   1B                 32B
```

`ack_mac = HMAC-SHA256(password, "ssl-proxy-v2-ack" || timestamp || port || host)`。

客户端必须校验该 MAC——它证明对端确实持有密码，即使 `danger_accept_invalid_certs`
跳过了证书校验，中间人伪造的“成功应答”也会被识破。首包字节已被消费，**不参与后续转发**。

### 5.4 隧道分帧与 padding（抗 TLS-in-TLS 指纹）

隧道建立后，客户端 → 服务端的字节流被封装为帧（见 [`framing.rs`](file:///e:/myProjects/ssl-proxy/ssl-proxy-project/crates/svr/src/services/framing.rs)）：

```text
+------+--------+--------+----------+-----+
| flag | len u16| padLen | payload  | pad |
+------+--------+--------+----------+-----+
  1B      2B       1B       len       padLen
```

- `flag = 0` 普通数据帧；`flag = 1` 表示此后切换为裸字节流；
- **上行（客户端→服务端）全程分帧**：≤2KB 的小包随机切片（64~512B）并随机填充（0~256B），
  把 ClientHello / 请求头的长度直方图打平；大包整段一帧、仅 0~32B 填充，上传吞吐几乎无损；
- **下行只在前 16KB（覆盖 TLS 握手）内 padding**，之后发 `RAW` 标记帧并裸透传，
  下载带宽与速度不受影响；
- v2 首包随首个上行帧一起被填充，消除 59 字节异常小记录的特征；
- 编码结果攒批后一次 `write_all`，不增加 syscall。

**帧格式必须与客户端 [`framing.rs`](file:///e:/myProjects/ssl-proxy/ssl-proxy-project/crates/gui/src/core/proxy/framing.rs) 保持一致。**

### 5.5 Mux 多路复用（参考 trojan-go + smux）

`hostLen = 0` 的 v2 首包表示「mux 连接」：认证通过后整条 TLS 连接进入复用模式，
每个目标连接对应一个逻辑流（sid），省掉反复的 TCP + TLS 握手。

```text
+------+--------+--------+--------+----------+-----+
| flag | sid u32| len u16| padLen | payload  | pad |
+------+--------+--------+--------+----------+-----+
  1B      4B       2B       1B       len       padLen
```

| flag | 含义 |
| ---- | ---- |
| 0 DATA | 流数据 |
| 1 OPEN | 新建流，payload = `port u16 BE | hostLen u8 | host` |
| 2 FIN | 发送方向结束（半关闭） |
| 3 RST | 中止流 |
| 4 / 5 | PING / PONG 保活 |

- 单连接最多 256 条并发流，客户端最多复用 4 条连接（满了再建新连接）；
- 流控为**连接级背压**：某流命令缓冲满时暂停整条连接读取，实现简单、单流大文件不受影响；
- 客户端每 25s 发 PING 保活；连接断开时所有流统一结束；
- DATA 帧继续做小包随机 padding，mux 帧头不会成为新的长度指纹；
- 服务端可用 `--no-mux`（或 YAML `server.mux: false`）关闭 mux，关闭后 mux 首包直接拒绝。

---

## 6. 关键实现细节

### 6.1 限流与黑名单（[rate_limit.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/libs/rate_limit.rs)）

- 基于 DashMap 的内存级实现，无外部存储；
- 滑动窗口计数：周期内计数达到 `max_requests` 即触发封禁；
- 封禁：写入黑名单（记录过期时间戳），期间直接拒绝；过期后**惰性清除**；
- 单 IP 被封不影响其他 IP。

### 6.2 日志（[logger.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/core/logger.rs)）

- 控制台 + 文件双输出；文件无 ANSI 色；
- 每次启动生成 `app-{YYYYMMDD-HHMMSS}.log`，单个文件超 `max_size` 后自动轮转到新文件；
- 级别：`RUST_LOG` 环境变量优先，否则取配置的 `log.level`。

### 6.3 TLS 证书加载（[socket_service.rs](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/services/socket_service.rs)）

- 提供 `--cert/--key`：读取 PEM 证书链 + 私钥（兼容 PKCS#8 / PKCS#1 / SEC1）；
- 两者均缺省：`rcgen` 生成 ECDSA P-256 自签证书，SAN 为 `tls.sni`（若配置）+ `localhost` + `127.0.0.1`，仅供本地开发；
- ALPN 只广告 `http/1.1`，与回落时的 HTTP/1.1 伪装保持一致，避免“协商了 h2 却回 HTTP/1.1”的破绽；
- 客户端证书校验关闭（`with_no_client_auth`）。

### 6.4 优雅关闭

- 支持 Ctrl+C（所有平台）与 SIGTERM（Unix）；
- 通过 `watch` 通道通知监听循环停止 accept；
- 用原子计数器跟踪活跃连接，停止时最多等待 5s 让存量连接自然结束。

---

## 7. 配置参考

完整示例见 [config.example.yaml](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/config.example.yaml)，CLI 参数优先级高于 YAML：

| 参数 | 说明 |
| ---- | ---- |
| `--config <FILE>` | YAML 配置文件路径 |
| `--listen <ADDR>` | 监听地址，默认 `0.0.0.0` |
| `--port <PORT>` | 监听端口，默认 `1888` |
| `--pwd <PWD>` | 代理密码，缺省随机 12 位 |
| `--no-mux` | 关闭 mux 多路复用（默认开启） |
| `--cert/--key <FILE>` | TLS 证书/私钥（PEM），须成对提供 |
| `--html <DIR>` | 静态伪装站点根目录 |
| `--log-dir <DIR>` / `--log-level <LEVEL>` | 日志目录 / 级别 |

### 快速启动示例

```bash
# 零配置：自签证书 + 静态站点
ssl-proxy-svr --html ./html

# 配置文件模式
ssl-proxy-svr --config ./config.example.yaml

# 正式证书模式
ssl-proxy-svr --cert ./certs/server.crt --key ./certs/server.key --html ./html
```

---

## 8. 安全设计要点

| 威胁 | 防护措施 |
| ---- | -------- |
| 路径穿越（`../`、绝对路径、盘符） | [`sanitize_path`](file:///e:/myProjects/ssl-proxy/ssl-proxy-project/crates/svr/src/services/static_sources_service.rs) 逐组件校验，违规返回 403 |
| 端口扫描 / 暴力请求 | 每 IP 限流 + 黑名单封禁 |
| 首包重放 | 时间戳（±120s 窗口）+ 参与签名的 HMAC-SHA256 |
| 密码泄露 / 暴力破解 | 密码不参与传输，仅发送 HMAC；失败直接回落静态站点，不暴露代理特征 |
| 首包篡改 | host / port / timestamp 全部参与签名，常量时间比对 |
| 中间人伪造服务端 | 客户端校验 ACK MAC（双向认证），跳过证书校验时仍能识别伪造应答 |
| 主动探测 / TLS 指纹 | ALPN 广告 `http/1.1`，非协议流量回落为正常 HTTP/1.1 站点 |
| TLS-in-TLS 流量指纹 | 隧道分帧 + 随机 padding 打散 record 长度；下行握手后裸透传 |
| 频繁 TLS 握手特征 | mux 复用：一条 TLS 连接承载多条流（trojan-go 式），显著减少握手次数 |
| 非法协议 | 非 HTTP 且认证失败统一回落，不返回错误特征 |

---

## 9. 构建与测试

```bash
# 构建
cargo build --release

# 运行
cargo run --release -- --html ./html

# 单元测试（限流、协议识别、协议解析）
cargo test
```
