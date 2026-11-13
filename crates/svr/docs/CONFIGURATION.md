# ssl-proxy-svr 配置文档

本文档说明 `ssl-proxy-svr` 的 YAML 配置、命令行参数、优先级规则与启动校验行为。

---

## 1. 配置来源与优先级

配置由三部分合并而成（见 [`AppConfig::merge`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/config.rs#L194-L277)）：

```
命令行参数  >  YAML 配置文件  >  内置默认值
```

- YAML 通过 `--config <FILE>`（简写 `-c`）加载；不提供时全部使用默认值；
- 启动命令：

```bash
ssl-proxy-svr --config ./config.example.yaml
ssl-proxy-svr -c ./config.yaml --port 9443 --html ./html
```

- YAML 的字段名统一使用 **kebab-case**（如 `max-size`、`rate-time-secs`、`static-sources`）；
- 未配置的键可整段省略，`tls: {}` 表示使用默认行为。

---

## 2. 字段参考

### 2.1 `server`

```yaml
server:
  listen: "0.0.0.0"
  port: 1888
  password: "your-strong-password"
  mux: true
  allow-private-targets: false
```

| 字段 | 类型 | 默认值 | 对应 CLI | 说明 |
| ---- | ---- | ------ | -------- | ---- |
| `listen` | string | `0.0.0.0` | `--listen` | 监听地址 |
| `port` | u16 | `1888` | `--port` / `-p` | 监听端口（1–65535） |
| `password` | string | 随机 12 位字母数字 | `--pwd` | 私有协议认证密码 |
| `mux` | bool | `true` | `--no-mux`（关闭） | 是否接受 mux 多路复用连接；关闭后 `hostLen=0` 的 mux 首包被直接拒绝 |
| `allow-private-targets` | bool | `false` | `--allow-private-targets` | 是否允许 TCP / UDP 隧道访问回环、内网、CGNAT、metadata 地址（默认拦截，防 SSRF） |

说明：

- `password` 为空字符串时视同未配置，会自动生成随机密码；
- 密码参与私有协议首包校验，**客户端必须与服务端保持一致**；
- 启动日志中密码是掩码显示的（保留首尾各 2 位，如 `yo****************rd`），因此**自动生成的随机密码无法从日志读取**，建议显式配置。

### 2.2 `tls`

```yaml
tls:
  cert: "./certs/server.crt"
  key: "./certs/server.key"
  sni: "example.com"
```

| 字段 | 类型 | 默认值 | 对应 CLI | 说明 |
| ---- | ---- | ------ | -------- | ---- |
| `cert` | path | 无 | `--cert` | 证书文件（PEM，可含证书链） |
| `key` | path | 无 | `--key` | 私钥文件（PEM） |
| `sni` | string | 无 | `--sni` | 自签证书使用的 SNI 域名（SAN） |

说明：

- `cert` 与 `key` **必须同时提供或同时缺省**，只给其一会启动失败；
- 私钥支持三种 PEM 格式：PKCS#8（`BEGIN PRIVATE KEY`）、PKCS#1（`BEGIN RSA PRIVATE KEY`）、SEC1（`BEGIN EC PRIVATE KEY`）；
- 两者都缺省时，启动期生成 ECDSA P-256 自签证书，SAN 为 `sni`（若配置）+ `localhost` + `127.0.0.1`；未配置 `sni` 时仅有后两者。例如 `sni: "example.com"` 的证书 SAN 为 `DNS:example.com, DNS:localhost, IP:127.0.0.1`；
- `sni` **只影响自签证书**，提供了 `cert`/`key` 时被忽略（此时证书域名由证书文件自身决定）；
- `sni` 为空白字符串时视同未配置；
- 自签证书未经 CA 签名，浏览器会提示不受信任，仅供本地开发/测试；
- 服务端不校验客户端证书，也不按 SNI 选择不同证书（只使用单一证书）。

### 2.3 `static-sources`

```yaml
static-sources:
  html: "./html"
  index: "index.html"
  fallback-url: "https://example.com"
```

| 字段 | 类型 | 默认值 | 对应 CLI | 说明 |
| ---- | ---- | ------ | -------- | ---- |
| `html` | path | 无 | `--html` | 伪装站点根目录 |
| `index` | string | `index.html` | 无 | 访问 `/` 时返回的首页文件名 |
| `fallback-url` | string | 无 | `--fallback-url` | 真实站点回落地址（绝对 URL）；配置后未认证流量反代到该站点，并启用 HTTP/2 |

说明：

- `html` 缺省时不报错，但**所有 HTTP 请求统一返回 404**（相当于只做隧道）；
- 一旦配置了 `html`，启动时会校验：目录不存在或不是目录 → 启动失败；
- `fallback-url` 配置后优先走反代，目标固定为配置值，不接受请求里的 Host/SNI 改写，避免成为开放代理/SSRF；
- 配置 `fallback-url` 时服务端 ALPN 会同时广告 `h2` 与 `http/1.1`，回落站点可用 HTTP/2；
- 行为约束：仅处理 `GET` / `HEAD`；命中文件返回 `200` + gzip 流式响应；`HEAD` 只返回响应头（`Content-Length: 0`）；路径含 `..`、绝对路径、盘符前缀一律 `403`。

### 2.4 `log`

```yaml
log:
  dir: "./logs"
  level: "info"
  max-size: 5242880
```

| 字段 | 类型 | 默认值 | 对应 CLI | 说明 |
| ---- | ---- | ------ | -------- | ---- |
| `dir` | path | `./logs` | `--log-dir` | 日志目录，不存在时自动创建 |
| `level` | string | `info` | `--log-level` | 日志级别：`trace`/`debug`/`info`/`warn`/`error` |
| `max-size` | u64 | `5242880`（5 MB） | 无 | 单个日志文件最大字节数，超出后轮转 |

说明：

- 同时输出到控制台与文件；文件不带 ANSI 颜色；
- 文件命名 `app-{YYYYMMDD-HHMMSS}.log`，每次启动新建，单文件写满 `max-size` 后自动切换到新文件；
- 环境变量 `RUST_LOG` 优先于 `log.level`（`RUST_LOG=debug` 可临时提升级别）。

### 2.5 `rate-limit`

```yaml
rate-limit:
  max-requests: 300
  rate-time-secs: 60
  black-time-secs: 600
```

| 字段 | 类型 | 默认值 | 对应 CLI | 说明 |
| ---- | ---- | ------ | -------- | ---- |
| `max-requests` | u32 | `300` | 无 | 单个统计窗口内的请求数上限 |
| `rate-time-secs` | u64 | `60` | 无 | 统计窗口时长（秒） |
| `black-time-secs` | u64 | `600` | 无 | 触发限流后的封禁时长（秒） |

限流语义（见 [`RateLimit::record`](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/src/libs/rate_limit.rs#L51-L95)）：

- 按**客户端 IP** 做固定窗口计数；窗口内第 `max-requests` 次请求即触发封禁（判断条件是 `count >= max`，因此实际放行 `max-requests - 1` 次）；
- 触发后计数清零，写入黑名单，封禁到期时间 = 触发时刻 + `black-time-secs`；
- 封禁期间该 IP 的连接被直接断开；到期后惰性清除，其他 IP 不受影响；
- **仅作用于"伪装/回落"流量**：已通过私有协议认证的隧道连接不受限流影响；
- **同时用于认证失败防爆破**：首包以私有协议魔数（`0x10 0xff`）开头但校验失败（含重放）会按同一配置计数，达到阈值后该 IP 在封禁期内不再做 HMAC 校验、直接回落（保持伪装表现）；普通 HTTP 访客不计入该计数；
- 计数与黑名单只存在内存中，进程重启即清空。

### 2.6 `udp`

```yaml
udp:
  enabled: false
  timeout-secs: 60
  rate-limit: 100
```

| 字段 | 类型 | 默认值 | 对应 CLI | 说明 |
| ---- | ---- | ------ | -------- | ---- |
| `enabled` | bool | `false` | 无 | 是否启用 UDP relay（UDP over TLS 转发） |
| `timeout-secs` | u64 | `60` | 无 | UDP 会话空闲超时（秒） |
| `rate-limit` | u32 | `100` | 无 | 每会话每秒报文数上限（令牌桶） |

说明：

- `enabled: false`（默认）时：客户端发来的 UDP 隧道认证（首包 `port = 0`）会先收到带能力位 `0x00` 的 ACK，随后连接被关闭，客户端据此自动降级为直连；mux UDP 流帧会被安全拒绝（连接直接关闭），TCP 路径不受影响；
- `enabled: true` 时，服务端按流 ID 维护 NAT 会话表：未命中则绑定临时端口新建并转发，回包按同一流 ID 封帧写回隧道；会话空闲超过 `timeout-secs` 无上下行报文即回收 socket，后续同流 ID 报文触发新建；
- 防滥用：每会话每秒报文数超过 `rate-limit` 时丢包（令牌桶，容量 = 速率）；目标为回环（127.0.0.0/8、::1）、内网（10/8、100.64/10、172.16/12、192.168/16、192.0.0/24、198.18/15）、链路本地（169.254/16、fe80::/10）、站点本地（fec0::/10）、0.0.0.0/8、组播/保留段（224/4、240/4、ff00::/8）、ULA（fc00::/7）、IPv6 过渡段（6to4 `2002::/16`、Teredo `2001::/32`、NAT64 `64:ff9b::/96` 与 `64:ff9b:1::/48`，其中 `64:ff9b::/96` 会提取内嵌 IPv4 复查）或服务端本机地址时丢弃并记录告警日志（域名解析后的地址同样检查）；
- 能力协商：`enabled: true` 时，携带扩展位的新客户端会在隧道 ACK 的能力位中读到 `0x01`（支持 UDP）；`enabled: false` 时能力位为 `0x00`，客户端据此自动降级为直连；
- DNS / QUIC 等域名目标由服务端解析（与 TCP 转发一致的系统解析器）。

---

## 3. 命令行参数对照

| 参数 | 值名 | 说明 |
| ---- | ---- | ---- |
| `-c, --config` | FILE | YAML 配置文件路径 |
| `--listen` | ADDR | 监听地址（**内置默认值 `0.0.0.0`**，见第 5 节注意事项） |
| `-p, --port` | PORT | 监听端口 |
| `--pwd` | PWD | 代理密码 |
| `--no-mux` | — | 关闭多路复用（mux）支持 |
| `--cert` | FILE | TLS 证书（PEM） |
| `--key` | FILE | TLS 私钥（PEM） |
| `--sni` | NAME | 自签证书的 SNI 域名（提供 `--cert/--key` 时忽略） |
| `--html` | DIR | 静态站点根目录 |
| `--fallback-url` | URL | 真实站点回落地址（启用反代与 HTTP/2） |
| `--log-dir` | DIR | 日志目录 |
| `--log-level` | LEVEL | 日志级别 |
| `-h, --help` | | 打印帮助 |

`log.max-size`、`rate-limit.*` 与 `udp.*` 没有对应的命令行参数，只能通过 YAML 配置。

---

## 4. 典型配置示例

**① 本地开发（零证书）**

```yaml
server:
  port: 1888
  password: "dev-password"
static-sources:
  html: "./html"
log:
  level: "debug"
```

**② 生产环境（正式证书 + 收紧限流）**

```yaml
server:
  listen: "0.0.0.0"
  port: 443
  password: "a-long-random-password"

tls:
  cert: "/etc/ssl/private/example.com.crt"
  key: "/etc/ssl/private/example.com.key"

static-sources:
  html: "/var/www/masquerade"
  index: "index.html"

log:
  dir: "/var/log/ssl-proxy"
  level: "info"
  max-size: 10485760

rate-limit:
  max-requests: 120
  rate-time-secs: 60
  black-time-secs: 1800
```

**③ 只做隧道（不需要伪装站点）**

```yaml
server:
  port: 8443
  password: "tunnel-only"
tls:
  cert: "./certs/server.crt"
  key: "./certs/server.key"
# 不配置 static-sources → 非代理流量统一 404
```

---

## 5. 启动校验与常见错误

| 错误信息 | 原因 | 处理 |
| -------- | ---- | ---- |
| `read config file ... failed` | `--config` 路径不存在或无权限 | 检查路径 |
| `parse YAML failed: ...` | YAML 语法错误 | 检查缩进与引号 |
| `deserializing from YAML containing more than one document is not supported` | 文件里出现多个 `---` 文档分隔符 | 只保留一个文档 |
| `--cert and --key must be provided together` | 只提供了其中一个 | 成对提供或都省略 |
| `open cert ...: No such file` | 证书路径错误 | 检查路径 |
| `no private key found in ...` | 私钥文件为空或格式不支持 | 使用 PKCS#8 / PKCS#1 / SEC1 格式 |
| `静态资源目录不存在: ...` | 配置了 `html` 但目录不存在 | 创建目录或删除该配置 |
| `bind 0.0.0.0:1888 failed` | 端口被占用或无权限 | 换端口或释放占用 |

### 注意事项

1. **`server.listen` 的 YAML 值当前不生效**：`--listen` 在 CLI 定义了默认值 `0.0.0.0`，导致合并时总是取 CLI 值。需要改监听地址时请用 `--listen 127.0.0.1` 显式指定。
2. **未知字段会被静默忽略**：YAML 结构未启用 `deny_unknown_fields`，键名拼错（如 `static_source`）不会报错，只会按默认值运行。配置后建议核对启动日志中的实际生效值。
3. **随机密码不可见**：不配置 `password` 时生成的随机密码在日志中为掩码，请显式配置。
4. **日志与限流无持久化**：日志文件不会自动清理旧文件；限流记录仅存内存，重启清零。
5. **首包与上游超时不可配置**：读取客户端首包固定 5 秒，连接上游固定 10 秒。

---

相关文档：[架构与设计文档](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/docs/ARCHITECTURE.md) · [配置示例](file:///e:/myProjects/ssl-proxy/ssl-proxy-svr/config.example.yaml)
