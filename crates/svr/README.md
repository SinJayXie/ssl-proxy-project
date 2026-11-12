# ssl-proxy-svr

A lightweight TLS proxy server built with tokio + rustls, refactored from the Node.js implementation.

Exposes a single TLS port that routes traffic based on protocol detection:

- **Private protocol** → transparent TCP tunnel to an upstream target
- **All other traffic** → static masquerade site (served from a local `html/` directory)

## Features

- TLS 1.3 support via rustls
- Auto-generated self-signed certificates (zero-config startup)
- Private protocol authentication with password protection
- Static site masquerade for non-proxy traffic
- Rate limiting with configurable blacklist duration
- Rotating file logging with configurable level and max file size
- YAML config file + CLI argument override
- Bidirectional zero-copy TCP forwarding

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — 架构设计、私有协议格式、请求处理流程与实现细节
- [CONFIGURATION.md](docs/CONFIGURATION.md) — YAML 配置项、命令行参数、优先级与启动校验

## Quick Start

```bash
# Build
cargo build --release

# Run with auto-generated self-signed cert and static site
ssl-proxy-svr --html ./html

# Run with config file
ssl-proxy-svr --config ./config.example.yaml

# Run with explicit cert/key
ssl-proxy-svr --cert ./certs/server.crt --key ./certs/server.key --html ./html
```

## Configuration

配置文件通过 `--config <FILE>`（简写 `-c`）加载，字段名统一使用 **kebab-case**。
优先级：**命令行参数 > YAML 配置 > 内置默认值**。未配置的键可整段省略。

完整示例见 [config.example.yaml](config.example.yaml)。

### 完整配置示例

```yaml
# ---- server ----
server:
  listen: "0.0.0.0"                 # 监听地址
  port: 1888                        # 监听端口
  password: "your-strong-password"  # 代理密码；缺省随机生成 12 位
  mux: true                         # 是否接受多路复用连接（默认 true）

# ---- tls ----
# cert/key 均缺省时启动期自动生成自签证书（SAN: sni + localhost + 127.0.0.1）
tls:
  cert: "./certs/server.crt"        # 证书 PEM（可含证书链）
  key: "./certs/server.key"         # 私钥 PEM（PKCS#8 / PKCS#1 / SEC1）
  sni: "example.com"                # 仅自签证书使用；提供 cert/key 时忽略

# ---- static-sources ----
# 伪装站点；缺省时所有 HTTP 请求统一返回 404
static-sources:
  html: "./html"                    # 站点根目录
  index: "index.html"               # 访问 "/" 返回的首页

# ---- log ----
log:
  dir: "./logs"                     # 日志目录，不存在时自动创建
  level: "info"                     # trace | debug | info | warn | error
  max-size: 5242880                 # 单文件上限（字节），超出后轮转

# ---- rate-limit ----
rate-limit:
  max-requests: 300                 # 单窗口请求上限
  rate-time-secs: 60                # 统计窗口（秒）
  black-time-secs: 600              # 触发后的封禁时长（秒）
```

### 字段说明

**`server`**

| 字段 | 类型 | 默认值 | CLI | 说明 |
| ---- | ---- | ------ | --- | ---- |
| `listen` | string | `0.0.0.0` | `--listen` | 监听地址（见注意事项 1） |
| `port` | u16 | `1888` | `-p, --port` | 监听端口（1–65535） |
| `password` | string | 随机 12 位 | `--pwd` | 私有协议认证密码，空字符串视同未配置 |
| `mux` | bool | `true` | `--no-mux`（关闭） | 是否接受多路复用连接；关闭后 `hostLen=0` 的 mux 首包会被直接拒绝 |

**`tls`**

| 字段 | 类型 | 默认值 | CLI | 说明 |
| ---- | ---- | ------ | --- | ---- |
| `cert` | path | 无 | `--cert` | 证书文件（PEM） |
| `key` | path | 无 | `--key` | 私钥文件（PEM） |
| `sni` | string | 无 | `--sni` | 自签证书的 SAN 域名，空白视同未配置 |

- `cert` 与 `key` 必须成对提供，只给其一启动失败；
- 两者都缺省时生成 ECDSA P-256 自签证书，SAN 为 `sni`（若配置）+ `localhost` + `127.0.0.1`；
- 自签证书未经 CA 签名，仅供本地开发/测试。

**`static-sources`**

| 字段 | 类型 | 默认值 | CLI | 说明 |
| ---- | ---- | ------ | --- | ---- |
| `html` | path | 无 | `--html` | 伪装站点根目录；配置后启动期校验目录存在 |
| `index` | string | `index.html` | 无 | 访问 `/` 返回的文件 |

- 仅处理 `GET` / `HEAD`；命中文件返回 `200` + gzip；路径穿越返回 `403`；
- 不配置 `html` 时所有 HTTP 请求统一 `404`（相当于纯隧道模式）。

**`log`**

| 字段 | 类型 | 默认值 | CLI | 说明 |
| ---- | ---- | ------ | --- | ---- |
| `dir` | path | `./logs` | `--log-dir` | 日志目录，自动创建 |
| `level` | string | `info` | `--log-level` | 环境变量 `RUST_LOG` 优先于此项 |
| `max-size` | u64 | `5242880`（5 MB） | 无 | 单文件写满后轮转到新文件 |

日志文件命名 `app-{YYYYMMDD-HHMMSS}.log`，控制台与文件双输出。

**`rate-limit`**

| 字段 | 类型 | 默认值 | CLI | 说明 |
| ---- | ---- | ------ | --- | ---- |
| `max-requests` | u32 | `300` | 无 | 单窗口请求上限（实际放行 `max-requests - 1` 次） |
| `rate-time-secs` | u64 | `60` | 无 | 统计窗口时长 |
| `black-time-secs` | u64 | `600` | 无 | 触发后的封禁时长 |

- 按客户端 IP 做固定窗口计数，触发后进入黑名单，期间连接直接断开；
- **仅作用于回落/伪装流量**，已通过私有协议认证的隧道与 mux 连接不受限流影响；
- 计数与黑名单仅存内存，重启清零。

### 命令行参数

| 参数 | 值名 | 说明 |
| ---- | ---- | ---- |
| `-c, --config` | FILE | YAML 配置文件路径 |
| `--listen` | ADDR | 监听地址 |
| `-p, --port` | PORT | 监听端口 |
| `--pwd` | PWD | 代理密码 |
| `--no-mux` | — | 关闭 mux 多路复用 |
| `--cert` | FILE | TLS 证书（PEM） |
| `--key` | FILE | TLS 私钥（PEM） |
| `--sni` | NAME | 自签证书 SNI 域名 |
| `--html` | DIR | 静态站点根目录 |
| `--log-dir` | DIR | 日志目录 |
| `--log-level` | LEVEL | 日志级别 |
| `-h, --help` | — | 打印帮助 |

`log.max-size` 与 `rate-limit.*` 没有对应命令行参数，只能通过 YAML 配置。

### 典型配置

**最小可用（零证书 + 伪装站点）**

```yaml
server:
  password: "dev-password"
static-sources:
  html: "./html"
```

**生产环境（正式证书 + 收紧限流 + 关闭 mux）**

```yaml
server:
  listen: "0.0.0.0"
  port: 443
  password: "a-long-random-password"
  mux: false

tls:
  cert: "/etc/ssl/private/example.com.crt"
  key: "/etc/ssl/private/example.com.key"

static-sources:
  html: "/var/www/masquerade"

log:
  dir: "/var/log/ssl-proxy"
  level: "info"

rate-limit:
  max-requests: 120
  rate-time-secs: 60
  black-time-secs: 1800
```

**纯隧道（不需要伪装站点）**

```yaml
server:
  port: 8443
  password: "tunnel-only"
tls:
  cert: "./certs/server.crt"
  key: "./certs/server.key"
# 不配置 static-sources → 非代理流量统一 404
```

### 注意事项

1. **`server.listen` 的 YAML 值当前不生效**：`--listen` 在 CLI 中带默认值 `0.0.0.0`，合并时总是覆盖 YAML。需要改监听地址请显式传 `--listen 127.0.0.1`。
2. **未知字段被静默忽略**：未启用 `deny_unknown_fields`，键名拼错不会报错，建议核对启动日志中的生效值。
3. **随机密码不可见**：自动生成的密码在日志中掩码显示，生产环境请显式配置。
4. **mux 需要两端匹配**：服务端 `--no-mux` 后，客户端若仍开启 mux 会被直接断开；客户端侧开关在设置页「多路复用（TLS 复用）」。
5. **超时固定**：读取客户端首包 5 秒、连接上游 10 秒，均不可配置。
6. **日志不自动清理**：旧日志文件需自行归档，限流记录不持久化。

## License

MIT
