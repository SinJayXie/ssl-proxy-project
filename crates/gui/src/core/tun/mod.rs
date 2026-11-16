//! TUN 控制面与安全不变量模块。
//!
//! 当前状态：**控制面与决策逻辑已实现，设备层（WinTun / 用户态协议栈 /
//! 系统路由 syscall）尚未接入**。因此本模块不创建任何网卡，也不会改动
//! 系统路由；它把 mihomo / Verge 调研中确认的安全不变量固化为可测试的
//! 纯逻辑，为后续阶段 B/C 的设备层提供稳定的调用契约。
//!
//! 模块职责：
//! - [`config`]：配置模型、默认值、CIDR 校验、热重载 `sort`/`equal`；
//! - [`route`]：接口探测防自环、代理节点自动排除、私网直连判定；
//! - [`dns`]：fake-ip 映射与 fail-closed 反查、DNS 劫持判定；
//! - [`lifecycle`]：能力门控与启停状态机（fail-closed）。
//!
//! 真正的流量分流复用 [`crate::core::proxy::route`]（TCP/UDP/TUN 同一决策引擎），
//! 保证「DIRECT 走物理网卡原生 socket，PROXY 才进 TLS 隧道」。

// 本模块的 API 是设备层（阶段 B/C）的调用契约，当前由单元测试覆盖；
// 设备层接入前编译器会判定为 dead_code，这是预期状态。
#![allow(dead_code)]

pub mod config;
pub mod device;
pub mod dns;
pub mod lifecycle;
pub mod netinfo;
pub mod netstack;
pub mod outbound;
pub mod route;
pub mod routes;
pub mod runner;
