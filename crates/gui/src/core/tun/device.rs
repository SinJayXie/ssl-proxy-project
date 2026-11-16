//! TUN 设备层：WinTun 用户态网卡封装（仅 Windows）。
//!
//! 职责极窄：创建/删除虚拟网卡、配置 IP、在内核 ring buffer 与
//! Rust 通道之间搬运 IP 包。协议栈（TCP/UDP/DNS）在 [`super::netstack`]，
//! 路由在 [`super::routes`] —— 本模块不做任何分流或系统路由操作。
//!
//! 运行时依赖 `wintun.dll`（wintun.net，需与 exe 同目录或 PATH 中）。

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 已打开的 TUN 设备。丢弃 `keepalive` 前必须先完成路由回滚（runner 负责）。
pub struct TunDevice {
    /// 从网卡读出的 IP 包（TUN → 用户态协议栈）。
    pub rx: Receiver<Vec<u8>>,
    /// 写入网卡的 IP 包（用户态协议栈 → TUN）。
    pub tx: Sender<Vec<u8>>,
    /// 实际网卡名（如 "SSLProxy"），供路由/绑定使用。
    pub name: String,
    pub mtu: u16,
    /// 接口索引（ifIndex，由 ConvertInterfaceLuidToIndex 转换得到），
    /// 供直连出站绑定与 netsh 路由。
    pub if_index: u32,
    /// 读线程停止信号。协议栈退出时置位，否则无流量时读线程永远不会
    /// 察觉通道已关闭，会一直轮询并持有 Session（线程泄漏 + CPU 空转）。
    pub stop: Arc<AtomicBool>,
    /// 保持 adapter/session 存活；必须由协议栈持有到线程退出后再 drop，
    /// 否则网卡会话在读写线程仍用 Arc 引用时就提前析构。
    pub keepalive: Option<Box<dyn Send>>,
}

/// 打开 TUN 设备失败的原因（fail-closed：调用方必须放弃启用，不得半开）。
pub type OpenError = String;

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use crate::core::tun::config::TunConfig;

    struct Keepalive {
        _adapter: Arc<wintun::Adapter>,
        _session: Arc<wintun::Session>,
    }

    unsafe impl Send for Keepalive {}

    /// ring buffer 大小：4 MiB，与官方示例一致。
    const RING_SIZE: u32 = 0x400_000;

    pub fn open(cfg: &TunConfig) -> Result<TunDevice, OpenError> {
        // wintun.dll：优先 exe 目录，其次 PATH/system32。
        let dll = {
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()));
            match exe_dir.map(|d| d.join("wintun.dll")) {
                Some(p) if p.exists() => unsafe { wintun::load_from_path(&p) },
                _ => unsafe { wintun::load() },
            }
        }
        .map_err(|e| format!("加载 wintun.dll 失败（应位于 exe 同目录）: {e}"))?;

        let adapter = wintun::Adapter::create(&dll, &cfg.device_name, "SSLProxy Tunnel", None)
            .map_err(|e| format!("创建 TUN 适配器失败（需管理员权限）: {e}"))?;

        // 接口索引：直连出站绑定 + 路由命令都要用。
        // LUID ≠ ifIndex，必须走系统 API ConvertInterfaceLuidToIndex 转换；
        // 直接取 LUID 位域可能得到 0，会误判为无效。
        // 注：wintun 内部用 windows 0.52 的 NET_LUID_LH，与本 crate 的 0.58
        // 类型不同名，但同为 repr(C) u64 联合体——按值重建一份再传入。
        let raw_luid = unsafe { adapter.get_luid().Value };
        let mut if_index: u32 = 0;
        let conv = unsafe {
            use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
            let luid = NET_LUID_LH { Value: raw_luid };
            windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex(&luid, &mut if_index)
        };
        if conv.is_err() || if_index == 0 {
            return Err(format!("TUN 接口索引无效（LUID→Index 转换失败: {conv:?}）").into());
        }

        // fake-ip 网关即 TUN 地址：198.18.0.1/30，网关指向自身（on-link）。
        let (ip_v4, mask_v4) = gateway_addrs(&cfg.fake_ip_range)?;
        let ip = std::net::IpAddr::V4(ip_v4);
        let mask = std::net::IpAddr::V4(mask_v4);
        adapter
            .set_network_addresses_tuple(ip.clone(), mask, Some(ip))
            .map_err(|e| format!("配置 TUN 地址失败: {e}"))?;

        let session = Arc::new(
            adapter
                .start_session(RING_SIZE)
                .map_err(|e| format!("启动 TUN 会话失败: {e}"))?,
        );

        let (in_tx, in_rx) = channel::<Vec<u8>>(); // TUN → 协议栈
        let (out_tx, out_rx) = channel::<Vec<u8>>(); // 协议栈 → TUN

        // 读线程：网卡 → 通道。显式 stop 信号保证协议栈退出后线程一定结束
        //（只依赖 send 失败会在"停用后无流量"时永久空转，泄漏 Session）。
        let stop = Arc::new(AtomicBool::new(false));
        {
            let session = session.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("tun-rx".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        match session.try_receive() {
                            Ok(Some(pkt)) => {
                                let bytes = pkt.bytes().to_vec();
                                if in_tx.send(bytes).is_err() {
                                    break;
                                }
                            }
                            // 1ms 空转：200µs 会造成每秒 5000 次唤醒抢 CPU。
                            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
                            Err(_) => break, // 会话已关闭
                        }
                    }
                })
                .map_err(|e| format!("启动 TUN 读线程失败: {e}"))?;
        }

        // 写线程：通道 → 网卡。通道关闭后退出。
        {
            let session = session.clone();
            std::thread::Builder::new()
                .name("tun-tx".into())
                .spawn(move || {
                    for pkt in out_rx {
                        // 只发送能完整放入 ring slot 的包：allocate_send_packet
                        // 的长度与 pkt 不一致时 copy_from_slice 会 panic。
                        let Some(len) = u16::try_from(pkt.len()).ok() else {
                            log::debug!("丢弃超长出站包: {} 字节", pkt.len());
                            continue;
                        };
                        let mut send = match session.allocate_send_packet(len) {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let dst = send.bytes_mut();
                        if dst.len() < pkt.len() {
                            log::debug!(
                                "丢弃出站包: 需要 {} 字节，ring slot 仅 {}",
                                pkt.len(),
                                dst.len()
                            );
                            continue;
                        }
                        dst[..pkt.len()].copy_from_slice(&pkt);
                        session.send_packet(send);
                    }
                })
                .map_err(|e| format!("启动 TUN 写线程失败: {e}"))?;
        }

        Ok(TunDevice {
            rx: in_rx,
            tx: out_tx,
            name: cfg.device_name.clone(),
            mtu: cfg.mtu,
            if_index,
            stop,
            keepalive: Some(Box::new(Keepalive { _adapter: adapter, _session: session })),
        })
    }

    /// 解析 fake-ip 网关（"198.18.0.1/16" → (IPv4, /30 掩码)）。
    /// TUN 使用 /30 与 mihomo/sing-box 一致。
    pub fn gateway_addrs(fake_range: &str) -> Result<(std::net::Ipv4Addr, std::net::Ipv4Addr), OpenError> {
        let (addr, _) = fake_range
            .split_once('/')
            .ok_or_else(|| "fake-ip-range 缺少前缀".to_string())?;
        let ip: std::net::Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("fake-ip-range 地址无效: {addr}"))?;
        Ok((ip, std::net::Ipv4Addr::new(255, 255, 255, 252)))
    }
}

#[cfg(target_os = "windows")]
pub use imp::open;

#[cfg(not(target_os = "windows"))]
mod imp {
    use super::*;
    use crate::core::tun::config::TunConfig;

    pub fn open(_cfg: &TunConfig) -> Result<TunDevice, OpenError> {
        Err("TUN 当前仅在 Windows 上支持".into())
    }
}

#[cfg(not(target_os = "windows"))]
pub use imp::open;

#[cfg(test)]
mod tests {
    use super::super::config::DEFAULT_FAKE_IP_RANGE;

    #[cfg(target_os = "windows")]
    use super::imp;

    #[cfg(target_os = "windows")]
    #[test]
    fn gateway_addrs_parses_fake_ip_range() {
        let (ip, mask) = imp::gateway_addrs(DEFAULT_FAKE_IP_RANGE).unwrap();
        assert_eq!(ip.to_string(), "198.18.0.1");
        assert_eq!(mask.to_string(), "255.255.255.252");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn gateway_addrs_rejects_invalid() {
        assert!(imp::gateway_addrs("198.18.0.1").is_err());
        assert!(imp::gateway_addrs("bad/16").is_err());
    }
}
