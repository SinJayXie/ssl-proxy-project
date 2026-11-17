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

/// 网卡名冲突时的候选名称：原名、原名-1 … 原名-4（最多 5 次尝试，与 meow-rs 一致）。
pub fn device_name_candidates(base: &str) -> Vec<String> {
    let mut names = Vec::with_capacity(5);
    names.push(base.to_string());
    for n in 1..5 {
        names.push(format!("{base}-{n}"));
    }
    names
}

/// 清理时需要考虑的全部名称：历次启动可能因名字被占用而轮转到 `-N`，
/// 这些设备都属于本程序的遗留物。
pub fn stale_adapter_names(base: &str) -> Vec<String> {
    device_name_candidates(base)
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use crate::core::tun::config::TunConfig;

    /// adapter / session 与读写线程的所有权。
    ///
    /// 析构顺序很关键：先置停止标志并 join 读写线程，再关闭会话与网卡。
    /// 字段按声明顺序析构，所以 `session` 必须写在 `adapter` 前面。
    struct Keepalive {
        stop: Arc<AtomicBool>,
        session: Arc<wintun::Session>,
        adapter: Arc<wintun::Adapter>,
        rx_thread: Option<std::thread::JoinHandle<()>>,
        tx_thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for Keepalive {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            // 读线程 1ms 轮询、写线程 100ms 超时：join 有界，不会卡住调用方。
            if let Some(t) = self.rx_thread.take() {
                let _ = t.join();
            }
            if let Some(t) = self.tx_thread.take() {
                let _ = t.join();
            }
        }
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
        .map_err(|e| format!("failed to load wintun.dll (should be next to the executable): {e}"))?;

        // 网卡名冲突轮转（对齐 meow-rs）：原名被占用时依次尝试 -1 … -4，
        // 每次失败等待 500ms（旧网卡可能在异步释放），五次都失败则 fail-closed。
        let mut used_name: Option<String> = None;
        let mut adapter: Option<Arc<wintun::Adapter>> = None;
        let mut last_err: Option<String> = None;
        let candidates = device_name_candidates(&cfg.device_name);
        let total = candidates.len();
        for (idx, name) in candidates.into_iter().enumerate() {
            match wintun::Adapter::create(&dll, &name, "SSLProxy Tunnel", None) {
                Ok(a) => {
                    used_name = Some(name);
                    adapter = Some(a);
                    break;
                }
                Err(e) => {
                    // 只在第一次失败时 warn，避免多次尝试刷屏。
                    if idx == 0 {
                        log::warn!("failed to create TUN adapter {name}, trying next name: {e}");
                    }
                    last_err = Some(e.to_string());
                    if idx + 1 < total {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        }
        let (used_name, adapter) = match (used_name, adapter) {
            (Some(name), Some(adapter)) => (name, adapter),
            _ => {
                let e = last_err.unwrap_or_else(|| "unknown error".to_string());
                return Err(format!("failed to create TUN adapter (admin privileges required): {e}"));
            }
        };
        if used_name != cfg.device_name {
            log::info!("TUN adapter name in use, using {used_name} instead");
        }

        // 创建之后任何一步失败都要把半创建的网卡设备一并卸载，
        // 否则"网络连接"里会永久残留一个未连接的虚拟网卡。
        let result = open_with_adapter(cfg, &used_name, adapter);
        if result.is_err() {
            remove_adapter(&used_name);
        }
        result
    }

    fn open_with_adapter(
        cfg: &TunConfig,
        used_name: &str,
        adapter: Arc<wintun::Adapter>,
    ) -> Result<TunDevice, OpenError> {
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
            return Err(format!("invalid TUN interface index (LUID->Index conversion failed: {conv:?})").into());
        }

        // fake-ip 网关即 TUN 地址：198.18.0.1/30，网关指向自身（on-link）。
        // 走 IP Helper 并关闭 DAD（对齐 meow-rs windows_device.rs）：网卡
        // 创建后地址立即是 Preferred，否则在 tentative 期间不能作为源地址，
        // 直连出站会一直超时。
        let (ip_v4, _mask_v4) = gateway_addrs(&cfg.fake_ip_range)?;
        configure_addresses(if_index, ip_v4)?;

        let session = Arc::new(
            adapter
                .start_session(RING_SIZE)
                .map_err(|e| format!("failed to start TUN session: {e}"))?,
        );

        let (in_tx, in_rx) = channel::<Vec<u8>>(); // TUN → 协议栈
        let (out_tx, out_rx) = channel::<Vec<u8>>(); // 协议栈 → TUN

        // 读线程：网卡 → 通道。显式 stop 信号保证协议栈退出后线程一定结束
        //（只依赖 send 失败会在"停用后无流量"时永久空转，泄漏 Session）。
        let stop = Arc::new(AtomicBool::new(false));
        let rx_thread = {
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
                .map_err(|e| format!("failed to start TUN rx thread: {e}"))?
        };

        // 写线程：通道 → 网卡。通道关闭或收到停止信号后退出。
        let tx_thread = {
            let session = session.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("tun-tx".into())
                .spawn(move || loop {
                    // 带超时接收：停用 TUN 时不必等通道关闭（对端可能仍有
                    // 在途连接持有 StackShared）就能及时退出、释放网卡会话。
                    let pkt = match out_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                        Ok(pkt) => pkt,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            continue;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    // 只发送能完整放入 ring slot 的包：allocate_send_packet
                    // 的长度与 pkt 不一致时 copy_from_slice 会 panic。
                    let Some(len) = u16::try_from(pkt.len()).ok() else {
                        log::debug!("dropping oversized outbound packet: {} bytes", pkt.len());
                        continue;
                    };
                    let mut send = match session.allocate_send_packet(len) {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let dst = send.bytes_mut();
                    if dst.len() < pkt.len() {
                        log::debug!(
                            "dropping outbound packet: need {} bytes, ring slot only {}",
                            pkt.len(),
                            dst.len()
                        );
                        continue;
                    }
                    dst[..pkt.len()].copy_from_slice(&pkt);
                    session.send_packet(send);
                })
                .map_err(|e| format!("failed to start TUN tx thread: {e}"))?
        };

        Ok(TunDevice {
            rx: in_rx,
            tx: out_tx,
            name: used_name.to_string(),
            mtu: cfg.mtu,
            if_index,
            stop: stop.clone(),
            keepalive: Some(Box::new(Keepalive {
                stop,
                session,
                adapter,
                rx_thread: Some(rx_thread),
                tx_thread: Some(tx_thread),
            })),
        })
    }

    /// 从系统卸载虚拟网卡设备（尽力而为）。
    ///
    /// `WintunCloseAdapter` 只关闭句柄，设备节点仍留在"网络连接"中；这里用
    /// SetupAPI 按友好名称（即 wintun adapter 名）匹配并删除设备实例，
    /// 做到"停用 TUN 即卸载网卡"。
    pub fn remove_adapter(name: &str) {
        remove_adapters(&[name.to_string()]);
    }

    /// 批量卸载友好名称匹配 `names` 的虚拟网卡设备，返回实际移除的数量。
    ///
    /// 删除设备实例会连带移除挂在该接口上的路由，因此启动时可用于
    /// 清理旧版本遗留（崩溃退出、昔日未卸载）的网卡。
    pub fn remove_adapters(names: &[String]) -> usize {
        if names.is_empty() {
            return 0;
        }
        use windows::core::PCWSTR;
        use windows::Win32::Devices::DeviceAndDriverInstallation::{
            SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
            SetupDiGetDeviceRegistryPropertyW, SetupDiRemoveDevice, DIGCF_PRESENT,
            GUID_DEVCLASS_NET, SPDRP_FRIENDLYNAME, SP_DEVINFO_DATA,
        };

        let mut removed = 0usize;
        unsafe {
            let set = match SetupDiGetClassDevsW(
                Some(&GUID_DEVCLASS_NET),
                PCWSTR::null(),
                None,
                DIGCF_PRESENT,
            ) {
                Ok(set) => set,
                Err(e) => {
                    log::warn!("failed to enumerate network adapters for cleanup: {e}");
                    return 0;
                }
            };

            let mut index = 0u32;
            loop {
                let mut info = SP_DEVINFO_DATA {
                    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                    ..Default::default()
                };
                if SetupDiEnumDeviceInfo(set, index, &mut info).is_err() {
                    break;
                }
                index += 1;

                // 友好名以 UTF-16 返回；缓冲区按字节视图传入。
                let mut buf = [0u16; 256];
                let mut bytes = std::slice::from_raw_parts_mut(
                    buf.as_mut_ptr().cast::<u8>(),
                    buf.len() * std::mem::size_of::<u16>(),
                );
                let mut needed = 0u32;
                let ok = SetupDiGetDeviceRegistryPropertyW(
                    set,
                    &info,
                    SPDRP_FRIENDLYNAME,
                    None,
                    Some(&mut bytes),
                    Some(&mut needed),
                )
                .is_ok();
                if !ok {
                    continue;
                }
                let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
                let friendly = String::from_utf16_lossy(&buf[..end]);
                if !names.iter().any(|n| *n == friendly) {
                    continue;
                }
                if SetupDiRemoveDevice(set, &mut info).as_bool() {
                    removed += 1;
                    log::info!("TUN adapter {friendly} removed from the system");
                } else {
                    log::warn!(
                        "failed to remove TUN adapter {friendly}: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
            let _ = SetupDiDestroyDeviceInfoList(set);
        }
        removed
    }

    /// 解析 fake-ip 网关（"198.18.0.1/16" → (IPv4, /30 掩码)）。
    /// TUN 使用 /30 与 mihomo/sing-box 一致。
    pub fn gateway_addrs(fake_range: &str) -> Result<(std::net::Ipv4Addr, std::net::Ipv4Addr), OpenError> {
        let (addr, _) = fake_range
            .split_once('/')
            .ok_or_else(|| "fake-ip-range missing prefix".to_string())?;
        let ip: std::net::Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("invalid fake-ip-range address: {addr}"))?;
        Ok((ip, std::net::Ipv4Addr::new(255, 255, 255, 252)))
    }

    /// TUN 地址前缀：/30（网关 + DNS + 两个保留），与 mihomo / meow-rs 一致。
    const TUN_PREFIX_LEN: u8 = 30;

    /// 用 IP Helper 给 TUN 网卡写地址，做法对齐 meow-rs `windows_device.rs`：
    /// 1. 关掉该接口的 DAD（`DadTransmits = 0`）；
    /// 2. 删除接口上的残留地址（上次异常退出 / 网卡重建）；
    /// 3. 写入新地址并标记 `Preferred`，避免 tentative 期间无法作为源地址。
    ///
    /// 失败时把 DAD 设置写回原值，不留半配置状态（fail-closed）。
    fn configure_addresses(if_index: u32, ip: std::net::Ipv4Addr) -> Result<(), OpenError> {
        use windows::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
        use windows::Win32::NetworkManagement::IpHelper::{
            CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable,
            GetIpInterfaceEntry, GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry,
            SetIpInterfaceEntry, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
            MIB_UNICASTIPADDRESS_TABLE,
        };
        use windows::Win32::Networking::WinSock::{
            AF_INET, IpDadStatePreferred, SOCKADDR_IN, SOCKADDR_INET,
        };

        // 1. 关闭 DAD：地址写入后直接 Preferred。
        let mut iface = MIB_IPINTERFACE_ROW::default();
        iface.Family = AF_INET;
        iface.InterfaceIndex = if_index;
        let rc = unsafe { GetIpInterfaceEntry(&raw mut iface) };
        if rc != NO_ERROR {
            return Err(format!("failed to read TUN interface info: {}", rc.0));
        }
        let previous_dad = iface.DadTransmits;
        iface.DadTransmits = 0;
        // GetIpInterfaceEntry 返回的 SitePrefixLength 会被 SetIpInterfaceEntry 拒绝。
        iface.SitePrefixLength = 0;
        let rc = unsafe { SetIpInterfaceEntry(&raw mut iface) };
        if rc != NO_ERROR {
            return Err(format!("failed to disable TUN DAD: {}", rc.0));
        }

        // 2. 清理该接口上的残留 IPv4 地址（保留链路本地）。
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        let rc = unsafe { GetUnicastIpAddressTable(AF_INET, &raw mut table) };
        if rc == NO_ERROR && !table.is_null() {
            let count = unsafe { (*table).NumEntries } as usize;
            let first =
                unsafe { std::ptr::addr_of!((*table).Table) as *const MIB_UNICASTIPADDRESS_ROW };
            let rows = unsafe { std::slice::from_raw_parts(first, count) };
            for row in rows {
                if row.InterfaceIndex != if_index {
                    continue;
                }
                let Some(existing) = row_ipv4(row) else { continue };
                if existing.is_link_local() {
                    continue;
                }
                let rc = unsafe { DeleteUnicastIpAddressEntry(&raw const *row) };
                if rc != NO_ERROR && rc != ERROR_NOT_FOUND {
                    log::warn!("failed to remove residual TUN address {existing}: {}", rc.0);
                }
            }
            unsafe { FreeMibTable(table.cast()) };
        }

        // 3. 写入地址，显式标记 Preferred。
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
        row.InterfaceIndex = if_index;
        row.OnLinkPrefixLength = TUN_PREFIX_LEN;
        row.DadState = IpDadStatePreferred;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        let mut addr = SOCKADDR_IN::default();
        addr.sin_family = AF_INET;
        // S_addr 是网络字节序：直接用 octets 的内存布局。
        addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        row.Address = SOCKADDR_INET { Ipv4: addr };
        let rc = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
        if rc != NO_ERROR {
            // 回滚 DAD 设置，避免网卡留下被改过的接口参数。
            if let Ok(()) = restore_dad(if_index, previous_dad) {
                log::warn!("failed to set TUN address, DAD setting restored");
            }
            return Err(format!("failed to configure TUN address {ip}/{TUN_PREFIX_LEN}: {}", rc.0));
        }
        log::info!("TUN address {ip}/{TUN_PREFIX_LEN} configured (DAD off, state Preferred)");
        Ok(())
    }

    /// 读取 IP Helper 地址行中的 IPv4（非 IPv4 行返回 `None`）。
    fn row_ipv4(row: &windows::Win32::NetworkManagement::IpHelper::MIB_UNICASTIPADDRESS_ROW) -> Option<std::net::Ipv4Addr> {
        use windows::Win32::Networking::WinSock::AF_INET;
        let (family, raw) = unsafe {
            (
                row.Address.si_family,
                row.Address.Ipv4.sin_addr.S_un.S_addr,
            )
        };
        if family != AF_INET {
            return None;
        }
        Some(std::net::Ipv4Addr::from(raw.to_ne_bytes()))
    }

    /// 把接口的 DAD 设置写回 `transmits`。
    fn restore_dad(if_index: u32, transmits: u32) -> Result<(), OpenError> {
        use windows::Win32::Foundation::NO_ERROR;
        use windows::Win32::NetworkManagement::IpHelper::{
            GetIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
        };
        use windows::Win32::Networking::WinSock::AF_INET;

        let mut row = MIB_IPINTERFACE_ROW::default();
        row.Family = AF_INET;
        row.InterfaceIndex = if_index;
        let rc = unsafe { GetIpInterfaceEntry(&raw mut row) };
        if rc != NO_ERROR {
            return Err(format!("failed to read TUN interface info: {}", rc.0));
        }
        row.DadTransmits = transmits;
        row.SitePrefixLength = 0;
        let rc = unsafe { SetIpInterfaceEntry(&raw mut row) };
        if rc != NO_ERROR {
            return Err(format!("failed to restore DAD setting: {}", rc.0));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub use imp::{open, remove_adapter, remove_adapters};

#[cfg(not(target_os = "windows"))]
mod imp {
    use super::*;
    use crate::core::tun::config::TunConfig;

    pub fn open(_cfg: &TunConfig) -> Result<TunDevice, OpenError> {
        Err("TUN is only supported on Windows".into())
    }

    /// 非 Windows 无 TUN 设备可卸载。
    pub fn remove_adapter(_name: &str) {}

    /// 非 Windows 无 TUN 设备可卸载。
    pub fn remove_adapters(_names: &[String]) -> usize {
        0
    }
}

#[cfg(not(target_os = "windows"))]
pub use imp::{open, remove_adapter, remove_adapters};

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

    #[test]
    fn device_name_candidates_rotates_suffix() {
        assert_eq!(
            super::device_name_candidates("SSLProxy"),
            vec![
                "SSLProxy".to_string(),
                "SSLProxy-1".to_string(),
                "SSLProxy-2".to_string(),
                "SSLProxy-3".to_string(),
                "SSLProxy-4".to_string(),
            ]
        );
    }

    /// 启动清理必须覆盖历次轮转出来的所有名称，否则 `-N` 设备会永久残留。
    #[test]
    fn stale_adapter_names_cover_all_candidates() {
        let names = super::stale_adapter_names("SSLProxy");
        assert_eq!(names.len(), 5);
        assert!(names.contains(&"SSLProxy".to_string()));
        for n in 1..5 {
            assert!(names.contains(&format!("SSLProxy-{n}")));
        }
    }
}
