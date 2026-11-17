//! 本机连接 → 进程名采集（仅 Windows 实现）。
//!
//! 连接列表用：给定应用侧本地端点（例如 `127.0.0.1:54321`），
//! 通过 IP Helper 的 TCP/UDP owner 表找到 socket 的 owning PID，
//! 再用 `QueryFullProcessImageNameW` 取 exe 路径并只保留文件名。
//! 其他平台统一返回 `None`，调用方回落到空字符串。

use std::net::SocketAddr;

#[cfg(target_os = "windows")]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::sync::{Mutex, OnceLock};

/// pid → exe 文件名缓存。建连时只查一次表，缓存能省掉重复的进程查询。
#[cfg(target_os = "windows")]
static CACHE: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();

/// TCP：应用侧本地端点 → 进程 exe 文件名。
#[cfg(target_os = "windows")]
pub fn process_name_for_tcp(local: SocketAddr) -> Option<String> {
    name_for_pid(tcp_owner_pid(local)?)
}

/// TCP：非 Windows 平台不采集进程名。
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)] // 与 Windows 版本保持一致的可调用 API。
pub fn process_name_for_tcp(_local: SocketAddr) -> Option<String> {
    None
}

/// UDP：应用侧本地端点 → 进程 exe 文件名。
#[cfg(target_os = "windows")]
pub fn process_name_for_udp(local: SocketAddr) -> Option<String> {
    name_for_pid(udp_owner_pid(local)?)
}

/// UDP：非 Windows 平台不采集进程名。
#[cfg(not(target_os = "windows"))]
pub fn process_name_for_udp(_local: SocketAddr) -> Option<String> {
    None
}

/// 表项中的地址/端口都是网络字节序，转成可直接比较的数值。
/// `dwLocalAddr` 的 4 个字节按网络序存放；`dwLocalPort` 的低 16 位是网络序端口。
#[cfg(any(target_os = "windows", test))]
fn endpoint_matches(
    raw_addr: u32,
    raw_port: u32,
    ip: std::net::Ipv4Addr,
    port: u16,
) -> bool {
    u32::from_be(raw_addr) == u32::from_be_bytes(ip.octets())
        && u16::from_be(raw_port as u16) == port
}

/// 从完整路径里取 exe 文件名（不含目录）。
#[cfg(any(target_os = "windows", test))]
fn exe_name_from_path(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
}

/// 查 TCP owner 表，返回匹配本地端点的 PID。
#[cfg(target_os = "windows")]
fn tcp_owner_pid(local: SocketAddr) -> Option<u32> {
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let SocketAddr::V4(local) = local else {
        // 只查询 IPv4 表；IPv6 端点暂时不采集。
        return None;
    };
    let ip = *local.ip();
    let port = local.port();

    let mut size = 0u32;
    let rc = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }

    // MIB_TCPTABLE_OWNER_PID = dwNumEntries + 变长 rows
    let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    if count == 0 {
        return None;
    }
    let rows_ptr = unsafe { std::ptr::addr_of!((*table).table) as *const MIB_TCPROW_OWNER_PID };
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, count) };

    rows.iter()
        .find(|row| endpoint_matches(row.dwLocalAddr, row.dwLocalPort, ip, port))
        .map(|row| row.dwOwningPid)
}

/// 查 UDP owner 表，返回匹配本地端点的 PID。
#[cfg(target_os = "windows")]
fn udp_owner_pid(local: SocketAddr) -> Option<u32> {
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let SocketAddr::V4(local) = local else {
        return None;
    };
    let ip = *local.ip();
    let port = local.port();

    let mut size = 0u32;
    let rc = unsafe {
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if rc != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }

    // MIB_UDPTABLE_OWNER_PID = dwNumEntries + 变长 rows
    let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    if count == 0 {
        return None;
    }
    let rows_ptr = unsafe { std::ptr::addr_of!((*table).table) as *const MIB_UDPROW_OWNER_PID };
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, count) };

    rows.iter()
        .find(|row| endpoint_matches(row.dwLocalAddr, row.dwLocalPort, ip, port))
        .map(|row| row.dwOwningPid)
}

/// PID → exe 文件名。跳过 0 与当前进程自身；无权限或进程已退出时返回 `None`。
#[cfg(target_os = "windows")]
fn name_for_pid(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::PWSTR;

    if pid == 0 || pid == std::process::id() {
        return None;
    }

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some(name) = map.get(&pid) {
            return Some(name.clone());
        }
    }

    // 无权限（受保护进程）时 OpenProcess 失败，按未知处理。
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

    let mut buffer = [0u16; 512];
    let mut len = buffer.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    };
    // 无论成功与否都要关闭句柄。
    let _ = unsafe { CloseHandle(handle) };
    if result.is_err() {
        return None;
    }

    let path = String::from_utf16_lossy(&buffer[..len as usize]);
    let name = exe_name_from_path(&path)?;
    if let Ok(mut map) = cache.lock() {
        map.insert(pid, name.clone());
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::{endpoint_matches, exe_name_from_path};
    use std::net::Ipv4Addr;

    #[test]
    fn endpoint_match_respects_network_byte_order() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        // Windows 表中字段按网络字节序存放，这里还原成字段的原始数值。
        let raw_addr = u32::from_ne_bytes(ip.octets());
        let raw_port = 1080u16.to_be() as u32;

        assert!(endpoint_matches(raw_addr, raw_port, ip, 1080));
        assert!(!endpoint_matches(raw_addr, raw_port, Ipv4Addr::new(127, 0, 0, 2), 1080));
        assert!(!endpoint_matches(raw_addr, raw_port, ip, 1081));
    }

    #[test]
    fn exe_name_keeps_only_file_name() {
        let path = std::path::Path::new("some").join("dir").join("app.exe");
        assert_eq!(
            exe_name_from_path(&path.to_string_lossy()),
            Some("app.exe".to_string())
        );
        assert_eq!(exe_name_from_path("app.exe"), Some("app.exe".to_string()));
        assert_eq!(exe_name_from_path(""), None);
    }
}
