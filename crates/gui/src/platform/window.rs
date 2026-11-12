use windows::core::PCWSTR;
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, FindWindowW, IsIconic, SetForegroundWindow, ShowWindow, SW_HIDE, SW_RESTORE,
    SW_SHOW,
};

const WINDOW_TITLE: &str = "SSL Proxy Client";

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn find_main_window() -> Option<windows::Win32::Foundation::HWND> {
    let title = wide(WINDOW_TITLE);
    unsafe { FindWindowW(None, PCWSTR::from_raw(title.as_ptr())).ok() }
}

pub fn hide_main_window() {
    if let Some(hwnd) = find_main_window() {
        unsafe {
            let _ = ShowWindow(hwnd, SW_HIDE);
        }
    }
}

pub fn show_main_window() {
    if let Some(hwnd) = find_main_window() {
        unsafe {
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            let _ = ShowWindow(hwnd, SW_SHOW);
            // 托盘线程不是前台进程，仅 SetForegroundWindow 可能被前台锁忽略，
            // 先提到 Z 序顶部再抢前台，恢复从托盘唤出的窗口。
            let _ = BringWindowToTop(hwnd);
            let _ = SetForegroundWindow(hwnd);
        }
    }
}
