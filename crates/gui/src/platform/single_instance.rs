use std::time::Duration;
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HWND,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, SetForegroundWindow, ShowWindow, IsIconic, SW_RESTORE, SW_SHOW,
};

const MUTEX_NAME: &str = "Global\\SSLProxyClient_SingleInstance\0";
const WINDOW_TITLE: &str = "SSL Proxy Client\0";
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Try to acquire the single-instance mutex.
///
/// `retries` is the number of extra attempts, [`RETRY_INTERVAL`] apart, before
/// giving up. A normally launched second instance passes `0`; the process
/// spawned by `Core::restart_process` passes a positive value so it can wait
/// for the previous instance to exit and release the mutex.
///
/// Returns `Some(handle)` if this is the first instance, `None` if another
/// instance already exists (its window is activated in that case).
pub fn try_acquire(retries: u32) -> Option<HANDLE> {
    try_acquire_named(MUTEX_NAME, retries)
}

/// Name-parameterized implementation, so tests can use a private mutex name
/// and not interfere with a running client.
fn try_acquire_named(name: &str, retries: u32) -> Option<HANDLE> {
    let mutex_name = name.encode_utf16().collect::<Vec<u16>>();

    for attempt in 0..=retries {
        unsafe {
            // CreateMutexW only sets the last error when the mutex already
            // exists; clear it first so a stale value cannot be mistaken for
            // "another instance is running".
            SetLastError(ERROR_SUCCESS);
            let mutex = CreateMutexW(
                None,
                true,
                windows::core::PCWSTR::from_raw(mutex_name.as_ptr()),
            );

            match mutex {
                Ok(handle) => {
                    if GetLastError() == ERROR_ALREADY_EXISTS {
                        // Mutex already exists → another instance is running
                        let _ = CloseHandle(handle);
                        if attempt < retries {
                            std::thread::sleep(RETRY_INTERVAL);
                            continue;
                        }
                        activate_existing_window();
                        return None;
                    }
                    // First instance, hold the mutex
                    return Some(handle);
                }
                Err(_) => {
                    // Failed to create mutex, proceed anyway
                    return None;
                }
            }
        }
    }

    None
}

/// Release the single-instance mutex.
#[allow(dead_code)]
pub fn release(handle: HANDLE) {
    unsafe {
        let _ = ReleaseMutex(handle);
        let _ = CloseHandle(handle);
    }
}

/// Find the existing window and bring it to the foreground.
fn activate_existing_window() {
    unsafe {
        // Search for the window by title
        let hwnd = FindWindowW(
            None,
            windows::core::PCWSTR::from_raw(
                WINDOW_TITLE
                    .encode_utf16()
                    .collect::<Vec<u16>>()
                    .as_ptr(),
            ),
        );

        let hwnd = match hwnd {
            Ok(h) => h,
            Err(_) => return,
        };

        if hwnd == HWND::default() {
            return;
        }

        // Restore if minimized
        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }

        // Show the window (in case it's hidden to tray)
        let _ = ShowWindow(hwnd, SW_SHOW);

        // Bring to foreground
        let _ = SetForegroundWindow(hwnd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A relaunched instance must keep retrying while the previous process is
    /// still alive, and succeed once it has released the mutex.
    #[test]
    fn relaunch_waits_for_previous_instance() {
        // Private name: do not touch the mutex of a running client.
        let name = format!("Local\\SslProxyRestartTest_{}\0", std::process::id());

        let holder = try_acquire_named(&name, 0).expect("first acquire should succeed");

        let started = Instant::now();
        assert!(
            try_acquire_named(&name, 3).is_none(),
            "second instance must not acquire while the mutex is held"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "second instance should retry instead of failing immediately"
        );

        // The previous process quits → OS closes the handle → mutex released.
        release(holder);
        assert!(
            try_acquire_named(&name, 0).is_some(),
            "relaunched instance must acquire the mutex after the old one exits"
        );
    }

    /// A normal second launch (retries = 0) gives up immediately.
    #[test]
    fn second_launch_fails_fast() {
        let name = format!("Local\\SslProxyRestartFastTest_{}\0", std::process::id());

        let holder = try_acquire_named(&name, 0).expect("first acquire should succeed");
        let started = Instant::now();
        assert!(try_acquire_named(&name, 0).is_none());
        assert!(
            started.elapsed() < RETRY_INTERVAL,
            "second launch must not wait"
        );
        release(holder);
    }
}
