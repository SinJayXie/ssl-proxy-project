pub mod logging;
pub mod paths;

#[cfg(windows)]
pub mod single_instance;
#[cfg(windows)]
pub mod tray;
#[cfg(windows)]
pub mod window;

#[cfg(target_os = "macos")]
pub mod mac;
