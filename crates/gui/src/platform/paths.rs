use std::path::PathBuf;

/// User data directory, per platform:
/// - Windows: `%USERPROFILE%/ssl-proxy-client`（HOME 兜底）
/// - macOS: `$HOME/Library/Application Support/ssl-proxy-client`
/// - 其它平台: `$HOME/ssl-proxy-client`
///
/// Matches the Tauri client so both versions share the same config.
///
/// `SSL_PROXY_GUI_CONFIG_DIR` overrides it (useful for development/QA).
pub fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SSL_PROXY_GUI_CONFIG_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("ssl-proxy-client")
        } else {
            PathBuf::from("ssl-proxy-client")
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(home) = std::env::var("USERPROFILE") {
            PathBuf::from(home).join("ssl-proxy-client")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join("ssl-proxy-client")
        } else {
            PathBuf::from("ssl-proxy-client")
        }
    }
}

/// Directory that contains `GeoDB.dat`.
///
/// Release: next to the executable.
/// Development (`cargo run`): fall back to `<manifest>/assets` so the
/// resource does not need to be copied manually.
pub fn resolve_app_path() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    if exe_dir.join("GeoDB.dat").exists() {
        return exe_dir;
    }

    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");
    if assets.join("GeoDB.dat").exists() {
        return assets;
    }

    exe_dir
}
