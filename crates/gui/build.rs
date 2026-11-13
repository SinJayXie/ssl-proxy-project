use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=assets/GeoDB.dat");
    println!("cargo:rerun-if-env-changed=SSL_PROXY_ICON");

    // Copy GeoDB.dat next to the built executable so release/debug runs
    // resolve it without relying on the development fallback.
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let out_dir = PathBuf::from(out_dir);
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());

    // target/<profile>/build/<pkg>-<hash>/out -> target/<profile>
    if let Some(profile_dir) = out_dir.ancestors().nth(3) {
        let source = manifest_dir.join("assets/GeoDB.dat");
        let destination = profile_dir.join("GeoDB.dat");
        if source.exists() {
            if let Err(err) = std::fs::copy(&source, &destination) {
                println!("cargo:warning=failed to copy GeoDB.dat: {err}");
            }
        }
    }

    // Windows 资源：exe 图标与版本信息，图标取自仓库根目录的 icons/。
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_windows_resources(&out_dir, &manifest_dir);
    }
}

fn embed_windows_resources(out_dir: &Path, manifest_dir: &Path) {
    let icon = icon_path(manifest_dir);
    println!("cargo:rerun-if-changed={}", icon.display());

    // 注意：不能用 canonicalize，Windows 会返回 \\?\ 前缀，rc.exe 无法识别。
    let icon = match std::path::absolute(&icon) {
        Ok(path) if path.exists() => path,
        _ => {
            println!(
                "cargo:warning=Windows icon not found at {}, the exe keeps the default icon",
                icon.display()
            );
            return;
        }
    };

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let [major, minor, patch] = numeric_version(&version);
    let rc_path = out_dir.join("app_resources.rc");
    // rc.exe 在 Windows 上接受反斜杠路径，字符串里不需要额外转义。
    let rc = format!(
        r#"1 ICON "{icon}"
1 VERSIONINFO
 FILEVERSION {major},{minor},{patch},0
 PRODUCTVERSION {major},{minor},{patch},0
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0x0L
 FILEOS 0x40004L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "ssl-proxy"
            VALUE "FileDescription", "SSL Proxy Client"
            VALUE "FileVersion", "{version}"
            VALUE "InternalName", "ssl-proxy-client"
            VALUE "OriginalFilename", "ssl-proxy-client.exe"
            VALUE "ProductName", "SSLProxyClient"
            VALUE "ProductVersion", "{version}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#,
        icon = icon.display()
    );

    if let Err(err) = std::fs::write(&rc_path, rc) {
        println!("cargo:warning=failed to write {rc_path:?}: {err}");
        return;
    }

    match embed_resource::compile(&rc_path, embed_resource::NONE).manifest_optional() {
        Ok(()) => {}
        Err(err) => println!("cargo:warning=Windows resources were not linked: {err}"),
    }
}

/// Prefer `SSL_PROXY_ICON`, then the shared icon at the workspace root
/// (crates/gui -> crates -> <workspace>/icons/icon.ico).
fn icon_path(manifest_dir: &Path) -> PathBuf {
    if let Some(path) = std::env::var_os("SSL_PROXY_ICON") {
        return PathBuf::from(path);
    }

    if let Some(root) = manifest_dir.ancestors().nth(2) {
        let candidate = root.join("icons/icon.ico");
        if candidate.exists() {
            return candidate;
        }
    }

    // Fallback: resolve from the crate directory without walking the layout.
    manifest_dir.join("../../icons/icon.ico")
}

/// `2.1.6` -> `[2, 1, 6]`；非数字段按 0 处理。
fn numeric_version(version: &str) -> [u64; 3] {
    let mut parts = version.split('.').map(|part| part.parse().unwrap_or(0));
    [
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    ]
}
