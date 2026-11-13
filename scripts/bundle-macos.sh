#!/usr/bin/env bash
# 构建 macOS 客户端 .app（dist/client/SSLProxyClient.app）。
# 仅做本地打包与 ad-hoc 签名；正式分发所需的 Apple Developer 签名与公证
# （notarization）不在本脚本范围内。
set -euo pipefail

# 该脚本依赖 macOS 自带工具（codesign 等），在其他系统上直接报错退出。
if [ "$(uname -s)" != "Darwin" ]; then
  echo "错误: 该脚本只能在 macOS 上运行（当前系统: $(uname -s)）" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GUI_CRATE="$ROOT/crates/gui"
APP="$ROOT/dist/client/SSLProxyClient.app"
GUI_BIN="$ROOT/target/release/ssl-proxy-gui"

# 从 Cargo.toml 解析版本号（与 build.sh 的 crate_version 保持一致）。
crate_version() {
  local manifest="$1"
  local version
  version="$(grep -m1 -E '^version[[:space:]]*=' "$manifest" | sed -E 's/^[^"]*"([^"]+)".*/\1/')"
  if [ -z "$version" ]; then
    echo "错误: 无法从 $manifest 解析版本号" >&2
    exit 1
  fi
  printf '%s' "$version"
}

VERSION="$(crate_version "$GUI_CRATE/Cargo.toml")"

echo '==> cargo build --release -p ssl-proxy-gui'
cargo build --release -p ssl-proxy-gui

if [ ! -f "$GUI_BIN" ]; then
  echo "错误: 找不到构建产物 $GUI_BIN" >&2
  exit 1
fi

# 每次重新生成 .app，避免残留旧文件。
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$GUI_BIN" "$APP/Contents/MacOS/ssl-proxy-gui"
chmod +x "$APP/Contents/MacOS/ssl-proxy-gui"

# GeoDB.dat 必须与可执行文件同目录：程序按 exe 所在目录查找它。
cp "$GUI_CRATE/assets/GeoDB.dat" "$APP/Contents/MacOS/GeoDB.dat"

cp "$ROOT/icons/icon.icns" "$APP/Contents/Resources/icon.icns"

# Info.plist 中除 ${VERSION} 外没有其他需要展开的字符，直接使用可展开的 heredoc。
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>SSL Proxy Client</string>
    <key>CFBundleDisplayName</key>
    <string>SSL Proxy Client</string>
    <key>CFBundleIdentifier</key>
    <string>com.sslproxy.client</string>
    <key>CFBundleExecutable</key>
    <string>ssl-proxy-gui</string>
    <key>CFBundleIconFile</key>
    <string>icon.icns</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
PLIST

# ad-hoc 签名（--sign -），便于本机直接打开；不涉及证书与公证。
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP"
else
  echo '==> 未找到 codesign，跳过签名'
fi

echo "    客户端应用包: $APP"
