#!/usr/bin/env bash
# 一键构建并打包：两个可执行文件 + 服务端 zip（GUI 安装包需要 Windows + makensis）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Windows 下委托给 PowerShell 脚本，统一使用 NSIS / UPX / Compress-Archive。
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    exec powershell -ExecutionPolicy Bypass -File "$ROOT/scripts/build.ps1" "$@"
    ;;
esac

TARGET="$ROOT/target"
DIST="$ROOT/dist"
GUI_CRATE="$ROOT/crates/gui"
SVR_CRATE="$ROOT/crates/svr"

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

find_bin() {
  local name="$1"
  if [ -f "$TARGET/release/$name" ]; then
    printf '%s' "$TARGET/release/$name"
  elif [ -f "$TARGET/release/$name.exe" ]; then
    printf '%s' "$TARGET/release/$name.exe"
  else
    echo "错误: 找不到构建产物 $TARGET/release/$name" >&2
    exit 1
  fi
}

case "$(uname -s)" in
  Darwin*) PLATFORM=darwin ;;
  Linux*) PLATFORM=linux ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM=win ;;
  *) PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
esac

mkdir -p "$DIST/client" "$DIST/server"

if [ "$PLATFORM" = "win" ]; then
  echo '==> cargo build --release --workspace'
  cargo build --release --workspace
  GUI_BIN="$(find_bin ssl-proxy-gui)"
  SVR_BIN="$(find_bin ssl-proxy-svr)"
elif [ "$PLATFORM" = "darwin" ]; then
  echo '==> cargo build --release -p ssl-proxy-gui -p ssl-proxy-svr（macOS）'
  cargo build --release -p ssl-proxy-gui -p ssl-proxy-svr
  GUI_BIN="$(find_bin ssl-proxy-gui)"
  SVR_BIN="$(find_bin ssl-proxy-svr)"
else
  echo '==> GUI 仅支持 Windows / macOS，本次只构建服务端'
  cargo build --release -p ssl-proxy-svr
  GUI_BIN=""
  SVR_BIN="$(find_bin ssl-proxy-svr)"
fi

GUI_VERSION="$(crate_version "$GUI_CRATE/Cargo.toml")"
SVR_VERSION="$(crate_version "$SVR_CRATE/Cargo.toml")"

if [ "$PLATFORM" = "darwin" ]; then
  # macOS 打 .app 包（内部会重新构建 GUI，增量构建很快），不走下面的 NSIS 分支。
  bash "$ROOT/scripts/bundle-macos.sh"
elif [ -n "$GUI_BIN" ] && command -v makensis >/dev/null 2>&1; then
  payload_dir="$TARGET/installer/payload"
  mkdir -p "$payload_dir"
  cp "$GUI_BIN" "$payload_dir/ssl-proxy-gui.exe"
  if command -v upx >/dev/null 2>&1 && ! upx --best "$payload_dir/ssl-proxy-gui.exe"; then
    cp "$GUI_BIN" "$payload_dir/ssl-proxy-gui.exe"
  fi
  setup="$DIST/client/SSLProxyClient_${GUI_VERSION}_x64-setup.exe"
  makensis /V2 "/DPRODUCT_VERSION=$GUI_VERSION" /DUSE_PAYLOAD \
    "/DPAYLOAD_EXE=$payload_dir/ssl-proxy-gui.exe" \
    "/DSOURCE_GEO=$GUI_CRATE/assets/GeoDB.dat" \
    "/DICON_FILE=$ROOT/icons/icon.ico" \
    "/DOUT_FILE=$setup" \
    "$GUI_CRATE/installer/installer.nsi"
  echo "    客户端安装包: $setup"
else
  echo '==> 跳过 GUI 安装包（需要 Windows 构建产物与 makensis）'
fi

NAME="ssl-proxy-svr-${PLATFORM}-${SVR_VERSION}"
STAGE="$DIST/server/$NAME"
rm -rf "$STAGE"
mkdir -p "$STAGE/certs" "$STAGE/logs"
cp "$SVR_BIN" "$STAGE/$(basename "$SVR_BIN")"
chmod +x "$STAGE/$(basename "$SVR_BIN")"
cp "$SVR_CRATE/config.example.yaml" "$STAGE/config.yaml"

if command -v upx >/dev/null 2>&1; then
  if ! upx --best "$STAGE/$(basename "$SVR_BIN")"; then
    echo '警告: upx 压缩失败，保留原始二进制' >&2
  fi
else
  echo '==> 未找到 upx，跳过服务端压缩'
fi

ZIP="$DIST/server/$NAME.zip"
rm -f "$ZIP"
if command -v zip >/dev/null 2>&1; then
  ( cd "$DIST/server" && zip -qr "$NAME.zip" "$NAME" )
elif command -v python3 >/dev/null 2>&1; then
  ( cd "$DIST/server" && python3 -c "import shutil, sys; shutil.make_archive(sys.argv[1], 'zip', '.', sys.argv[1])" "$NAME" )
else
  echo '错误: 需要 zip 或 python3 才能打包' >&2
  exit 1
fi

echo "    服务端发布包: $ZIP"
