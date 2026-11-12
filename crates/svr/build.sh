#!/usr/bin/env bash
# 构建并打包 release 产物
#
#   cargo build --release
#     → releases/ssl-proxy-svr-{darwin|linux|win}-{version}/
#          ├── ssl-proxy-svr        可执行文件（若已安装 upx，则 upx --best 压缩）
#          ├── config.yaml          配置模板（源自 config.example.yaml）
#          ├── certs/               证书目录（空，放入正式证书）
#          └── logs/                日志目录（空）
#     → releases/ssl-proxy-svr-{darwin|linux|win}-{version}.zip
#
# 用法: ./build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Workspace root: <root>/crates/svr -> <root>
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
cd "$ROOT"

# ---- 版本号 ----
VERSION="$(grep -m1 -E '^version[[:space:]]*=' Cargo.toml | sed -E 's/^[^"]*"([^"]+)".*/\1/')"
if [ -z "$VERSION" ]; then
    echo "错误: 无法从 Cargo.toml 解析版本号" >&2
    exit 1
fi

# ---- 平台标识 ----
case "$(uname -s)" in
    Darwin*)              PLATFORM=darwin ;;
    Linux*)               PLATFORM=linux ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM=win ;;
    *)                    PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
esac

NAME="ssl-proxy-svr-${PLATFORM}-${VERSION}"
RELEASES="$ROOT/releases"
STAGE="$RELEASES/$NAME"
ZIP="$RELEASES/$NAME.zip"

# ---- 构建 ----
echo "==> 平台: $PLATFORM, 版本: $VERSION"
echo "==> cargo build --release"
cargo build --release

# 显式优先 Windows 产物：MSYS/Cygwin 下 `-f foo` 对 `foo.exe` 也成立，
# 若走「找不到再加 .exe」的写法，传给 upx 的路径会丢掉后缀。
if [ -f "$WORKSPACE/target/release/ssl-proxy-svr.exe" ]; then
    BIN="$WORKSPACE/target/release/ssl-proxy-svr.exe"
elif [ -f "$WORKSPACE/target/release/ssl-proxy-svr" ]; then
    BIN="$WORKSPACE/target/release/ssl-proxy-svr"
else
    echo "错误: 找不到构建产物 $WORKSPACE/target/release/ssl-proxy-svr" >&2
    exit 1
fi

# ---- 组装目录 ----
echo "==> 组装 $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE/certs" "$STAGE/logs"

cp "$BIN" "$STAGE/"
chmod +x "$STAGE/$(basename "$BIN")"
cp "$ROOT/config.example.yaml" "$STAGE/config.yaml"

# ---- UPX 压缩（可选） ----
STAGED_BIN="$STAGE/$(basename "$BIN")"
if command -v upx >/dev/null 2>&1; then
    echo "==> upx --best $(basename "$BIN")"
    if ! upx --best "$STAGED_BIN"; then
        echo "警告: upx 压缩失败，保留原始二进制" >&2
    fi
else
    echo "==> 未找到 upx 命令，跳过压缩"
fi

# ---- 打包 ----
echo "==> 打包 $ZIP"
rm -f "$ZIP"
if command -v zip >/dev/null 2>&1; then
    ( cd "$RELEASES" && zip -qr "$NAME.zip" "$NAME" )
elif command -v python3 >/dev/null 2>&1; then
    ( cd "$RELEASES" && python3 -c \
        "import shutil, sys; shutil.make_archive(sys.argv[1], 'zip', '.', sys.argv[1])" "$NAME" )
else
    echo "错误: 需要 zip 或 python3 才能打包" >&2
    exit 1
fi

echo
echo "完成: $ZIP"
echo "解压后:"
echo "  1. 编辑 config.yaml（端口 / 密码）"
echo "  2. 正式证书放入 certs/；想用自签证书则注释掉 tls.cert 与 tls.key"
echo "  3. 运行 ./ssl-proxy-svr -c config.yaml"
