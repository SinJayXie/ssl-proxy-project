#!/usr/bin/env bash
# 在 WSL(Ubuntu) 中编译 Linux musl 服务端并打包。
#
# 用法（Windows 侧）：
#   wsl -d Ubuntu-22.04 -e bash /mnt/e/myProjects/ssl-proxy/ssl-proxy-project/scripts/build-svr-musl.sh
# 用法（WSL 内）：
#   ./scripts/build-svr-musl.sh
#
# 环境变量：
#   TOOLCHAIN=<name>    指定 rustup 工具链；缺省自动挑选已安装 musl 标准库的工具链
#   CARGO_TARGET_DIR=…  自定义构建目录；缺省 $HOME/.cache/ssl-proxy-target-musl
#
# 依赖：
#   - rustup + x86_64-unknown-linux-musl 标准库
#   - musl-gcc（sudo apt-get install -y musl-tools）
#   - rustc 自带的 rust-lld（静态链接用；不要用 musl-gcc -static 直接链接，
#     与 Rust 自带 CRT 混用会导致运行时段错误）
#
# 产物：
#   dist/server/ssl-proxy-svr-linux-musl-<version>/
#   dist/server/ssl-proxy-svr-linux-musl-<version>.tar.gz
#   dist/server/ssl-proxy-svr-linux-musl-<version>.zip（系统有 zip 时）

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="x86_64-unknown-linux-musl"

# ---- 环境检查 ----
if ! command -v cargo >/dev/null 2>&1; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
command -v cargo >/dev/null 2>&1 || {
  echo "未找到 cargo，请先安装 rustup（https://rustup.rs）" >&2
  exit 1
}

command -v musl-gcc >/dev/null 2>&1 || {
  echo "未找到 musl-gcc，请先安装：sudo apt-get install -y musl-tools" >&2
  exit 1
}

# ---- 选择带 musl 标准库的工具链 ----
TOOLCHAIN="${TOOLCHAIN:-}"
if command -v rustup >/dev/null 2>&1; then
  if [[ -z "$TOOLCHAIN" ]]; then
    while read -r tc _rest; do
      [[ -z "${tc:-}" ]] && continue
      if rustup target list --installed --toolchain "$tc" 2>/dev/null | grep -qx "$TARGET"; then
        TOOLCHAIN="$tc"
        break
      fi
    done < <(rustup toolchain list 2>/dev/null)
  fi

  if [[ -z "$TOOLCHAIN" ]]; then
    echo "没有找到已安装 $TARGET 标准库的工具链，请执行：" >&2
    echo "  rustup target add $TARGET" >&2
    exit 1
  fi

  if ! rustup target list --installed --toolchain "$TOOLCHAIN" | grep -qx "$TARGET"; then
    echo "工具链 $TOOLCHAIN 缺少 $TARGET 标准库，请执行：" >&2
    echo "  rustup target add --toolchain $TOOLCHAIN $TARGET" >&2
    exit 1
  fi
fi

CARGO=(cargo)
if [[ -n "$TOOLCHAIN" ]]; then
  CARGO+=("+$TOOLCHAIN")
fi

# ---- 交叉编译环境 ----
# 仅 C 依赖（aws-lc-sys 等）使用 musl-gcc；Rust 侧用 rust-lld + 自带 libc 静态链接。
export CC_x86_64_unknown_linux_musl="musl-gcc"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="rust-lld"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=yes"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/ssl-proxy-target-musl}"

# ---- 版本号（取自服务端 Cargo.toml）----
VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
  "$ROOT/crates/svr/Cargo.toml" | head -n1)"
[[ -n "$VERSION" ]] || {
  echo "无法从 crates/svr/Cargo.toml 解析版本号" >&2
  exit 1
}

echo "==> 编译 ssl-proxy-svr $VERSION ($TARGET, toolchain=${TOOLCHAIN:-default})"
(cd "$ROOT" && "${CARGO[@]}" build --release -p ssl-proxy-svr --target "$TARGET")

BIN="$CARGO_TARGET_DIR/$TARGET/release/ssl-proxy-svr"
[[ -f "$BIN" ]] || {
  echo "构建产物不存在：$BIN" >&2
  exit 1
}

echo "==> 校验二进制"
if command -v file >/dev/null 2>&1; then
  file "$BIN"
  if file "$BIN" | grep -q "dynamically linked"; then
    echo "警告：产物是动态链接，期望 static-pie（请确认未设置 link-arg=-static）" >&2
  fi
fi
"$BIN" --version

# ---- 打包 ----
STAGE_NAME="ssl-proxy-svr-linux-musl-$VERSION"
STAGE="$ROOT/dist/server/$STAGE_NAME"
TARBALL="$ROOT/dist/server/$STAGE_NAME.tar.gz"

mkdir -p "$STAGE/certs" "$STAGE/logs"
cp "$BIN" "$STAGE/ssl-proxy-svr"
cp "$ROOT/crates/svr/config.example.yaml" "$STAGE/config.yaml"
tar -czf "$TARBALL" -C "$ROOT/dist/server" "$STAGE_NAME"

if command -v zip >/dev/null 2>&1; then
  (cd "$ROOT/dist/server" && zip -qr "$STAGE_NAME.zip" "$STAGE_NAME")
fi

echo
echo "==> 完成"
ls -l "$STAGE/ssl-proxy-svr" "$TARBALL"
sha256sum "$STAGE/ssl-proxy-svr" "$TARBALL"
