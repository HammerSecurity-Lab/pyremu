#!/usr/bin/env bash
# 编译 bsp/linux 内核树 (riscv64), 产出 Image 与 vmlinux。
#
# bsp/linux 内核源码树未纳入 git (bsp/* 默认忽略), 本脚本是唯一可复现的构建入口:
#   - 配置来源: bsp/.linux-config (git 跟踪的参考配置)
#   - 产物:     arch/riscv/boot/Image  (模拟器 --kernel 加载)
#               vmlinux                (模拟器 sym load 加载调试符号)
#
# 工具链三种 (默认 gcc, 与 local-build.sh 的驱动编译对齐):
#   gcc          标准 Debian 交叉 gcc (riscv64-linux-gnu-gcc 14)
#   clang        标准 clang + lld (LLVM=1), 内核无厂商私有指令, 无需 custom-llvm
#   custom-llvm  厂商定制 clang 22 + lld (LLVM=1 + LLVM_PREFIX), 见 .linux-config 头注释
#
set -euo pipefail

usage() {
    cat <<EOF
用法: $0 [make 目标 ...]

    $0                      按内核默认目标构建 (gcc)
    TOOLCHAIN=clang $0      标准 clang 构建
    TOOLCHAIN=custom-llvm $0
    $0 Image                只构建 Image

无参数时按内核的默认目标构建; 参数原样传给 make.
环境变量:
    TOOLCHAIN   工具链, 取 gcc、clang 或 custom-llvm, 默认 gcc
    JOBS        并行数, 默认 8
EOF
}

for arg in "$@"; do
    case "$arg" in
        -h | --help)
            usage
            exit 0
            ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LINUX="$ROOT/bsp/linux"
CONFIG_REF="$ROOT/bsp/.linux-config"

# 默认 8 路并行, 与 .linux-config 头注释的 -j8 一致; 可 JOBS=N ./build-linux.sh 覆盖。
JOBS="${JOBS:-8}"
# 默认 gcc
TOOLCHAIN="${TOOLCHAIN:-gcc}"

# 前置检查: 内核源码树与参考配置缺一不可。
if [ ! -f "$LINUX/Makefile" ]; then
    echo "错误: 缺少内核源码树 $LINUX 需自行配置" >&2
    exit 1
fi
if [ ! -f "$CONFIG_REF" ]; then
    echo "错误: 缺少参考配置 $CONFIG_REF" >&2
    exit 1
fi

case "$TOOLCHAIN" in
    gcc)
        MAKE_FLAGS=(HOSTCC=gcc ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-)
        ;;
    clang)
        MAKE_FLAGS=(LLVM=1 HOSTCC=gcc ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-)
        ;;
    custom-llvm)
        MAKE_FLAGS=(LLVM=1 HOSTCC=gcc ARCH=riscv \
            "LLVM_PREFIX=/opt/custom-llvm/bin/" \
            "PATH=/opt/custom-llvm/bin:$PATH" \
            CROSS_COMPILE=riscv64-unknown-linux-gnu-)
        ;;
    *)
        echo "错误: 缺乏已知的编译工具链 (当前: $TOOLCHAIN)" >&2
        exit 1
        ;;
esac

cd "$LINUX"

# olddefconfig 重跑 Kconfig, 使编译器探测
# 符号 (CONFIG_CC_IS_GCC / CONFIG_CC_IS_CLANG 等) 与所选工具链一致。
cp "$CONFIG_REF" .config
make "${MAKE_FLAGS[@]}" olddefconfig

# 编译内核。
# 与 .linux-config 头注释的命令一致
# 传参则透传给 make，例如 `./build-linux.sh Image`。
make "${MAKE_FLAGS[@]}" -j"$JOBS" "$@"

ls -l arch/riscv/boot/Image vmlinux
