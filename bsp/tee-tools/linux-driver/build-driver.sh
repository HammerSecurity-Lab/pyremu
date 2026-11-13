#!/usr/bin/env bash
# SPDX-LICENSE-IDENTIFIER: MIT
# Author: <jajune257@gmail.com> 2026

# 模块编译要求: 编译工具链必须与编译内核树时一致。
# TOOLCHAIN 的取值与 bsp/build-linux.sh 相同
# 未指定时按内核树 .config 记录的编译器选择。

case "${1:-}" in
	-h | --help)
		cat <<EOF
用法: $0

于 bsp/linux 内核树上编译本目录的 tee_enclave_drv.ko.
需要已配置的 bsp/linux 源码树与对应工具链，无额外参数

    TOOLCHAIN=gcc           标准 gcc (与内核树 .config 一致时的默认值)
    TOOLCHAIN=clang         标准 clang + lld (LLVM=1)
    TOOLCHAIN=custom-llvm   厂商定制 clang (LLVM=1 + LLVM_PREFIX)

未指定 TOOLCHAIN 时按内核树 .config 的 CONFIG_CC_IS_GCC / CONFIG_CC_IS_CLANG
选择 gcc 或 clang; 厂商定制工具链位于 /opt/custom-llvm/bin, 须显式指定.
EOF
		exit 0
		;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
KDIR=$(cd "$HERE/../../linux" && pwd)
CONFIG="$KDIR/.config"

if [ ! -f "$CONFIG" ]; then
	echo "缺少 $CONFIG, 请先按 bsp/build-linux.sh 配置并构建内核" >&2
	exit 1
fi

TOOLCHAIN="${TOOLCHAIN:-}"
if [ -z "$TOOLCHAIN" ]; then
	if grep -qx 'CONFIG_CC_IS_CLANG=y' "$CONFIG"; then
		TOOLCHAIN=clang
	else
		TOOLCHAIN=gcc
	fi
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
		echo "错误: 缺乏已知的编译工具链. 当前选择: $TOOLCHAIN" >&2
		exit 1
		;;
esac

if grep -qx 'CONFIG_CC_IS_CLANG=y' "$CONFIG" && [ "$TOOLCHAIN" = "gcc" ]; then
	echo "错误:模块须以 TOOLCHAIN=clang 构建" >&2
	exit 1
fi
if grep -qx 'CONFIG_CC_IS_GCC=y' "$CONFIG" && [ "$TOOLCHAIN" != "gcc" ]; then
	echo "错误: 模块须以 TOOLCHAIN=gcc编译工具链构建" >&2
	exit 1
fi

make -C "$KDIR" M="$HERE" "${MAKE_FLAGS[@]}" modules
