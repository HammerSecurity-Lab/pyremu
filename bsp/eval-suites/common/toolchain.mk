# bsp/eval-suites/common/toolchain.mk
# 评测套件共用的交叉编译参数: 宿主程序用 Linux glibc, 飞地载荷用 musl 静态链接.
# 各套件目录的 Makefile 以 include ../common/toolchain.mk 引入本文件.

EVAL_ROOT      := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
EVAL_INCLUDE   := $(EVAL_ROOT)/common

# ---- 宿主程序: Linux glibc ----
CROSS_CC ?= $(shell command -v riscv64-linux-gnu-gcc 2>/dev/null || echo riscv64-unknown-linux-gnu-gcc)
HOST_CFLAGS = -static -O2 -Wall

# ---- 飞地载荷: musl 静态链接 ----
# musl 源码树由 vendor/musl 子模块提供 (release 1.2.6, 以 rv64gc/lp64d 构建).
# 必须硬浮点 lp64d: 软浮点 lp64 会与 crt1.o 的硬浮点 ABI 冲突.
MUSL_DIR    = $(abspath $(EVAL_ROOT)/../../vendor/musl)
MUSL_CC     = clang
MUSL_TARGET = riscv64-linux-musl
MUSL_ARCH   = rv64gc
MUSL_ABI    = lp64d
LIBGCC      = /usr/lib/gcc/riscv64-unknown-elf/14.2.0/rv64iafd/lp64d/libgcc.a

MUSL_CFLAGS = --target=$(MUSL_TARGET) -march=$(MUSL_ARCH) -mabi=$(MUSL_ABI) \
              -static -nostdlib -nostdinc -O2 -Wall \
              -isystem $(MUSL_DIR)/arch/riscv64 \
              -isystem $(MUSL_DIR)/arch/generic \
              -isystem $(MUSL_DIR)/obj/include \
              -isystem $(MUSL_DIR)/include

MUSL_LDLIBS = $(MUSL_DIR)/lib/crt1.o \
              $(MUSL_DIR)/lib/crti.o \
              $(MUSL_DIR)/lib/crtn.o \
              $(MUSL_DIR)/lib/libc.a \
              $(LIBGCC)
