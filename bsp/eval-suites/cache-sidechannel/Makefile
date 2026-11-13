# 跨飞地缓存侧信道测试
#
# 两套编译链:
#   Linux glibc  (riscv64-linux-gnu-gcc)  - cross_enclave_cache, tee_test, ...
#   Enclave musl (clang + musl libc.a)    - victim_cache, victim_kalman, attacker_cache
#
# 目标:
#   make all              编译 host 程序 (glibc)
#   make musl             编译飞地载荷 (musl)
#   make clean            清理

phony =

# 取消 GNU Make 内置的 %: %.c 隐式模式规则:
# 防止在源码目录直接生成无 bin/ 前缀的二进制 (如 tee_concurrent).
%: %.c

# 交叉编译器与参数
CROSS_CC ?= $(shell command -v riscv64-linux-gnu-gcc 2>/dev/null || echo riscv64-unknown-linux-gnu-gcc)
LIBGCC      = /usr/lib/gcc/riscv64-unknown-elf/14.2.0/rv64iafd/lp64d/libgcc.a

# 模块请求服务的宿主实现, 与本套件同属主机侧工具, 位于 bsp/eval-suites/mod-loader。
MOD_LOADER_DIR = ../mod-loader

# musl 飞地编译链
# musl 源码树由 vendor/musl 子模块提供 (release 1.2.6, 以 rv64gc/lp64d 构建)。
MUSL_DIR   = $(abspath ../../../vendor/musl)
MUSL_CC    = clang
MUSL_TARGET = riscv64-linux-musl


# 必须硬浮点 lp64d: musl sysroot 以 rv64imafdc/lp64d 构建, 软浮点 lp64 会
# 与 crt1.o 的硬浮点 ABI 冲突。
MUSL_ARCH   = rv64gc
MUSL_ABI    = lp64d

CFLAGS  = -static -O2 -Wall
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

OUT_DIR    = bin
PROGRAMS   = cross_enclave_cache tee_test tee_concurrent tee_malice random_victim_loader \
             tee_ecall_regress
MUSL_PROGS = victim_musl probe_musl tlb_leak_musl \
             victim_cache victim_kalman attacker_cache

BINS      = $(addprefix $(OUT_DIR)/, $(PROGRAMS))
MUSL_BINS = $(addprefix $(OUT_DIR)/, $(MUSL_PROGS))

# 默认目标
all: $(BINS)
phony += all

musl: $(MUSL_BINS)
phony += musl

# Linux glibc 编译
$(OUT_DIR)/%: %.c tee_enclave.h
	@mkdir -p $(@D)
	$(CROSS_CC) $(CFLAGS) $< -o $@

$(OUT_DIR)/tee_ecall_regress: tee_ecall_regress.c tee_enclave.h \
                              $(MOD_LOADER_DIR)/mod-loader.c $(MOD_LOADER_DIR)/mod-loader.h \
                              $(MOD_LOADER_DIR)/ext_mod_table.inc
	@mkdir -p $(@D)
	$(CROSS_CC) $(CFLAGS) -I. -I$(MOD_LOADER_DIR) $< $(MOD_LOADER_DIR)/mod-loader.c -o $@

$(OUT_DIR)/%_musl: %_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -fuse-ld=lld $(MUSL_LDLIBS) $< -o $@

$(OUT_DIR)/victim_cache: victim_cache_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -fuse-ld=lld $(MUSL_LDLIBS) $< -o $@

$(OUT_DIR)/victim_kalman: victim_kalman_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -fuse-ld=lld $(MUSL_LDLIBS) $< -o $@

$(OUT_DIR)/attacker_cache: attacker_cache_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -fuse-ld=lld $(MUSL_LDLIBS) $< -o $@

clean:
	rm -rf $(OUT_DIR)
phony += clean

help:
	@echo "bsp/eval-suites/cache-sidechannel"
	@echo "  make          build host programs (glibc)"
	@echo "  make musl     build enclave payloads (musl)"
	@echo "  make clean    remove bin/"
	@echo "  Host:    $(PROGRAMS)"
	@echo "  Enclave: $(MUSL_PROGS)"
phony += help

.PHONY: $(phony)
