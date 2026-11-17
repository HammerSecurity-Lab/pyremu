# bsp/eval-suites/cache-sidechannel/Makefile
# 跨飞地缓存侧信道测试 — 源目录, 部署为 /eval/cache-sidechannel
#
# 目录划分:
#   host/     宿主侧控制与探测程序, 采用 Linux glibc 交叉编译
#   payload/  飞地内载荷, 采用 musl 静态编译
# 公共定义: ../common/enclave_abi.h (设备与 ioctl 定义), ../common/toolchain.mk
#
# 目标:
#   make all              编译宿主程序 (glibc)
#   make musl             编译飞地载荷 (musl)
#   make clean            清理

include ../common/toolchain.mk

phony =

# 取消 GNU Make 内置的 %: %.c 隐式模式规则, 防止在源码目录直接生成二进制
%: %.c

OUT_DIR  = bin
PROGRAMS = cross_enclave_cache tee_test tee_concurrent tee_malice \
           random_victim_loader tee_ecall_regress
MUSL_PROGS = victim_musl probe_musl tlb_leak_musl \
             victim_cache victim_kalman attacker_cache

BINS      = $(addprefix $(OUT_DIR)/, $(PROGRAMS))
MUSL_BINS = $(addprefix $(OUT_DIR)/, $(MUSL_PROGS))

all: $(BINS)
phony += all

musl: $(MUSL_BINS)
phony += musl

# ---- 宿主程序 (glibc) ----
# 宿主程序共用 common/host_util.c 中的辅助函数
HOST_COMMON = $(EVAL_INCLUDE)/host_util.c $(EVAL_INCLUDE)/enclave_abi.h

$(OUT_DIR)/%: host/%.c $(HOST_COMMON)
	@mkdir -p $(@D)
	$(CROSS_CC) $(HOST_CFLAGS) -I$(EVAL_INCLUDE) \
		$< $(EVAL_INCLUDE)/host_util.c -o $@

# 模块请求服务由 ../common 提供, 与本套件的主机侧工具共用实现
$(OUT_DIR)/tee_ecall_regress: host/tee_ecall_regress.c $(HOST_COMMON) \
                              $(EVAL_INCLUDE)/mod_loader.c \
                              $(EVAL_INCLUDE)/mod_loader.h \
                              $(EVAL_INCLUDE)/ext_mod_table.inc
	@mkdir -p $(@D)
	$(CROSS_CC) $(HOST_CFLAGS) -I$(EVAL_INCLUDE) \
		$< $(EVAL_INCLUDE)/host_util.c $(EVAL_INCLUDE)/mod_loader.c -o $@

# ---- 飞地载荷 (musl) ----
$(OUT_DIR)/%_musl: payload/%_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -fuse-ld=lld $(MUSL_LDLIBS) $< -o $@

$(OUT_DIR)/victim_cache: payload/victim_cache_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -fuse-ld=lld $(MUSL_LDLIBS) $< -o $@

$(OUT_DIR)/victim_kalman: payload/victim_kalman_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -fuse-ld=lld $(MUSL_LDLIBS) $< -o $@

$(OUT_DIR)/attacker_cache: payload/attacker_cache_payload.c
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
