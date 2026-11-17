# bsp/eval-suites/basic-test/Makefile
# TEE 飞地生命周期批处理测试 — 源目录, 部署为 /eval/basic-test
#
# 目录划分:
#   host/     宿主侧控制程序, 采用 Linux glibc 交叉编译
#   payload/  飞地内载荷, 采用 musl 静态编译
# 公共定义: ../common/enclave_abi.h (设备与 ioctl 定义), ../common/stress_common.h
#           (载荷侧压力操作), ../common/toolchain.mk
#
# 目标:
#   make all              编译全部宿主程序与载荷
#   make clean            清理

include ../common/toolchain.mk

phony =

# 取消 GNU Make 内置的 %: %.c 隐式模式规则
%: %.c

OUT_DIR  = bin
PROGRAMS = tee_stress tee_max_online tee_concurrent_enter
PAYLOADS = stress_payload hello_payload

BINS     = $(addprefix $(OUT_DIR)/, $(PROGRAMS))
PAY_BINS = $(addprefix $(OUT_DIR)/, $(PAYLOADS))

all: $(BINS) $(PAY_BINS)
phony += all

# ---- 宿主程序 (glibc) ----
# 宿主程序共用 common/host_util.c 中的辅助函数
HOST_COMMON = $(EVAL_INCLUDE)/host_util.c $(EVAL_INCLUDE)/enclave_abi.h

$(OUT_DIR)/%: host/%.c $(HOST_COMMON)
	@mkdir -p $(@D)
	$(CROSS_CC) $(HOST_CFLAGS) -I$(EVAL_INCLUDE) \
		$< $(EVAL_INCLUDE)/host_util.c -o $@

# ---- 飞地载荷 (musl) ----
$(OUT_DIR)/stress_payload: payload/stress_payload.c $(EVAL_INCLUDE)/stress_common.h
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -I$(EVAL_INCLUDE) -fuse-ld=lld $(MUSL_LDLIBS) \
		$< -o $@

$(OUT_DIR)/hello_payload: payload/hello_payload.c
	@mkdir -p $(@D)
	$(MUSL_CC) $(MUSL_CFLAGS) -I$(EVAL_INCLUDE) -fuse-ld=lld $(MUSL_LDLIBS) \
		$< -o $@

clean:
	rm -rf $(OUT_DIR)
phony += clean

.PHONY: $(phony)
