# sbi.mk — opensbi 的编译与链接参数

# 源码目录与构建输出目录, 两者都可由命令行或环境变量给出.
# custom-opensbi 缺失时，取 bsp/opensbi.
FW_SRC_DIR     ?= $(firstword $(wildcard $(bsp_dir)/custom-opensbi) $(bsp_dir)/opensbi)
FW_BUILD_DIR   ?= $(FW_SRC_DIR)/build/platform/generic/firmware

# 编译固件所需的源码组件
fw_src_components  = Makefile firmware lib include platform Kconfig scripts
fw_src_paths       = $(addprefix $(FW_SRC_DIR)/,$(fw_src_components))
fw_src_missing     = $(filter-out $(wildcard $(fw_src_paths)),$(fw_src_paths))
fw_src_missing_name = $(patsubst $(FW_SRC_DIR)/%,%,$(fw_src_missing))

# 依赖固件产物的规则以本目标为首个前提: 源码目录缺失或缺少任一组件时报告原因并终止.
# 各项取值在命令执行时展开, 故 bsp_dir 等变量的定义顺序不影响检查结果.
fw-src-check:
	$(if $(wildcard $(FW_SRC_DIR)),,$(error 固件源码目录 "$(FW_SRC_DIR)" 不存在, 以 FW_SRC_DIR=<目录> 指定))
	$(if $(fw_src_missing),$(error 固件源码目录 "$(FW_SRC_DIR)" 缺少编译组件: $(fw_src_missing_name)))
	@:
phony += fw-src-check

# 拷贝到 $(elf_dir) 的固件产物
fw_payload     = $(elf_dir)/custom_opensbi_fw_payload.elf
fw_jump        = $(elf_dir)/custom_opensbi_fw_jump.elf
fw_dynamic     = $(elf_dir)/custom_opensbi_fw_dynamic.elf
# 内嵌 Linux 内核的 fw_payload
fw_payload_linux = $(elf_dir)/custom_opensbi_fw_payload_linux.elf

# 全量编译 opensbi.
# 依赖:
#   - Rust S-mode runtime (嵌入 .sittim 段)
#   - opensbi 自身全部源码, 以及顶层的 ext-configs.mk
# 当任一依赖更新或产物缺失时自动触发 distclean + 全量重编译.
FW_SRC_DEPS  = $(FW_SRC_DIR)/Makefile
FW_SRC_DEPS += $(FW_SRC_DIR)/ext-configs.mk
FW_SRC_DEPS += $(shell find $(FW_SRC_DIR)/firmware $(FW_SRC_DIR)/lib -type f 2>/dev/null)
FW_SRC_DEPS += $(shell find $(FW_SRC_DIR)/include $(FW_SRC_DIR)/platform -type f 2>/dev/null)
FW_SRC_DEPS += $(shell find $(FW_SRC_DIR)/Kconfig $(FW_SRC_DIR)/scripts -type f 2>/dev/null)

# 参数覆盖 opensbi 默认值, 确保确定性构建
fw_basic_flag  = PLATFORM=generic
fw_basic_flag += PLATFORM_RISCV_XLEN=64
fw_basic_flag += PLATFORM_RISCV_ABI=lp64
# fw_basic_flag += FW_SKIP_BSS_ZERO=1

# 以下取值并入固件的 .config
# 池的起始与大小在 pyremu 侧读同一对变量
fw_basic_flag += CONFIG_POOL_BASE=$(RESERVED_MEM_BASE)
fw_basic_flag += CONFIG_POOL_SIZE=$(RESERVED_MEM_SIZE)
# 飞地侧网卡的基址取模拟器注册该设备时的同一取值. 该值取 0 即模拟器未注册这块
# 网卡, 固件据此不为它保留 PMP 条目, 飞地域的可分配条目上界随之回到 PMP_COUNT - 2
fw_basic_flag += CONFIG_ENCLAVE_NET_BASE=$(VIRTIO_NET_M_BASE)

## ---- fw_payload 构建 (内嵌 payload) ----
FW_MAKE_FLAGS  = $(fw_basic_flag)
FW_MAKE_FLAGS += FW_PAYLOAD=y

## ---- fw_jump 构建 (无内嵌 payload, mret 后跳转到 FW_JUMP_ADDR) ----
FW_JUMP_FLAGS  = $(fw_basic_flag)
FW_JUMP_FLAGS += FW_JUMP=y
# 该地址等于 FW_RESERVED_MEM_BASE + FW_RESERVED_MEM_SIZE,
# 即固件映像保留区的上界.
FW_JUMP_FLAGS += FW_JUMP_ADDR=0x80400000
