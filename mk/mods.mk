# mods.mk — 导入 mk/ 下除本文件外的全部分片

mods_dir := $(dir $(lastword $(MAKEFILE_LIST)))
include $(filter-out $(mods_dir)mods.mk,$(sort $(wildcard $(mods_dir)*.mk)))

export

# ---- 装载位置的一致性 ----
# 设备树与预加载载荷的区间范围都须落在所属窗口之内, 即各自的偏移小于窗口大小.
# 两者的默认起始地址须满足 RAM_PRELOAD_OFFSET > RAM_DTB_OFFSET, 即载荷的默认起始
# 地址小于设备树的起始地址. 实际字节数在装载时才确定, 此处只检查与长度无关的关系.

rom_base_dec        := $(shell printf '%d' $(ROM_BASE))
rom_size_dec        := $(shell printf '%d' $(ROM_SIZE))
ram_size_dec        := $(shell printf '%d' $(RAM_SIZE))
rom_dtb_ofs_dec     := $(shell printf '%d' $(ROM_DTB_OFFSET))
ram_dtb_ofs_dec     := $(shell printf '%d' $(RAM_DTB_OFFSET))
ram_preload_ofs_dec := $(shell printf '%d' $(RAM_PRELOAD_OFFSET))

### 必要的编译检查
ifneq ($(rom_base_dec),0)
ifeq ($(shell expr $(rom_dtb_ofs_dec) \< $(rom_size_dec)),0)
$(error ROM_DTB_OFFSET=$(ROM_DTB_OFFSET) must be less than ROM_SIZE=$(ROM_SIZE))
endif
endif

ifeq ($(shell expr $(ram_dtb_ofs_dec) \< $(ram_size_dec)),0)
$(error RAM_DTB_OFFSET=$(RAM_DTB_OFFSET) must be less than RAM_SIZE=$(RAM_SIZE))
endif

ifeq ($(shell expr $(ram_preload_ofs_dec) \< $(ram_size_dec)),0)
$(error RAM_PRELOAD_OFFSET=$(RAM_PRELOAD_OFFSET) must be less than RAM_SIZE=$(RAM_SIZE))
endif

ifeq ($(shell expr $(ram_preload_ofs_dec) \> $(ram_dtb_ofs_dec)),0)
$(error RAM_PRELOAD_OFFSET=$(RAM_PRELOAD_OFFSET) must be greater than \
	RAM_DTB_OFFSET=$(RAM_DTB_OFFSET))
endif
