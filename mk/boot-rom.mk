# boot-rom.mk — 引导只读存储器配置

# 生成到 pyremu/configs_gen.py, 作为 PlatformConfig 的字段默认值.

# 基址存放零阶段引导程序; 设备树位于基址加 ROM_DTB_OFFSET, 与零阶段引导程序
# 按 _start + 0x10000 算出的地址一致. zsbl的字节数不得超过该偏移,
# 否则与设备树的区间范围重叠. PlatformConfig.rom_base 取 0 时不注册rom.
ROM_BASE        ?= 0x40000000
ROM_SIZE        ?= 0x20000
ROM_DTB_OFFSET  ?= 0x10000

# 启动地址寄存器: 每 hart 一个 64 位寄存器, 偏移 8 * hartid, 由引导只读存储器内的
# 代码读取. 基址取 0 时不注册该设备.
BOOT_REGS_ADDR  ?= 0
BOOT_REGS_SIZE  ?= 0x1000
