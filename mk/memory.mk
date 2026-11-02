# memory.mk — 主存布局
# 生成到 pyremu/configs_gen.py, 作为 PlatformConfig 的字段默认值.

# 物理 RAM 起始地址与大小 (字节)
RAM_BASE             ?= 0x80000000
RAM_SIZE             ?= 0x08000000
# 上电复位入口地址
PROG_CNT             ?= 0x80000000

# 设备树的位置由本次启动是否经过引导只读存储器决定. 当未注册rom或复位地址不在
# [rom_base, rom_base + rom_size) 这一范围内时,
# 	由模拟器把设备树设置到 RAM中，地址为 ram_base + ram_size - RAM_DTB_OFFSET
# 	相应地，预加载载荷的默认注入地址为 ram_base + ram_size - RAM_PRELOAD_OFFSET
# 复位地址落在该窗口内时, 设备树随该存储器
# 的镜像位于 rom_base + ROM_DTB_OFFSET.
RAM_DTB_OFFSET     ?= 0x10000
RAM_PRELOAD_OFFSET ?= 0x20000

# 确保 Linux 内核线性映射排除该区域, 避免内核分配器使用固件、可信应用所处物理内存区域而产生访问陷态.
RESERVED_MEM_BASE    ?= 0x83000000

# 2.25 GiB. ram 须不小于 6G, 以留出内核与根文件系统的空间.
RESERVED_MEM_SIZE    ?= 0x90000000

# 固件所处内存基地址
FW_RESERVED_MEM_BASE ?= 0x80000000
# 容量 4 MiB: 固件映像及其后须嵌入的驱动性代码的末尾终止于 0x80382F68。
# 故上界取下一个 2 MiB 边界，确保这一范围内的区域能被设置为保留内存区域。
FW_RESERVED_MEM_SIZE ?= 0x400000
