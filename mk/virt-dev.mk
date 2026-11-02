# virt-dev.mk — 虚拟设备的 MMIO 基址
#
# 虚拟块设备与两块虚拟网卡不对应芯片上的实际硬件, 基址由本分片单独给出, 槽位排在
# 有线外设之后. 经 mk/mods.mk 导入, 最终生成到 pyremu/configs_gen.py, 作为
# PeripheralConfig 的字段默认值. 基址取 0 表示该设备不注册.

VIRTIO_BLK_BASE      ?= 0x10005000
VIRTIO_NET_S_BASE    ?= 0
VIRTIO_NET_M_BASE    ?= 0
