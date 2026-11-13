#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""DTB 的 /memory 与 /reserved-memory 节点.

锁定两类行为:

- reg 按 64-bit 编码为 4 个大端 u32 (addr_hi, addr_lo, size_hi, size_lo),
  地址与大小的高 32 位取自其自身取值. 覆盖 configs.mk 的 ram 默认值 6 GiB,
  该值的高 32 位非零.
- PlatformConfig.reserved_memory_ranges 非空时生成 /reserved-memory 的 no-map
  子节点, 供 Linux 内核从 enclave 池与固件映像区中排除物理内存区域.

注意: 必须通过 Emulator 导入链以规避 core.decoder ⟷ utils.disassem 循环导入.
"""

import struct

import libfdt
import pytest

from pyremu.configs_gen import (
    FW_RESERVED_MEM_BASE,
    FW_RESERVED_MEM_SIZE,
    RESERVED_MEM_BASE,
    RESERVED_MEM_SIZE,
)
from pyremu.emulator import Emulator
from pyremu.utils import dev_tree
from tests.conftest import make_test_config

# configs.mk 的 ram 默认值. 6 GiB 的高 32 位为 1, 低 32 位为 0x8000_0000.
RAM_SIZE_6GIB = 6 * 1024 * 1024 * 1024

# 固件内嵌 .sittim 飞地运行时的物理地址: 链接地址 0x100000 + 加载偏移 0x80000000
SITTIM_PA = 0x8010_0000


def _reg(path: str, blob: bytes) -> tuple[int, int]:
    """读取 *path* 节点 reg 属性, 返回 (地址, 大小)."""
    fdt = libfdt.Fdt(blob)
    node = fdt.path_offset(path)
    addr_hi, addr_lo, size_hi, size_lo = struct.unpack(
        ">IIII", bytes(fdt.getprop(node, "reg"))
    )
    return ((addr_hi << 32) | addr_lo, (size_hi << 32) | size_lo)


def _reserved_nodes(fdt: libfdt.Fdt) -> list[tuple[int, int, bool]]:
    """收集 /reserved-memory 全部子节点, 返回 (base, size, no-map) 列表."""
    rm = fdt.path_offset("/reserved-memory")
    out: list[tuple[int, int, bool]] = []
    node = fdt.first_subnode(rm, libfdt.QUIET_NOTFOUND)
    while node >= 0:
        reg = bytes(fdt.getprop(node, "reg"))
        base_hi, base_lo, size_hi, size_lo = struct.unpack(">IIII", reg)
        # no-map 为布尔属性, 长度 0 表示已设置
        no_map = len(bytes(fdt.getprop(node, "no-map"))) == 0
        out.append(
            ((base_hi << 32) | base_lo, (size_hi << 32) | size_lo, no_map)
        )
        node = fdt.next_subnode(node, libfdt.QUIET_NOTFOUND)
    return out


# ============================================================
#  /memory 与 /reserved-memory 的 reg 编码
# ============================================================


def test_memory_reg_encodes_size_above_4gib():
    """回归: ram 取 6 GiB 时 /memory 的 reg 必须把大小的高 32 位写出来.

    旧实现把 addr_hi 与 size_hi 两个单元硬写成 0, 6 GiB 超出 u32 的表示范围,
    struct.pack 抛 struct.error, 整个 DTB 无法生成, emu-linux-sh 因此中止.
    6 GiB 与 2 GiB 的高 32 位分别为 1 与 0, 两个取值一并锁定.
    """
    base, size = _reg(
        "/memory",
        dev_tree.build_default_dtb(make_test_config(ram_size=RAM_SIZE_6GIB)),
    )
    assert (base, size) == (0x8000_0000, RAM_SIZE_6GIB)
    assert size >> 32 == 1, "6 GiB 的高 32 位必须落在 reg 的 size_hi 单元"

    base, size = _reg(
        "/memory",
        dev_tree.build_default_dtb(
            make_test_config(ram_size=2 * 1024 * 1024 * 1024)
        ),
    )
    assert (base, size) == (0x8000_0000, 2 * 1024 * 1024 * 1024)
    assert size >> 32 == 0, "2 GiB 的高 32 位必须为 0"


def test_reserved_memory_reg_encodes_base_above_4gib():
    """reg 的地址高于 4 GiB 时, 其高 32 位落在 addr_hi 单元."""
    ranges = [(0x1_0000_0000, 0x20_0000)]
    blob = dev_tree.build_default_dtb(
        make_test_config(ram_size=128 * 1024 * 1024), reserved_ranges=ranges
    )
    assert _reg("/reserved-memory/reserved-0@100000000", blob) == ranges[0]


# ============================================================
#  /reserved-memory 节点生成
# ============================================================


def test_reserved_memory_default_pool():
    """默认 reserved_memory_ranges 应为固件映像区与 enclave 池两个
    no-map 节点."""
    cfg = make_test_config()
    assert len(cfg.reserved_memory_ranges) == 2, (
        "default should reserve fw + pool"
    )

    emu = Emulator(cfg, bootargs="console=ttySIF0")
    blob = emu.build_default_dtb()
    fdt = libfdt.Fdt(blob)
    rm = fdt.path_offset("/reserved-memory")
    assert rm >= 0

    nodes = _reserved_nodes(fdt)
    assert [(base, size) for base, size, _ in nodes] == [
        (int(FW_RESERVED_MEM_BASE), int(FW_RESERVED_MEM_SIZE)),
        (int(RESERVED_MEM_BASE), int(RESERVED_MEM_SIZE)),
    ]
    assert all(no_map for _, _, no_map in nodes), (
        "reserved regions must all be no-map"
    )


def test_reserved_memory_covers_firmware_region():
    """固件映像区必须被 no-map 保留, 且覆盖内嵌 .sittim 的物理地址.

    回归: 固件映像 (ram_base 起, 含尾部内嵌的 .sittim 飞地运行时) 未保留时,
    内核分配器会把页面分到固件映像上, 设备 DMA (virtio-blk 读写) 直接覆写
    .sittim 对应的物理页面, 使 CREATE 复制进飞地池的载荷变成垃圾数据; 飞地
    入口取指即故障, 且该异常未委派到 S 模式, 表现为 M 模式静默挂起 (无任何
    后续输出). 此处锁定 "0x80100000 落在某个 no-map 保留区间内".
    """
    cfg = make_test_config()
    assert int(FW_RESERVED_MEM_BASE) == cfg.ram_base, "fw 区应自 ram_base 起"

    emu = Emulator(cfg, bootargs="console=ttySIF0")
    fdt = libfdt.Fdt(emu.build_default_dtb())
    nodes = _reserved_nodes(fdt)

    covering = [
        (base, size)
        for base, size, no_map in nodes
        if no_map and base <= SITTIM_PA < base + size
    ]
    assert covering, (
        f"固件内嵌 .sittim (PA {SITTIM_PA:#x}) "
        f"未被任何 no-map 区间覆盖: {nodes}"
    )


def test_reserved_memory_multiple_ranges():
    """多个 reserved 区域应分别生成子节点."""
    cfg = make_test_config()
    cfg.reserved_memory_ranges = [
        (0x8300_0000, 0x0080_0000),
        (0x9000_0000, 0x0100_0000),
    ]
    emu = Emulator(cfg, bootargs="console=ttySIF0")
    blob = emu.build_default_dtb()
    fdt = libfdt.Fdt(blob)

    nodes = _reserved_nodes(fdt)
    assert len(nodes) == 2, f"expected 2 children, got {len(nodes)}"
    for base, _, _ in nodes:
        assert base in (0x8300_0000, 0x9000_0000), f"unexpected base=0x{base:x}"


def test_reserved_memory_empty_no_node():
    """空 reserved_memory_ranges 不生成 /reserved-memory 节点."""
    cfg = make_test_config()
    cfg.reserved_memory_ranges = []
    emu = Emulator(cfg, bootargs="console=ttySIF0")
    blob = emu.build_default_dtb()
    fdt = libfdt.Fdt(blob)
    try:
        fdt.path_offset("/reserved-memory")
        assert False, "/reserved-memory must be absent with empty ranges"
    except libfdt.FdtException:
        pass  # expected — node not present


# ============================================================
#  Emulator 的设备树生成与装载位置校验
# ============================================================


class TestDeviceTree:
    """设备树生成与加载."""

    def test_build_default_dtb_returns_valid_dtb(self):
        """build_default_dtb 返回非空 DTB blob."""
        emu = Emulator()
        dtb = emu.build_default_dtb()
        assert len(dtb) > 0
        # DTB 应以 FDT magic 开头 (0xD00DFEED big-endian)
        magic = int.from_bytes(dtb[:4], "big")
        assert magic == 0xD00DFEED, f"DTB magic 错误: 0x{magic:08x}"

    def test_build_default_dtb_contains_memory_node(self):
        """build_default_dtb DTB 包含 memory 节点信息."""
        emu = Emulator()
        dtb = emu.build_default_dtb()
        # DTB 应包含 "memory" 字符串 (节点名)
        assert b"memory" in dtb, "DTB 应包含 memory 节点"

    def test_load_dtb_blob_sets_a1(self):
        """load_dtb_blob 写入 DTB 并设置所有 hart 的 a1."""
        emu = Emulator(num_harts=2, ram_size=16 * 1024 * 1024)
        dtb = emu.build_default_dtb()
        addr = 0x80FF0000
        emu.load_dtb_blob(addr, dtb)
        # 验证写入
        readback = emu.bus.read(addr, len(dtb))
        assert readback == dtb
        # 验证所有 hart 的 a1 已设置
        for h in emu.harts:
            assert h.gprs[11] == addr

    def test_load_dtb_generates_and_loads(self):
        """load_default_dtb 生成并加载 DTB, a1 指向该地址."""
        emu = Emulator(num_harts=1, ram_size=128 * 1024 * 1024)
        addr = 0x87FF0000
        emu.load_default_dtb(addr)
        # 验证 a1
        assert emu.harts[0].gprs[11] == addr
        # 验证 DTB 可读
        magic_bytes = emu.bus.read(addr, 4)
        magic = int.from_bytes(magic_bytes, "big")
        assert magic == 0xD00DFEED

    def test_default_bootargs_provides_console(self):
        """未指定 bootargs 时, 默认包含 earlycon=sbi console=ttySIF0."""
        emu = Emulator()
        dtb = emu.build_default_dtb()
        assert b"earlycon=sbi" in dtb, (
            "默认 bootargs 应包含 earlycon=sbi 以确保内核输出可见"
        )
        assert b"console=ttySIF0" in dtb, (
            "默认 bootargs 应包含 console=ttySIF0 以将 UART 设为首选控制台"
        )
        assert b"random.trust_bootloader=on" in dtb, (
            "默认 bootargs 应包含 random.trust_bootloader=on 以完成 CRNG 初始化"
        )

    def test_explicit_bootargs_overrides_default(self):
        """显式指定 bootargs 时使用用户值而非默认值."""
        emu = Emulator(bootargs="console=ttyS0 debug")
        dtb = emu.build_default_dtb()
        assert b"console=ttyS0 debug" in dtb
        # 默认值不应出现
        assert b"console=ttySIF0" not in dtb


class TestLoadPlacement:
    """设备树与 initramfs 的装载位置校验."""

    RAM_SIZE = 16 * 1024 * 1024

    def _emu(self) -> Emulator:
        return Emulator(num_harts=1, ram_size=self.RAM_SIZE)

    def test_dtb_outside_windows_is_rejected(self):
        emu = self._emu()
        with pytest.raises(ValueError):
            emu.load_dtb_blob(0x0, b"DTB")

    def test_dtb_crossing_ram_top_is_rejected(self):
        """最后一个字节越出窗口上界时拒绝, 不能只检查起始地址."""
        emu = self._emu()
        addr = emu.bus.ram_base + emu.bus.ram_size - 2
        with pytest.raises(ValueError):
            emu.load_dtb_blob(addr, b"DTB")

    def test_dtb_overlapping_initrd_is_rejected(self, tmp_path):
        emu = self._emu()
        img = tmp_path / "initramfs.cpio"
        img.write_bytes(b"\x00" * 0x1000)
        initrd = emu.load_initrd(str(img), emu.bus.ram_base + 0x10_0000)
        with pytest.raises(ValueError) as exc_info:
            emu.load_dtb_blob(initrd.end - 4, b"DTB")
        assert "initramfs" in str(exc_info.value)

    def test_dtb_touching_initrd_end_is_accepted(self, tmp_path):
        """端点相接不算重叠."""
        emu = self._emu()
        img = tmp_path / "initramfs.cpio"
        img.write_bytes(b"\x00" * 0x1000)
        initrd = emu.load_initrd(str(img), emu.bus.ram_base + 0x10_0000)
        emu.load_dtb_blob(initrd.end, b"DTB")
        assert emu.dtb_addr == initrd.end

    def test_initrd_crossing_ram_top_is_rejected(self, tmp_path):
        emu = self._emu()
        img = tmp_path / "initramfs.cpio"
        img.write_bytes(b"\x00" * 16)
        addr = emu.bus.ram_base + emu.bus.ram_size - 8
        with pytest.raises(ValueError) as exc_info:
            emu.load_initrd(str(img), addr)
        assert "RAM" in str(exc_info.value)

    def test_initrd_touching_ram_top_is_accepted(self, tmp_path):
        emu = self._emu()
        img = tmp_path / "initramfs.cpio"
        img.write_bytes(b"\x00" * 16)
        addr = emu.bus.ram_base + emu.bus.ram_size - 16
        assert emu.load_initrd(str(img), addr).start == addr
