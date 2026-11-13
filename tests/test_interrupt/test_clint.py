#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""CLINT 设备测试: MSIP (IPI), MTIMECMP (定时器), MTIME."""

import pytest

from pyremu.core.decoder import Hart
from pyremu.core.hart import RiscvMode
from pyremu.core.priv_defs import (
    MSTATUS_MIE,
)
from pyremu.interrupt.clint import (
    CLINT,
    CLINT_BASE,
    MSIP_OFFSET,
    MTIME_OFFSET,
    MTIMECMP_OFFSET,
)
from pyremu.interrupt.controller import INT_SOURCE_MIP_MASK, IntSource
from pyremu.memory.bus import Bus


class TestCLINTRegisters:
    """CLINT 寄存器读写."""

    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        self.clint = CLINT(num_harts=4)
        return self.clint

    def test_read_msip_initial_zero(self):
        """初始 MSIP 应为 0."""
        data = self.clint.read(MSIP_OFFSET, 4)  # hart 0
        assert data == b"\x00\x00\x00\x00"

    def test_write_msip_triggers_ipi(self):
        """写 MSIP 应设置软件中断挂起."""
        self.clint.write(
            MSIP_OFFSET + 4, b"\x01\x00\x00\x00"
        )  # hart 1 msip = 1
        has_pending, mip, src = self.clint.check_interrupt(1)
        assert has_pending
        assert mip & INT_SOURCE_MIP_MASK[IntSource.MSI]
        assert src == IntSource.MSI

    def test_write_msip_zero_clears_ipi(self):
        """写 0 到 MSIP 应清除中断."""
        self.clint.write(MSIP_OFFSET, b"\x01\x00\x00\x00")  # hart 0 msip = 1
        has_pending, _, _ = self.clint.check_interrupt(0)
        assert has_pending
        self.clint.write(MSIP_OFFSET, b"\x00\x00\x00\x00")  # hart 0 msip = 0
        has_pending, _, _ = self.clint.check_interrupt(0)
        assert not has_pending

    def test_send_ipi(self):
        """send_ipi 辅助方法."""
        self.clint.send_ipi(2)  # 向 hart 2 发送 IPI
        has_pending, _, _ = self.clint.check_interrupt(2)
        assert has_pending

    def test_clear_ipi(self):
        """clear_ipi 辅助方法."""
        self.clint.send_ipi(3)
        self.clint.clear_ipi(3)
        has_pending, _, _ = self.clint.check_interrupt(3)
        assert not has_pending

    def test_mtimecmp_timer_interrupt(self):
        """mtime >= mtimecmp 时应触发定时器中断."""
        self.clint.tick(100)  # mtime = 100
        # 设置 hart 0 的 mtimecmp = 50 (已过期)
        self.clint.write(MTIMECMP_OFFSET, (50).to_bytes(8, "little"))
        has_pending, mip, src = self.clint.check_interrupt(0)
        assert has_pending
        assert mip & INT_SOURCE_MIP_MASK[IntSource.MTI]

    def test_mtimecmp_not_reached(self):
        """mtime < mtimecmp 时不应触发定时器中断."""
        self.clint.tick(10)  # mtime = 10
        self.clint.write(MTIMECMP_OFFSET, (100).to_bytes(8, "little"))
        has_pending, _, _ = self.clint.check_interrupt(0)
        assert not has_pending

    def test_mtime_read(self):
        """MTIME 寄存器读."""
        self.clint.tick(42)
        data = self.clint.read(MTIME_OFFSET, 8)
        val = int.from_bytes(data, "little")
        assert val == 42

    def test_mtime_write(self):
        """MTIME 寄存器写."""
        self.clint.write(MTIME_OFFSET, (0xDEAD).to_bytes(8, "little"))
        assert self.clint.get_mtime() == 0xDEAD

    def test_interrupt_priority(self):
        """中断优先级: MSI > MTI."""
        self.clint.send_ipi(0)  # MSI
        self.clint.tick(100)
        self.clint.write(MTIMECMP_OFFSET, (50).to_bytes(8, "little"))  # MTI
        _, _, src = self.clint.check_interrupt(0)
        assert src == IntSource.MSI, "MSI 优先级应高于 MTI"


class TestCLINTPartialWidthAccess:
    """64 位寄存器的窄宽度访问.

    固件以全 1 写入 mtimecmp 关闭定时器, 该取值的字节数超出 1、2、4 字节的
    读取宽度; 旧实现在各宽度上直接调用 to_bytes, 抛出
    OverflowError: int too big to convert.
    """

    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        self.clint = CLINT(num_harts=4)
        return self.clint

    def test_read_disarmed_mtimecmp_each_width(self):
        """全 1 的 mtimecmp 在 1、2、4 字节宽度下读出低字节."""
        self.clint.write(MTIMECMP_OFFSET, b"\xff" * 8)
        assert self.clint.read(MTIMECMP_OFFSET, 1) == b"\xff"
        assert self.clint.read(MTIMECMP_OFFSET, 2) == b"\xff\xff"
        assert self.clint.read(MTIMECMP_OFFSET, 4) == b"\xff\xff\xff\xff"
        assert self.clint.read(MTIMECMP_OFFSET, 8) == b"\xff" * 8

    def test_read_mtimecmp_halves(self):
        """偏移 0 与偏移 4 起的读取分别给出 mtimecmp 的低 32 位与高 32 位."""
        self.clint.set_mtimecmp(0, 0x1234_5678_9ABC_DEF0)
        assert self.clint.read(MTIMECMP_OFFSET, 4) == b"\xf0\xde\xbc\x9a"
        assert self.clint.read(MTIMECMP_OFFSET + 4, 4) == b"\x78\x56\x34\x12"

    def test_read_mtimecmp_byte_offset(self):
        """非 4 字节对齐的偏移从该字节起取值."""
        self.clint.set_mtimecmp(0, 0x0123_4567_89AB_CDEF)
        assert self.clint.read(MTIMECMP_OFFSET + 3, 2) == b"\x89\x67"

    def test_read_mtimecmp_value_beyond_64_bits(self):
        """存储中的值超出 64 位时按 64 位截断读出."""
        self.clint._mtimecmp[0] = 1 << 64
        assert self.clint.read(MTIMECMP_OFFSET, 8) == b"\x00" * 8

    def test_read_mtime_partial_width(self):
        """MTIME 在全 1 取值下按 1、2、4 字节宽度读出低字节."""
        self.clint.write(MTIME_OFFSET, b"\xff" * 8)
        assert self.clint.read(MTIME_OFFSET, 1) == b"\xff"
        assert self.clint.read(MTIME_OFFSET + 4, 4) == b"\xff\xff\xff\xff"

    def test_write_mtimecmp_low_half_preserves_high_half(self):
        """4 字节写入 mtimecmp 的低半部时保留高半部."""
        self.clint.set_mtimecmp(0, 0x1234_5678_0000_0000)
        self.clint.write(MTIMECMP_OFFSET, (0x9ABC_DEF0).to_bytes(4, "little"))
        assert self.clint.get_mtimecmp(0) == 0x1234_5678_9ABC_DEF0

    def test_write_mtimecmp_across_register_end_is_dropped(self):
        """越过单个 mtimecmp 末尾的写入被丢弃, 相邻 hart 的比较值不变."""
        self.clint.set_mtimecmp(0, 0x1111)
        self.clint.set_mtimecmp(1, 0x2222)
        self.clint.write(MTIMECMP_OFFSET + 6, b"\xff\xff\xff\xff")
        assert self.clint.get_mtimecmp(0) == 0x1111
        assert self.clint.get_mtimecmp(1) == 0x2222

    def test_write_mtime_high_half_preserves_low_half(self):
        """4 字节写入 MTIME 的高半部时保留低半部."""
        self.clint.write(MTIME_OFFSET, (0x9ABC_DEF0).to_bytes(8, "little"))
        self.clint.write(MTIME_OFFSET + 4, (0x1234_5678).to_bytes(4, "little"))
        assert self.clint.get_mtime() == 0x1234_5678_9ABC_DEF0


class TestCLINTBusIntegration:
    """通过 Bus 访问 CLINT."""

    def test_bus_write_to_msip(self):
        """通过总线写 MSIP 触发 IPI."""
        clint = CLINT(num_harts=4)
        bus = Bus(ram_size=1024 * 1024)
        bus.add_device(CLINT_BASE, clint)

        # hart 0 写 hart 1 的 msip
        bus.write(CLINT_BASE + MSIP_OFFSET + 4, b"\x01\x00\x00\x00")
        has_pending, _, _ = clint.check_interrupt(1)
        assert has_pending

    def test_bus_read_device_addr_detected(self):
        """Bus.is_device_addr 应检测 CLINT 地址."""
        clint = CLINT(num_harts=2)
        bus = Bus(ram_size=1024 * 1024)
        bus.add_device(CLINT_BASE, clint)
        assert bus.is_device_addr(CLINT_BASE)
        assert bus.is_device_addr(CLINT_BASE + MSIP_OFFSET)
        assert bus.is_device_addr(CLINT_BASE + MTIME_OFFSET)


class TestCLINTMmioPath:
    """验证 CLINT MSIP 通过 MMIO 存储指令的完整路径.

    固件 (OpenSBI / Linux) 通过 store 指令写 CLINT MSIP 寄存器
    来发送/清除核间中断。该路径必须正确通过
    Hart -> mem_write -> Bus.write -> CLINT.write。
    """

    # RV64 指令编码
    SW_INSTR = 0x00552023  # sw x5, 0(x10) — 将 x5 的值存入 *x10
    SD_INSTR = 0x00553023  # sd x5, 0(x10) — 同上 (64-bit)
    LW_INSTR = 0x00052283  # lw x5, 0(x10)
    WFI_INSTR = 0x10500073  # wfi

    BASE_REG = 10  # x10 (a0) — 用于 store 指令的基址寄存器

    @staticmethod
    def _make_hart_with_clint(
        hart_id: int = 0,
        num_harts: int = 2,
    ):
        """创建带 Bus + CLINT 的 Hart, M-mode."""
        clint = CLINT(num_harts=num_harts)
        clint.base_addr = CLINT_BASE
        bus = Bus(ram_size=1024 * 1024, ram_base=0x8000_0000)
        bus.add_device(CLINT_BASE, clint)

        h = Hart(id=hart_id)
        h.pc = 0x80000000
        h.mode = RiscvMode.M
        h.mstatus_val = MSTATUS_MIE
        h.csrs["mtvec"].val = 0x80000100
        h.csrs["mie"].val = 1 << 3  # MSIE
        h.interrupt_ctrl = clint
        h.mem_read_phy = bus.read
        h.mem_write_phy = bus.write
        h.bus = bus

        return h, clint, bus

    def test_store_to_msip_sets_hardware_bit(self):
        """Store 指令写入 CLINT MSIP 使 _msip[hart_id] 置位."""
        h, clint, bus = self._make_hart_with_clint()

        # 设置 store 目标地址 = CLINT MSIP[hart0]
        msip_addr = CLINT_BASE + MSIP_OFFSET
        h.write_gpr(self.BASE_REG, msip_addr)  # rs1 (base addr reg)
        h.write_gpr(5, 1)  # rs2 (value = 1)

        # 将 SW 指令写入 RAM
        bus.write(0x80000000, self.SW_INSTR.to_bytes(4, "little"))

        # 执行 store
        h.exec_instr(self.SW_INSTR)

        # 验证 CLINT _msip 已置位
        assert clint._msip[0] == 1, (
            f"MMIO store 应置位 _msip[0], 实际={clint._msip[0]}"
        )
        has_pending, mip, src = clint.check_interrupt(0)
        assert has_pending, "check_interrupt 应返回 pending"
        assert src is not None and src.name == "MSI", (
            f"中断源应为 MSI, 实际={src}"
        )

    def test_store_zero_to_msip_clears_hardware_bit(self):
        """Store 指令写 0 到 CLINT MSIP 使 _msip[hart_id] 清零."""
        h, clint, bus = self._make_hart_with_clint()

        # 先通过 Python API 置位 MSIP (模拟先前的 IPI)
        clint.send_ipi(0)
        assert clint._msip[0] == 1, "send_ipi 应置位 _msip"

        # 现在通过 store 指令清除 MSIP
        msip_addr = CLINT_BASE + MSIP_OFFSET
        h.write_gpr(self.BASE_REG, msip_addr)  # rs1
        h.write_gpr(5, 0)  # rs2 (value = 0)

        bus.write(0x80000000, self.SW_INSTR.to_bytes(4, "little"))
        h.exec_instr(self.SW_INSTR)

        assert clint._msip[0] == 0, (
            f"MMIO store 写 0 应清零 _msip[0], 实际={clint._msip[0]}"
        )
        has_pending, _, _ = clint.check_interrupt(0)
        assert not has_pending, "check_interrupt 应返回 no pending"

    def test_store_to_other_hart_msip_sets_correct_bit(self):
        """Hart 0 store 到 CLINT MSIP[hart1] 使 _msip[1] 置位, _msip[0] 不变."""
        h, clint, bus = self._make_hart_with_clint(hart_id=0, num_harts=4)

        # 目标: CLINT MSIP[hart3] (offset = MSIP_OFFSET + 3 * 4)
        msip_addr = CLINT_BASE + MSIP_OFFSET + 3 * 4
        h.write_gpr(self.BASE_REG, msip_addr)  # rs1
        h.write_gpr(5, 1)  # rs2 (value = 1)

        bus.write(0x80000000, self.SW_INSTR.to_bytes(4, "little"))
        h.exec_instr(self.SW_INSTR)

        # 验证只有 hart 3 收到 MSIP
        for hid in range(4):
            expected = 1 if hid == 3 else 0
            assert clint._msip[hid] == expected, (
                f"_msip[{hid}] 应为 {expected}, 实际={clint._msip[hid]}"
            )
        has_pending, _, _ = clint.check_interrupt(3)
        assert has_pending, "hart 3 应有 pending MSIP"

    def test_msip_clear_via_mmio_and_verify_no_pending(self):
        """MMIO 清零 MSIP 后 mip CSR 通过 update_hw_mip 反映已清零状态.

        回归: 若只清零 _msip 但 mip CSR 未同步, check_pending_interrupts
        仍会看到过时的 MSIP=1 导致虚假中断投递与 MSIP 风暴.
        """
        h, clint, bus = self._make_hart_with_clint(hart_id=0, num_harts=2)

        # Step 1: 通过 MMIO store 置位 MSIP[0]
        msip_addr = CLINT_BASE + MSIP_OFFSET
        h.write_gpr(self.BASE_REG, msip_addr)
        h.write_gpr(5, 1)
        bus.write(0x80000000, self.SW_INSTR.to_bytes(4, "little"))
        h.exec_instr(self.SW_INSTR)
        assert clint._msip[0] == 1

        # Step 2: 同步 mip CSR 从硬件
        has_pending, mip_bits, _ = clint.check_interrupt(0)
        h.update_hw_mip(mip_bits)
        assert h.mip_val & (1 << 3), "mip.MSIP 应置位"

        # Step 3: 通过 MMIO store 清零 MSIP[0]
        h.pc = 0x80000004
        h.write_gpr(self.BASE_REG, msip_addr)  # 重置基址寄存器
        h.write_gpr(5, 0)  # value = 0
        bus.write(0x80000004, self.SW_INSTR.to_bytes(4, "little"))
        h.exec_instr(self.SW_INSTR)
        assert clint._msip[0] == 0, "MSIP 应已被 MMIO store 清零"

        # Step 4: 重新同步 mip CSR 后 MSIP 必须为 0
        has_pending, mip_bits, _ = clint.check_interrupt(0)
        h.update_hw_mip(mip_bits)
        assert not (h.mip_val & (1 << 3)), (
            f"清零后 mip.MSIP 必须为 0, 实际 mip={h.mip_val:#x}"
        )
        assert not has_pending, "check_interrupt 应返回 no pending"
