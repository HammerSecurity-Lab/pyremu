#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""CLINT 设备测试: MSIP (IPI), MTIMECMP (定时器), MTIME."""

import pytest

from pyremu.core.hart import RiscvMode
from pyremu.core.priv_defs import (
    MSTATUS_MIE,
)
from pyremu.emu.hart import Hart
from pyremu.interrupt.clint import (
    CLINT,
    CLINT_BASE,
    MSIP_OFFSET,
    MTIME_OFFSET,
    MTIMECMP_OFFSET,
)
from pyremu.interrupt.controller import INT_SOURCE_MIP_MASK, IntSource
from pyremu.memory.bus import Bus
from tests.hart_helpers import make_hart, make_pmp, set_mie, set_msip


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


class TestHardwareMipClear:
    def test_msip_cleared_after_clint_write_zero(self):
        """CLINT MSIP 写 0 后, check_pending_interrupts 应清除 mip.MSIP."""
        bus = Bus(ram_base=0x80000000, ram_size=128 * 1024 * 1024)
        clint = CLINT(num_harts=2)
        h0 = make_hart(0, bus, clint, make_pmp())

        # 设置为 M 模式, 使能 MSIE, mtvec 指向有效地址
        h0.mode = RiscvMode.M
        h0.mstatus_val |= MSTATUS_MIE  # 全局中断使能 (mstatus.MIE)
        set_mie(h0, 1 << 3)  # MSIE
        h0.csrs["mtvec"].val = 0x80000000

        # Step 1: 设置 MSIP 后 mip 应有 MSIP
        set_msip(clint, 0, 1)
        has_pending, mip_bits, _ = clint.check_interrupt(0)
        assert has_pending and (mip_bits & (1 << 3)), "MSIP=1 时应 pending"

        # Step 2: check_pending_interrupts 投递中断
        delivered = h0.check_pending_interrupts()
        assert delivered, "MSIP pending + MSIE enabled -> 应投递中断"
        # 进入 M-mode trap handler 后 MIE 被硬件清除
        assert not h0.mie, "trap 入口应清除 MIE"
        # 模拟 handler 处理: 清除 CLINT MSIP
        clint.clear_ipi(0)
        assert clint._msip[0] == 0, "clear_ipi 后 MSIP 应为 0"

        # Step 3: 模拟 mret 后恢复 MIE
        h0._csr_write_raw("mstatus", h0.mstatus_val | MSTATUS_MIE)
        assert h0.mie, "mret 后 MIE 应恢复为 1"

        # Step 4: 再次调用 check_pending_interrupts
        # ── 核心断言: MSIP 已清, 不应再投递任何中断 ──
        delivered_again = h0.check_pending_interrupts()
        assert not delivered_again, (
            "CLINT MSIP 已清零, check_pending_interrupts 不应再投递中断 "
            "(旧 bug: mip MSIP 位未清除, 导致虚假重入)"
        )

        # 验证 mip CSR 中 MSIP 位确已清除
        mip_after = h0._csr_read_raw("mip")
        assert (mip_after & (1 << 3)) == 0, (
            f"mip.MSIP 应在 CLINT 清零后撤除, 实际 mip={mip_after:#x}"
        )

    def test_mtip_cleared_after_mtimecmp_disabled(self):
        """mtimecmp=0 (禁用) 后, MTIP 不再挂起."""
        bus = Bus(ram_base=0x80000000, ram_size=128 * 1024 * 1024)
        clint = CLINT(num_harts=2)
        h0 = make_hart(0, bus, clint, make_pmp())

        h0.mode = RiscvMode.M
        h0.mstatus_val |= MSTATUS_MIE  # 全局中断使能
        set_mie(h0, 1 << 7)  # MTIE
        h0.csrs["mtvec"].val = 0x80000000

        # Step 1: 设置 mtimecmp 并使 mtime 超过它
        clint._mtimecmp[0] = 100
        clint._mtime = 200
        has_pending, mip_bits, _ = clint.check_interrupt(0)
        assert has_pending and (mip_bits & (1 << 7)), (
            "mtime >= mtimecmp 时 MTIP 应 pending"
        )

        # Step 2: 投递中断
        delivered = h0.check_pending_interrupts()
        assert delivered, "MTIP pending + MTIE enabled -> 应投递中断"

        # Step 3: 模拟 handler 清除定时器 (写入 mtimecmp=0)
        clint._mtimecmp[0] = 0

        # Step 4: 恢复 MIE (模拟 mret)
        h0._csr_write_raw("mstatus", h0.mstatus_val | MSTATUS_MIE)

        # Step 5: 核心断言 — MTIP 已清除
        delivered_again = h0.check_pending_interrupts()
        assert not delivered_again, (
            "mtimecmp 已禁用, check_pending_interrupts 不应再投递 MTIP 中断"
        )
        mip_after = h0._csr_read_raw("mip")
        assert (mip_after & (1 << 7)) == 0, (
            f"mip.MTIP 应在 mtimecmp=0 后清除, 实际 mip={mip_after:#x}"
        )

    def test_msip_clear_prevents_spurious_retrap_loop(self):
        """模拟 MSIP 风暴场景: 依次执行 IPI、trap、clear 与 mret 后不重入.

        这是诊断中观察到的真实故障模式: 两个 hart 在 M-mode 之间无限往返,
        每次 ~5500 traps/10s, 900s 内共投递 214K 次 MSIP 中断.
        """
        bus = Bus(ram_base=0x80000000, ram_size=128 * 1024 * 1024)
        clint = CLINT(num_harts=2)
        h0 = make_hart(0, bus, clint, make_pmp())

        h0.mode = RiscvMode.M
        h0.mstatus_val |= MSTATUS_MIE  # 全局中断使能
        set_mie(h0, 1 << 3)  # MSIE
        h0.csrs["mtvec"].val = 0x80000000

        trap_count = 0

        # 模拟一次完整的 IPI 处理循环
        for _ in range(10):
            # 外部 hart 发 IPI (置 MSIP)
            if trap_count == 0:
                clint.send_ipi(0)

            # 检查中断
            if h0.check_pending_interrupts():
                trap_count += 1
                # handler: 清除本 hart 的 MSIP
                clint.clear_ipi(0)
                # mret: 恢复 MIE
                h0._csr_write_raw("mstatus", h0.mstatus_val | MSTATUS_MIE)

        # 核心断言: 只投递了 1 次中断, 不是 10 次
        assert trap_count == 1, (
            f"IPI 清除后不应再有中断重入. "
            f"预期 1 次, 实际 {trap_count} 次 "
            f"(旧 bug: 每次 check_pending_interrupts 都重投递 MSIP)"
        )

    def test_cross_hart_msip_no_storm(self):
        """跨 hart 完整流程: Hart 0 发 IPI, Hart 1 收到后清除, 不重入."""
        bus = Bus(ram_base=0x80000000, ram_size=128 * 1024 * 1024)
        clint = CLINT(num_harts=2)
        h0 = make_hart(0, bus, clint, make_pmp())
        h1 = make_hart(1, bus, clint, make_pmp())

        # 两 hart 均 M 模式, MSIE 使能, 全局中断开启
        for h in [h0, h1]:
            h.mode = RiscvMode.M
            h.mstatus_val |= MSTATUS_MIE  # 全局中断使能
            set_mie(h, 1 << 3)  # MSIE
            h.csrs["mtvec"].val = 0x80000000

        # Hart 0 发 IPI 给 Hart 1
        clint.send_ipi(1)

        # Hart 1 收到中断
        delivered = h1.check_pending_interrupts()
        assert delivered, "Hart 1 应收到 MSIP 中断"

        # Hart 1 handler 清除自己的 MSIP
        clint.clear_ipi(1)

        # mret 恢复 MIE
        h1._csr_write_raw("mstatus", h1.mstatus_val | (1 << 3))

        # Hart 1 不应再有中断
        assert not h1.check_pending_interrupts(), "清除后 Hart 1 不应重入"

        # Hart 0 不受影响
        assert (h0._csr_read_raw("mip") & (1 << 3)) == 0, (
            "Hart 0 的 MSIP 不应被污染"
        )
