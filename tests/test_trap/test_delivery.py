#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""陷态投递: M/S 模式入口、委派、嵌套投递与 IPI 清除."""

import pytest

from pyremu.core.decoder import Hart
from pyremu.core.hart import RiscvMode
from pyremu.core.priv_defs import (
    MSTATUS_MIE,
    MSTATUS_SIE,
)
from pyremu.core.trap_def import TrapType
from pyremu.interrupt.clint import CLINT
from pyremu.memory.bus import Bus
from tests.test_trap.support import (
    MTVEC,
    STVEC,
)


class TestTakeTrap:
    """验证 _take_trap 的寄存器保存/恢复流程."""

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置陷态向量与 MIE."""
        hart.csrs["mtvec"].val = 0x80000000
        hart.pc = 0x1000
        # 预设 mstatus 值: MIE=1, mode=M
        hart.mstatus_val = MSTATUS_MIE
        return hart

    def test_take_trap_saves_context(self, hart):
        """异常触发后 mepc/mcause/mtval/mstatus 应正确保存."""
        hart.deliver_trap(TrapType.IllInstr, tval=0xDEAD, is_interrupt=False)

        assert hart.mepc_val == 0x1000, "mepc 应保存触发异常的 PC"
        assert hart.mcause_val == 2, "mcause 应为 IllInstr 编码 2"
        assert hart.mtval_val == 0xDEAD, "mtval 应保存附加信息"
        # MIE=1 应被保存到 MPIE, MIE 清零
        assert hart.mpie is True, "进入 trap 前 MIE=1 应保存为 MPIE=1"
        assert hart.mie is False, "进入 trap 后 MIE 应为 0"
        assert hart.mpp == RiscvMode.M, "MPP 应保存先前的 M 模式"

    def test_take_trap_jumps_to_mtvec_direct(self, hart):
        """直接模式: PC 应跳转到 mtvec.BASE."""
        hart.csrs["mtvec"].val = 0xC0000000  # MODE=0 (direct)
        hart.deliver_trap(TrapType.Breakpoint, is_interrupt=False)
        assert hart.pc == 0xC0000000, "直接模式应跳转到 mtvec BASE"

    def test_take_trap_jumps_to_mtvec_vectored(self, hart):
        """向量模式 + 中断: PC = BASE + 4 * code."""
        hart.csrs["mtvec"].val = 0xC0000001  # MODE=1 (vectored)
        hart.deliver_trap(TrapType.SmodeTimerInterrupt, is_interrupt=True)
        # SmodeTimerInterrupt code = 5
        expected_pc = 0xC0000000 + 4 * 5
        assert hart.pc == expected_pc, (
            f"向量模式应跳转到 BASE+4*5 = 0x{expected_pc:x}"
        )

    def test_take_trap_vectored_ignored_for_exception(self, hart):
        """向量模式对异常不生效, 仍使用直接模式."""
        hart.csrs["mtvec"].val = 0xC0000001
        hart.deliver_trap(TrapType.IllInstr, is_interrupt=False)
        assert hart.pc == 0xC0000000, "异常在向量模式下仍应使用直接模式"

    def test_take_trap_switches_to_m_mode(self, hart):
        """trap 后应切换到 M 模式."""
        hart.mode = RiscvMode.U
        hart.deliver_trap(TrapType.EcallFromUmode, is_interrupt=False)
        assert hart.mode == RiscvMode.M, "trap 后应进入 M 模式"


class TestTakeTrapResolution:
    """验证 Hart (继承 TrapHandler mixin) 的 _take_trap 实现."""

    def test_trap_handler_mixin_provides_implementation(self, hart):
        """Hart 通过 TrapHandler mixin 获得 _take_trap 实现,
        而非 HartWithRegs 的 stub (已移除)."""
        hart.csrs["mtvec"].val = 0x80000000
        hart.mstatus_val = 0
        # _take_trap 由 TrapHandler mixin 提供, 不应抛 NotImplementedError
        try:
            hart.deliver_trap(TrapType.IllInstr, tval=0x42, is_interrupt=False)
        except NotImplementedError:
            pytest.fail("Hart._take_trap 应由 TrapHandler mixin 提供实现")
        assert hart.mcause_val == 2
        assert hart.mtval_val == 0x42

    def test_check_pending_uses_overridden_method(self, hart):
        """check_pending_interrupts 定义在 Hart, 正确调用覆写后的 _take_trap."""
        clint = CLINT(num_harts=1)
        hart.interrupt_ctrl = clint
        hart.mie = True
        hart.csrs["mie"].val = 1 << 3  # MSIP enable
        hart.csrs["mtvec"].val = 0x80000000
        hart.pc = 0x2000

        clint.send_ipi(0)
        interrupted = hart.check_pending_interrupts()
        assert interrupted
        # MSI: bit63=1, code=3
        assert hart.mcause_val == (1 << 63) | 3


class TestTrapDelegation:
    """验证 medeleg/mideleg 将异常/中断委派到 S 模式的流程.

    RISC-V Privileged Spec §3.1.9:
    - M 模式下发生的 trap 永不委派
    - 委派时跳转 stvec、写入 sepc/scause/stval、更新 SPP/SPIE/SIE
    """

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置陷态向量、MIE 与 M 模式."""
        hart.csrs["mtvec"].val = 0x80000000
        hart.csrs["stvec"].val = 0x80004000
        hart.pc = 0x1000
        hart.mstatus_val = MSTATUS_MIE
        hart.mode = RiscvMode.M
        return hart

    # ---- Exception delegation ----

    def test_medeleg_ecall_u_to_s(self, hart):
        """medeleg[8]=1: U 模式 ecall 委派到 S 模式."""
        hart.csrs["medeleg"].val = 1 << 8
        hart.mode = RiscvMode.U
        hart.deliver_trap(TrapType.EcallFromUmode, tval=0, is_interrupt=False)

        assert hart.pc == 0x80004000, "委派后应跳转到 stvec"
        assert hart.mode == RiscvMode.S, "应进入 S 模式"
        assert hart.sepc_val == 0x1000, "sepc 应保存 PC"
        assert hart.scause_val == 8, "scause 应为 8"
        assert hart.mcause_val == 0, "不应修改 mcause"

    def test_medeleg_not_from_m_mode(self, hart):
        """即使 medeleg 已设置, M 模式下永不委派."""
        hart.csrs["medeleg"].val = 1 << 8
        hart.mode = RiscvMode.M
        hart.deliver_trap(TrapType.EcallFromUmode, tval=0, is_interrupt=False)

        assert hart.pc == 0x80000000, "应走 mtvec"
        assert hart.mode == RiscvMode.M
        assert hart.mepc_val == 0x1000
        assert hart.mcause_val == 8

    def test_medeleg_ill_instr_to_s(self, hart):
        """medeleg[2]=1: 非法指令异常委派到 S 模式."""
        hart.csrs["medeleg"].val = 1 << 2
        hart.mode = RiscvMode.U
        hart.deliver_trap(TrapType.IllInstr, tval=0xBAD, is_interrupt=False)

        assert hart.pc == 0x80004000
        assert hart.mode == RiscvMode.S
        assert hart.scause_val == 2
        assert hart.stval_val == 0xBAD

    # ---- Interrupt delegation ----

    def test_mideleg_timer_to_s(self, hart):
        """mideleg[5]=1: 定时器中断委派到 S 模式."""
        hart.csrs["mideleg"].val = 1 << 5
        hart.mode = RiscvMode.U
        hart.deliver_trap(
            TrapType.SmodeTimerInterrupt, tval=0, is_interrupt=True
        )

        assert hart.pc == 0x80004000
        assert hart.mode == RiscvMode.S
        assert hart.sepc_val == 0x1000
        expected_scause = (1 << 63) | 5
        assert hart.scause_val == expected_scause, (
            f"scause 应为: bit63=1 code=5, 实际 {hart.scause_val:#x}"
        )

    def test_mideleg_not_set_goes_to_m(self, hart):
        """mideleg=0: 中断照旧进入 M 模式."""
        hart.mode = RiscvMode.U
        hart.deliver_trap(
            TrapType.SmodeTimerInterrupt, tval=0, is_interrupt=True
        )

        assert hart.pc == 0x80000000
        assert hart.mode == RiscvMode.M
        assert hart.mepc_val == 0x1000

    # ---- mstatus S-level fields ----

    def test_delegated_trap_saves_spp(self, hart):
        """委派 trap 应将当前模式编码为 SPP."""
        hart.csrs["medeleg"].val = 1 << 8
        hart.mode = RiscvMode.U
        hart.deliver_trap(TrapType.EcallFromUmode, is_interrupt=False)
        assert hart.spp == RiscvMode.U

    def test_delegated_trap_clears_sie_sets_spie(self, hart):
        """委派 trap: SIE -> SPIE, SIE ← 0."""
        hart.csrs["medeleg"].val = 1 << 8
        hart.mode = RiscvMode.U
        hart.mstatus_val = MSTATUS_SIE
        hart.deliver_trap(TrapType.EcallFromUmode, is_interrupt=False)

        assert hart.sie is False, "进入 S 模式 trap 后 SIE 应为 0"
        assert hart.spie is True, "SPIE 应保存先前的 SIE=1"

    def test_delegated_trap_spie_zero_when_sie_zero(self, hart):
        """委派 trap 前 SIE=0: SPIE 亦记录为 0."""
        hart.csrs["medeleg"].val = 1 << 8
        hart.mode = RiscvMode.U
        hart.mstatus_val = 0  # SIE=0
        hart.deliver_trap(TrapType.EcallFromUmode, is_interrupt=False)

        assert hart.spie is False

    # ---- SRET after delegated trap ----

    def test_sret_after_delegated_trap(self, hart):
        """委派 trap -> SRET 应恢复到原模式."""
        hart.csrs["medeleg"].val = 1 << 8
        hart.mode = RiscvMode.U
        hart.pc = 0x4000
        hart.mstatus_val = MSTATUS_SIE  # SIE=1
        hart.deliver_trap(TrapType.EcallFromUmode, is_interrupt=False)

        hart.trap_sret()
        assert hart.pc == 0x4000
        assert hart.mode == RiscvMode.U
        assert hart.sie is True, "SRET 应恢复 SIE"

    # ---- Vectored stvec ----

    def test_delegated_vector_stvec(self, hart):
        """委派中断 + stvec MODE=1: PC = BASE + 4*code."""
        hart.csrs["stvec"].val = 0xC0001001
        hart.csrs["mideleg"].val = 1 << 7  # delegate MTI (code=7)
        hart.mode = RiscvMode.U
        hart.deliver_trap(TrapType.MmodeTimerInterrupt, is_interrupt=True)

        expected = 0xC0001000 + 4 * 7
        assert hart.pc == expected, f"应为 0x{expected:x}, 实际 0x{hart.pc:x}"

    def test_delegated_vector_ignored_for_exception(self, hart):
        """委派异常在 stvec 向量模式下仍使用 BASE."""
        hart.csrs["stvec"].val = 0xC0001001
        hart.csrs["medeleg"].val = 1 << 8
        hart.mode = RiscvMode.U
        hart.deliver_trap(TrapType.EcallFromUmode, is_interrupt=False)

        assert hart.pc == 0xC0001000, "异常不使用向量偏移"

    # ---- check_pending_interrupts + CLINT + delegation ----

    def test_check_pending_msip_delegated_to_s(self, hart):
        """CLINT MSIP + mideleg[3]=1 -> 中断进入 S 模式."""
        clint = CLINT(num_harts=1)
        hart.interrupt_ctrl = clint
        hart.mode = RiscvMode.U
        hart.mie = True
        hart.csrs["mie"].val = 1 << 3  # MSIE
        hart.csrs["mideleg"].val = 1 << 3  # delegate MSI
        hart.csrs["stvec"].val = 0x80004000
        hart.pc = 0x2000

        clint.send_ipi(0)
        interrupted = hart.check_pending_interrupts()
        assert interrupted
        assert hart.mode == RiscvMode.S, "委派后应进入 S 模式"
        assert hart.pc == 0x80004000  # stvec
        assert hart.sepc_val == 0x2000

    def test_check_pending_not_delegated_stays_m(self, hart):
        """mideleg=0 -> MSIP 照旧进入 M 模式."""
        clint = CLINT(num_harts=1)
        hart.interrupt_ctrl = clint
        hart.mode = RiscvMode.U
        hart.mie = True
        hart.csrs["mie"].val = 1 << 3
        hart.pc = 0x2000

        clint.send_ipi(0)
        interrupted = hart.check_pending_interrupts()
        assert interrupted
        assert hart.mode == RiscvMode.M, "非委派应进入 M 模式"
        assert hart.mepc_val == 0x2000

    def test_s_mode_sie_zero_blocks_delegated_interrupt(self, hart):
        """S 模式 + SIE=0: 已委派中断被阻塞; 非委派中断仍可抢占."""
        clint = CLINT(num_harts=1)
        hart.interrupt_ctrl = clint
        hart.mode = RiscvMode.S
        hart.sie = False  # S 级全局关中断
        hart.mie = True  # M 级全局开中断 (允许非委派抢占)
        hart.csrs["mie"].val = 1 << 3  # MSIE
        hart.csrs["mideleg"].val = 1 << 3  # delegate MSI -> S

        clint.send_ipi(0)
        interrupted = hart.check_pending_interrupts()
        # 已委派 + SIE=0 -> 不应触发
        assert not interrupted, "SIE=0 应阻塞已委派中断"

    def test_s_mode_sie_zero_allows_non_delegated(self, hart):
        """S 模式 + SIE=0: 非委派 M 级中断仍可抢占."""
        clint = CLINT(num_harts=1)
        hart.interrupt_ctrl = clint
        hart.mode = RiscvMode.S
        hart.sie = False
        hart.mie = True
        hart.csrs["mie"].val = 1 << 3  # MSIE
        # mideleg = 0 -> MSI stays M-level, preempts S
        hart.csrs["mtvec"].val = 0x80000000

        clint.send_ipi(0)
        interrupted = hart.check_pending_interrupts()
        assert interrupted, "非委派 M 级中断应能抢占 S 模式"
        assert hart.mode == RiscvMode.M


class TestNestedDelivery:
    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置陷态向量与 PC."""
        hart.csrs["mtvec"].val = MTVEC
        hart.csrs["stvec"].val = STVEC
        hart.pc = 0x8000_4000
        return hart

    def test_exception_in_mmode_uses_mtvec(self, hart):
        hart.deliver_trap_nested_enabled(TrapType.IllInstr, tval=0xDEAD)
        assert hart.mcause_val == 2
        assert hart.mtval_val == 0xDEAD
        assert hart.mepc_val == 0x8000_4000
        assert hart.pc == MTVEC
        assert hart.mode is RiscvMode.M

    def test_exception_delegated_by_medeleg(self, hart):
        hart.mode = RiscvMode.S
        hart.csrs["medeleg"].val = 1 << 12
        hart.deliver_trap_nested_enabled(TrapType.InstrPageFault, tval=0x1000)
        assert hart.mode is RiscvMode.S
        assert hart.pc == STVEC
        assert hart.scause_val == 12
        assert hart.stval_val == 0x1000

    def test_interrupt_delegated_by_mideleg(self, hart):
        hart.mode = RiscvMode.U
        hart.csrs["mideleg"].val = 1 << 7
        hart.deliver_trap_nested_enabled(
            TrapType.MmodeTimerInterrupt, is_interrupt=True
        )
        assert hart.mode is RiscvMode.S
        assert hart.scause_val == (1 << 63) | 7
        assert hart.sepc_val == 0x8000_4000

    def test_reservation_is_cleared(self, hart):
        hart.set_reservation(0x8000_2000, 8)
        hart.deliver_trap_nested_enabled(TrapType.Breakpoint)
        assert not hart.reservation_valid

    def test_wfi_waiter_is_woken(self, hart):
        hart._waiting = True
        hart.deliver_trap_nested_enabled(TrapType.Breakpoint)
        assert not hart._waiting
        assert hart._wfi_woken


class TestDeliveryBranches:
    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置陷态向量与 PC."""
        hart.csrs["mtvec"].val = MTVEC
        hart.csrs["stvec"].val = STVEC
        hart.pc = 0x8000_4000
        return hart

    def test_ssip_trap_preserves_pending_bit(self, hart):
        """投递不改变 mip.SSIP: 该位由软件清除."""
        hart.mode = RiscvMode.U
        hart.csrs["mideleg"].val = 1 << 1
        hart.update_hw_mip(1 << 1)
        hart.deliver_trap(TrapType.SmodeSoftInterrupt, is_interrupt=True)
        assert hart.mip_val & (1 << 1)
        assert hart.scause_val == (1 << 63) | 1

    def test_msip_trap_preserves_pending_bit(self, hart):
        """投递不改变 mip.MSIP: 该位反映 CLINT 的 msip 寄存器."""
        hart.update_hw_mip(1 << 3)
        hart.deliver_trap(TrapType.MmodeSoftInterrupt, is_interrupt=True)
        assert hart.mip_val & (1 << 3)
        assert hart.mcause_val == (1 << 63) | 3

    def test_hypervisor_ecall_traps_ill_instr(self, hart):
        hart.mode = RiscvMode.H
        hart.trap_ecall()
        assert hart.mcause_val == 2
        assert hart.mtval_val == 0x8000_4000


class TestMsipSurvivesTrapDelivery:
    """mip.MSIP 反映 CLINT 的 msip 寄存器, 投递陷态不改变该位.

    RISC-V 规范: mip 中由硬件源断言的位只随硬件源改变. 收到软件中断后, 受调试
    程序的陷态处理函数须写入 CLINT 的 msip 撤销该中断; 未撤销时返回后再次投递,
    与真实硬件一致.
    """

    NOP_INSTR = 0x00000013
    MRET_INSTR = 0x30200073

    @staticmethod
    def _make_hart_with_clint(
        hart_id: int = 0,
        num_harts: int = 2,
        mode=RiscvMode.M,
    ):
        """创建带 Bus + CLINT 的 Hart."""
        clint = CLINT(num_harts=num_harts)
        clint.base_addr = 0x0200_0000
        bus = Bus(ram_size=1024 * 1024, ram_base=0x8000_0000)
        bus.add_device(clint.base_addr, clint)

        h = Hart(id=hart_id)
        h.pc = 0x80000000
        h.mode = mode
        # M-mode: MIE.  S-mode: SIE (required for delegated interrupt delivery).
        if mode == RiscvMode.S:
            h.mstatus_val = MSTATUS_MIE | MSTATUS_SIE
        else:
            h.mstatus_val = MSTATUS_MIE
        h.csrs["mtvec"].val = 0x80000100
        h.csrs["stvec"].val = 0x80000400
        h.csrs["mie"].val = 1 << 3  # MSIE
        h.interrupt_ctrl = clint
        h.mem_read_phy = bus.read
        h.mem_write_phy = bus.write
        h.bus = bus

        return h, clint, bus

    def test_deliver_msip_to_mmode_keeps_clint_msip(self):
        """投递到 M 模式后, CLINT 的 msip 与 mip.MSIP 保持置位."""
        h, clint, _ = self._make_hart_with_clint(hart_id=0, mode=RiscvMode.S)

        clint.send_ipi(0)
        assert clint._msip[0] == 1, "前置: _msip 应为 1"

        taken = h.check_pending_interrupts()
        assert taken, "MSIP 应被投递"
        assert h.mode == RiscvMode.M, "应切换到 M 模式"
        assert h.mcause_val == 0x8000_0000_0000_0003, (
            f"mcause 应为 MSI, 实际={h.mcause_val:#x}"
        )

        assert clint._msip[0] == 1, (
            f"投递不改变硬件源, _msip 应仍为 1, 实际={clint._msip[0]}"
        )
        assert h.mip_val & (1 << 3), (
            f"投递后 mip.MSIP 应保持置位, 实际 mip={h.mip_val:#x}"
        )

    def test_deliver_msip_delegated_to_smode_keeps_clint_msip(self):
        """MSIP 委派到 S 模式 (mideleg[3]=1) 时, 硬件源同样保持置位."""
        h, clint, _ = self._make_hart_with_clint(hart_id=0, mode=RiscvMode.S)

        h.csrs["mideleg"].val |= 1 << 3
        assert h.csrs["mideleg"].val & (1 << 3), "前置: mideleg[3] 必须置位"

        clint.send_ipi(0)
        assert clint._msip[0] == 1, "前置: _msip 应为 1"

        taken = h.check_pending_interrupts()
        assert taken, "MSIP 应被投递"
        assert h.mode == RiscvMode.S, "委派中断应保持 S 模式"
        assert h.scause_val == 0x8000_0000_0000_0003, (
            f"scause 应为 MSI, 实际={h.scause_val:#x}"
        )

        assert clint._msip[0] == 1, (
            f"投递不改变硬件源, _msip 应仍为 1, 实际={clint._msip[0]}"
        )
        assert h.mip_val & (1 << 3), (
            f"投递后 mip.MSIP 应保持置位, 实际 mip={h.mip_val:#x}"
        )

    def test_handler_clearing_clint_msip_revokes_pending(self):
        """陷态处理函数写入 CLINT 的 msip 后, mip.MSIP 随之清除,
        返回后不再投递."""
        h, clint, bus = self._make_hart_with_clint(hart_id=0, mode=RiscvMode.S)

        ret_addr = 0x80001000
        bus.write(ret_addr, self.NOP_INSTR.to_bytes(4, "little"))

        clint.send_ipi(0)
        h.pc = ret_addr
        assert h.check_pending_interrupts()
        assert h.mode == RiscvMode.M
        assert h.mepc_val == ret_addr, (
            f"mepc 应为 ret_addr, 实际={h.mepc_val:#x}"
        )

        # 陷态处理函数写入 msip 撤销中断
        clint.write(0, (0).to_bytes(4, "little"))
        assert clint._msip[0] == 0

        h.exec_instr(self.MRET_INSTR)
        assert h.mode == RiscvMode.S, f"MRET 后应为 S 模式, 实际={h.mode}"
        assert h.pc == ret_addr, f"MRET 后 PC 应为 ret_addr, 实际={h.pc:#x}"

        h.exec_instr(self.NOP_INSTR)
        assert not h.check_pending_interrupts(), (
            f"撤销 msip 后不应再投递, mip={h.mip_val:#x} _msip={clint._msip[0]}"
        )
        assert not (h.mip_val & (1 << 3)), "撤销 msip 后 mip.MSIP 应为 0"

    def test_uncleared_msip_is_redelivered_after_return(self):
        """未撤销 msip 时, mret 返回后重新投递, 中断不会在投递时被丢弃."""
        h, clint, bus = self._make_hart_with_clint(hart_id=0, mode=RiscvMode.S)

        ret_addr = 0x80001000
        bus.write(ret_addr, self.NOP_INSTR.to_bytes(4, "little"))

        clint.send_ipi(0)
        h.pc = ret_addr
        assert h.check_pending_interrupts()
        assert h.mode == RiscvMode.M

        h.exec_instr(self.MRET_INSTR)
        assert h.mode == RiscvMode.S

        assert h.check_pending_interrupts(), (
            f"未撤销的 MSIP 应在返回后重新投递, "
            f"mip={h.mip_val:#x} _msip={clint._msip[0]}"
        )
        assert h.mode == RiscvMode.M
        assert h.mepc_val == ret_addr, (
            f"再次投递的 mepc 应为 ret_addr, 实际={h.mepc_val:#x}"
        )
