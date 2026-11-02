#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""中断: 定时器、Sstc, SIP/MIP 只读掩码与中断检查顺序."""

import pytest

from pyremu.core.decoder import Hart
from pyremu.core.hart import RatifiedHartAttrs, RiscvMode
from pyremu.core.priv_defs import (
    MSTATUS_MIE,
    MSTATUS_SIE,
)
from pyremu.core.registers import CsrAccessError
from pyremu.interrupt.clint import CLINT
from tests.test_trap.support import (
    MTVEC,
    StubImsic,
    StubPlic,
    STVEC,
)


class TestTimerInterrupt:
    """验证 CLINT 定时器中断 (MTI) 通过 check_pending_interrupts 正确投递.

    CLINT.check_interrupt() 在 mtime >= mtimecmp (且 mtimecmp > 0) 时
    设置 mip 的 MTIP 位 (bit 7), 之后由 check_pending_interrupts(Hart)
    按优先级 (MSI > MTI > ...) 和 mideleg 委派投递.

    覆盖场景:
    - M-mode 直接接收 MTI
    - MIE=0 阻塞
    - mtimecmp=0 禁用
    - mideleg 委派到 S-mode
    - S-mode 全局中断使能阻塞
    """

    MTECMP_OFFSET = 0x4000  # CLINT mtimecmp 区域偏移

    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        """单 hart CLINT."""
        self.clint = CLINT(num_harts=1)
        return self.clint

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """hart 连接到 CLINT, M 模式, MIE 使能, MTIE 使能."""
        hart.csrs["mtvec"].val = 0x80000000
        hart.csrs["stvec"].val = 0x80004000
        hart.pc = 0x1000
        hart.mode = RiscvMode.M
        hart.mstatus_val = MSTATUS_MIE
        # 使能 M 模式定时器中断 (MTIE = bit 7)
        hart.csrs["mie"].val = 1 << 7
        hart.interrupt_ctrl = self.clint
        return hart

    def _set_mtimecmp(self, hart_id: int, val: int):
        """通过内存映射接口写入 hart 的 mtimecmp."""
        self.clint.write(self.MTECMP_OFFSET + hart_id * 8, val.to_bytes(8, "little"))

    @staticmethod
    def _cause_is_timer(mcause: int) -> bool:
        """mcause 表示 MTI (code=7, bit63=1 -> 0x8000000000000007)."""
        return mcause == 0x8000_0000_0000_0007

    # ---- M-mode 定时器中断 ----

    def test_mti_taken_mmode(self, hart):
        """mtime >= mtimecmp -> MTI 投递到 M 模式."""
        self._set_mtimecmp(0, 50)
        self.clint.tick(100)  # mtime = 100 >= 50

        taken = hart.check_pending_interrupts()
        assert taken, "应识别待处理定时器中断"
        assert hart.pc == 0x80000000, "应跳转到 mtvec"
        assert hart.mode == RiscvMode.M
        assert self._cause_is_timer(hart.mcause_val), (
            f"mcause 应为 MTI (0x8000000000000007), 实际 {hart.mcause_val:#018x}"
        )
        # MIE 应在进入 trap 后清零
        assert not hart.mie, "进入 trap 后 MIE 应清零"

    def test_mti_not_taken_before_threshold(self, hart):
        """mtime < mtimecmp -> 无中断."""
        self._set_mtimecmp(0, 100)
        self.clint.tick(50)  # mtime = 50 < 100

        taken = hart.check_pending_interrupts()
        assert not taken
        assert hart.pc == 0x1000, "PC 不应变化"
        assert hart.mode == RiscvMode.M

    def test_mti_not_taken_mtimecmp_zero(self, hart):
        """mtimecmp == 0 -> 禁用定时器, 不触发中断."""
        self._set_mtimecmp(0, 0)
        self.clint.tick(100)  # mtime = 100 >= 0, 但 mtimecmp=0 表示禁用

        taken = hart.check_pending_interrupts()
        assert not taken

    def test_mti_not_taken_mie_off(self, hart):
        """MIE=0 -> 全局关中断, MTI 被阻塞."""
        self._set_mtimecmp(0, 50)
        self.clint.tick(100)
        hart.mie = False  # 关 M 模式全局中断

        taken = hart.check_pending_interrupts()
        assert not taken
        assert hart.pc == 0x1000

    def test_mti_not_taken_mtie_off(self, hart):
        """mie[7] (MTIE) = 0 -> 即使 mip[7] 挂起也不响应."""
        self._set_mtimecmp(0, 50)
        self.clint.tick(100)
        hart.csrs["mie"].val = 0  # 清除全部中断使能

        taken = hart.check_pending_interrupts()
        assert not taken

    # ---- 委派到 S-mode ----

    def test_mti_delegated_to_smode(self, hart):
        """mideleg[7]=1, U 模式: MTI 委派到 S 模式."""
        self._set_mtimecmp(0, 50)
        self.clint.tick(100)
        hart.csrs["mideleg"].val = 1 << 7  # 委派 MTI
        hart.mode = RiscvMode.U
        hart.mstatus_val = MSTATUS_MIE | MSTATUS_SIE  # SIE 也需要使能

        taken = hart.check_pending_interrupts()
        assert taken
        assert hart.pc == 0x80004000, "委派后应跳转到 stvec"
        assert hart.mode == RiscvMode.S, "应进入 S 模式"
        # scause = bit63=1, code=7 (原 cause 不变)
        expected_scause = (1 << 63) | 7
        assert hart.scause_val == expected_scause, (
            f"scause 应为 0x{expected_scause:x}, 实际 0x{hart.scause_val:x}"
        )
        assert hart.sepc_val == 0x1000
        assert not hart.sie, "进入 trap 后 SIE 应清零"

    def test_mti_delegated_but_sie_off_blocked(self, hart):
        """已委派的 MTI 在 S 模式且 SIE=0 时被阻塞."""
        self._set_mtimecmp(0, 50)
        self.clint.tick(100)
        hart.csrs["mideleg"].val = 1 << 7
        hart.mode = RiscvMode.S
        hart.sie = False  # S-mode 全局关中断

        taken = hart.check_pending_interrupts()
        assert not taken

    # ---- 优先级 ----

    def test_msi_higher_priority_than_mti(self, hart):
        """MSI 优先级高于 MTI: 同时挂起时先响应 MSI."""
        self._set_mtimecmp(0, 50)
        self.clint.tick(100)
        self.clint.send_ipi(0)  # 同时设置 MSI
        # 需同时使能 MSIE (bit 3) 和 MTIE (bit 7)
        hart.csrs["mie"].val = (1 << 3) | (1 << 7)

        taken = hart.check_pending_interrupts()
        assert taken
        # MSI = cause code 3 | (1<<63)
        assert hart.mcause_val == 0x8000_0000_0000_0003, (
            f"MSI 优先于 MTI, 应为 MSI (0x8000000000000003), 实际 {hart.mcause_val:#018x}"
        )

    # ---- 连续触发 ----

    def test_mti_fires_after_clearing_mip(self, hart):
        """清除 mip 后再次 tick -> MTI 再次触发."""
        self._set_mtimecmp(0, 50)
        self.clint.tick(100)

        # 第一次中断
        taken = hart.check_pending_interrupts()
        assert taken
        assert self._cause_is_timer(hart.mcause_val)

        # 模拟 MRET 后恢复, 设置新的 mtimecmp
        hart.mie = True
        hart.mode = RiscvMode.M
        hart.pc = 0x2000
        self._set_mtimecmp(0, 200)
        self.clint.tick(150)  # mtime = 250 >= 200

        # 第二次中断
        taken = hart.check_pending_interrupts()
        assert taken
        assert self._cause_is_timer(hart.mcause_val)


class TestStimecmpSTI:
    """验证 stimecmp CSR (Sstc) 触发 STI 中断.

    RISC-V Sstc 扩展允许 S 模式通过直接写 stimecmp CSR (0x14D)
    设置定时器, 无需 SBI ecall 往返 M 模式.
    硬件: mtime >= stimecmp > 0 时 STIP 置位 (mip bit 5),
    STIE 使能且 S 模式全局中断使能时投递 STI.
    """

    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        self.clint = CLINT(num_harts=1)
        return self.clint

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置陷态向量与 S 模式中断使能."""
        hart.csrs["mtvec"].val = 0x80000000
        hart.csrs["stvec"].val = 0x80004000
        hart.pc = 0x1000
        hart.mode = RiscvMode.S
        # S 模式全局中断使能 + STIE (bit 5) + mideleg[5]=1 (委派 STI 到 S)
        hart.mstatus_val = MSTATUS_SIE
        hart.csrs["mie"].val = 1 << 5  # STIE
        hart.csrs["mideleg"].val = 1 << 5  # 委派 STI
        hart.interrupt_ctrl = self.clint
        return hart

    @staticmethod
    def _cause_is_sti(mcause: int) -> bool:
        """mcause bit63=1, code=5 (STI)."""
        return mcause == 0x8000_0000_0000_0005

    # ---- S-mode 直接触发 ----

    def test_sti_taken_smode(self, hart):
        """mtime >= stimecmp > 0 -> STI 投递到 S 模式."""
        hart.csrs["stimecmp"].val = 50
        self.clint.tick(100)  # mtime = 100 >= 50

        taken = hart.check_pending_interrupts()
        assert taken, "STI 应被触发"
        # STI 是非委派的 S 模式中断 (S 模式本身就处理它)
        # 在此配置下 (S-mode, 无 mideleg 位), 走 deliver_trap -> S 模式投递
        assert hart.pc == 0x80004000, f"应跳转到 stvec=0x80004000, 实际 pc={hart.pc:#x}"
        assert self._cause_is_sti(hart.scause_val), (
            f"scause 应为 STI (0x8000000000000005), 实际 {hart.scause_val:#018x}"
        )
        assert not hart.sie, "进入 trap 后 SIE 应清零"

    def test_sti_not_taken_before_threshold(self, hart):
        """mtime < stimecmp -> 无中断."""
        hart.csrs["stimecmp"].val = 100
        self.clint.tick(50)  # mtime = 50 < 100

        taken = hart.check_pending_interrupts()
        assert not taken
        assert hart.pc == 0x1000

    def test_sti_not_taken_stimecmp_zero(self, hart):
        """stimecmp == 0 -> 禁用定时器, 不触发中断."""
        hart.csrs["stimecmp"].val = 0
        self.clint.tick(100)

        taken = hart.check_pending_interrupts()
        assert not taken

    def test_sti_not_taken_sie_off(self, hart):
        """SIE=0 -> S 模式全局关中断, STI 被阻塞."""
        hart.csrs["stimecmp"].val = 50
        self.clint.tick(100)
        hart.mstatus_val = 0  # SIE=0

        taken = hart.check_pending_interrupts()
        assert not taken
        assert hart.pc == 0x1000

    def test_sti_not_taken_stie_off(self, hart):
        """mie[5] (STIE) = 0 -> 即使 STIP 挂起也不响应."""
        hart.csrs["stimecmp"].val = 50
        self.clint.tick(100)
        hart.csrs["mie"].val = 0  # 清除全部中断使能

        taken = hart.check_pending_interrupts()
        assert not taken

    # ---- 委派到 S-mode (来自 M/U 模式) ----

    def test_sti_delegated_from_umode(self, hart):
        """U 模式: mideleg[5]=1 -> STI 委派到 S 模式."""
        hart.csrs["stimecmp"].val = 50
        self.clint.tick(100)
        hart.mode = RiscvMode.U
        hart.csrs["mideleg"].val = 1 << 5  # 委派 STI
        # U 模式进入时需要有 SIE 使能
        hart.mstatus_val = MSTATUS_MIE | MSTATUS_SIE

        taken = hart.check_pending_interrupts()
        assert taken
        assert hart.pc == 0x80004000, "委派后应跳转到 stvec"
        assert hart.mode == RiscvMode.S
        assert self._cause_is_sti(hart.scause_val), (
            f"scause 应为 STI, 实际 {hart.scause_val:#018x}"
        )
        assert hart.sepc_val == 0x1000

    def test_sti_mip_stip_set(self, hart):
        """验证 mip.STIP 位在条件满足时被置位."""
        hart.csrs["stimecmp"].val = 30
        self.clint.tick(50)

        taken = hart.check_pending_interrupts()
        assert taken
        # mip bit 5 (STIP) 应被设置
        assert hart.mip_val & (1 << 5), "mip[5] (STIP) 应被置位"

    def test_sti_mip_stip_cleared_after_threshold_update(self, hart):
        """更新 stimecmp 到未来值后 STIP 应清除."""
        hart.csrs["stimecmp"].val = 30
        self.clint.tick(50)  # mtime >= 30 -> STIP set

        taken = hart.check_pending_interrupts()
        assert taken
        assert hart.mip_val & (1 << 5)

        # 在 trap handler 中: 写 stimecmp 到未来值
        hart.csrs["stimecmp"].val = 1000
        # 清除 mip.STIP (模拟 trap handler 中的 csrc sip, STIP)
        hart.mip_val &= ~(1 << 5)
        # 恢复 SIE (模拟 sret 后)
        hart.sie = True
        hart.pc = 0x1000

        # 下一次检查: stimecmp=1000 > mtime=50 -> 不应再触发
        taken2 = hart.check_pending_interrupts()
        assert not taken2, "stimecmp 已更新到未来值, STI 不应再次触发"


class TestStimecmpClintSync:
    """验证 stimecmp 与 CLINT mtimecmp 互相独立 (匹配 QEMU / 真实硬件).

    QEMU 验证: time_helper.c 中 riscv_timer_write_timecmp() 仅管理 STIP;
    riscv_aclint.c 中 riscv_aclint_mtimer_write_timecmp() 仅管理 MTIP.
    两者是完全独立的比较器。"""

    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        self.clint = CLINT(num_harts=1)
        return self.clint

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置 PC、S 模式与 CLINT."""
        hart.pc = 0x1000
        hart.mode = RiscvMode.S
        hart.interrupt_ctrl = self.clint
        return hart

    def test_stimecmp_independent_of_mtimecmp(self, hart):
        """写 stimecmp CSR 不影响 CLINT mtimecmp (独立比较器)."""
        # Set mtimecmp directly (simulating OpenSBI)
        self.clint.set_mtimecmp(0, 0xFFFF_FFFF_FFFF_FFFF)
        # Write stimecmp — must NOT overwrite mtimecmp
        hart.write_csr(0x14D, 0x12345_6789_ABCD)
        assert self.clint._mtimecmp[0] == 0xFFFF_FFFF_FFFF_FFFF, (
            "stimecmp 写入后 CLINT mtimecmp 应保持不变 (独立比较器)"
        )
        assert hart.csrs["stimecmp"].val == 0x12345_6789_ABCD, "stimecmp CSR 应正确存储写入值"

    def test_mtimecmp_independent_of_stimecmp(self, hart):
        """写 CLINT mtimecmp (MMIO) 不影响 stimecmp CSR."""
        hart.write_csr(0x14D, 0xAAAA_BBBB_CCCC_DDDD)
        self.clint.set_mtimecmp(0, 0xDEAD_BEEF)
        assert hart.csrs["stimecmp"].val == 0xAAAA_BBBB_CCCC_DDDD, (
            "CLINT mtimecmp 写入后 stimecmp 应保持不变 (独立比较器)"
        )

    def test_stimecmp_zero_does_not_affect_mtimecmp(self, hart):
        """stimecmp=0 不影响已设置的 mtimecmp."""
        self.clint.set_mtimecmp(0, 0x100)
        hart.write_csr(0x14D, 0)
        assert self.clint._mtimecmp[0] == 0x100, "stimecmp=0 写入后 mtimecmp 应保持不变"

    def test_clint_check_interrupt_uses_mtimecmp_not_stimecmp(self, hart):
        """CLINT.check_interrupt 的 MTIP 仅取决于 mtimecmp, 不取决于 stimecmp."""
        # Set stimecmp far in the "past" — MTIP should NOT fire
        hart.write_csr(0x14D, 100)
        self.clint.set_mtimecmp(0, 0xFFFFFFFF_FFFFFFFF)  # far future
        self.clint.tick(200)
        has, mip, _src = self.clint.check_interrupt(0)
        assert not (mip & (1 << 7)), "MTIP 仅取决于 CLINT mtimecmp; stimecmp 到期不应触发 MTIP"

    def test_stimecmph_write_merges_to_stimecmp(self, hart):
        """stimecmph (0x15D) 写入高 32 位合并到 stimecmp (RV64)."""
        # 先写低 32 位
        hart.write_csr(0x14D, 0xDEAD_BEEF)
        # 再写高 32 位
        hart.write_csr(0x15D, 0x1234_5678)
        expected = 0x1234_5678_DEAD_BEEF
        assert hart.csrs["stimecmp"].val == expected, (
            f"stimecmph 写入后 stimecmp 应为 {expected:#018x}"
        )


class TestSoftwareStipTimerFallback:
    """设备树未声明 sstc 时, 固件以 mtimecmp 与 mip.STIP 承担 S 模式定时器.

    M 模式在 mtimecmp 到期时置位 STIP 把定时器中断交给 S 模式, 并在重新装定
    mtimecmp 时清除该位. 该路径上 stimecmp 恒为 0, 定时器状态的同步不得清除
    软件写入的 STIP, 否则 S 模式定时器中断永不投递.
    """

    STI_CAUSE = 0x8000_0000_0000_0005
    CSR_MIP = 0x344
    CSR_STIMECMP = 0x14D
    CSR_STOPI = 0xDB0

    class StubImsic:
        """读取 stopi 路径使用的 IMSIC 替身, 其中没有挂起的中断."""

        def peek_topei(self, hart_id: int, view: str) -> int:
            return 0

    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        self.clint = CLINT(num_harts=1)
        return self.clint

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置陷态向量与 S 模式中断使能."""
        hart.csrs["mtvec"].val = MTVEC
        hart.csrs["stvec"].val = STVEC
        hart.pc = 0x8000_4000
        hart.mode = RiscvMode.S
        hart.mstatus_val = MSTATUS_SIE
        hart.csrs["mie"].val = 1 << 5  # STIE
        hart.csrs["mideleg"].val = 1 << 5  # 委派 STI
        hart.interrupt_ctrl = self.clint
        hart.csrs["stimecmp"].val = 0  # 未使用 sstc 定时器
        return hart

    def test_sync_keeps_software_stip(self, hart):
        """stimecmp 为 0 时 sync_pending_interrupts 保留软件写入的 STIP."""
        hart.mip_val |= 1 << 5
        self.clint.tick(100)
        hart.sync_pending_interrupts()
        assert hart.mip_val & (1 << 5), "stimecmp 为 0 时不得清除软件写入的 STIP"

    def test_sti_taken_from_software_stip(self, hart):
        """只有软件写入的 STIP 时, STI 仍投递到 S 模式."""
        hart.mip_val |= 1 << 5
        self.clint.tick(100)

        taken = hart.check_pending_interrupts()

        assert taken, "软件写入的 STIP 应触发 STI"
        assert hart.pc == STVEC, f"应跳转 stvec={STVEC:#x}, 实际 pc={hart.pc:#x}"
        assert hart.scause_val == self.STI_CAUSE, (
            f"scause 应为 STI ({self.STI_CAUSE:#018x}), 实际 {hart.scause_val:#018x}"
        )

    def test_armed_sstc_clears_software_stip(self, hart):
        """stimecmp 已装定且未到期时, STIP 由 sstc 定时器决定, 软件写入的该位被清除."""
        hart.mip_val |= 1 << 5
        hart.write_csr(self.CSR_STIMECMP, 1000)
        self.clint.tick(100)

        hart.sync_pending_interrupts()

        assert not (hart.mip_val & (1 << 5)), "sstc 定时器已装定且未到期, STIP 应清除"

    def test_stopi_reports_software_stip(self, hart):
        """stimecmp 为 0 时 stopi 仍报告 IID=5, 即 STI."""
        hart._imsic = self.StubImsic()
        hart.mip_val |= 1 << 5
        self.clint.tick(100)

        stopi = hart.read_csr(self.CSR_STOPI)

        iid = (stopi >> 16) & 0x7FF
        assert iid == 5, f"stopi 应报告 STI (5), 实际 IID={iid}"


class TestSipMipReadonlyMask:
    """验证 sip (0x144) / mip (0x344) 的可写位.

    与 sie 不同, sip 并非对所有 mideleg 委派位都可写: 唯一可写位是 SSIP (bit 1),
    STIP (bit 5) 由 SSTC 定时器、SEIP (bit 9) 由 PLIC 硬件驱动. 飞地上下文切换
    (csr_write(CSR_SIP, saved)) 写回陈旧 sip, 若把 SEIP/STIP 一并覆写会丢失挂起的
    外设/定时器中断 (飞地回归测试后输入冻结). mip 的 SSIP 与 STIP 均可写, 其余
    S 级位与 M 级位由硬件驱动."""

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置 PC 与 S 模式."""
        hart.pc = 0x1000
        hart.mode = RiscvMode.S
        return hart

    def test_csrw_sip_preserves_stip_and_seip(self, hart):
        """`csrw sip, 0` 只清除 SSIP, 保留硬件驱动的 STIP/SEIP."""
        hart.csrs["mideleg"].val = (1 << 5) | (1 << 9) | (1 << 1)  # STIP/SEIP/SSIP 委派
        hart.csrs["mip"].val = (1 << 5) | (1 << 9) | (1 << 1)
        hart.write_csr(0x144, 0)  # csrw sip, 0
        mip = hart.mip_val
        assert mip & (1 << 5), "STIP 由 SSTC 硬件驱动, 不得被 csrw sip 覆写"
        assert mip & (1 << 9), "SEIP 由 PLIC 硬件驱动, 不得被 csrw sip 覆写"
        assert not (mip & (1 << 1)), "SSIP 是 sip 唯一可写位, 应被清除"

    def test_csrw_mip_writes_stip_and_preserves_seip(self, hart):
        """`csrw mip, 0` 清除 SSIP 与 STIP, 保留硬件驱动的 SEIP."""
        hart.csrs["mip"].val = (1 << 5) | (1 << 9) | (1 << 1)
        hart.write_csr(0x344, 0)  # csrw mip, 0
        mip = hart.mip_val
        assert not (mip & (1 << 5)), "STIP 软件可写, 应被清除"
        assert mip & (1 << 9), "SEIP 由中断控制器驱动, 不得被 csrw mip 覆写"
        assert not (mip & (1 << 1)), "SSIP 软件可写, 应被清除"

    def test_csrw_mip_sets_stip(self, hart):
        """M 模式 `csrw mip` 置位 STIP, 供固件转交 S 模式定时器中断."""
        hart.csrs["mip"].val = 0
        hart.write_csr(0x344, 1 << 5)  # csrw mip, STIP
        assert hart.mip_val & (1 << 5), "STIP 可写, csrw mip 应置位该位"


class TestNestedInterruptCheck:
    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        self.clint = CLINT(num_harts=1)
        return self.clint

    @pytest.fixture
    def hart(self, hart) -> Hart:
        """通用 hart 之上设置陷态向量与 M 模式中断使能."""
        hart.csrs["mtvec"].val = MTVEC
        hart.csrs["stvec"].val = STVEC
        hart.pc = 0x8000_4000
        hart.mstatus_val = MSTATUS_MIE
        hart.interrupt_ctrl = self.clint
        return hart

    def test_missing_controller_reports_none(self, hart):
        assert not hart.check_pending_interrupts_nested_enabled()

    def test_idle_timer_is_cached_then_delivered(self, hart):
        """首次全量检查无中断, 之后命中缓存, 到期后投递."""
        self.clint.set_mtimecmp(0, 100)
        hart.csrs["mie"].val = 1 << 7
        self.clint.tick(50)
        assert not hart.check_pending_interrupts_nested_enabled()
        assert not hart.check_pending_interrupts_nested_enabled(), "第二次应命中缓存"

        self.clint.tick(50)
        assert hart.check_pending_interrupts_nested_enabled()
        assert hart.mcause_val == (1 << 63) | 7
        assert hart.pc == MTVEC

    def test_mmode_global_disable_blocks(self, hart):
        self.clint.send_ipi(0)
        hart.csrs["mie"].val = 1 << 3
        hart.mstatus_val = 0
        assert not hart.check_pending_interrupts_nested_enabled()

    def test_source_disable_blocks(self, hart):
        self.clint.set_mtimecmp(0, 50)
        self.clint.tick(100)
        hart.csrs["mie"].val = 0
        assert not hart.check_pending_interrupts_nested_enabled()

    def test_delegated_interrupt_needs_smode_global_enable(self, hart):
        self.clint.set_mtimecmp(0, 50)
        self.clint.tick(100)
        hart.csrs["mie"].val = 1 << 7
        hart.csrs["mideleg"].val = 1 << 7
        hart.mode = RiscvMode.S
        hart.mstatus_val = MSTATUS_MIE
        assert not hart.check_pending_interrupts_nested_enabled()

    def test_stimecmp_sets_stip(self, hart):
        """STIP 由 stimecmp 与 mtime 的比较结果给出."""
        self.clint.tick(100)
        hart.csrs["stimecmp"].val = 50
        hart.csrs["mie"].val = 1 << 5
        assert hart.check_pending_interrupts_nested_enabled()
        assert hart.mcause_val == (1 << 63) | 5

    def test_plic_pending_bit_is_delivered(self, hart):
        hart.plic = StubPlic(1 << 11)
        hart.csrs["mie"].val = 1 << 11
        assert hart.check_pending_interrupts_nested_enabled()
        assert hart.mcause_val == (1 << 63) | 11

    def test_imsic_pending_bit_is_delivered(self, hart):
        hart.imsic = StubImsic(1 << 9)
        hart.csrs["mie"].val = 1 << 9
        assert hart.check_pending_interrupts_nested_enabled()
        assert hart.mcause_val == (1 << 63) | 9

    def test_wfi_waiter_is_woken_by_nested_delivery(self, hart):
        self.clint.send_ipi(0)
        hart.csrs["mie"].val = 1 << 3
        hart._waiting = True
        assert hart.check_pending_interrupts_nested_enabled()
        assert not hart._waiting
        assert hart._wfi_woken


class TestSstcNotDeclared:
    """平台未声明 sstc 时 stimecmp 不存在, STIP 只取软件写入的 mip.STIP."""

    CSR_STIMECMP = 0x14D
    STI_CAUSE = (1 << 63) | 5

    @pytest.fixture(autouse=True)
    def clint(self) -> CLINT:
        self.clint = CLINT(num_harts=1)
        return self.clint

    @pytest.fixture
    def hart(self, hart) -> Hart:
        hart.ratified_hart_attrs = RatifiedHartAttrs(isa_exts={"i": True, "c": True})
        hart.csrs["mtvec"].val = MTVEC
        hart.csrs["stvec"].val = STVEC
        hart.pc = 0x8000_4000
        hart.csrs["mie"].val = 1 << 5
        hart.csrs["mideleg"].val = 1 << 5
        hart.interrupt_ctrl = self.clint
        return hart

    def test_stimecmp_write_rejected(self, hart):
        with pytest.raises(CsrAccessError):
            hart.validate_csr(self.CSR_STIMECMP, is_write=True)

    def test_stip_ignores_stimecmp_value(self, hart):
        """未声明 sstc 时, 内部残留的 stimecmp 取值不参与 STIP 的判定."""
        hart.csrs["stimecmp"].val = 50
        self.clint.tick(100)

        hart.sync_pending_interrupts()

        assert not (hart.mip_val & (1 << 5))

    def test_software_stip_still_delivered(self, hart):
        """软件写入的 mip.STIP 不受残留 stimecmp 影响, 仍投递到 S 模式."""
        hart.csrs["stimecmp"].val = 50
        self.clint.tick(100)
        hart.mip_val |= 1 << 5
        hart.mode = RiscvMode.S
        hart.mstatus_val = MSTATUS_SIE

        assert hart.check_pending_interrupts()

        assert hart.scause_val == self.STI_CAUSE
        assert hart.pc == STVEC
