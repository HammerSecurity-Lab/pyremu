#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""IPI delivery chain tests: cross-hart seteipnum -> SEIP -> stopi ->
claim -> clear.

Verifies the complete IMSIC IPI path at the Python level (no native batch),
then at the Emulator integration level.  Native batch is disabled by default
via conftest.py

CSR read/write: the hart's read_csr_by_name()/write_csr_by_name() methods
route AIA CSRs through the Python IMSIC backend.  CSR addresses:
  stopi  = 0xDB0  (combined S-level view, no auto-claim on read)
  stopei = 0x15C  (IMSIC S-file only, auto-claim on read)
  mtopi  = 0xFB0  (combined M-level view, no auto-claim on read)
  mtopei = 0x35C  (IMSIC M-file only, auto-claim on read)
"""

import pytest

from pyremu.core.hart import RiscvMode
from pyremu.emulator import Emulator
from pyremu.interrupt.imsic import IID_M_IPI, IID_S_IPI, IMSIC

# ============================================================
#  常量
# ============================================================

_IMSIC_M_BASE = 0x2400_0000
_PAGE_STRIDE = 0x1000
_EIPNUM_SET_OFF = 0x0000

# CSR addresses (RISC-V AIA spec)
_CSR_STOPEI = 0x15C
_CSR_MTOPEI = 0x35C
_CSR_MTOPI = 0xFB0
_CSR_STOPI = 0xDB0


# ============================================================
#  IMSIC 单元级: 完整的 IPI 生命周期 (与 Rust imsic.rs 逻辑一致)
# ============================================================


class TestIpiLifecycle:
    """Single-hart IPI lifecycle: set -> peek -> claim -> clear."""

    def test_ipi_set_peek_claim_clear(self):
        """S-file seteipnum(1) -> peek sees IID=1 -> claim clears eip."""
        imsic = IMSIC(num_harts=2, m_base_addr=_IMSIC_M_BASE)
        s_base = 2 * _PAGE_STRIDE  # N=2, S-files after M-files
        imsic.write(s_base + _EIPNUM_SET_OFF, (1).to_bytes(4, "little"))

        sf = imsic._file_for(0, "S")
        assert sf is not None
        assert sf.eip[0] & (1 << IID_S_IPI), "S-file eip[0] bit 1 should be set"

        peek = imsic.peek_topei(0, "S")
        assert peek != 0, f"peek_topei non-zero, got {peek}"
        assert ((peek >> 16) & 0x7FF) == IID_S_IPI

        # Claim via read_topei — clears eip
        claim = imsic.read_topei(0, "S")
        assert claim != 0
        assert imsic.peek_topei(0, "S") == 0, "after claim, peek should be 0"

    def test_peek_does_not_claim(self):
        """peek_topei should NOT clear eip — idempotent."""
        imsic = IMSIC(num_harts=1, m_base_addr=_IMSIC_M_BASE)
        s_base = 1 * _PAGE_STRIDE
        imsic.write(s_base + _EIPNUM_SET_OFF, (1).to_bytes(4, "little"))

        p1 = imsic.peek_topei(0, "S")
        p2 = imsic.peek_topei(0, "S")
        assert p1 == p2, "peek should be idempotent (no claim)"
        assert p1 != 0

    def test_eidelivery_zero_ipi_visible(self):
        """With eidelivery=0, IPI should still be visible via peek_topei."""
        imsic = IMSIC(num_harts=1, m_base_addr=_IMSIC_M_BASE)
        s_base = 1 * _PAGE_STRIDE
        imsic.write(s_base + _EIPNUM_SET_OFF, (1).to_bytes(4, "little"))
        assert imsic.peek_topei(0, "S") != 0
        assert imsic.get_pending_mip(0) & (1 << 9), "SEIP should be set"

    def test_mfile_ipi_stays_in_mfile(self):
        """M-file seteipnum + IID=1 -> stays in M-file
        (no cross-file routing)."""
        imsic = IMSIC(num_harts=2, m_base_addr=_IMSIC_M_BASE)
        imsic.write(
            0 * _PAGE_STRIDE, (1).to_bytes(4, "little")
        )  # M-file, IID=1

        mf = imsic._file_for(0, "M")
        assert mf is not None
        assert mf.eip[0] & (1 << IID_S_IPI), "M-file eip[0] bit 1 should be set"
        assert imsic.peek_topei(0, "M") != 0, "M-file should have pending IPI"
        assert imsic.peek_topei(0, "S") == 0, (
            "S-file should have no pending IPI"
        )

    def test_external_interrupt_blocked_without_eidelivery(self):
        """External IID blocked when eidelivery=0; IPI IIDs still visible."""
        imsic = IMSIC(num_harts=1, m_base_addr=_IMSIC_M_BASE)
        s_base = 1 * _PAGE_STRIDE
        # External IID=10 with eidelivery=0
        imsic.write(s_base + _EIPNUM_SET_OFF, (10).to_bytes(4, "little"))
        # Should NOT be visible — peek_topei blocks external IIDs
        # without eidelivery
        assert imsic.peek_topei(0, "S") == 0, (
            "external IID blocked without eidelivery"
        )
        assert imsic.get_pending_mip(0) == 0, (
            "external IID should not set SEIP with eidelivery=0"
        )

        # But IPI (IID=1) should still be visible via IPI fast-path
        imsic.write(s_base + _EIPNUM_SET_OFF, (1).to_bytes(4, "little"))
        assert imsic.peek_topei(0, "S") != 0, (
            "IPI visible even with eidelivery=0"
        )
        assert imsic.get_pending_mip(0) & (1 << 9), (
            "IPI should set SEIP via peek_topei fast-path"
        )


# ============================================================
#  跨 hart IPI (Python IMSIC 级别)
# ============================================================


class TestCrossHartIpi:
    """Cross-hart IPI delivery via IMSIC seteipnum."""

    def test_hart0_sends_ipi_to_hart1_sfile(self):
        """Write to hart 1's S-file seteipnum -> hart 1 sees IPI,
        hart 0 does not."""
        imsic = IMSIC(num_harts=2, m_base_addr=_IMSIC_M_BASE)
        s_base = 2 * _PAGE_STRIDE
        target = s_base + 1 * _PAGE_STRIDE + _EIPNUM_SET_OFF
        imsic.write(target, (1).to_bytes(4, "little"))

        assert imsic.peek_topei(1, "S") != 0, "Hart 1 sees IPI"
        assert imsic.peek_topei(0, "S") == 0, "Hart 0 unaffected"
        assert imsic.get_pending_mip(1) & (1 << 9), "Hart 1 SEIP set"

    def test_mfile_ipi_stays_in_target_mfile(self):
        """M-file seteipnum for hart 1 + IID=1 stays in hart 1's M-file."""
        imsic = IMSIC(num_harts=2, m_base_addr=_IMSIC_M_BASE)
        target = 1 * _PAGE_STRIDE + _EIPNUM_SET_OFF  # hart 1 M-file
        imsic.write(target, (1).to_bytes(4, "little"))

        mf_h1 = imsic._file_for(1, "M")
        assert mf_h1 is not None
        assert mf_h1.eip[0] & (1 << IID_S_IPI)
        assert imsic.get_pending_mip(1) & (1 << 11), "hart 1 MEIP should be set"

    def test_set_ip_number_all_harts_independent(self):
        """set_ip_number to hart 2 leaves harts 0,1,3 unaffected."""
        imsic = IMSIC(num_harts=4, m_base_addr=_IMSIC_M_BASE)
        imsic.set_ip_number(2, "S", IID_S_IPI)
        assert imsic.peek_topei(2, "S") != 0
        for h in (0, 1, 3):
            assert imsic.peek_topei(h, "S") == 0, f"Hart {h} unaffected"


# ============================================================
#  CSR 级别: hart.read_csr_by_name / write_csr_by_name
# ============================================================


class TestIpiCsrLevel:
    """Integration: hart CSR path for stopi / stopei / mtopi / mtopei.

    Native batch disabled by conftest.py -> CSR ops stay in Python.
    """

    # ---- stopi (0xDB0, S-mode combined view) ----

    def test_stopi_read_after_ipi(self, make_aia_emu):
        """stopi (0xDB0) read -> IID=9 (SEI); write stopi to claim ->
        next read returns 0."""
        emu = make_aia_emu(num_harts=2)
        imsic = emu.imsic
        h1 = emu.harts[1]
        h1.mode = RiscvMode.S
        assert imsic
        imsic.csr_write(1, "S", 0x70, 1)  # eidelivery=1
        imsic.set_ip_number(1, "S", IID_S_IPI)

        val = h1.read_csr(_CSR_STOPI)
        assert val != 0, f"stopi after IPI: expected non-zero, got {val}"
        iid = (val >> 16) & 0x7FF
        assert iid == 9, f"stopi IID: expected 9 (SEI), got {iid}"

        # Claim
        h1.write_csr(_CSR_STOPI, val)
        val2 = h1.read_csr(_CSR_STOPI)
        assert val2 == 0, f"stopi after claim: expected 0, got {val2}"

    def test_stopi_ipi_major_identity_is_sei_regression(self, make_aia_emu):
        """Regression: S-file IPI (minor 1) -> stopi returns
        major identity 9 (SEI).

        Linux 的 riscv_intc_aia_irq() 将 stopi>>16 分发给 intc domain。
        若 stopi 对 S-file IPI 返回 1 (SSI) 而非 9 (SEI)，IMSIC 模式下
        SSI 没有 handler，IPI 丢失，发送方 hart 卡死在
        smp_call_function_many_cond 等待目标 hart 应答。
        """
        emu = make_aia_emu(num_harts=2)
        imsic = emu.imsic
        h1 = emu.harts[1]
        h1.mode = RiscvMode.S
        assert imsic
        imsic.csr_write(1, "S", 0x70, 1)  # eidelivery=1
        imsic.set_ip_number(1, "S", IID_S_IPI)

        # stopi must report the MAJOR identity (SEI=9), not the minor (1).
        stopi = h1.read_csr(_CSR_STOPI)
        assert ((stopi >> 16) & 0x7FF) == 9, (
            f"stopi>>16 must be SEI (9) for the S-file IPI, "
            f"got {(stopi >> 16) & 0x7FF}"
        )

        # stopei must still reveal the MINOR identity (1 = IPI).
        stopei = h1.read_csr(_CSR_STOPEI)
        assert ((stopei >> 16) & 0x7FF) == IID_S_IPI, (
            f"stopei>>16 must be the minor IPI identity (1), "
            f"got {(stopei >> 16) & 0x7FF}"
        )

    def test_stopi_read_idempotent_no_auto_claim(self, make_aia_emu):
        """stopi read does NOT auto-claim —
        same IID returned on repeated reads."""
        emu = make_aia_emu(num_harts=1)
        imsic = emu.imsic
        h = emu.harts[0]
        h.mode = RiscvMode.S
        assert imsic
        imsic.csr_write(0, "S", 0x70, 1)
        imsic.set_ip_number(0, "S", IID_S_IPI)

        v1 = h.read_csr(_CSR_STOPI)
        v2 = h.read_csr(_CSR_STOPI)
        assert v1 == v2, "stopi read should be idempotent"
        assert v1 != 0

    def test_stopi_zero_when_no_interrupts(self, make_aia_emu):
        """stopi returns 0 when no interrupts are pending."""
        emu = make_aia_emu(num_harts=1)
        h = emu.harts[0]
        h.mode = RiscvMode.S
        h.mip_val = 0
        h.csrs["mie"].val = 0

        val = h.read_csr(_CSR_STOPI)
        assert val == 0, f"stopi with no interrupts should be 0, got {val}"

    # ---- stopei (0x15C, IMSIC S-file only, auto-claim on read) ----

    def test_stopei_read_auto_claims(self, make_aia_emu):
        """stopei (0x15C) read auto-claims: second read returns 0."""
        emu = make_aia_emu(num_harts=1)
        imsic = emu.imsic
        h = emu.harts[0]
        h.mode = RiscvMode.S
        assert imsic
        imsic.csr_write(0, "S", 0x70, 1)  # eidelivery=1
        imsic.set_ip_number(0, "S", IID_S_IPI)

        v1 = h.read_csr(_CSR_STOPEI)
        assert v1 != 0, f"first stopei: expected non-zero, got {v1}"
        v2 = h.read_csr(_CSR_STOPEI)
        assert v2 == 0, f"second stopei (auto-claimed): expected 0, got {v2}"

    # ---- mtopi (0xFB0, M-mode combined view) ----

    def test_mtopi_read_after_mfile_ipi(self, make_aia_emu):
        """mtopi (0xFB0) sees IID=11 (MEI) for M-mode IPI (minor 3)."""
        emu = make_aia_emu(num_harts=1)
        imsic = emu.imsic
        h = emu.harts[0]
        h.mode = RiscvMode.M
        assert imsic
        imsic.csr_write(0, "M", 0x70, 1)  # eidelivery=1
        imsic.set_ip_number(0, "M", IID_M_IPI)

        val = h.read_csr(_CSR_MTOPI)
        iid = (val >> 16) & 0x7FF
        assert iid == 11, f"mtopi: expected IID=11 (MEI), got {iid}"

    # ---- mtopei (0x35C, IMSIC M-file only, auto-claim on read) ----

    def test_mtopei_read_auto_claims(self, make_aia_emu):
        """mtopei (0x35C) read auto-claims IMSIC M-file."""
        emu = make_aia_emu(num_harts=1)
        imsic = emu.imsic
        h = emu.harts[0]
        h.mode = RiscvMode.M

        assert imsic
        imsic.csr_write(0, "M", 0x70, 1)
        imsic.set_ip_number(0, "M", IID_M_IPI)
        v1 = h.read_csr(_CSR_MTOPEI)
        assert v1 != 0
        v2 = h.read_csr(_CSR_MTOPEI)
        assert v2 == 0, "mtopei auto-claim: second read should be 0"

    # ---- Integration: IPI -> trap ----

    def test_ipi_raises_seip_trap(self, make_aia_emu):
        """set_ip_number -> check_pending_interrupts fires for target hart."""

        emu = make_aia_emu(num_harts=2)
        imsic = emu.imsic
        h1 = emu.harts[1]
        h1.mode = RiscvMode.S

        # mie CSR (interrupt enable), not mstatus.MIE (global enable)
        h1.csrs["mie"].val = 1 << 9  # SEIE
        assert h1.mie_val & (1 << 9), "SEIE should be set in mie CSR"
        assert imsic
        imsic.set_ip_number(1, "S", IID_S_IPI)

        # check_pending_interrupts returns True if a trap was delivered
        result = h1.check_pending_interrupts()
        assert result, "check_pending_interrupts should deliver SEI trap"

        # After delivery, mcause should reflect SEI
        mcause = h1.csrs["mcause"].val
        assert (mcause & 0x7FFFFFFFFFFFFFFF) == 9, (
            f"mcause should be 9 (SEI), got {mcause}"
        )


# ============================================================
#  CSR 状态一致性 (eidelivery / eie / eip 通过 CSR 读写)
# ============================================================


class TestCsrStateConsistency:
    """IMSIC register readback through CSR indirect access."""

    def test_eidelivery_roundtrip(self):
        """miselect=0x70 -> mireg write 1 -> mireg read 1."""
        imsic = IMSIC(num_harts=1, m_base_addr=_IMSIC_M_BASE)
        imsic.csr_write(0, "M", 0x70, 1)
        assert imsic.csr_read(0, "M", 0x70) == 1

        imsic.csr_write(0, "S", 0x70, 1)
        assert imsic.csr_read(0, "S", 0x70) == 1

    def test_eie_roundtrip_through_csr(self):
        """miselect=0xC0 -> mireg write -> mireg read."""
        imsic = IMSIC(num_harts=1, m_base_addr=_IMSIC_M_BASE)
        imsic.csr_write(0, "M", 0xC0, 0xDEAD)
        assert imsic.csr_read(0, "M", 0xC0) == 0xDEAD

    def test_eip_visible_through_csr_after_seteipnum(self):
        """seteipnum -> eip visible via mireg read."""
        imsic = IMSIC(num_harts=1, m_base_addr=_IMSIC_M_BASE)
        imsic.csr_write(0, "M", 0x70, 1)  # eidelivery=1
        imsic.set_ip_number(0, "M", 3)

        val = imsic.csr_read(0, "M", 0x80)  # eip[0]
        assert val & (1 << 3), f"eip bit 3 should be visible, got {val:#x}"

    def test_eie_controls_external_interrupt_visibility(self):
        """External interrupt needs eie: topei returns 0 when eie bit is
        clear."""
        imsic = IMSIC(num_harts=1, m_base_addr=_IMSIC_M_BASE)
        imsic.csr_write(0, "M", 0x70, 1)  # eidelivery=1
        imsic.set_ip_number(0, "M", 10)  # external IID=10

        # eie[0] bit 10 is clear -> peek_topei should return 0
        assert imsic.peek_topei(0, "M") == 0, "external IID blocked without eie"

        # Set eie for bit 10
        imsic.csr_write(0, "M", 0xC0, 1 << 10)
        assert imsic.peek_topei(0, "M") != 0, (
            "external IID visible with eie set"
        )


# ============================================================
#  DTB 布局验证: IMSIC 地址解码一致性
# ============================================================


class TestImsicAddressing:
    """IMSIC MMIO 地址解码: DTB reg 与 decode_imsic_addr 一致."""

    def test_mfile_offset_maps_to_correct_hart(self):
        """M-file offset = hart_id * 0x1000 -> correct (hart_id, M-file)."""
        imsic = IMSIC(num_harts=4, m_base_addr=_IMSIC_M_BASE)
        # _resolve maps MMIO offset -> (hart_id, file, file_off)
        for h in range(4):
            off = h * _PAGE_STRIDE
            resolved = imsic._resolve(off)
            assert resolved is not None
            hart_id, file, file_off = resolved
            assert hart_id == h, (
                f"offset {off:#x} -> hart {hart_id}, expected {h}"
            )
            assert file_off == 0, (
                f"offset {off:#x} -> file_off {file_off}, expected 0"
            )

    def test_sfile_offset_maps_to_correct_hart(self):
        """S-file offset = N*0x1000 + hart_id * 0x1000 ->
        correct (hart_id, S-file)."""
        num_harts = 4
        imsic = IMSIC(num_harts=num_harts, m_base_addr=_IMSIC_M_BASE)
        for h in range(num_harts):
            off = num_harts * _PAGE_STRIDE + h * _PAGE_STRIDE
            resolved = imsic._resolve(off)
            assert resolved is not None
            hart_id, file, file_off = resolved
            assert hart_id == h, (
                f"S-file offset {off:#x} -> hart {hart_id}, expected {h}"
            )
            assert file_off == 0


# ============================================================
#  多 hart 间 IPI: Emulator 级投递与 trap 上下文
# ============================================================


class TestEmulatorIPI:
    """多 hart 间 IPI (核间中断) — 参数化 hart 数量, 多目标同时接收."""

    @staticmethod
    def _ipi_targets(num_harts: int, max_targets: int = 3):
        """返回应开启中断的 target hart 列表 (跳过 hart 0)."""
        return list(range(1, min(num_harts, max_targets + 1)))

    # fmt: off
    @pytest.mark.parametrize("num_harts", [4, 8, 9, 10, 12, 16])
    # fmt: on
    def test_ipi_pending_detection(self, num_harts: int):
        """CLINT send_ipi -> 多个目标 hart 同时检测到待处理 MSIP."""
        emu = Emulator(
            num_harts=num_harts,
            prog_cnt=0x1000,
            ram_base=0,
            ram_size=0x6000,
        )
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 10)

        targets = self._ipi_targets(num_harts)
        assert len(targets) >= 2, f"需要至少 2 个 target, num_harts={num_harts}"

        for tid in targets:
            emu.harts[tid].mie = True
            emu.harts[tid].csrs["mie"].val = 1 << 3  # MSIE
            emu.harts[tid].csrs["mtvec"].val = 0x80000000

        # 向所有 target hart 发送 IPI
        for tid in targets:
            emu.clint.send_ipi(tid)

        # 每个 target 都应检测到 MSIP
        for tid in targets:
            interrupted = emu.harts[tid].check_pending_interrupts()
            assert interrupted, (
                f"hart {tid} 应检测到 MSIP "
                f"(num_harts={num_harts})"
            )

        # hart 0 未开启 MSIE, check 应返回 False (中断不使能)
        emu.harts[0].mie = True
        emu.harts[0].csrs["mie"].val = 0  # 无任何使能位
        assert not emu.harts[0].check_pending_interrupts(), (
            f"hart 0 未使能 MSIE, 不应检测到中断 (num_harts={num_harts})"
        )

    # fmt: off
    @pytest.mark.parametrize("num_harts", [4, 8, 9, 10, 12, 16])
    # fmt: on
    def test_ipi_diverges_hart_pc(self, num_harts: int):
        """多目标 hart 收到 IPI 后跳转 mtvec; 未开启中断的 hart 正常推进 PC."""
        emu = Emulator(
            num_harts=num_harts,
            prog_cnt=0x1000,
            ram_base=0,
            ram_size=0x6000,
        )
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 10)

        for h in emu.harts:
            assert h.pc == 0x1000

        targets = self._ipi_targets(num_harts)
        for tid in targets:
            emu.harts[tid].mie = True
            emu.harts[tid].csrs["mie"].val = 1 << 3
            emu.harts[tid].csrs["mtvec"].val = 0x80000000

        for tid in targets:
            emu.clint.send_ipi(tid)

        emu.step()

        # targets: PC 应跳转到 mtvec
        for tid in targets:
            assert emu.harts[tid].pc == 0x80000000, (
                f"hart {tid} 应跳转到 mtvec (num_harts={num_harts}), "
                f"PC={emu.harts[tid].pc:#x}"
            )

        # hart 0 (未开启中断): PC 正常 +4
        assert emu.harts[0].pc == 0x1004, (
            f"hart 0 应正常推进 PC (num_harts={num_harts})"
        )

        # 编号最大的非 target hart (若存在): PC 也应正常 +4
        non_target = targets[-1] + 1
        if non_target < num_harts:
            assert emu.harts[non_target].pc == 0x1004, (
                f"hart {non_target} (非 target) 应正常推进 PC "
                f"(num_harts={num_harts})"
            )

    # fmt: off
    @pytest.mark.parametrize("num_harts", [4, 8, 9, 10, 12, 16])
    # fmt: on
    def test_ipi_causes_trap_context_save(self, num_harts: int):
        """多 target 同时收 IPI, 每个 hart 的 mepc/mcause/MIE 独立正确."""
        emu = Emulator(
            num_harts=num_harts,
            prog_cnt=0x1000,
            ram_base=0,
            ram_size=0x6000,
        )
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 10)

        targets = self._ipi_targets(num_harts)
        saved_pcs = {}
        for tid in targets:
            h = emu.harts[tid]
            h.mie = True
            h.csrs["mie"].val = 1 << 3
            h.csrs["mtvec"].val = 0x80000000
            saved_pcs[tid] = h.pc  # 0x1000

        for tid in targets:
            emu.clint.send_ipi(tid)

        emu.step()

        for tid in targets:
            h = emu.harts[tid]
            next_pc = saved_pcs[tid] + 4  # 0x1004
            assert h.mepc_val == next_pc, (
                f"hart {tid}: mepc 应={next_pc:#x}, 实际={h.mepc_val:#x}"
            )
            assert h.mie is False, f"hart {tid}: 进入 trap 后 MIE 应清零"
            assert (h.mcause_val >> 63) & 1 == 1, (
                f"hart {tid}: mcause bit63 应置位 (中断)"
            )
            assert (h.mcause_val & ~(1 << 63)) == 3, (
                f"hart {tid}: mcause code 应为 3 (MSI)"
            )

        # hart 0 没有中断使能, 不应 trap
        assert emu.harts[0].mcause_val == 0, (
            f"hart 0 不应 trap (num_harts={num_harts})"
        )
