#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""基础整数运算: 除零、溢出与位宽规范化."""

import pytest

from pyremu.core.decoder import Hart
from pyremu.emulator import Emulator
from pyremu.memory.bus import Bus
from pyremu.utils.mask import mask64
from tests.instr_encode import i_type, pack_funct, pack_src_regs, r_type


class TestMDivideByZero:
    """验证 DIV/DIVU/REM/REMU 在除数为零时的行为.

    RISC-V 特权架构规定:
    - DIV[U] 除零 -> 返回 −1 (所有位为 1)
    - REM[U] 除零 -> 返回被除数 (dividend)
    不触发异常.
    """

    @pytest.fixture
    def emu(self) -> Emulator:
        return Emulator(
            num_harts=1, ram_base=0, ram_size=0x2000, prog_cnt=0x1000
        )

    def _exec_rtype(self, emu, funct: int, rd: int, src_regs: int):
        """执行一条 R-type 指令并返回目标寄存器结果.

        funct 为 funct7 与 funct3 打包后的取值,
        src_regs 为 rs1 与 rs2 打包后的取值.
        """
        h = emu.harts[0]
        h.exec_instr(r_type(0b0110011, rd, funct, src_regs))
        return h.gprs[rd]

    def test_div_by_zero(self, emu):
        """DIV x5, x10, x0 (divisor=0) -> x5 = -1."""
        emu.harts[0].gprs[10] = 42
        result = self._exec_rtype(
            emu, pack_funct(1, 4), 5, pack_src_regs(10, 0)
        )
        assert result == 0xFFFF_FFFF_FFFF_FFFF, f"应为 -1, 实际 {result:#x}"

    def test_divu_by_zero(self, emu):
        """DIVU x5, x10, x0 -> x5 = -1 (all-1s)."""
        emu.harts[0].gprs[10] = 0x8000_0000_0000_0000
        result = self._exec_rtype(
            emu, pack_funct(1, 5), 5, pack_src_regs(10, 0)
        )
        assert result == 0xFFFF_FFFF_FFFF_FFFF

    def test_rem_by_zero(self, emu):
        """REM x5, x10, x0 -> x5 = x10 (dividend)."""
        emu.harts[0].gprs[10] = 42
        result = self._exec_rtype(
            emu, pack_funct(1, 6), 5, pack_src_regs(10, 0)
        )
        assert result == 42

    def test_remu_by_zero(self, emu):
        """REMU x5, x10, x0 -> x5 = x10."""
        emu.harts[0].gprs[10] = 0xDEAD
        result = self._exec_rtype(
            emu, pack_funct(1, 7), 5, pack_src_regs(10, 0)
        )
        assert result == 0xDEAD

    def test_div_normal(self, emu):
        """DIV x5, x10, x2 (10 / 3 = 3)."""
        emu.harts[0].gprs[10] = 10
        emu.harts[0].gprs[2] = 3
        result = self._exec_rtype(
            emu, pack_funct(1, 4), 5, pack_src_regs(10, 2)
        )
        assert result == 3

    def test_rem_normal(self, emu):
        """REM x5, x10, x2 (10 % 3 = 1)."""
        emu.harts[0].gprs[10] = 10
        emu.harts[0].gprs[2] = 3
        result = self._exec_rtype(
            emu, pack_funct(1, 6), 5, pack_src_regs(10, 2)
        )
        assert result == 1


class TestAluEdgeCases:
    """
    ALU boundary tests:
        shift truncation,
        INT64_MAX/MIN arithmetic,
        zero-sub,
        wrap,
        DIV overflow.
    """

    INT64_MAX = 0x7FFF_FFFF_FFFF_FFFF
    INT64_MIN = 0x8000_0000_0000_0000
    UINT64_MAX = 0xFFFF_FFFF_FFFF_FFFF

    # -- helpers --

    @pytest.fixture
    def h(self):
        bus = Bus(ram_size=0x10000, ram_base=0x80000000)
        hart = Hart(id=0)
        hart.mem_read_phy = bus.read
        hart.mem_write_phy = bus.write
        hart.bus = bus
        hart.pc = 0x80000000
        return hart

    @staticmethod
    def _exec(hart, instr: int):
        """执行一条指令并返回其目的寄存器的取值."""
        advance = hart.exec_instr(instr)
        if advance:
            hart.pc = mask64(hart.pc + advance)
        return hart.gprs[(instr >> 7) & 0x1F]

    @staticmethod
    def _exec_r(hart, funct7: int, src_regs: int, funct3: int, rd: int):
        """执行一条 R-type 指令; src_regs 为 rs1 与 rs2 打包后的取值."""
        instr = r_type(0b0110011, rd, pack_funct(funct7, funct3), src_regs)
        return TestAluEdgeCases._exec(hart, instr)

    # ============================================================
    #  shift by 64 -- shamt[5:0] = 0, same as shift by 0
    # ============================================================

    # fmt: off
    @pytest.mark.parametrize("funct6,funct3,desc", [
        (0b000000, 0b001, "SLLI"),
        (0b000000, 0b101, "SRLI"),
        (0b010000, 0b101, "SRAI"),
    ])
    # fmt: on
    def test_shift_by_64_is_nop(self, h, funct6, funct3, desc):
        """Shift by 64: shamt[5:0]=0, acts as NOP."""
        val = 0xABCD_0000_1234_5678
        h.gprs[10] = val
        imm12 = (funct6 << 6) | 64
        self._exec(h, i_type(0b0010011, 10, funct3, 10, imm12))
        assert h.gprs[10] == val, f"{desc} shamt=64 should be NOP"

    def test_sll_rtype_shift_by_64_is_nop(self, h):
        """SLL (R-type): rs2=64, rs2[5:0]=0 means no shift."""
        val = 0xDEAD_BEEF_CAFE_BABE
        h.gprs[10] = val
        h.gprs[11] = 64
        self._exec_r(h, 0, pack_src_regs(10, 11), 0b001, 10)  # SLL
        assert h.gprs[10] == val

    # ============================================================
    #  ADD/SUB wrap-around
    # ============================================================

    def test_uint64_max_add_1_wraps_to_zero(self, h):
        """UINT64_MAX + 1 = 0 (wrap)."""
        h.gprs[10] = TestAluEdgeCases.UINT64_MAX
        h.gprs[11] = 1
        result = self._exec_r(h, 0, pack_src_regs(10, 11), 0b000, 10)  # ADD
        assert result == 0, f"UINT64_MAX + 1 should be 0, got 0x{result:x}"

    def test_zero_sub_1_wraps_to_uint64_max(self, h):
        """0 - 1 = UINT64_MAX (SUB wrap)."""
        h.gprs[10] = 0
        h.gprs[11] = 1
        result = self._exec_r(
            h, 0b0100000, pack_src_regs(10, 11), 0b000, 10
        )  # SUB
        assert result == TestAluEdgeCases.UINT64_MAX, (
            f"0 - 1 should be UINT64_MAX, got 0x{result:x}"
        )

    # ============================================================
    #  INT64_MAX boundary
    # ============================================================

    def test_int64_max_add_self(self, h):
        """INT64_MAX + INT64_MAX = 0xFFFFFFFFFFFFFFFE (wraps)."""
        val = TestAluEdgeCases.INT64_MAX
        h.gprs[10] = val
        h.gprs[11] = val
        result = self._exec_r(h, 0, pack_src_regs(10, 11), 0b000, 10)
        assert result == 0xFFFF_FFFF_FFFF_FFFE, (
            f"INT64_MAX + INT64_MAX expected 0xFFFFFFFFFFFFFFFE, "
            f"got 0x{result:x}"
        )

    def test_int64_max_add_1_overflows_to_int64_min(self, h):
        """INT64_MAX + 1 = INT64_MIN (signed overflow wrap)."""
        h.gprs[10] = TestAluEdgeCases.INT64_MAX
        h.gprs[11] = 1
        result = self._exec_r(h, 0, pack_src_regs(10, 11), 0b000, 10)
        assert result == TestAluEdgeCases.INT64_MIN, (
            f"INT64_MAX + 1 should be INT64_MIN, got 0x{result:x}"
        )

    def test_int64_max_mul_self(self, h):
        """INT64_MAX * INT64_MAX: low 64 = 1,
        MULH high 64 = 0x3FFFFFFFFFFFFFFF."""
        val = TestAluEdgeCases.INT64_MAX
        h.gprs[10] = val
        h.gprs[11] = val
        result_lo = self._exec_r(h, 1, pack_src_regs(10, 11), 0b000, 10)  # MUL
        assert result_lo == 1, (
            f"INT64_MAX^2 lo64 should be 1, got 0x{result_lo:x}"
        )
        h.gprs[10] = val
        result_hi = self._exec_r(h, 1, pack_src_regs(10, 11), 0b001, 10)  # MULH
        assert result_hi == 0x3FFF_FFFF_FFFF_FFFF, (
            f"INT64_MAX^2 hi64 should be 0x3FFFFFFFFFFFFFFF, "
            f"got 0x{result_hi:x}"
        )

    # ============================================================
    #  INT64_MIN boundary
    # ============================================================

    def test_int64_min_add_self_wraps_to_zero(self, h):
        """INT64_MIN + INT64_MIN = 0 (wraps)."""
        val = TestAluEdgeCases.INT64_MIN
        h.gprs[10] = val
        h.gprs[11] = val
        result = self._exec_r(h, 0, pack_src_regs(10, 11), 0b000, 10)
        assert result == 0, (
            f"INT64_MIN + INT64_MIN should be 0, got 0x{result:x}"
        )

    def test_int64_min_sub_1(self, h):
        """INT64_MIN - 1 = INT64_MAX."""
        h.gprs[10] = TestAluEdgeCases.INT64_MIN
        h.gprs[11] = 1
        result = self._exec_r(h, 0b0100000, pack_src_regs(10, 11), 0b000, 10)
        assert result == TestAluEdgeCases.INT64_MAX, (
            f"INT64_MIN - 1 should be INT64_MAX, got 0x{result:x}"
        )

    def test_int64_min_mul_self(self, h):
        """INT64_MIN * INT64_MIN: low 64 = 0, MULH = 0x4000000000000000."""
        val = TestAluEdgeCases.INT64_MIN
        h.gprs[10] = val
        h.gprs[11] = val
        result_lo = self._exec_r(h, 1, pack_src_regs(10, 11), 0b000, 10)
        assert result_lo == 0, (
            f"INT64_MIN^2 lo64 should be 0, got 0x{result_lo:x}"
        )
        h.gprs[10] = val
        result_hi = self._exec_r(h, 1, pack_src_regs(10, 11), 0b001, 10)
        assert result_hi == 0x4000_0000_0000_0000, (
            f"INT64_MIN^2 hi64 should be 0x4000000000000000, "
            f"got 0x{result_hi:x}"
        )

    # ============================================================
    #  DIV overflow -- INT64_MIN / -1
    # ============================================================

    def test_div_overflow_int64_min_div_neg1(self, h):
        """INT64_MIN / -1 overflows; RISC-V spec returns dividend."""
        h.gprs[10] = TestAluEdgeCases.INT64_MIN
        h.gprs[11] = TestAluEdgeCases.UINT64_MAX  # -1
        result = self._exec_r(h, 1, pack_src_regs(10, 11), 0b100, 10)  # DIV
        assert result == TestAluEdgeCases.INT64_MIN, (
            f"INT64_MIN / -1 overflow should return INT64_MIN, got 0x{result:x}"
        )

    def test_rem_int64_min_rem_neg1(self, h):
        """INT64_MIN % -1 = 0 (remainder of overflow is 0 per spec)."""
        h.gprs[10] = TestAluEdgeCases.INT64_MIN
        h.gprs[11] = TestAluEdgeCases.UINT64_MAX  # -1
        result = self._exec_r(h, 1, pack_src_regs(10, 11), 0b110, 10)  # REM
        assert result == 0, f"INT64_MIN % -1 should be 0, got 0x{result:x}"

    # ============================================================
    #  32-bit word ops -- ADDIW / SLLIW truncation + sign-extend
    # ============================================================

    def test_addiw_sign_extends_negative(self, h):
        """ADDIW: 0x7FFFFFFF + 1 = 0xFFFFFFFF80000000 (sign-extended)."""
        h.gprs[10] = 0x7FFF_FFFF
        instr = (1 << 20) | (10 << 15) | (0b000 << 12) | (10 << 7) | 0b0011011
        advance = h.exec_instr(instr)
        if advance:
            h.pc = (h.pc + advance) & 0xFFFF_FFFF_FFFF_FFFF
        assert h.gprs[10] == 0xFFFF_FFFF_8000_0000, (
            f"ADDIW: expected 0xFFFFFFFF80000000, got 0x{h.gprs[10]:016x}"
        )

    def test_slliw_shamt_0_truncates_32bit(self, h):
        """SLLIW shamt=0: truncates to 32-bit, sign-extends to 64."""
        h.gprs[10] = 0xABCD_0000_8765_4321  # bit31=1 -> negative
        instr = (
            (0 << 25)
            | (0 << 20)
            | (10 << 15)
            | (0b001 << 12)
            | (10 << 7)
            | 0b0011011
        )
        advance = h.exec_instr(instr)
        if advance:
            h.pc = (h.pc + advance) & 0xFFFF_FFFF_FFFF_FFFF
        expected = 0xFFFF_FFFF_8765_4321
        assert h.gprs[10] == expected, (
            f"SLLIW: expected 0x{expected:016x}, got 0x{h.gprs[10]:016x}"
        )


class TestRegValueCanonicalization:
    """回归: 不同指令路径产生的相同 64-bit 值必须在 Python 中 == 相等.

    SLLIW 通过 _sext 返回负 Python int 时, 与 LUI+ADDI 产生的正 64-bit 值
    在 Python == 比较中不相等, 导致 BEQ/BNE 误判. 此测试验证修复.
    """

    @pytest.fixture
    def h(self):
        bus = Bus(ram_size=0x10000, ram_base=0x80000000)
        hart = Hart(id=0)
        hart.mem_read_phy = bus.read
        hart.mem_write_phy = bus.write
        hart.bus = bus
        hart.pc = 0x80000000
        return hart

    # -- helpers --

    @staticmethod
    def _addi(rd, rs1, imm12):
        return (
            (imm12 << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b0010011
        )

    @staticmethod
    def _slliw(rd, rs1, shamt):
        """slliw rd, rs1, shamt — RV64 32-bit word shift left."""
        return (
            (0b0000000 << 25)  # funct7
            | (shamt << 20)  # 5-bit shamt
            | (rs1 << 15)
            | (0b001 << 12)  # funct3
            | (rd << 7)
            | 0b0011011  # opcode OP-IMM32
        )

    @staticmethod
    def _slli(rd, rs1, shamt):
        return (
            (0b000000 << 26)
            | (shamt << 20)
            | (rs1 << 15)
            | (0b001 << 12)
            | (rd << 7)
            | 0b0010011
        )

    @staticmethod
    def _or(rd, rs1, rs2):
        return (rs2 << 20) | (rs1 << 15) | (0b110 << 12) | (rd << 7) | 0b0110011

    @staticmethod
    def _lui(rd, imm20):
        return (imm20 << 12) | (rd << 7) | 0b0110111

    @staticmethod
    def _beq(rs1, rs2, offset_imm):
        """beq rs1, rs2, offset — B-type."""
        # B-type immediate encoding
        imm = offset_imm & 0x1FFF  # 13-bit signed
        b_imm = (
            ((imm >> 12) & 1) << 31
            | ((imm >> 5) & 0x3F) << 25
            | (rs2 << 20)
            | (rs1 << 15)
            | (0b000 << 12)
            | ((imm >> 1) & 0xF) << 8
            | ((imm >> 11) & 1) << 7
            | 0b1100011
        )
        return b_imm

    @staticmethod
    def _bne(rs1, rs2, offset_imm):
        imm = offset_imm & 0x1FFF
        b_imm = (
            ((imm >> 12) & 1) << 31
            | ((imm >> 5) & 0x3F) << 25
            | (rs2 << 20)
            | (rs1 << 15)
            | (0b001 << 12)
            | ((imm >> 1) & 0xF) << 8
            | ((imm >> 11) & 1) << 7
            | 0b1100011
        )
        return b_imm

    def _exec(self, hart, instr):
        """Execute one instruction and advance PC if the handler didn't."""
        saved_pc = hart.pc
        advance = hart.exec_instr(instr)
        # If handler returned an advance (not 0), increment PC.
        # The handler may have already changed PC (branches/jumps); if so,
        # advance is 0 and we don't touch PC.
        if advance != 0 and hart.pc == saved_pc:
            hart.pc = (saved_pc + advance) & 0xFFFF_FFFF_FFFF_FFFF

    # -- tests --

    def test_slliw_produces_64bit_canonical(self, h):
        """SLLIW 结果应为规范化的 64-bit 无符号值, 不是负 Python int."""
        # 模拟固件中 slliw a1, a1, 24 的操作 (a1 = 0xd0)
        h.gprs[11] = 0xD0
        self._exec(h, self._slliw(11, 11, 24))
        result = h.gprs[11]
        # 硬件上应为 0xFFFFFFFFD0000000 (64-bit unsigned)
        assert result == 0xFFFFFFFFD0000000, (
            f"slliw result: {result:#018x}, expected 0xffffffffd0000000"
        )
        # 关键回归: 结果必须是规范化的 64-bit 值 (非负 Python int)
        assert result >= 0, f"slliw produced negative value: {result}"
        assert result < (1 << 64), f"slliw produced overflow: {result}"

    def test_slliw_and_lui_produce_equal_values(self, h):
        """通过 SLLIW+OR 组合和 LUI+ADDI 构建相同值, 必须 == 相等."""
        # 路径 1: 模拟固件中构造 0xFFFFFFFFD00DFEED 的 SLLIW 路径
        h.gprs[11] = 0xD0
        self._exec(h, self._slliw(11, 11, 24))  # a1 = 0xFFFFFFFFD0000000
        h.gprs[12] = 0x0D
        self._exec(h, self._slli(12, 12, 16))  # a2 = 0x0D0000
        self._exec(h, self._or(13, 12, 11))  # a3 = a2 | a1 = 0xFFFFFFFFD00D0000
        h.gprs[14] = 0xFE
        self._exec(h, self._slli(14, 14, 8))  # a4 = 0xFE00
        self._exec(h, self._addi(14, 14, 0xED))  # a4 = 0xFEED (a4 = a4 + 0xED)
        self._exec(h, self._or(15, 13, 14))  # a5 = 0xFFFFFFFFD00DFEED
        via_slliw = h.gprs[15]

        # 路径 2: 通过 LUI+ADDI 构建同一值
        self._exec(h, self._lui(16, 0xD00E0))  # a6 = 0xFFFFFFFFD00E0000
        self._exec(h, self._addi(16, 16, -0x113))  # a6 = 0xFFFFFFFFD00DFEED
        via_lui = h.gprs[16]

        assert via_slliw == via_lui, (
            f"via SLLIW: {via_slliw:#018x}, via LUI: {via_lui:#018x}"
        )

    def test_beq_with_values_from_different_paths(self, h):
        """BEQ 应正确判定不同路径构建的相等值."""
        # 构建 0xFFFFFFFFD00DFEED 通过 SLLIW 路径
        h.gprs[11] = 0xD0
        self._exec(h, self._slliw(11, 11, 24))
        h.gprs[12] = 0x0D
        self._exec(h, self._slli(12, 12, 16))
        self._exec(h, self._or(13, 12, 11))
        h.gprs[14] = 0xFE
        self._exec(h, self._slli(14, 14, 8))
        self._exec(h, self._addi(14, 14, 0xED))
        self._exec(h, self._or(15, 13, 14))

        # 构建相同值通过 LUI 路径
        self._exec(h, self._lui(16, 0xD00E0))
        self._exec(h, self._addi(16, 16, -0x113))

        # BEQ x15, x16, +8 (跳过下一条, 即 success)
        h.pc = 0x80000100
        self._exec(h, self._beq(15, 16, 8))
        # 分支应被采用 (相等), PC 跳转 +8
        assert h.pc == 0x80000108, (
            f"BEQ should be taken for equal values, PC={h.pc:#x}"
        )

    def test_bne_with_values_from_different_paths(self, h):
        """BNE 应正确判定不同路径构建的相等值 (不应分支)."""
        h.gprs[11] = 0xD0
        self._exec(h, self._slliw(11, 11, 24))
        h.gprs[12] = 0x0D
        self._exec(h, self._slli(12, 12, 16))
        self._exec(h, self._or(13, 12, 11))
        h.gprs[14] = 0xFE
        self._exec(h, self._slli(14, 14, 8))
        self._exec(h, self._addi(14, 14, 0xED))
        self._exec(h, self._or(15, 13, 14))

        self._exec(h, self._lui(16, 0xD00E0))
        self._exec(h, self._addi(16, 16, -0x113))

        # 验证值相等
        assert h.gprs[15] == h.gprs[16]

        # BNE x15, x16, +8 — 值相等, 不应分支
        h.pc = 0x80000200
        self._exec(h, self._bne(15, 16, 8))
        assert h.pc == 0x80000204, (
            f"BNE should NOT be taken for equal values, PC={h.pc:#x}"
        )
