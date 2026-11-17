#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""纯 Python 路径的算术与立即数运算, 以及各回退分支的行为."""

from __future__ import annotations

from unittest import mock

import pytest

from pyremu import _native
from pyremu._native import (
    native_available,
)
from pyremu.disasm import Opc
from tests.instr_encode import (
    b_type,
    i_type,
    j_type,
    pack_funct,
    pack_src_regs,
    r_type,
    u_type,
)
from tests.test_calc.test_compressed_diff import c1
from tests.test_native.common import (
    assert_ill_instr,
    MASK64,
    OP32,
    OP_ALU,
    OP_IMM,
    OP_IMM32,
)


def test_fallback_correctness(no_native, hart):
    """无加速执行库时 32-bit / 压缩指令均正确执行 (复用 diff test 编码辅助)。"""
    h = hart

    # ---- 32-bit ----
    h.gprs[5] = 10
    h.exec_instr(i_type(Opc.op_imm.value, 5, 0, 5, 7))  # ADDI x5, 7
    assert h.gprs[5] == 17

    h.pc = 0x80000000
    h.exec_instr(j_type(Opc.jal.value, 1, 40))  # JAL x1, +40
    assert h.gprs[1] == 0x80000004
    assert h.pc == 0x80000028

    h.pc = 0x80000000
    h.exec_instr(j_type(Opc.jal.value, 0, -2))  # JAL 负偏移 (sext21)
    assert h.pc == 0x7FFFFFFE

    h.exec_instr(u_type(Opc.lui.value, 10, 0x12345))  # LUI
    assert h.gprs[10] == 0x12345000

    h.gprs[10] = 0
    h.gprs[11] = 0
    h.pc = 0x80000000
    h.exec_instr(b_type(Opc.br.value, 0, 10, 11, 24))  # BEQ (taken)
    assert h.pc == 0x80000018

    # ---- 压缩 ----
    h.gprs[10] = 5
    h.exec_instr(0x050D)  # C.ADDI x10, 3
    assert h.gprs[10] == 8

    h.pc = 0x80000000
    h.gprs[8] = 0
    c_beqz = c1(
        6,
        1,
        int(  # rs1'=x9, offset=+8
            ((8 >> 8) & 0x1) << 12
            | ((8 >> 3) & 0x3) << 10
            | ((8 >> 7) & 0x3) << 5
            | ((8 >> 1) & 0x3) << 3
            | ((8 >> 5) & 0x1) << 2
        ),
    )
    h.exec_instr(c_beqz)  # C.BEQZ x9, +8 (taken)
    assert h.pc == 0x80000008

    h.gprs[2] = 0x80000
    h.exec_instr(0x717D)  # C.ADDI16SP -16
    assert h.gprs[2] == 0x7FFF0

    # ADDI 与 LUI 经纯 Python 算术路径, native_available 必须确实被查询过
    assert no_native.called, "纯 Python 路径未被走到: native_available 未被查询"


def test_native_available_true():
    """测试环境中加速执行库应已装载。"""
    assert native_available() is True


# =====================================================================
#  纯 Python 算术路径 — 逐分支覆盖
# =====================================================================


class TestPurePythonAlu:
    """handle_alu 的纯 Python 分支: 全部 funct3 与 funct7 组合."""

    @pytest.mark.parametrize(
        "case",
        [
            (5, 7, 0b000, 0, 12),
            (6, 7, 0b000, 1, 42),
            (10, 3, 0b000, 0x20, 7),
            (1, 4, 0b001, 0, 16),
            (MASK64, 1, 0b001, 1, MASK64),
            (0x8000_0000_0000_0001, 1, 0b001, 0x30, 3),
            (MASK64, 1, 0b010, 0, 1),
            (MASK64, 1, 0b010, 1, MASK64),
            (1, MASK64, 0b011, 0, 1),
            (1 << 63, 2, 0b011, 1, 1),
            (0xF0, 0x0F, 0b100, 0, 0xFF),
            (7, 2, 0b100, 1, 3),
            (0x10, 2, 0b101, 0, 4),
            (7, 2, 0b101, 1, 3),
            (MASK64 - 7, 1, 0b101, 0x20, MASK64 - 3),
            (1, 1, 0b101, 0x30, 1 << 63),
            (0x0F, 0xF0, 0b110, 0, 0xFF),
            (7, 2, 0b110, 1, 1),
            (0xFF, 0x0F, 0b111, 0, 0x0F),
            (7, 2, 0b111, 1, 1),
            # Zbb 子指令: 按位同或, 有符号最小与最大, 或非, 与非, 无符号最大
            (0xF0, 0x0F, 0b100, 0x20, MASK64 ^ 0xFF),
            (MASK64, 1, 0b100, 0x05, MASK64),
            (0xF0, 0x0F, 0b110, 0x20, MASK64 ^ 0x0F),
            (0, 7, 0b110, 0x05, 7),
            (MASK64, 1, 0b111, 0x20, MASK64 - 1),
            (1, MASK64, 0b111, 0x05, MASK64),
            # Zbb 子指令: 无符号最小, 循环移位
            (0xF0, 0x0F, 0b101, 0x05, 0x0F),
            (1, 2, 0b001, 0x30, 4),
            (1, 2, 0b101, 0x30, 1 << 62),
            # Zba 子指令: 左移后与 rs2 相加
            (1, 0, 0b010, 0x10, 2),
            (1, 0, 0b100, 0x10, 4),
            (1, 0, 0b110, 0x10, 8),
            # Zbs 子指令: 第 40 位, 移位量取 rs2 的低 6 位
            (0, 40, 0b001, 0x14, 1 << 40),
            (MASK64, 40, 0b001, 0x24, MASK64 ^ (1 << 40)),
            (0, 40, 0b001, 0x34, 1 << 40),
            (1 << 40, 40, 0b101, 0x24, 1),
            (0, 0x60, 0b001, 0x14, 1 << 32),
        ],
    )
    def test_alu_branch(self, no_native, hart, case):
        v1, v2, funct3, funct7, expect = case
        hart.gprs[1] = v1
        hart.gprs[2] = v2
        hart.exec_instr(
            r_type(OP_ALU, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2))
        )
        assert hart.gprs[3] == expect
        assert no_native.called

    @pytest.mark.parametrize(
        "case",
        [
            (7, 0b100, 1, MASK64),  # DIV / 0
            (7, 0b101, 1, MASK64),  # DIVU / 0
            (7, 0b110, 1, 7),  # REM / 0
            (7, 0b111, 1, 7),  # REMU / 0
        ],
    )
    def test_alu_divide_by_zero(self, no_native, hart, case):
        v1, funct3, funct7, expect = case
        hart.gprs[1] = v1
        hart.gprs[2] = 0
        hart.exec_instr(
            r_type(OP_ALU, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2))
        )
        assert hart.gprs[3] == expect

    @pytest.mark.parametrize("funct3", [0b000, 0b001, 0b011, 0b101])
    def test_alu_invalid_funct7_traps(self, no_native, hart, funct3):
        assert_ill_instr(
            hart,
            r_type(OP_ALU, 3, pack_funct(0x10, funct3), pack_src_regs(1, 2)),
        )

    def test_alu_invalid_zbb_traps(self, no_native, hart):
        """funct7 属于 Zbb 但 funct3 不对应任何子指令."""
        assert_ill_instr(
            hart,
            r_type(OP_ALU, 3, pack_funct(0x05, 0b010), pack_src_regs(1, 2)),
        )


class TestPurePyOpImm:
    """handle_op_imm 的纯 Python 分支."""

    @pytest.mark.parametrize(
        "case",
        [
            (5, 0b000, 7, 12),
            (1, 0b001, 4, 16),
            (MASK64 - 1, 0b010, 0xFFF, 1),  # SLTI, imm=-1, v1=-2
            (0, 0b011, 1, 1),
            (0xF0, 0b100, 0x0F, 0xFF),
            (0x10, 0b101, 4, 1),
            (MASK64 - 7, 0b101, (0x20 << 5) | 1, MASK64 - 3),  # SRAI
            (0x0F, 0b110, 0xF0, 0xFF),
            (0xFF, 0b111, 0x0F, 0x0F),
        ],
    )
    def test_op_imm_branch(self, no_native, hart, case):
        v1, funct3, imm12, expect = case
        hart.gprs[1] = v1
        hart.exec_instr(i_type(OP_IMM, 3, funct3, 1, imm12))
        assert hart.gprs[3] == expect

    @pytest.mark.parametrize(
        "case",
        [
            (0, 0b001, 0x600, 64),  # clz
            (0x100, 0b001, 0x601, 8),  # ctz
            (0xFF, 0b001, 0x602, 8),  # cpop
            (0x80, 0b001, 0x604, MASK64 - 0x7F),  # sext.b
            (0x8000, 0b001, 0x605, MASK64 - 0x7FFF),  # sext.h
            (1, 0b101, 0x601, 1 << 63),  # rori
            (0x0100, 0b101, 0x287, 0xFF00),  # orc.b
            # rev8
            (0x0123_4567_89AB_CDEF, 0b101, 0x6B8, 0xEFCD_AB89_6745_2301),
            # Zbs 立即数形式: 第 40 位
            (0, 0b001, 0x2A8, 1 << 40),  # bseti
            (MASK64, 0b001, 0x4A8, MASK64 ^ (1 << 40)),  # bclri
            (0, 0b001, 0x6A8, 1 << 40),  # binvi
            (1 << 40, 0b101, 0x4A8, 1),  # bexti
        ],
    )
    def test_op_imm_zbb(self, no_native, hart, case):
        v1, funct3, imm12, expect = case
        hart.gprs[1] = v1
        hart.exec_instr(i_type(OP_IMM, 3, funct3, 1, imm12))
        assert hart.gprs[3] == expect

    def test_op_imm_invalid_slli_funct6_traps(self, no_native, hart):
        assert_ill_instr(hart, i_type(OP_IMM, 3, 0b001, 1, 0x200))

    def test_op_imm_invalid_srli_funct6_traps(self, no_native, hart):
        assert_ill_instr(hart, i_type(OP_IMM, 3, 0b101, 1, 0x220))

    def test_op_imm_invalid_zbb_shamt_traps(self, no_native, hart):
        assert_ill_instr(hart, i_type(OP_IMM, 3, 0b001, 1, 0x603))


class TestPurePythonOp32:
    """handle_op32 的纯 Python 分支."""

    @pytest.mark.parametrize(
        "case",
        [
            (0x7FFF_FFFF, 1, 0b000, 0, 0xFFFF_FFFF_8000_0000),
            (2, 3, 0b000, 1, 6),
            (5, 7, 0b000, 0x20, 0xFFFF_FFFF_FFFF_FFFE),
            (1, 4, 0b001, 0, 16),
            (0x8000_0000, 2, 0b001, 1, MASK64),
            (0x8000_0001, 1, 0b001, 0x30, 3),
            (MASK64, 1, 0b010, 0, 1),
            (MASK64, 1, 0b010, 1, MASK64),
            (1, 0xFFFF_FFFF, 0b011, 0, 1),
            (0x8000_0000, 2, 0b011, 1, 1),
            (0xFF, 0x0F, 0b100, 0, 0xF0),
            (7, 2, 0b100, 1, 3),
            (0x8000_0000, 4, 0b101, 0, 0x0800_0000),
            (7, 2, 0b101, 1, 3),
            (0x8000_0000, 1, 0b101, 0x20, 0xFFFF_FFFF_C000_0000),
            (1, 1, 0b101, 0x30, 0xFFFF_FFFF_8000_0000),
            (0x0F, 0xF0, 0b110, 0, 0xFF),
            (7, 2, 0b110, 1, 1),
            (0xFF, 0x0F, 0b111, 0, 0x0F),
            (7, 2, 0b111, 1, 1),
            # Zba 的 uw 形式: 只截断 rs1, rs2 取完整的 64 位
            (MASK64, 0, 0b000, 0x04, 0xFFFF_FFFF),
            (MASK64, 0x1_0000_0000, 0b010, 0x10, 0x2_FFFF_FFFE),
            (MASK64, 0, 0b100, 0x10, 0x3_FFFF_FFFC),
            (MASK64, 0, 0b110, 0x10, 0x7_FFFF_FFF8),
            # Zbb 的 32 位旋转
            (0x8000_0001, 1, 0b001, 0x30, 3),
            (0x0000_0001, 1, 0b101, 0x30, 0xFFFF_FFFF_8000_0000),
        ],
    )
    def test_op32_branch(self, no_native, hart, case):
        v1, v2, funct3, funct7, expect = case
        hart.gprs[1] = v1
        hart.gprs[2] = v2
        hart.exec_instr(
            r_type(OP32, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2))
        )
        assert hart.gprs[3] == expect

    # funct7=0x10 只适用于 funct3 为 010 / 100 / 110 的 shXadd.uw
    @pytest.mark.parametrize("funct3", [0b000, 0b001, 0b011, 0b101, 0b111])
    def test_op32_invalid_funct7_traps(self, no_native, hart, funct3):
        assert_ill_instr(
            hart, r_type(OP32, 3, pack_funct(0x10, funct3), pack_src_regs(1, 2))
        )


class TestPurePyOpImm32:
    """handle_op_imm32 的纯 Python 分支."""

    @pytest.mark.parametrize(
        "case",
        [
            (1, 0b000, 1, 2),
            (1, 0b001, 4, 16),
            (0, 0b001, 0x600, 32),  # clzw
            (0x100, 0b001, 0x601, 8),  # ctzw
            (0xFF, 0b001, 0x602, 8),  # cpopw
            (0x10, 0b101, 2, 4),
            (0x8000_0000, 0b101, (0x20 << 5) | 1, 0xFFFF_FFFF_C000_0000),
            (0x1234_5678, 0b101, 0x604, 0xFFFF_FFFF_8123_4567),  # roriw
            # slli.uw 的移位量为 6 位, 不小于 32 时 funct7 变为 0x05
            (MASK64, 0b001, 0x081, 0x1_FFFF_FFFE),  # slli.uw shamt=1
            # slli.uw shamt=33
            (0xFFFF_FFFF, 0b001, 0x0A1, 0xFFFF_FFFE_0000_0000),
        ],
    )
    def test_op_imm32_branch(self, no_native, hart, case):
        v1, funct3, imm12, expect = case
        hart.gprs[1] = v1
        hart.exec_instr(i_type(OP_IMM32, 3, funct3, 1, imm12))
        assert hart.gprs[3] == expect

    def test_op_imm32_invalid_funct7_traps(self, no_native, hart):
        assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b001, 1, 0x200))

    def test_op_imm32_invalid_srliw_funct7_traps(self, no_native, hart):
        """funct3=101 的立即数形式只接受 funct7 为 0x00 / 0x20 / 0x30."""
        assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b101, 1, 0x200))

    def test_op_imm32_invalid_funct3_traps(self, no_native, hart):
        assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b010, 1, 0))


class TestDivisionPrecision:
    """商的绝对值达到 2**53 之后, 商与余数不得因浮点舍入而改变。"""

    def test_div_beyond_53_bit_significand(self, pure_python):
        """被除数取 i64 上界、除数为 3: 真商 3074457345618258602。

        改前用 ``int(a / b)``, 双精度把商舍入到 3074457345618258432。
        """
        got = _native.exec_alu_op(0b100, 1, 0x7FFF_FFFF_FFFF_FFFF, 3).value
        assert got == 3074457345618258602 and got != 3074457345618258432

    def test_rem_beyond_53_bit_significand(self, pure_python):
        """被除数取 2**60、除数为 7: 真余数 1。

        改前余数由被舍入的商算出: 商少 9, 误差乘 7 使余数成为 64。
        """
        got = _native.exec_alu_op(0b110, 1, 1 << 60, 7).value
        assert got == 1 and got != 64

    def test_quotient_truncates_toward_zero(self, pure_python):
        """商的取整方向是向零: DIV(-7, 2) 为 -3, REM(-7, 2) 为 -1。"""
        assert _native.exec_alu_op(0b100, 1, MASK64 - 6, 2).value == MASK64 - 2
        assert _native.exec_alu_op(0b110, 1, MASK64 - 6, 2).value == MASK64

    def test_div_zero_returns_all_ones(self, pure_python):
        """除数为零: DIV 与 DIVU 返回全 1, 不抛出异常。"""
        assert _native.exec_alu_op(0b100, 1, 5, 0).value == MASK64
        assert _native.exec_alu_op(0b101, 1, 5, 0).value == MASK64

    def test_rem_zero_returns_dividend(self, pure_python):
        """除数为零: REM 与 REMU 返回被除数。"""
        assert _native.exec_alu_op(0b110, 1, 5, 0).value == 5
        assert _native.exec_alu_op(0b111, 1, 5, 0).value == 5

    def test_division_overflow_wraps(self, pure_python):
        """i64 最小值除以 -1: 商为 i64 最小值, 余数为 0。"""
        assert _native.exec_alu_op(0b100, 1, 1 << 63, MASK64).value == 1 << 63
        assert _native.exec_alu_op(0b110, 1, 1 << 63, MASK64).value == 0


class TestWordResultSignExtension:
    """32 位运算的结果按第 31 位符号扩展到 64 位。"""

    def test_addw_sign_extends(self, pure_python):
        """ADDW(0x7FFF_FFFF, 1) 为 0xFFFF_FFFF_8000_0000."""
        assert (
            _native.exec_op32(0b000, 0, 0x7FFF_FFFF, 1).value
            == 0xFFFF_FFFF_8000_0000
        )

    def test_addw_positive_result_unchanged(self, pure_python):
        """结果为非负时不扩展出高位: ADDW(1, 1) 为 2。"""
        assert _native.exec_op32(0b000, 0, 1, 1).value == 2

    def test_subw_zero_minus_one(self, pure_python):
        """SUBW(0, 1) 为 -1 的 64 位表示。"""
        assert _native.exec_op32(0b000, 0x20, 0, 1).value == MASK64

    def test_sllw_sign_extends(self, pure_python):
        """SLLW(1, 31) 的 32 位结果为 0x8000_0000,
        扩展后为 0xFFFF_FFFF_8000_0000."""
        assert _native.exec_op32(0b001, 0, 1, 31).value == 0xFFFF_FFFF_8000_0000

    def test_srlw_does_not_introduce_high_bits(self, pure_python):
        """SRLW 是逻辑右移: 结果为 0x0800_0000, 第 31 位为 0。"""
        assert _native.exec_op32(0b101, 0, 0x8000_0000, 4).value == 0x0800_0000

    def test_sraw_shifts_negative_value(self, pure_python):
        """SRAW(0x8000_0000, 4) 为 0xFFFF_FFFF_F800_0000。"""
        assert (
            _native.exec_op32(0b101, 0x20, 0x8000_0000, 4).value
            == 0xFFFF_FFFF_F800_0000
        )

    def test_divw_negative_dividend(self, pure_python):
        """DIVW(0xFFFF_FFFE, 2) 为 -1。"""
        assert _native.exec_op32(0b100, 1, 0xFFFF_FFFE, 2).value == MASK64

    def test_divw_overflow_wraps(self, pure_python):
        """i32 最小值除以 -1: 商为 i32 最小值,
        扩展后为 0xFFFF_FFFF_8000_0000。"""
        got = _native.exec_op32(0b100, 1, 0x8000_0000, MASK64).value
        assert got == 0xFFFF_FFFF_8000_0000

    def test_divuw_reinterprets_quotient(self, pure_python):
        """DIVUW 的商按有符号数扩展: DIVUW(0xFFFF_FFFF, 1) 为全 1。"""
        assert _native.exec_op32(0b101, 1, 0xFFFF_FFFF, 1).value == MASK64

    def test_remw_values(self, pure_python):
        """REMW 按有符号数取余, 除数为零时返回符号扩展后的被除数。"""
        assert _native.exec_op32(0b110, 1, 0xFFFF_FFFE, 2).value == 0
        assert _native.exec_op32(0b110, 1, 5, 0).value == 5

    def test_remuw_values(self, pure_python):
        """REMUW 按无符号数取余, 除数为零时返回符号扩展后的被除数。"""
        assert _native.exec_op32(0b111, 1, 0xFFFF_FFFE, 2).value == 0
        assert _native.exec_op32(0b111, 1, 5, 0).value == 5

    def test_addiw_sign_extends(self, pure_python):
        """ADDIW(0x7FFF_FFFF, 1) 为 0xFFFF_FFFF_8000_0000。"""
        assert (
            _native.exec_op_imm32(0b000, 0, 0x7FFF_FFFF, 1).value
            == 0xFFFF_FFFF_8000_0000
        )

    def test_sraiw_shifts_negative_value(self, pure_python):
        """SRAIW(0x8000_0000, 4) 为 0xFFFF_FFFF_F800_0000。"""
        got = _native.exec_op_imm32(0b101, 0x20, 0x8000_0000, 4).value
        assert got == 0xFFFF_FFFF_F800_0000

    def test_srliw_does_not_introduce_high_bits(self, pure_python):
        """SRLIW(0x8000_0000, 4) 为 0x0800_0000。"""
        assert (
            _native.exec_op_imm32(0b101, 0, 0x8000_0000, 4).value == 0x0800_0000
        )


class TestSltiImmediate:
    """SLTI 把立即数按有符号数比较, SLTIU 按无符号数比较。"""

    def test_slti_with_negative_immediate(self, pure_python):
        """SLTI(0, -1) 为 0: 0 不小于 -1 (改前把立即数当无符号数, 取值为 1)。"""
        assert _native.exec_op_imm(0b010, 0, 0, MASK64).value == 0

    def test_slti_with_positive_immediate(self, pure_python):
        """SLTI 的正立即数不受影响: SLTI(5, 7) 为 1, SLTI(5, 3) 为 0。"""
        assert _native.exec_op_imm(0b010, 0, 5, 7).value == 1
        assert _native.exec_op_imm(0b010, 0, 5, 3).value == 0

    def test_slti_with_negative_operand(self, pure_python):
        """SLTI(-1, 0) 为 1: 被除数按有符号数解释。"""
        assert _native.exec_op_imm(0b010, 0, MASK64, 0).value == 1

    def test_sltiu_compares_unsigned(self, pure_python):
        """SLTIU 的对照组: SLTIU(0, -1) 为 1, 因为 0 小于 2**64-1。"""
        assert _native.exec_op_imm(0b011, 0, 0, MASK64).value == 1


class TestFallbackMatchesNative:
    """回退分支与加速执行库在整段语料上逐位一致。"""

    def test_compressed_decode_over_all_halfwords(self):
        """全部 65536 个半字的字段逐一比对。"""
        native = {h: _native.decode_compressed(h) for h in range(0x10000)}
        with mock.patch("pyremu._native._lib", None):
            fallback = {h: _native.decode_compressed(h) for h in range(0x10000)}
        fields = [name for name, _ in _native.CompressedFields._fields_]
        diff = [
            h
            for h in range(0x10000)
            if [getattr(native[h], k) for k in fields]
            != [getattr(fallback[h], k) for k in fields]
        ]
        assert diff == []

    def test_word_alu_over_edge_operands(self):
        """32 位与 32 位立即数两个入口在边界操作数上逐一比对。"""
        values = (
            0,
            1,
            2,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            1 << 53,
            MASK64 - 1,
            MASK64,
        )
        for funct3 in range(8):
            for funct7 in (0, 1, 0x20):
                for v1 in values:
                    for v2 in values:
                        native = _native.exec_op32(funct3, funct7, v1, v2).value
                        with mock.patch("pyremu._native._lib", None):
                            fallback = _native.exec_op32(
                                funct3, funct7, v1, v2
                            ).value
                        assert native == fallback, (funct3, funct7, v1, v2)

    def test_div_rem_over_edge_operands(self):
        """除法与取余在边界操作数上逐一比对。"""
        dividends = (
            0,
            1,
            7,
            1 << 53,
            (1 << 53) + 1,
            (1 << 63),
            MASK64 - 1,
            MASK64,
        )
        divisors = (0, 1, 2, 3, 7, 0x8000_0000, MASK64 - 1, MASK64)
        for funct3 in (0b100, 0b101, 0b110, 0b111):
            for funct7 in (1, 0x20):
                for a in dividends:
                    for b in divisors:
                        native = _native.exec_alu_op(funct3, funct7, a, b).value
                        with mock.patch("pyremu._native._lib", None):
                            fallback = _native.exec_alu_op(
                                funct3, funct7, a, b
                            ).value
                        assert native == fallback, (funct3, funct7, a, b)

    def test_bitmanip_alu_matches_fallback(self):
        """Zba / Zbb / Zbs 的 R 型编码在两个实现上逐位一致."""
        values = (0, 1, 40, 0x60, 0x8000_0000, MASK64)
        for funct3 in range(8):
            for funct7 in (0x04, 0x05, 0x10, 0x14, 0x24, 0x30, 0x34):
                for v1 in values:
                    for v2 in values:
                        native = _native.exec_alu_op(funct3, funct7, v1, v2)
                        with mock.patch("pyremu._native._lib", None):
                            fallback = _native.exec_alu_op(
                                funct3, funct7, v1, v2
                            )
                        assert (native.value, native.trap) == (
                            fallback.value,
                            fallback.trap,
                        ), (funct3, funct7, v1, v2)

    def test_bitmanip_imm_matches_fallback(self):
        """Zba / Zbb / Zbs 的立即数编码在两个实现上逐位一致."""
        imms = (
            0,
            1,
            0x1F,
            0x20,
            0x081,
            0x0A1,
            0x287,
            0x2A8,
            0x4A8,
            0x6A8,
            0x6B8,
            0x6B9,
        )
        for entry, funct3_set in (
            (_native.exec_op_imm, (0b001, 0b101)),
            (_native.exec_op_imm32, (0b001, 0b101)),
        ):
            for funct3 in funct3_set:
                for imm in imms:
                    for v1 in (0, 40, MASK64):
                        native = entry(funct3, imm >> 5, v1, imm)
                        with mock.patch("pyremu._native._lib", None):
                            fallback = entry(funct3, imm >> 5, v1, imm)
                        assert (native.value, native.trap) == (
                            fallback.value,
                            fallback.trap,
                        ), (funct3, imm, v1)

    def test_bitmanip_word_alu_matches_fallback(self):
        """Zba 的 uw 形式与 Zbb 的 32 位旋转在两个实现上逐位一致."""
        values = (0, 1, 0x60, 0x8000_0000, 0xFFFF_FFFF, 0x1_0000_0000, MASK64)
        for funct3 in range(8):
            for funct7 in (0x04, 0x10, 0x30):
                for v1 in values:
                    for v2 in values:
                        native = _native.exec_op32(funct3, funct7, v1, v2)
                        with mock.patch("pyremu._native._lib", None):
                            fallback = _native.exec_op32(funct3, funct7, v1, v2)
                        assert (native.value, native.trap) == (
                            fallback.value,
                            fallback.trap,
                        ), (funct3, funct7, v1, v2)

    def test_pte_parse_over_perm_combinations(self):
        """页表项的权限组合逐一比对, 含 U 位与 V 位的全部组合。"""
        for low in range(0x100):
            raw = ((0x80200 << 10) | low) & MASK64
            native = _native.pte_parse(raw)
            with mock.patch("pyremu._native._lib", None):
                fallback = _native.pte_parse(raw)
            fields = [name for name, _ in _native.PteFields._fields_]
            assert [getattr(native, k) for k in fields] == [
                getattr(fallback, k) for k in fields
            ], hex(raw)


# ============================================================
#  加速执行引擎: 结构体布局、状态搬运与批处理行为
# ============================================================
