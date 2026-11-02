#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""无 Rust 动态库时纯 Python 路径与各回退分支的行为.

两部分:

- 指令执行经 ``native_available()`` 门控退回纯 Python 实现时的行为;
- ``pyremu._native`` 各回退分支 (以模块级 ``_lib`` 为门控) 的取值符合 RISC-V 语义.
  这些用例的期望值取自 RISC-V 规范与原生实现, 不取自回退自身的当前输出, 使每个用例
  在缺少动态库时同样能判定回退是否正确.
"""

from __future__ import annotations

import ctypes
import time
from unittest import mock

import pytest

from pyremu import _native
from pyremu._native import (
    HartState,
    InstrToBeExec,
    IsaExtsC,
    native_available,
    run_parallel,
    TlbEntry,
)
from pyremu.configs_gen import CPU_FREQ_HZ
from pyremu.core.decoder import Hart
from pyremu.core.hart import RatifiedHartAttrs, RiscvMode
from pyremu.emulator import Emulator, RunStopReason
from pyremu.utils.disassem import Opc
from pyremu.utils.isa import encode_misa, isa_ext_list
from pyremu.utils.mask import mask64
from tests.conftest import make_test_config, make_test_emu
from tests.instr_encode import (
    b_type,
    i_type,
    j_type,
    pack_funct,
    pack_src_regs,
    r_type,
    s_type,
    u_type,
)
from tests.test_calc.test_compressed_diff import c1


@pytest.fixture
def no_native():
    """关闭加速执行, 使指令执行走纯 Python 路径.

    ``handle_alu`` / ``handle_op_imm`` / ``handle_op32`` / ``handle_op_imm32``
    以公开门控 ``native_available()`` 判断是否调用加速执行库, 故替换该函数返回
    False 即退回纯 Python 实现, 无须触及动态库的装载状态。
    """
    with mock.patch("pyremu.core.decoder.alu.native_available", return_value=False) as gate:
        yield gate


@pytest.fixture
def pure_python():
    """使 pyremu._native 的各个入口走纯 Python 回退分支。"""
    with mock.patch("pyremu._native._lib", None):
        yield


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

    # ADDI 与 LUI 经纯 Python 算术路径, 门控必须确实被查询过
    assert no_native.called, "纯 Python 路径未被走到: native_available 门控未被查询"


def test_native_available_true():
    """测试环境中加速执行库应已装载。"""
    assert native_available() is True


# =====================================================================
#  纯 Python 算术路径 — 逐分支覆盖
# =====================================================================

OP_ALU = 0b0110011
OP_IMM = 0b0010011
OP_IMM32 = 0b0011011
OP32 = 0b0111011
OP_LOAD = 0b0000011
OP_STORE = 0b0100011
OP_BRANCH = 0b1100011
OP_SYS = 0b1110011
OP_FENCE = 0b0001111
OP_AMO = 0b0101111
OP_FP_LOAD = 0b0000111
OP_FP_STORE = 0b0100111
OP_FP_OP = 0b1010011
OP_FMADD = 0b1000011
OP_FMSUB = 0b1000111

MASK64 = 0xFFFF_FFFF_FFFF_FFFF
FS_ON = 0b11 << 13
PTE_U = 1 << 4


def _assert_ill_instr(h: Hart, instr: int) -> None:
    """断言 *instr* 触发非法指令陷态."""
    h.csrs["mtvec"].val = 0x1000
    h.pc = 0x2000
    assert h.exec_instr(instr) == 0
    assert h.pc == 0x1000
    assert h.csrs["mcause"].val == 2


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
        hart.exec_instr(r_type(OP_ALU, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2)))
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
        hart.exec_instr(r_type(OP_ALU, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2)))
        assert hart.gprs[3] == expect

    @pytest.mark.parametrize("funct3", [0b000, 0b001, 0b011, 0b101])
    def test_alu_invalid_funct7_traps(self, no_native, hart, funct3):
        _assert_ill_instr(
            hart, r_type(OP_ALU, 3, pack_funct(0x10, funct3), pack_src_regs(1, 2))
        )

    def test_alu_invalid_zbb_traps(self, no_native, hart):
        """funct7 属于 Zbb 但 funct3 不对应任何子指令."""
        _assert_ill_instr(
            hart, r_type(OP_ALU, 3, pack_funct(0x05, 0b010), pack_src_regs(1, 2))
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
            (0x0123_4567_89AB_CDEF, 0b101, 0x6B8, 0xEFCD_AB89_6745_2301),  # rev8
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
        _assert_ill_instr(hart, i_type(OP_IMM, 3, 0b001, 1, 0x200))

    def test_op_imm_invalid_srli_funct6_traps(self, no_native, hart):
        _assert_ill_instr(hart, i_type(OP_IMM, 3, 0b101, 1, 0x220))

    def test_op_imm_invalid_zbb_shamt_traps(self, no_native, hart):
        _assert_ill_instr(hart, i_type(OP_IMM, 3, 0b001, 1, 0x603))


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
        hart.exec_instr(r_type(OP32, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2)))
        assert hart.gprs[3] == expect

    # funct7=0x10 只适用于 funct3 为 010 / 100 / 110 的 shXadd.uw
    @pytest.mark.parametrize("funct3", [0b000, 0b001, 0b011, 0b101, 0b111])
    def test_op32_invalid_funct7_traps(self, no_native, hart, funct3):
        _assert_ill_instr(hart, r_type(OP32, 3, pack_funct(0x10, funct3), pack_src_regs(1, 2)))


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
            (0xFFFF_FFFF, 0b001, 0x0A1, 0xFFFF_FFFE_0000_0000),  # slli.uw shamt=33
        ],
    )
    def test_op_imm32_branch(self, no_native, hart, case):
        v1, funct3, imm12, expect = case
        hart.gprs[1] = v1
        hart.exec_instr(i_type(OP_IMM32, 3, funct3, 1, imm12))
        assert hart.gprs[3] == expect

    def test_op_imm32_invalid_funct7_traps(self, no_native, hart):
        _assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b001, 1, 0x200))

    def test_op_imm32_invalid_srliw_funct7_traps(self, no_native, hart):
        """funct3=101 的立即数形式只接受 funct7 为 0x00 / 0x20 / 0x30."""
        _assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b101, 1, 0x200))

    def test_op_imm32_invalid_funct3_traps(self, no_native, hart):
        _assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b010, 1, 0))


class TestNativePathEncodingTraps:
    """加速执行库返回无效编码后, 算术处理函数自身抛出的非法指令."""

    def test_alu_invalid_funct7_traps(self, hart):
        """funct7=0x10 且 funct3=000 不对应任何指令, 抛出 ValueError."""
        _assert_ill_instr(
            hart, r_type(OP_ALU, 3, pack_funct(0x10, 0b000), pack_src_regs(1, 2))
        )

    def test_alu_invalid_zbb_funct3_traps(self, hart):
        """funct7 属于 Zbb 但 funct3 不对应任何子指令."""
        _assert_ill_instr(
            hart, r_type(OP_ALU, 3, pack_funct(0x05, 0b010), pack_src_regs(1, 2))
        )

    @pytest.mark.parametrize(
        "funct3, funct7",
        [
            (0b000, 0x10),  # funct7 不属于任何 32 位字运算
            (0b010, 0x30),  # funct7=0x30 只适用于 001 / 101
        ],
    )
    def test_op32_invalid_encoding_traps(self, hart, funct3, funct7):
        _assert_ill_instr(
            hart, r_type(OP32, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2))
        )

    def test_op_imm32_invalid_funct7_traps(self, hart):
        _assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b001, 1, 0x200))

    def test_op_imm32_invalid_zbb_funct3_traps(self, hart):
        """funct7=0x30 且 funct3=010 不对应任何子指令, 抛出非法指令."""
        _assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b010, 1, 0x600))


class TestBranchAndMemoryEncodings:
    """分支与访存的边界编码."""

    @pytest.mark.parametrize(
        "funct3, v1, v2, taken",
        [
            (0b110, 1, 2, True),  # BLTU
            (0b110, 2, 1, False),
            (0b111, 2, 1, True),  # BGEU
            (0b111, 1, 2, False),
        ],
    )
    def test_unsigned_branches(self, hart, funct3, v1, v2, taken):
        hart.gprs[1] = v1
        hart.gprs[2] = v2
        hart.pc = 0x2000
        hart.exec_instr(b_type(OP_BRANCH, funct3, 1, 2, 8))
        assert hart.pc == (0x2008 if taken else 0x2000)

    def test_branch_invalid_funct3_advances(self, hart):
        hart.pc = 0x2000
        assert hart.exec_instr(b_type(OP_BRANCH, 0b010, 1, 2, 8)) == 4
        assert hart.pc == 0x2000

    @pytest.mark.parametrize(
        "funct3, raw, expect",
        [
            (0b000, bytes([0x80, 0, 0, 0, 0, 0, 0, 0]), MASK64 - 0x7F),  # LB
            (0b100, bytes([0x80, 0, 0, 0, 0, 0, 0, 0]), 0x80),  # LBU
            (0b001, bytes([0x00, 0x80, 0, 0, 0, 0, 0, 0]), MASK64 - 0x7FFF),  # LH
            (0b101, bytes([0x00, 0x80, 0, 0, 0, 0, 0, 0]), 0x8000),  # LHU
        ],
    )
    def test_load_sign_extension(self, hart, funct3, raw, expect):
        hart.mem_write_phy(0x100, raw)
        hart.gprs[1] = 0x100
        hart.exec_instr(i_type(OP_LOAD, 3, funct3, 1, 0))
        assert hart.gprs[3] == expect

    def test_load_invalid_funct3_traps(self, hart):
        _assert_ill_instr(hart, i_type(OP_LOAD, 3, 0b111, 1, 0))

    @pytest.mark.parametrize(
        "funct3, val, expect",
        [
            (0b001, 0x1234, bytes([0x34, 0x12])),
            (0b010, 0x1234_5678, bytes([0x78, 0x56, 0x34, 0x12])),
            (
                0b011,
                0x0123_4567_89AB_CDEF,
                bytes([0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]),
            ),
        ],
    )
    def test_store_widths(self, hart, funct3, val, expect):
        hart.gprs[1] = 0x100
        hart.gprs[2] = val
        hart.exec_instr(s_type(OP_STORE, funct3, 1, 2, 0))
        assert hart.mem_read_phy(0x100, len(expect)) == expect

    def test_store_invalid_funct3_traps(self, hart):
        _assert_ill_instr(hart, s_type(OP_STORE, 0b100, 1, 2, 0))

    def test_fence_and_fence_i(self, hart):
        hart.pc = 0x2000
        assert hart.exec_instr(0b0001111) == 4  # FENCE
        assert hart.exec_instr(0b0001111 | (1 << 12)) == 4  # FENCE.I

    def test_fence_invalid_funct3_traps(self, hart):
        _assert_ill_instr(hart, 0b0001111 | (0b010 << 12))

    def test_amo_invalid_encoding_traps(self, hart):
        _assert_ill_instr(hart, r_type(OP_AMO, 3, pack_funct(0, 0b100), pack_src_regs(1, 2)))

    def test_sys_invalid_funct3_traps(self, hart):
        _assert_ill_instr(hart, r_type(OP_SYS, 3, pack_funct(0, 0b100), pack_src_regs(1, 2)))


class TestCsrImmediateForms:
    """CSRRWI / CSRRSI / CSRRCI."""

    MSCRATCH = 0x340

    def _csr_instr(self, funct3: int, rd: int, csr: int, uimm: int) -> int:
        return r_type(OP_SYS, rd, pack_funct(csr >> 5, funct3), pack_src_regs(uimm, 0)) | (
            (csr & 0x1F) << 20
        )

    def test_csrrwi(self, hart):
        hart.csrs["mscratch"].val = 7
        hart.exec_instr(self._csr_instr(0b101, 3, self.MSCRATCH, 5))
        assert hart.gprs[3] == 7
        assert hart.csrs["mscratch"].val == 5

    def test_csrrsi_with_zero_uimm_reads_only(self, hart):
        hart.csrs["mscratch"].val = 7
        hart.exec_instr(self._csr_instr(0b110, 3, self.MSCRATCH, 0))
        assert hart.gprs[3] == 7
        assert hart.csrs["mscratch"].val == 7

    def test_csrrsi_or_immediate(self, hart):
        hart.csrs["mscratch"].val = 0b100
        hart.exec_instr(self._csr_instr(0b110, 3, self.MSCRATCH, 0b011))
        assert hart.csrs["mscratch"].val == 0b111

    def test_csrrci_clear_immediate(self, hart):
        hart.csrs["mscratch"].val = 0b111
        hart.exec_instr(self._csr_instr(0b111, 3, self.MSCRATCH, 0b011))
        assert hart.csrs["mscratch"].val == 0b100


class TestFpDisabled:
    """mstatus.FS=Off 时全部浮点指令触发非法指令陷态."""

    def test_fp_load_disabled(self, hart):
        _assert_ill_instr(hart, i_type(OP_FP_LOAD, 3, 0b010, 1, 0))

    def test_fp_load_invalid_funct3(self, hart):
        hart.mstatus_val |= FS_ON
        _assert_ill_instr(hart, i_type(OP_FP_LOAD, 3, 0b100, 1, 0))

    def test_fp_store_disabled(self, hart):
        _assert_ill_instr(hart, s_type(OP_FP_STORE, 0b010, 1, 2, 0))

    def test_fp_store_invalid_funct3(self, hart):
        hart.mstatus_val |= FS_ON
        _assert_ill_instr(hart, s_type(OP_FP_STORE, 0b100, 1, 2, 0))

    def test_fp_op_disabled(self, hart):
        _assert_ill_instr(hart, r_type(OP_FP_OP, 3, pack_funct(0, 0b000), pack_src_regs(1, 2)))

    def test_fp_op_invalid_encoding(self, hart):
        hart.mstatus_val |= FS_ON
        _assert_ill_instr(
            hart, r_type(OP_FP_OP, 3, pack_funct(0x7C, 0b000), pack_src_regs(1, 2))
        )

    def test_fp_fma_disabled(self, hart):
        _assert_ill_instr(hart, r_type(OP_FMADD, 3, pack_funct(0, 0b000), pack_src_regs(1, 2)))

    def test_fp_fma_invalid_fmt(self, hart):
        hart.mstatus_val |= FS_ON
        _assert_ill_instr(
            hart, r_type(OP_FMSUB, 3, pack_funct(0b10, 0b000), pack_src_regs(1, 2))
        )


# =====================================================================
#  pyremu._native 回退分支
# =====================================================================


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
        """ADDW(0x7FFF_FFFF, 1) 为 0xFFFF_FFFF_8000_0000 (改前为 0x8000_0000)。"""
        assert _native.exec_op32(0b000, 0, 0x7FFF_FFFF, 1).value == 0xFFFF_FFFF_8000_0000

    def test_addw_positive_result_unchanged(self, pure_python):
        """结果为非负时不扩展出高位: ADDW(1, 1) 为 2。"""
        assert _native.exec_op32(0b000, 0, 1, 1).value == 2

    def test_subw_zero_minus_one(self, pure_python):
        """SUBW(0, 1) 为 -1 的 64 位表示。"""
        assert _native.exec_op32(0b000, 0x20, 0, 1).value == MASK64

    def test_sllw_sign_extends(self, pure_python):
        """SLLW(1, 31) 的 32 位结果为 0x8000_0000, 扩展后为 0xFFFF_FFFF_8000_0000。"""
        assert _native.exec_op32(0b001, 0, 1, 31).value == 0xFFFF_FFFF_8000_0000

    def test_srlw_does_not_introduce_high_bits(self, pure_python):
        """SRLW 是逻辑右移: 结果为 0x0800_0000, 第 31 位为 0。"""
        assert _native.exec_op32(0b101, 0, 0x8000_0000, 4).value == 0x0800_0000

    def test_sraw_shifts_negative_value(self, pure_python):
        """SRAW(0x8000_0000, 4) 为 0xFFFF_FFFF_F800_0000 (改前按无符号移位得 0x0800_0000)。"""
        assert _native.exec_op32(0b101, 0x20, 0x8000_0000, 4).value == 0xFFFF_FFFF_F800_0000

    def test_divw_negative_dividend(self, pure_python):
        """DIVW(0xFFFF_FFFE, 2) 为 -1 (改前把被除数当无符号数, 得 0x7FFF_FFFF)。"""
        assert _native.exec_op32(0b100, 1, 0xFFFF_FFFE, 2).value == MASK64

    def test_divw_overflow_wraps(self, pure_python):
        """i32 最小值除以 -1: 商为 i32 最小值, 扩展后为 0xFFFF_FFFF_8000_0000。"""
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
        assert _native.exec_op_imm32(0b000, 0, 0x7FFF_FFFF, 1).value == 0xFFFF_FFFF_8000_0000

    def test_sraiw_shifts_negative_value(self, pure_python):
        """SRAIW(0x8000_0000, 4) 为 0xFFFF_FFFF_F800_0000。"""
        got = _native.exec_op_imm32(0b101, 0x20, 0x8000_0000, 4).value
        assert got == 0xFFFF_FFFF_F800_0000

    def test_srliw_does_not_introduce_high_bits(self, pure_python):
        """SRLIW(0x8000_0000, 4) 为 0x0800_0000。"""
        assert _native.exec_op_imm32(0b101, 0, 0x8000_0000, 4).value == 0x0800_0000


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


class TestPtePermBits:
    """PTE 权限字段取 bits[4:1], 即 R|W|X|U。"""

    def test_u_bit_is_reported(self, pure_python):
        """raw 置 U 位时 perm 必须含 U 位 (改前掩码为 0xF, U 位恒缺)。"""
        perm = _native.pte_parse(0x1F).perm
        assert perm == 0x1E
        assert perm & PTE_U

    def test_perm_excludes_valid_bit(self, pure_python):
        """raw=0xCF 的 perm 为 0x0E: V 位不进 perm (改前为 0x0F)。"""
        assert _native.pte_parse(0xCF).perm == 0x0E

    def test_rwx_bits_are_preserved(self, pure_python):
        """R/W/X 三位逐位保留, 与 raw 的 bits[3:1] 相同。"""
        for raw in (0x0F, 0x1B, 0x1E, 0xCF, 0xDF, 0xEF):
            assert _native.pte_parse(raw).perm & 0b1110 == raw & 0b1110


class TestCompressedDecode:
    """压缩指令的立即数位段与 RISC-V 编码一致。"""

    def test_lwsp_offset_bits(self, pure_python):
        """C.LWSP 的 uimm[7:6] 取 bits[3:2]、uimm[4:2] 取 bits[6:4]。

        0x4522 的偏移为 8 (改前取 bits[5:4] 与 bits[4:2], 得 64)。
        """
        assert _native.decode_compressed(0x4522).imm == 8
        assert _native.decode_compressed(0x5522).imm == 40

    def test_ldsp_and_fldsp_share_uimm(self, pure_python):
        """C.FLDSP 与 C.LDSP 共用 uimm[5|4:3|8:6]: 0x2006 与 0x6006 均为 64。"""
        assert _native.decode_compressed(0x2006).imm == 64
        assert _native.decode_compressed(0x6006).imm == 64

    def test_c0_floating_load_store_uimm(self, pure_python):
        """C.FLD 与 C.FSD 与 C.LD / C.SD 共用 uimm[5:3|6|7]。

        0x2020 (funct3=1) 与 0xA020 (funct3=5) 均为 64 (改前返回 0)。
        """
        assert _native.decode_compressed(0x2020).imm == 64
        assert _native.decode_compressed(0xA020).imm == 64

    def test_fsdsp_uimm2(self, pure_python):
        """C.FSDSP 与 C.SDSP 共用 uimm[5:3|8:6]: 0xA082 为 64 (改前返回 0)。"""
        assert _native.decode_compressed(0xA082).imm2 == 64
        assert _native.decode_compressed(0xE082).imm2 == 64


@pytest.mark.skipif(not native_available(), reason="需要加速执行库作为对照")
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
        values = (0, 1, 2, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF, 1 << 53, MASK64 - 1, MASK64)
        for funct3 in range(8):
            for funct7 in (0, 1, 0x20):
                for v1 in values:
                    for v2 in values:
                        native = _native.exec_op32(funct3, funct7, v1, v2).value
                        with mock.patch("pyremu._native._lib", None):
                            fallback = _native.exec_op32(funct3, funct7, v1, v2).value
                        assert native == fallback, (funct3, funct7, v1, v2)

    def test_div_rem_over_edge_operands(self):
        """除法与取余在边界操作数上逐一比对。"""
        dividends = (0, 1, 7, 1 << 53, (1 << 53) + 1, (1 << 63), MASK64 - 1, MASK64)
        divisors = (0, 1, 2, 3, 7, 0x8000_0000, MASK64 - 1, MASK64)
        for funct3 in (0b100, 0b101, 0b110, 0b111):
            for funct7 in (1, 0x20):
                for a in dividends:
                    for b in divisors:
                        native = _native.exec_alu_op(funct3, funct7, a, b).value
                        with mock.patch("pyremu._native._lib", None):
                            fallback = _native.exec_alu_op(funct3, funct7, a, b).value
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
                            fallback = _native.exec_alu_op(funct3, funct7, v1, v2)
                        assert (native.value, native.trap) == (
                            fallback.value,
                            fallback.trap,
                        ), (funct3, funct7, v1, v2)

    def test_bitmanip_imm_matches_fallback(self):
        """Zba / Zbb / Zbs 的立即数编码在两个实现上逐位一致."""
        imms = (0, 1, 0x1F, 0x20, 0x081, 0x0A1, 0x287, 0x2A8, 0x4A8, 0x6A8, 0x6B8, 0x6B9)
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


class TestNativeBatchLayout:
    """Python ctypes ↔ Rust repr(C) 结构体布局一致性验证.

    Rust 侧将 TLB 存储为 ``[TlbEntry; 32]`` (array-of-structs).
    若 Python 侧错误地使用分离数组 (如 itlb_vpn, itlb_ppn, ...)
    会造成内存布局不匹配 -> SIGBUS (Bus error).
    这些用例在每次构建后锁死布局合约.
    """

    def test_tlb_entry_size_40(self) -> None:
        """TlbEntry 必须恰好 40 字节.

        mdid 从 u8 加宽为 u64 后 TlbEntry 由 32B 涨到 40B (mdid 对齐到偏移 24).
        与 Rust ``state::TlbEntry`` 逐字节一致, 否则 Rust 在错误偏移读字段 -> SIGBUS.
        """
        assert ctypes.sizeof(TlbEntry) == 40, (
            f"TlbEntry 应为 40 字节, 实际 {ctypes.sizeof(TlbEntry)}B"
        )

    def test_hart_state_8byte_aligned(self) -> None:
        """HartState 必须 8 字节对齐."""
        assert ctypes.sizeof(HartState) % 8 == 0

    def test_hart_state_reasonable_size(self) -> None:
        """HartState 不应异常膨胀 (与 Rust 侧 ``hart_state_size_reasonable`` 对齐).

        256 TLB 条目 × 40B × 2 (itlb+dtlb) ≈ 20 KB, 实际 ~22 KB < 64 KB.
        若某次 FFI 改动让布局爆炸 (如把整块 RAM 塞进 HartState), 此测试会拦住.
        """
        assert ctypes.sizeof(HartState) < 65536

    def test_batch_result_8byte_aligned(self) -> None:
        """InstrToBeExec (原 BatchResult) 必须 8 字节对齐."""
        assert ctypes.sizeof(InstrToBeExec) % 8 == 0

    def test_itlb_is_array_of_structs(self) -> None:
        """itlb 确保 array-of-structs 而非 struct-of-arrays.

        struct-of-arrays 会导致 Rust 在 offsetof(itlb[i].ppn) 读到垃圾 -> SIGBUS.
        """
        hs = HartState()
        assert len(hs.itlb) % 32 == 0
        assert hasattr(hs.itlb[0], "vpn")
        assert hasattr(hs.itlb[0], "ppn")
        assert hasattr(hs.itlb[0], "valid")

    def test_dtlb_is_array_of_structs(self) -> None:
        """dtlb 确保 array-of-structs."""
        hs = HartState()
        assert len(hs.dtlb) % 32 == 0
        assert hasattr(hs.dtlb[0], "vpn")
        assert hasattr(hs.dtlb[0], "ppn")
        assert hasattr(hs.dtlb[0], "valid")

    def test_isa_exts_layout(self) -> None:
        """IsaExtsC 每项占 1 字节, 字段偏移与 Rust ``state::IsaExts`` 相同.

        两侧的字段总数、每项宽度与字段顺序任一不符, 引擎读到的开关就会落到
        其他扩展上. 此处锁死的偏移与 Rust 侧 ``isa_exts_offsets`` 用例相同.
        """
        assert ctypes.sizeof(IsaExtsC) == 21
        assert IsaExtsC.is_i.offset == 0
        assert IsaExtsC.is_zicsr.offset == 9
        assert IsaExtsC.is_sstc.offset == 17
        assert IsaExtsC.is_smepmp.offset == 20
        for name, val in IsaExtsC._fields_:
            assert val is ctypes.c_bool, f"{name} 应为布尔字段"
        # 追加在 HartState 末尾: 其后只有对齐填充, 不挤占已有字段
        extent = HartState.isa_exts.offset + ctypes.sizeof(IsaExtsC)
        assert extent <= ctypes.sizeof(HartState) < extent + 8

    def test_marshal_isa_exts_writes_switches(self) -> None:
        """平台声明决定各开关, 未声明的扩展保持关闭."""
        h = Hart(
            id=0,
            ratified_hart_attrs=RatifiedHartAttrs.from_platform(16, "rv64imac_zicsr_zifencei"),
        )
        state = HartState()
        h.marshal_isa_exts(state)
        assert state.isa_exts.is_i and state.isa_exts.is_m and state.isa_exts.is_c
        assert state.isa_exts.is_zicsr and state.isa_exts.is_zifencei
        assert not state.isa_exts.is_sstc
        assert not state.isa_exts.is_f and not state.isa_exts.is_d
        assert not state.isa_exts.is_b and not state.isa_exts.is_smaia

    def test_marshal_to_leaves_isa_exts_untouched(self) -> None:
        """逐轮编组与解组都不写扩展开关.

        扩展开关是平台的静态属性, 只在状态数组分配时写入一次. 若 marshal_to
        恢复为逐轮写入, 该用例中预先置位的开关会被平台的取值覆盖.
        """
        h = Hart(id=0, ratified_hart_attrs=RatifiedHartAttrs.from_platform(16, "rv64i"))
        state = HartState()
        state.isa_exts.is_sstc = True
        h.marshal_to(state)
        h.unmarshal_from(state)
        assert state.isa_exts.is_sstc is True


class TestSstcSwitch:
    """平台未声明 sstc 时 stimecmp 不存在, 两条执行路径均投递 IllInstr.

    回归: 引擎原先无条件接受 ``csr 0x14D``. OpenSBI 以 ``csr_read_allowed`` 探测
    该 CSR 判断硬件是否支持 sstc, 引擎在未声明的平台上返回合法值会使固件误判,
    与 Python 侧 ``validate_csr`` 的判定不一致.
    """

    ISA_WITHOUT_SSTC = "rv64imac_zicsr_zifencei"
    ISA_WITH_SSTC = "rv64imac_zicsr_zifencei_sstc"
    # csrr x5, 0x14d 与 csrw 0x14d, x5
    CSRR = i_type(Opc.sys.value, 5, 2, 0, 0x14D)
    CSRW = i_type(Opc.sys.value, 0, 1, 5, 0x14D)

    def test_python_path_rejects_stimecmp(self, hart) -> None:
        """Python 路径: 未声明 sstc 时读取该 CSR 产生 IllInstr."""
        h = hart
        h.ratified_hart_attrs = RatifiedHartAttrs.from_platform(16, self.ISA_WITHOUT_SSTC)
        h.pc = 0x8000_0000
        h.exec_instr(self.CSRR)
        assert h.csrs["mcause"].val == 2, "应为 IllInstr"
        assert h.csrs["mepc"].val == 0x8000_0000

    PC, MTVEC = 0x8000_0000, 0x8000_1000

    def _run_engine(
        self,
        isa: str,
        instr: int,
        stimecmp: int = 0,
    ) -> tuple[mock.Mock, Emulator, Hart]:
        """以给定的 ISA 字符串装配模拟器, 经加速执行引擎执行一条指令.

        mtvec 与 pc+4 各设一个断点: 投递陷态时停在 mtvec, 指令正常完成时停在
        pc+4. 引擎调用被记录, 用于确认本用例确实经过 Rust 侧而非纯 Python 路径.
        """
        cfg = make_test_config()
        cfg.isa = isa
        emu = Emulator(cfg)
        emu.load_code(self.PC, instr.to_bytes(4, "little"))
        emu.load_code(self.MTVEC, b"\x13\x00\x00\x00" * 4)
        h = emu.harts[0]
        h.csrs["mtvec"].val = self.MTVEC
        h.csrs["stimecmp"].val = stimecmp
        emu.add_breakpoint(self.PC + 4)
        emu.add_breakpoint(self.MTVEC)
        with mock.patch("pyremu.emu.native.run_parallel", wraps=run_parallel) as engine:
            emu.run(timeout=10)
        return engine, emu, h

    @pytest.mark.parametrize("instr", [CSRR, CSRW])
    def test_engine_rejects_stimecmp(self, instr: int) -> None:
        """加速执行引擎: 未声明 sstc 时读写该 CSR 均产生 IllInstr."""
        engine, _emu, h = self._run_engine(self.ISA_WITHOUT_SSTC, instr)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.MTVEC, f"应陷入 mtvec, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 2, f"应为 IllInstr, 实际 {h.csrs['mcause'].val:#x}"

    def test_engine_accepts_stimecmp_when_declared(self) -> None:
        """声明 sstc 时引擎读取该 CSR 不投递任何异常."""
        engine, _emu, h = self._run_engine(self.ISA_WITH_SSTC, self.CSRR, stimecmp=0x1234)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.PC + 4, f"不应陷入, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 0
        assert h.gprs[5] == 0x1234, f"应读回 stimecmp, 实际 {h.gprs[5]:#x}"


# 各可选扩展与一条属于该扩展的指令. 每项为 (含该扩展的 ISA 字符串, 指令字,
# 指令字节数); 判定拒绝时统一以 "rv64i" 作为未声明该扩展的平台.
_EXT_INSTR_CASES = [
    pytest.param(
        "rv64im",
        r_type(Opc.op.value, 5, pack_funct(0x01, 0b000), pack_src_regs(6, 7)),
        4,
        id="m-mul",
    ),
    pytest.param(
        "rv64ia",
        r_type(Opc.amo.value, 5, pack_funct(0, 0b010), pack_src_regs(7, 6)),
        4,
        id="a-amoadd",
    ),
    pytest.param("rv64if", i_type(Opc.ld_fp.value, 1, 0b010, 2, 0), 4, id="f-flw"),
    pytest.param("rv64id", i_type(Opc.ld_fp.value, 1, 0b011, 2, 0), 4, id="d-fld"),
    pytest.param(
        "rv64i_zba",
        r_type(Opc.op.value, 5, pack_funct(0x10, 0b010), pack_src_regs(6, 7)),
        4,
        id="zba-sh1add",
    ),
    pytest.param(
        "rv64i_zbb",
        r_type(Opc.op.value, 5, pack_funct(0x30, 0b001), pack_src_regs(6, 7)),
        4,
        id="zbb-rol",
    ),
    pytest.param(
        "rv64i_zbs",
        r_type(Opc.op.value, 5, pack_funct(0x14, 0b001), pack_src_regs(6, 7)),
        4,
        id="zbs-bset",
    ),
    pytest.param(
        "rv64i_zicsr", i_type(Opc.sys.value, 5, 2, 0, 0x301), 4, id="zicsr-csrr-misa"
    ),
    pytest.param("rv64i_zifencei", 0x0000_100F, 4, id="zifencei-fence-i"),
    pytest.param("rv64ic", 0x0085, 2, id="c-c-addi"),
]


class TestExtSwitch:
    """平台未声明的扩展所对应的指令不存在, 两条执行路径均投递 IllInstr.

    回归: 解码原先不看平台声明的扩展集合, 关闭 M/A/F/D/C/Zba/Zbb/Zbs/Zicsr/Zifencei
    之后这些指令仍被接受并执行, 使固件以 ``csr_read_allowed`` 与试探性执行探测扩展
    支持时得到与平台声明不符的结果.
    """

    PC, MTVEC = 0x8000_0000, 0x8000_1000
    # csrr x5, misa
    CSRR_MISA = i_type(Opc.sys.value, 5, 2, 0, 0x301)

    @staticmethod
    def _prepare(h: Hart, isa: str, mem_base: int) -> None:
        """按给定 ISA 字符串装配 hart: 设定 pc、mtvec、浮点状态与访存基址."""
        h.ratified_hart_attrs = RatifiedHartAttrs.from_platform(16, isa)
        h.pc = TestExtSwitch.PC
        h.csrs["mtvec"].val = TestExtSwitch.MTVEC
        # 浮点指令要求 mstatus.FS 非零, 否则会因浮点状态关闭而产生同样的异常
        h.csrs["mstatus"].val |= 3 << 13
        h.gprs[2] = mem_base
        h.gprs[7] = mem_base

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_python_path_rejects_undeclared_ext(self, hart, isa_with, instr, length) -> None:
        """Python 路径: 所属扩展未声明时投递 IllInstr, 不执行该指令."""
        h = hart
        self._prepare(h, "rv64i", 0x1000)
        assert h.exec_instr(instr) == 0
        assert h.csrs["mcause"].val == 2, "应为 IllInstr"
        assert h.csrs["mepc"].val == self.PC
        assert h.pc == self.MTVEC

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_python_path_accepts_declared_ext(self, hart, isa_with, instr, length) -> None:
        """Python 路径: 声明所属扩展时不产生异常, 按指令长度推进 pc."""
        h = hart
        self._prepare(h, isa_with, 0x1000)
        assert h.exec_instr(instr) == length
        assert h.csrs["mcause"].val == 0

    def _run_engine(
        self,
        isa: str,
        instr: int,
        length: int,
    ) -> tuple[mock.Mock, Emulator, Hart]:
        """以给定 ISA 字符串装配模拟器, 经加速执行引擎执行一条指令.

        指令正常完成时停在 pc 加指令长度处, 投递陷态时停在 mtvec. 引擎调用被记录,
        用于确认本用例确实经过 Rust 侧.
        """
        cfg = make_test_config()
        cfg.isa = isa
        emu = Emulator(cfg)
        emu.load_code(self.PC, instr.to_bytes(length, "little"))
        emu.load_code(self.MTVEC, b"\x13\x00\x00\x00" * 4)
        h = emu.harts[0]
        self._prepare(h, isa, 0x8000_2000)
        emu.add_breakpoint(self.PC + length)
        emu.add_breakpoint(self.MTVEC)
        with mock.patch("pyremu.emu.native.run_parallel", wraps=run_parallel) as engine:
            emu.run(timeout=10)
        return engine, emu, h

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_engine_rejects_undeclared_ext(self, isa_with, instr, length) -> None:
        """加速执行引擎: 所属扩展未声明时同样投递 IllInstr."""
        engine, _emu, h = self._run_engine("rv64i", instr, length)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.MTVEC, f"应陷入 mtvec, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 2, f"应为 IllInstr, 实际 {h.csrs['mcause'].val:#x}"

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_engine_accepts_declared_ext(self, isa_with, instr, length) -> None:
        """加速执行引擎: 声明所属扩展时不产生异常, 执行到下一条指令."""
        engine, _emu, h = self._run_engine(isa_with, instr, length)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.PC + length, f"不应陷入, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 0

    @pytest.mark.parametrize(
        "isa",
        ["rv64i_zicsr", "rv64imac_zicsr", "rv64imafdc_zicsr_zbb"],
    )
    def test_engine_misa_matches_isa_string(self, isa: str) -> None:
        """引擎读到的 misa 与 Python 侧由同一 ISA 字符串算出的取值相同."""
        engine, _emu, h = self._run_engine(isa, self.CSRR_MISA, 4)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.gprs[5] == encode_misa(isa_ext_list(isa))
        assert h.csrs["mcause"].val == 0


class TestNativePmpSlice:
    """每个 hart 的 PMP 切片步长取该 hart 的实际条目数.

    旧实现按固定 64 项划分切片, 并把每 hart 的条目数报为 64. 配置 16 项时,
    加速执行引擎因此把 pmpaddr16..63 视为已实现, 与 Python 侧实际实现的条目数
    不符; 芯片设备树声明其余条目数时同样错位.
    """

    @pytest.mark.parametrize("entries", [16, 32, 57, 64])
    def test_slice_stride_equals_entry_count(self, entries: int) -> None:
        """切片总长与每 hart 条目数均为配置值; 57 等非 2 的幂同样适用."""
        emu = Emulator(num_harts=2, pmp_entries=entries)
        info = emu._native_marshal_pmp([])
        assert info.num == entries
        assert len(info.cfg) == entries * 2
        assert len(info.addr) == entries * 2

    def test_configured_16_entries_report_16(self) -> None:
        """配置 16 项时引擎看到的条目数为 16, 不再是修复前的 64."""
        emu = Emulator(num_harts=1, pmp_entries=16)
        info = emu._native_marshal_pmp([])
        assert info.num == 16
        assert info.num != 64

    def test_each_hart_slice_is_independent(self) -> None:
        """写入一个 hart 的切片不改变另一个 hart 的切片."""
        emu = Emulator(num_harts=2, pmp_entries=16)
        emu.harts[0].csrs["pmpcfg0"].val = 0x1F
        emu.harts[0]._pmp.invalidate_cache()
        info = emu._native_marshal_pmp([])
        assert info.cfg[0] == 0x1F
        assert info.cfg[16] == 0


@pytest.mark.usefixtures("legacy_plic")
class TestPlicNativeInline:
    """PLIC 内联 (Rust batch) 的 Python 侧 marshal/unmarshal 契约.

    回归: kernel 直映射包含 PLIC MMIO (enable 写约 767/s), 旧实现每次访问都
    退出 Rust batch 回落到 Python MMIO, 使 EXT4 recovery 阶段吞吐跌至 ~0.6M/s.
    修复为 Rust 内联处理 PLIC MMIO (claim/complete/enable/threshold/priority),
    状态经持久 ctypes 数组在 batch 边界 marshal/unmarshal 往返, 设备线程
    ``irq_sink`` 直接 write-through pending/level, 保证 batch 内新设备
    中断对 Rust 内联仲裁可见.
    """

    def test_marshal_plic_fields(self):
        """marshal 产出正确的 base/num_sources/num_contexts 与位打包 enable."""
        emu = Emulator(num_harts=2)
        plic = emu.plic
        assert plic is not None
        plic._priority[10] = 5
        plic._enable[0][10] = True  # word 0, bit 10
        plic._enable[0][33] = True  # word 1, bit 1 (source 33)
        plic._enable[1][7] = True  # context 1, word 0, bit 7
        info = emu._native_marshal_plic()
        assert info is not None
        assert info.base == plic.base_addr
        assert info.num_sources == plic._num_sources
        assert info.num_contexts == plic._num_contexts
        # enable 数组: context * num_words + word
        nw = (plic._num_sources + 31) // 32
        assert len(info.enable) == plic._num_contexts * nw
        assert info.priority[10] == 5
        assert info.enable[0 * nw + 0] & (1 << 10) != 0, "source 10 应落 word 0 bit 10"
        assert info.enable[0 * nw + 1] & (1 << 1) != 0, "source 33 应落 word 1 bit 1"
        assert info.enable[1 * nw + 0] & (1 << 7) != 0, "context 1 source 7"

    def test_unmarshal_plic_roundtrip(self):
        """marshal -> (模拟 Rust 内联改 state) -> unmarshal 往返保真."""
        emu = Emulator(num_harts=2)
        plic = emu.plic
        plic._priority[10] = 5
        plic._enable[0][10] = True
        plic._enable[1][7] = True
        plic._threshold[1] = 3
        plic._claimed[0] = 10
        # pending/level 由 set_irq 写穿 FFI 数组 (直接改 Python 列表不会同步)
        plic.set_irq(10, True)
        info = emu._native_marshal_plic()
        # 模拟 Rust 内联: claim 清 pending, 记录 claimed; complete 后电平仍高重挂.
        info.pending[10] = 0
        info.claimed[0] = 10
        info.pending[10] = 1
        info.threshold[0] = 7
        emu._native_unmarshal_plic(info)
        assert plic._priority[10] == 5
        assert plic._pending[10] is True
        assert plic._level[10] is True
        assert plic._enable[0][10] is True
        assert plic._enable[1][7] is True
        assert plic._threshold[1] == 3
        assert plic._threshold[0] == 7
        assert plic._claimed[0] == 10

    def test_irq_sink_write_through(self):
        """设备线程经 irq_sink 写穿到 FFI 持久数组, 使 batch 内对 Rust 可见."""
        emu = Emulator(num_harts=2)
        emu._native_marshal_plic()  # 首次分配持久数组
        emu.irq_sink(25, True)
        assert emu.plic._ffi_pending[25] == 1
        assert emu.plic._ffi_level[25] == 1
        emu.irq_sink(25, False)
        assert emu.plic._ffi_pending[25] == 0
        assert emu.plic._ffi_level[25] == 0

    def test_marshal_plic_none_when_no_plic(self):
        """无 PLIC 时 marshal 返回 None (native 侧回落 MMIO)."""
        emu = Emulator(num_harts=1)
        emu.plic = None
        assert emu._native_marshal_plic() is None
        assert emu._native_unmarshal_plic(None) is None


class TestClockDecoupling:
    """指令计数时钟模型: mtime 按已执行指令数推进, mcycle 按时钟源推进.

    回归: 旧实现按时钟源 (time.monotonic()) 推进 mtime, 使 mtime 速率与执行
    速度无关 — 固件忙等 (rdtime 自旋) 期间 mtime 仍推进, SMP bringup 超时.
    改为 mtime 按指令计数推进 (100 指令 = 1 tick), mcycle 仍按时钟源推进.
    """

    @pytest.fixture
    def nop_emu(self) -> Emulator:
        """单 hart 模拟器, 加载 4096 条 NOP — 无 WFI/ECALL/trap.

        时钟源频率固定为 10 MHz, 使换算结果不随 TIMER_FREQ 变化.
        """
        emu = Emulator(num_harts=1, timebase_freq=10_000_000)
        nops = b"\x13\x00\x00\x00" * 4096  # addi x0, x0, 0
        emu.load_code(0x8000_0000, nops)
        return emu

    def test_mtime_advances_per_100_instructions(self, nop_emu):
        """mtime 按指令计数推进: 100 条指令 = 20 tick (10 MHz × NS_PER_INSTR=20ns)."""
        emu = nop_emu
        mtime_before = emu.clint.get_mtime()
        for _ in range(100):
            emu.step()
        assert emu.clint.get_mtime() - mtime_before == 20, (
            "100 条指令应推进 mtime 恰好 20 tick (5 指令/tick)"
        )

    def test_advance_mtime_instr_conversion(self, nop_emu):
        """_advance_mtime_instr 按 timebase_freq*NS_PER_INSTR 换算, 余数跨调用累积."""
        emu = nop_emu
        mtime_before = emu.clint.get_mtime()

        # 5 指令 -> 恰好 1 tick (10 MHz × 20ns/instr)
        emu._advance_mtime_instr(5)
        assert emu.clint.get_mtime() - mtime_before == 1

        # 4 指令 -> 0 tick (余数累积 0.8); 再 1 指令 -> 满 1 tick
        emu._advance_mtime_instr(4)
        assert emu.clint.get_mtime() - mtime_before == 1
        emu._advance_mtime_instr(1)
        assert emu.clint.get_mtime() - mtime_before == 2

    def test_advance_mcycle_clock_source(self, nop_emu, monkeypatch):
        """_advance_mcycle 按时钟源推进 mcycle, 不动 mtime."""
        now_holder = {"t": 100.0}
        monkeypatch.setattr(time, "monotonic", lambda: now_holder["t"])
        emu = nop_emu
        emu._last_clock_sync = 100.0
        cyc_before = emu._cycle
        mtime_before = emu.clint.get_mtime()

        now_holder["t"] = 101.0
        emu._advance_mcycle()
        assert emu._cycle - cyc_before == CPU_FREQ_HZ
        assert emu.clint.get_mtime() == mtime_before

    def test_marshal_clint_no_mtime_advance(self, nop_emu, monkeypatch):
        """_native_marshal_clint 不再按时钟源推进 mtime (mtime 与时钟源解耦)."""
        now_holder = {"t": 300.0}
        monkeypatch.setattr(time, "monotonic", lambda: now_holder["t"])
        emu = nop_emu
        emu._last_clock_sync = 300.0
        mtime_before = emu.clint.get_mtime()

        now_holder["t"] = 300.5
        info = emu._native_marshal_clint()
        assert emu.clint.get_mtime() == mtime_before, "marshal_clint 不得再按时钟源推进 mtime"
        assert info.mtime == mtime_before

    def test_native_batch_mtime_pure_instruction_count(self, nop_emu):
        """native batch (run_parallel) 下 mtime 纯按指令计数推进, 与流逝时间解耦.

        回归: 工作树曾把 Rust ``advance_clock_source`` 改为实时/混合模型,
        legacy 模式 PLIC 相位后 HZ=250 的 4ms tick 指令预算不足 (~8-12K 条),
        低于 kernel post-PLIC timer handler 路径 -> mret 后立即再 trap 的活锁,
        kernel_init 被饿死, 串口停在 plic 设备树节点输出. 修复为纯指令源
        (20ns/instr) 后, native 路径 mtime 推进率必须与 Python 路径一致:
        5 条指令 = 1 tick, 流逝时间完全不参与.
        """
        emu = nop_emu
        assert emu._speedup_hart_states is not None, "回归测试必须走 native batch"
        # 断点设在第 2000 条 NOP 之后, run() 经 native batch 返回
        emu._bp_addrs = [0x8000_0000 + 2000 * 4]
        emu.run(timeout=15)
        assert emu._run_stop_reason == RunStopReason.BREAKPOINT, (
            f"应命中断点, 实际 reason={emu._run_stop_reason}"
        )
        assert emu._total_instrs == 2000, f"应恰好执行 2000 条 NOP, 实际 {emu._total_instrs}"
        mtime = emu.clint.get_mtime()
        # 5 条指令 = 1 tick (10 MHz × 20ns/instr / 1e9). 边界滞后 <=1 条
        # (advance_clock_source 在每条指令执行前的循环顶推进), 故期望落在
        # elapsed*timebase ≈ 10^3~10^4+ tick, 远越上界 -> 复现修复前行为.
        lo = emu._total_instrs // 5 - 1
        hi = emu._total_instrs // 5
        assert lo <= mtime <= hi, (
            f"native batch 2000 条指令 mtime 应为 [{lo}, {hi}] tick (纯指令源), 实际 {mtime}"
        )
        emu.close()

    def test_native_mtime_no_wallclock_leak_on_idle(self, nop_emu):
        """无指令执行时, mtime 不随流逝时间推进 (无实时泄漏).

        回归: 实时/混合模型在空闲批次 instr_delta=0 时仍按真实流逝推进 mtime,
        与 Python 侧 ``_wfi_sleep_if_idle`` 的 clint.tick 实时补偿叠加成
        ~2× real 双倍计数, 重新制造 tick 风暴压力. 修复后空闲期 mtime 静止,
        由 WFI 补偿独占实时源.
        """
        emu = nop_emu
        emu._bp_addrs = [0x8000_0000 + 2000 * 4]
        emu.run(timeout=15)
        assert emu._run_stop_reason == RunStopReason.BREAKPOINT
        mtime_before = emu.clint.get_mtime()
        time.sleep(0.3)  # 无指令执行, 流逝 300ms
        assert emu.clint.get_mtime() == mtime_before, (
            "空闲期 mtime 不得随流逝时间推进 (实时泄漏)"
        )
        emu.close()


class TestMarshalUnmarshalRoundtrip:
    """marshal_to 与 unmarshal_from 的双向数据完整性验证.

    batch 边界 marshal/unmarshal 是 Python HartWithRegs ↔ Rust HartState
    的唯一数据通道.  若任一字段在往返过程中丢失或损坏, batch 内部的 Rust
    执行会基于错误状态继续运行 — 产生静默错误 (如 ld-linux s4=-1 消失).

    本测试覆盖 HartState 中所有非 pad 字段的往返保真度.
    """

    # ---------- helpers ----------
    @staticmethod
    def _fresh_hart(hart_id: int = 0) -> Hart:
        """创建一个处于 M 模式的 Hart (__init__ 默认)."""
        return Hart(id=hart_id)

    @staticmethod
    def _roundtrip(hart: Hart) -> Hart:
        """把状态编组后解组到新 hart, 返回新 hart."""
        state = HartState()
        hart.marshal_to(state)
        out = Hart(id=hart.id + 1)
        out.unmarshal_from(state)
        return out

    # ---------- GPR 往返 ----------
    def test_gpr_all_zero_init(self) -> None:
        """所有 GPR 初始为 0 时往返不变."""
        hart = self._fresh_hart()
        out = self._roundtrip(hart)
        for i in range(32):
            assert out.gprs[i] == 0, f"gprs[{i}] = {out.gprs[i]}, expected 0"

    def test_gpr_fills_pattern_roundtrip(self) -> None:
        """每寄存器写入唯一值后往返不变."""
        hart = self._fresh_hart()
        for i in range(32):
            hart.gprs[i] = mask64(i * 0x1111_1111_1111_1111 + 0xDEAD_BEEF_CAFE_BABE)
        # x0 写保护 — GprFile 应忽略写入
        hart.gprs[0] = 0  # explicitly ensure
        out = self._roundtrip(hart)
        assert out.gprs[0] == 0, "x0 must always be 0"
        for i in range(1, 32):
            expected = mask64(i * 0x1111_1111_1111_1111 + 0xDEAD_BEEF_CAFE_BABE)
            assert out.gprs[i] == expected, (
                f"gprs[{i}] = {out.gprs[i]:#018x}, expected {expected:#018x}"
            )

    def test_s4_negative_one_preserved(self) -> None:
        """s4 (x20) = -1 (0xFFFF_FFFF_FFFF_FFFF) 在往返后必须保持.

        ld-linux 用 s4=-1 作为循环退出哨兵.  若 unmarshal 在某处将其清零
        或截断, BNE s2,s4 将永不退出 — 继续迭代到 DT_RELA=7 -> LoadPageFault.
        """
        hart = self._fresh_hart()
        hart.gprs[20] = 0xFFFF_FFFF_FFFF_FFFF  # s4 = -1
        out = self._roundtrip(hart)
        assert out.gprs[20] == 0xFFFF_FFFF_FFFF_FFFF, f"s4 = {out.gprs[20]:#018x}, expected -1"

    def test_gpr_edge_values_roundtrip(self) -> None:
        """GPR 极端值 (0, -1, MAX, 符号位, 交替 bits) 往返不变."""
        hart = self._fresh_hart()
        test_values = {
            1: 0,  # zero
            2: 0xFFFF_FFFF_FFFF_FFFF,  # -1 (ld-linux s4 sentinel)
            3: 0x7FFF_FFFF_FFFF_FFFF,  # max positive signed
            4: 0x8000_0000_0000_0000,  # min negative signed
            5: 0xAAAA_AAAA_AAAA_AAAA,  # alternating bits
            6: 0x5555_5555_5555_5555,  # alternating bits (inverted)
            7: 0x0000_0000_0000_0001,  # 1 (smallest non-zero)
            8: 0x8000_0000_0000_0001,  # sign bit + 1
        }
        for idx, val in test_values.items():
            hart.gprs[idx] = val
        out = self._roundtrip(hart)
        for idx, val in test_values.items():
            assert out.gprs[idx] == val, (
                f"gprs[{idx}] = {out.gprs[idx]:#018x}, expected {val:#018x}"
            )

    # ---------- 关键 CSR 往返 ----------
    @pytest.mark.parametrize(
        "csr_name,val",
        [
            ("mstatus", 0x0000000A00001800),  # MPP=M, SPP=S, FS=1, XS=1
            ("mtvec", 0x80001000),  # vectored M-mode
            ("stvec", 0x80200000),  # direct S-mode
            ("mepc", 0x80001234),
            ("sepc", 0x3FFF_FFFF_F000),
            ("mcause", 0x8000_0000_0000_000D),  # LoadPageFault interrupt
            ("scause", 0x0000_0000_0000_0008),  # EcallFromUmode
            ("mtval", 0x0000_0033D),
            ("stval", 0x3FFF_FFFF_F000),
            ("satp", 0x8000_0000_0001_2345),  # Sv39, PPN=0x12345
            ("mie", 0x888),  # MEIE | SEIE | MTIE
            ("mip", 0x080),  # STIP
            ("medeleg", 0xBEEF),
            ("mideleg", 0xDEAD),
        ],
    )
    def test_csr_roundtrip(self, csr_name: str, val: int) -> None:
        """关键 CSR 往返不变."""
        hart = self._fresh_hart()
        hart.csrs[csr_name].val = val
        out = self._roundtrip(hart)
        actual = out.csrs[csr_name].val
        assert actual == val, f"{csr_name}: {actual:#018x} ≠ expected {val:#018x}"

    # ---------- 状态字段 ----------
    def test_pc_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart.pc = 0x3FFF_FFFF_3ABA
        out = self._roundtrip(hart)
        assert out.pc == 0x3FFF_FFFF_3ABA

    @pytest.mark.parametrize("mode", [RiscvMode.U, RiscvMode.S, RiscvMode.M])
    def test_mode_roundtrip(self, mode: RiscvMode) -> None:
        hart = Hart(id=0)
        hart.mode = mode
        out = self._roundtrip(hart)
        assert out.mode == mode

    def test_mmu_mode_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._mmu_mode = 8  # Sv39
        out = self._roundtrip(hart)
        assert out.mmu_mode == 8

    # ---------- LR/SC reservation ----------
    def test_reservation_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._reservation_valid = True
        hart._reservation_addr = 0x8000_1234
        out = self._roundtrip(hart)
        assert out._reservation_valid is True
        assert out._reservation_addr == 0x8000_1234

    def test_reservation_invalid_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._reservation_valid = False
        out = self._roundtrip(hart)
        assert out._reservation_valid is False

    # ---------- WFI / halted ----------
    def test_waiting_wfi_woken_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._waiting = True
        hart._wfi_woken = True
        out = self._roundtrip(hart)
        assert out._waiting is True
        assert out._wfi_woken is True

    def test_halted_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._halted = True
        out = self._roundtrip(hart)
        assert out._halted is True

    # ---------- TEE CSRs ----------
    def test_mdid_pmpsplit_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._mdid_val = 5
        hart._pmpsplit_val = 2
        out = self._roundtrip(hart)
        assert out.mdid_val == 5
        assert out.pmpsplit_val == 2

    def test_mdid_above_255_roundtrip(self) -> None:
        """
        mdid 超过 255 时 marshal 往返必须保持完整 64-bit 值.

        回归: HartState.mdid / TlbEntry.mdid 曾声明为 c_uint8 (Rust 侧 u8),
        与 csr.rs ``val as u8`` 截断共同构成 batch-4 (2000 并发, id >= 256)
        挂死根因 — 300->44, 256->0 (别名回 host, SUSPEND handler 误判而挂死).
        c_uint8 字段赋值 300 会直接抛 ValueError, 本用例在旧布局下无法通过.
        """
        hart = self._fresh_hart()
        hart._mdid_val = 300
        out = self._roundtrip(hart)
        assert out.mdid_val == 300

        # 256 ≡ 0 (mod 256) 是最危险别名 (-> host), 必须保留原值
        hart2 = self._fresh_hart()
        hart2._mdid_val = 256
        out2 = self._roundtrip(hart2)
        assert out2.mdid_val == 256

    # ---------- Extra CSRs ----------
    def test_extra_csrs_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart.csrs["mscratch"].val = 0xDEAD_BEEF_0000_1111
        hart.csrs["sscratch"].val = 0xCAFE_BABE_2222_3333

        # mhartid is read-only (set in __init__ to hart.id)
        # Write mcounteren directly
        hart.csrs["mcounteren"].val = 0x0000_0000_0000_0007  # CY|TM|IR

        out = self._roundtrip(hart)
        assert out.csrs["mscratch"].val == 0xDEAD_BEEF_0000_1111
        assert out.csrs["sscratch"].val == 0xCAFE_BABE_2222_3333
        assert out.csrs["mhartid"].val == 0  # original hart had id=0
        assert out.csrs["mcounteren"].val == 0x0000_0000_0000_0007

    # ---------- instruction counter ----------
    def test_total_instrs_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._total_instrs = 123456789
        out = self._roundtrip(hart)
        assert out._total_instrs == 123456789

    # ---------- float ----------
    def test_fpr_roundtrip(self) -> None:
        hart = self._fresh_hart()
        for i in range(32):
            hart._fpr_bits[i] = mask64(0x3FF0_0000_0000_0000 + i * 0x1000_0000_0000)
        out = self._roundtrip(hart)
        for i in range(32):
            expected = mask64(0x3FF0_0000_0000_0000 + i * 0x1000_0000_0000)
            assert out._fpr_bits[i] == expected, f"fpr[{i}] mismatch"

    def test_fcsr_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart.csrs["fcsr"].val = 0x0000_0000_0000_00A0  # FRM=2, NV|DZ flags
        out = self._roundtrip(hart)
        assert out.csrs["fcsr"].val == 0x0000_0000_0000_00A0


class TestNativeBatchBitmanip:
    """加速执行引擎执行 Zba / Zbb / Zbs 指令.

    回归: 加速执行引擎曾对 orc.b 返回非法指令陷态, Linux 的 strlen_zbb 首次执行
    时投递 IllInstr, 内核停在 sepc 指向 orc.b 的位置 (mtval=0x28735313).
    """

    TEXT_PA = 0x1000
    # orc.b x6,x6 / rev8 x7,x7 / sh1add x9,x8,x9
    PROG = bytes.fromhex("1353732893d3836bb3249420")

    def test_bitmanip_executes_in_batch(self):
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=64 * 1024)
        h = emu.harts[0]
        h.gprs[6] = 0x0100
        h.gprs[7] = 0x0123_4567_89AB_CDEF
        h.gprs[8] = 1
        h.gprs[9] = 0
        emu.load_code(self.TEXT_PA, self.PROG)
        h.pc = self.TEXT_PA
        emu._bp_addrs = [self.TEXT_PA + len(self.PROG)]

        emu.run(timeout=15)

        assert emu._run_stop_reason == RunStopReason.BREAKPOINT, (
            f"应在程序末尾命中断点, 实际 reason={emu._run_stop_reason} "
            f"pc=0x{h.pc:x} mcause=0x{h.csrs['mcause'].val:x}"
        )
        assert h.csrs["mcause"].val == 0, "不应投递任何异常"
        assert h.gprs[6] == 0xFF00, f"orc.b 结果错误: {h.gprs[6]:#x}"
        assert h.gprs[7] == 0xEFCD_AB89_6745_2301, f"rev8 结果错误: {h.gprs[7]:#x}"
        assert h.gprs[9] == 2, f"sh1add 结果错误: {h.gprs[9]:#x}"


class TestNativeXonlyFetch:
    """native 引擎对 X-only 页 (R=0, W=0, X=1) 的取指回归.

    回归 (Batch-20 trap loop 根因): Rust ``walk_l0`` / ``walk_l1_leaf`` 对
    取指也强制 PTE_R, 使 runtime 映射在 0xffffffe000001000 的 X-only text
    (trap_vector) 取指被误判 InstrPageFault. 修复后取指仅要求 PTE_X.

    本测试通过 emulator 的 native run_parallel 引擎端到端复现: STIP 投递到
    stvec=trap_vector (X-only 高 VA 页), 若取指失败则陷入 M 模式 trap loop,
    永远命不中断点; 修复后 trap_vector 首条指令被取指+执行, 断点命中.
    """

    # 与 runtime identity_map_trampoline / map_sections 生成值逐位一致:
    #   L1[0x57] = 0x22b800cf  R|W|X 2 MiB superleaf  -> PA 0x8ae00000
    #   L0[1]    = 0x22b804c9  X-only 4 KiB leaf       -> PA 0x8ae01000
    MAN_PA = 0x8AE0_0000
    TRAP_VEC_VA = 0xFFFF_FFE0_0000_1000
    ROOT_PA = 0x8AE0_A000
    L1_LOW_PA = 0x8AE0_B000
    L1_HIGH_PA = 0x8AE0_C000
    L0_HIGH_PA = 0x8AE0_D000
    TEXT_PA = 0x8AE0_1000

    @staticmethod
    def _pte_ptr(target_pa: int) -> int:
        """指针 PTE (V=1, R=W=X=0), 指向 *target_pa*."""
        return 1 | ((target_pa >> 12) << 10)

    def _build_page_tables(
        self,
        emu: Emulator,
    ) -> None:
        """写入 Sv39 页表: 低 VA identity 超页 + 高 VA X-only trap_vector 映射."""
        ram = emu.bus

        def wr64(pa: int, val: int) -> None:
            ram.write_ram_direct(pa, val.to_bytes(8, "little"))

        # root[vpn2=2] -> L1_LOW (低 VA identity 区域)
        wr64(self.ROOT_PA + 2 * 8, self._pte_ptr(self.L1_LOW_PA))
        # root[vpn2=0x180] -> L1_HIGH (高 VA trap_vector 区域)
        wr64(self.ROOT_PA + 0x180 * 8, self._pte_ptr(self.L1_HIGH_PA))
        # L1_LOW[vpn1=0x57] = R|W|X 2 MiB superleaf -> PA 0x8ae00000
        wr64(self.L1_LOW_PA + 0x57 * 8, 0x22B8_00CF)
        # L1_HIGH[vpn1=0] -> L0_HIGH
        wr64(self.L1_HIGH_PA + 0 * 8, self._pte_ptr(self.L0_HIGH_PA))
        # L0_HIGH[vpn0=1] = X-only leaf (R=0 W=0 X=1, A|D 预置) -> PA 0x8ae01000
        wr64(self.L0_HIGH_PA + 1 * 8, 0x22B8_04C9)

    def _make_enclave_emu(
        self,
    ) -> tuple[Emulator, object]:
        """构建单 hart 模拟器: 页表 + 代码 + S 模式飞地入口态 (STIP 立即 pending)."""
        # MAN_PA=0x8ae00000 偏移 0xae00000 (182 MiB) > 默认 128 MiB RAM —
        # 必须扩 RAM 才能覆盖 enclave 池与页表 (对齐 make stress 场景).
        emu = make_test_emu(ram_size=0x1000_0000)
        h = emu.harts[0]
        self._build_page_tables(emu)
        # trap_vector: lui x1, 0x5AA (5AA005B7) 然后 NOP 填充
        trap_code = (0x5AA0_05B7).to_bytes(4, "little") + b"\x13\x00\x00\x00" * 255
        emu.load_code(self.TEXT_PA, trap_code)
        # 低 VA 预中断点 NOP 填充
        emu.load_code(self.MAN_PA, b"\x13\x00\x00\x00" * 64)

        # ---- hart 状态 (镜像 OpenSBI 飞地入口 + 全权限 PMP) ----
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["stvec"].val = self.TRAP_VEC_VA
        h.csrs["mideleg"].val = 0x222  # SSI|STI|SEI 委派 S
        h.csrs["mie"].val |= 1 << 5  # STIE
        h.mstatus_val |= 1 << 1  # SIE
        h.csrs["pmpaddr0"].val = (1 << 64) - 1
        h.csrs["pmpcfg0"].val = 0xF
        h._pmp.invalidate_cache()
        # SSTC: stimecmp=1, mtime 置为 1 -> STIP 立即 pending (native 引擎用
        # stimecmp/mtime 重新评估 STIP, 手工 mip 位会被 sync 覆盖)
        h.csrs["stimecmp"].val = 1
        emu.clint._mtime = 1
        # M-mode trap handler 指向低 VA (identity 映射), 便于失败时观察 trap loop
        h.csrs["mtvec"].val = self.MAN_PA
        h.pc = self.MAN_PA
        return emu, h

    def test_xonly_fetch_via_stip_trap_vector(
        self,
    ) -> None:
        """X-only 高 VA trap_vector 在 native 引擎下取指成功并执行.

        修复前 walk_l0 对取指强制 PTE_R -> InstrPageFault -> M 模式 trap loop,
        永不抵达断点; 修复后 trap_vector 首条指令执行, pc 推进到 +4 命中断点.
        """
        emu, h = self._make_enclave_emu()
        emu._bp_addrs = [self.TRAP_VEC_VA + 4]

        emu.run(timeout=15)

        assert emu._run_stop_reason == RunStopReason.BREAKPOINT, (
            f"应在 trap_vector+4 命中断点, 实际 reason={emu._run_stop_reason} "
            f"pc=0x{h.pc:x} mode={h.mode} mcause=0x{h.csrs['mcause'].val:x}"
        )
        assert h.pc == self.TRAP_VEC_VA + 4, (
            "trap_vector 首条指令应被取指+执行 (X-only 页取指成功)"
        )
        assert h.mode == RiscvMode.S, f"不应陷入 M 模式 trap loop, 实际 mode={h.mode}"
        assert h.csrs["mcause"].val == 0, (
            f"不应投递任何异常, 实际 mcause=0x{h.csrs['mcause'].val:x}"
        )

    def test_xonly_page_data_read_still_faults(
        self,
    ) -> None:
        """X-only 页数据读仍被拒绝 (取指放宽不影响 R 位要求)."""
        emu, h = self._make_enclave_emu()
        # 让 S 模式从 X-only 页读取: 若实现错误地把取指放宽波及数据读,
        # 这里将不再触发 LoadPageFault.
        h.pc = self.TRAP_VEC_VA
        h.gprs[4] = self.TRAP_VEC_VA  # ld x1, 0(x4) 的源地址指向 X-only 页
        # 在 trap_vector 放一条加载指令: ld x1, 0(x4) = 0x00023083
        emu.load_code(
            self.TEXT_PA,
            (0x0002_3083).to_bytes(4, "little") + b"\x13\x00\x00\x00" * 255,
        )
        # 关闭 STIP 干扰 (stimecmp 设远未来), 专注数据访问
        h.csrs["stimecmp"].val = 1 << 40
        emu.clint._mtime = 0
        # LoadPageFault (bit 13) 委派 S — 否则同步异常投递到 M 模式写
        # mcause/mtval, scause 不更新 (与 runtime 显式委派页错误的配置一致)
        h.csrs["medeleg"].val |= 1 << 13

        emu.step()

        # S 模式同步异常投递到 stvec, cause 存于 scause (非 mcause)
        assert h.csrs["scause"].val == 13, (  # LoadPageFault
            f"X-only 页数据读应触发 LoadPageFault, 实际 scause=0x{h.csrs['scause'].val:x}"
        )
        assert h.csrs["stval"].val == self.TRAP_VEC_VA
