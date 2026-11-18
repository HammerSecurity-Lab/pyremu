#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""tests/test_native 各文件共用的常量与辅助."""

from __future__ import annotations

from pyremu import generic_ops
from pyremu.core.decoder import Hart
from pyremu.utils.mask import mask64, sext12

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


def assert_ill_instr(h: Hart, instr: int) -> None:
    """断言 *instr* 触发非法指令陷态."""
    h.csrs["mtvec"].val = 0x1000
    h.pc = 0x2000
    assert h.exec_instr(instr) == 0
    assert h.pc == 0x1000
    assert h.csrs["mcause"].val == 2


# 用例按原始字段驱动 ALU, 本适配层负责装配 DecodedFields 并统一返回值形态.


class AluResult:
    """ALU 计算的返回值, 保留 ``value`` 与 ``trap`` 形态供既有断言使用."""

    def __init__(self, value: int, trap: int = 0) -> None:
        self.value = value
        self.trap = trap


def alu_fields(func3: int, func7: int):
    """造一个只带 func3 与 func7 的字段对象."""
    f = generic_ops.decode_fields(0)
    f.func3 = func3
    f.func7 = func7
    return f


def _alu_result(call) -> AluResult:
    """把非法编码抛出的 ValueError 换算为全 1, 与引擎的陷态标记同义."""
    try:
        return AluResult(call())
    except ValueError:
        return AluResult(0xFFFF_FFFF_FFFF_FFFF, 1)


def alu_op(func3: int, func7: int, v1: int, v2: int) -> AluResult:
    """R 型 ALU 的原始字段入口."""
    f = alu_fields(func3, func7)
    return _alu_result(lambda: generic_ops.exec_alu(f, v1, v2))


def op_imm(func3: int, func7: int, v1: int, imm: int) -> AluResult:
    """I 型立即数 ALU 的原始字段入口."""
    f = alu_fields(func3, func7)
    f.imm12_se = mask64(sext12(imm))
    return _alu_result(lambda: generic_ops.exec_op_imm(f, v1))


def op32(func3: int, func7: int, v1: int, v2: int) -> AluResult:
    """RV64 32 位字运算的原始字段入口."""
    f = alu_fields(func3, func7)
    return _alu_result(lambda: generic_ops.exec_op32(f, v1, v2))


def op_imm32(func3: int, func7: int, v1: int, imm: int) -> AluResult:
    """I 型 32 位字立即数运算的原始字段入口."""
    f = alu_fields(func3, func7)
    f.imm12_se = mask64(sext12(imm))
    return _alu_result(lambda: generic_ops.exec_op_imm32(f, v1))
