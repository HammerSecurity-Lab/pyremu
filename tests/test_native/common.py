#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""tests/test_native 各文件共用的常量与辅助."""

from __future__ import annotations

from pyremu.core.decoder import Hart

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
