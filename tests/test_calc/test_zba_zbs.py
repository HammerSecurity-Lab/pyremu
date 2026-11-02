#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""Zba 与 Zbs 位操作扩展指令测试.

Zba (地址生成): sh1add, sh2add, sh3add, add.uw, sh1add.uw, sh2add.uw,
sh3add.uw, slli.uw. uw 形式只把 rs1 截断为 32 位, rs2 取完整的 64 位参与加法,
结果不做符号扩展.

Zbs (单比特): bset, bclr, binv, bext, bseti, bclri, binvi, bexti. 寄存器形式的
移位量取 rs2 的低 6 位, 立即数形式取 imm 的低 6 位.
"""

import pytest

from pyremu.core.decoder import Hart
from tests.instr_encode import i_type, pack_funct, pack_src_regs, r_type

# Opcode 常量
OP_ALU = 0b0110011  # R-type ALU
OP_IMM = 0b0010011  # I-type immediate
OP_IMM32 = 0b0011011  # I-type 32-bit
OP32 = 0b0111011  # R-type 32-bit

# Zba funct7 常量
ZBA_FUNCT7_ADDR_GEN = 0x10
ZBA_FUNCT7_ADD_UW = 0x04

# Zbs funct7 常量
ZBS_FUNCT7_BSET = 0x14
ZBS_FUNCT7_BCLR_BEXT = 0x24
ZBS_FUNCT7_BINV = 0x34

# Zbs 立即数形式: funct6 左移 6 位再接移位量
ZBS_FUNCT6_BSETI = 0x0A
ZBS_FUNCT6_BCLRI_BEXTI = 0x12
ZBS_FUNCT6_BINVI = 0x1A

MASK64 = (1 << 64) - 1
BIT40 = 1 << 40


# =====================================================================
#  Zba: sh1add, sh2add, sh3add
# =====================================================================


class TestZbaAddressGeneration:
    """Zba 地址生成指令的 64 位形式."""

    @pytest.mark.parametrize(
        "rs1, rs2, fn3, expect_rd, instr_name",
        [
            # 移位次数由 funct3 区分: rs1=1 时结果为 2/4/8
            (1, 0, 0b010, 2, "sh1add"),
            (1, 0, 0b100, 4, "sh2add"),
            (1, 0, 0b110, 8, "sh3add"),
            # rs2 参与完整加法
            (0x1000, 0x234, 0b010, 0x2234, "sh1add"),
            (0x1000, 0x234, 0b110, 0x8234, "sh3add"),
            # 高位左移后按 64 位截断
            (0x8000_0000_0000_0000, 0, 0b010, 0, "sh1add"),
            (0x4000_0000_0000_0000, 0, 0b100, 0, "sh2add"),
            (0x2000_0000_0000_0000, 0, 0b110, 0, "sh3add"),
            # 加法溢出按 64 位截断
            (
                0x8000_0000_0000_0000,
                0x8000_0000_0000_0000,
                0b010,
                0x8000_0000_0000_0000,
                "sh1add",
            ),
        ],
    )
    def test_zba_rtype(  # noqa: PLR0913, PLR0917 — 参数化测试, 每列一个形参
        self,
        hart: Hart,
        rs1: int,
        rs2: int,
        fn3: int,
        expect_rd: int,
        instr_name: str,
    ):
        hart.gprs[1] = rs1
        hart.gprs[2] = rs2
        instr = r_type(OP_ALU, 3, pack_funct(ZBA_FUNCT7_ADDR_GEN, fn3), pack_src_regs(1, 2))
        hart.exec_instr(instr)
        assert hart.gprs[3] == expect_rd, (
            f"wrong at instr<{instr_name}>:fn3<{fn3}>, gpr1<{rs1}>, gpr2<{rs2}>"
        )


# =====================================================================
#  Zba: add.uw / shXadd.uw (OP-32 = 0x3B)
# =====================================================================


class TestZbaWordAddressGeneration:
    """Zba 的 uw 形式: 只截断 rs1, rs2 取完整值, 结果不做符号扩展."""

    @pytest.mark.parametrize(
        "rs1, rs2, fn7, fn3, expect_rd, instr_name",
        [
            # rs1 的第 32 位至第 63 位被丢弃
            (0xFFFF_FFFF_FFFF_FFFF, 0, ZBA_FUNCT7_ADD_UW, 0b000, 0xFFFF_FFFF, "add.uw"),
            (0x0000_0000_8000_0000, 0, ZBA_FUNCT7_ADD_UW, 0b000, 0x8000_0000, "add.uw"),
            # rs2 的第 32 位保留, 结果不做符号扩展
            (
                0xFFFF_FFFF,
                0x1_0000_0000,
                ZBA_FUNCT7_ADD_UW,
                0b000,
                0x1_FFFF_FFFF,
                "add.uw",
            ),
            # shXadd.uw: rs1 截断后左移, 再与完整的 rs2 相加
            (
                0xFFFF_FFFF_FFFF_FFFF,
                0x1_0000_0000,
                ZBA_FUNCT7_ADDR_GEN,
                0b010,
                0x2_FFFF_FFFE,
                "sh1add.uw",
            ),
            (
                0xFFFF_FFFF_FFFF_FFFF,
                0x1_0000_0000,
                ZBA_FUNCT7_ADDR_GEN,
                0b100,
                0x4_FFFF_FFFC,
                "sh2add.uw",
            ),
            (
                0xFFFF_FFFF_FFFF_FFFF,
                0x1_0000_0000,
                ZBA_FUNCT7_ADDR_GEN,
                0b110,
                0x8_FFFF_FFF8,
                "sh3add.uw",
            ),
            # 左移进入第 32 位以上
            (0xFFFF_FFFF, 0, ZBA_FUNCT7_ADDR_GEN, 0b110, 0x7_FFFF_FFF8, "sh3add.uw"),
        ],
    )
    def test_zba_uw_rtype(  # noqa: PLR0913, PLR0917 — 参数化测试, 每列一个形参
        self,
        hart: Hart,
        rs1: int,
        rs2: int,
        fn7: int,
        fn3: int,
        expect_rd: int,
        instr_name: str,
    ):
        hart.gprs[1] = rs1
        hart.gprs[2] = rs2
        instr = r_type(OP32, 3, pack_funct(fn7, fn3), pack_src_regs(1, 2))
        hart.exec_instr(instr)
        assert hart.gprs[3] == expect_rd, (
            f"wrong at instr<{instr_name}>:fn3<{fn3}>, gpr1<{rs1}>, gpr2<{rs2}>"
        )


# =====================================================================
#  Zba: slli.uw (OP-IMM-32 = 0x1B, funct3 = 001)
# =====================================================================


class TestZbaSlliUw:
    """slli.uw 的移位量为 6 位, 取值为 0 至 63."""

    @pytest.mark.parametrize(
        "rs1, shamt, expect_rd",
        [
            (0xFFFF_FFFF_FFFF_FFFF, 1, 0x1_FFFF_FFFE),
            (1, 32, 0x1_0000_0000),
            # 移位量不小于 32 时编码的 funct7 最低位为 1, 必须仍按该移位量计算
            (0xFFFF_FFFF, 33, 0xFFFF_FFFE_0000_0000),
            (1, 63, 0x8000_0000_0000_0000),
            (0xDEAD_BEEF, 0, 0xDEAD_BEEF),
        ],
    )
    def test_slli_uw(
        self,
        hart: Hart,
        rs1: int,
        shamt: int,
        expect_rd: int,
    ):
        hart.gprs[1] = rs1
        # I 型的 imm[11:5] 为 funct7, 第 6 个移位位并入 funct7 的最低位
        imm = (ZBA_FUNCT7_ADD_UW << 5) | shamt
        hart.exec_instr(i_type(OP_IMM32, 3, 0b001, 1, imm))
        assert hart.gprs[3] == expect_rd, f"wrong at slli.uw:shamt<{shamt}>, gpr1<{rs1}>"


# =====================================================================
#  Zbs: bset, bclr, binv, bext
# =====================================================================


class TestZbsRtype:
    """Zbs 寄存器形式: 移位量取 rs2 的低 6 位."""

    @pytest.mark.parametrize(
        "rs1, rs2, fn7, fn3, expect_rd, instr_name",
        [
            # 第 40 位: 5 位移位量无法表示, 区分 6 位与 5 位实现
            (0, 40, ZBS_FUNCT7_BSET, 0b001, BIT40, "bset"),
            (MASK64, 40, ZBS_FUNCT7_BCLR_BEXT, 0b001, MASK64 ^ BIT40, "bclr"),
            (0, 40, ZBS_FUNCT7_BINV, 0b001, BIT40, "binv"),
            (BIT40, 40, ZBS_FUNCT7_BINV, 0b001, 0, "binv"),
            (BIT40, 40, ZBS_FUNCT7_BCLR_BEXT, 0b101, 1, "bext"),
            (BIT40, 0, ZBS_FUNCT7_BCLR_BEXT, 0b101, 0, "bext"),
            # 移位量对 64 取模: rs2=0x60 的低 6 位为 32
            (0, 0x60, ZBS_FUNCT7_BSET, 0b001, 0x1_0000_0000, "bset"),
            (0, 0x140, ZBS_FUNCT7_BSET, 0b001, 1, "bset"),
            # rs1 的对应位已置位时 bset 保持不变
            (MASK64, 40, ZBS_FUNCT7_BSET, 0b001, MASK64, "bset"),
        ],
    )
    def test_zbs_rtype(  # noqa: PLR0913, PLR0917 — 参数化测试, 每列一个形参
        self,
        hart: Hart,
        rs1: int,
        rs2: int,
        fn7: int,
        fn3: int,
        expect_rd: int,
        instr_name: str,
    ):
        hart.gprs[1] = rs1
        hart.gprs[2] = rs2
        instr = r_type(OP_ALU, 3, pack_funct(fn7, fn3), pack_src_regs(1, 2))
        hart.exec_instr(instr)
        assert hart.gprs[3] == expect_rd, (
            f"wrong at instr<{instr_name}>:fn7<{fn7}>, gpr1<{rs1}>, gpr2<{rs2}>"
        )


# =====================================================================
#  Zbs: bseti / bclri / binvi / bexti (OP-IMM = 0x13)
# =====================================================================


class TestZbsItype:
    """Zbs 立即数形式: 移位量取 imm 的低 6 位."""

    @pytest.mark.parametrize(
        "rs1, funct6, fn3, shamt, expect_rd, instr_name",
        [
            # 第 40 位: 掩码到 5 位会错误地置第 8 位
            (0, ZBS_FUNCT6_BSETI, 0b001, 40, BIT40, "bseti"),
            (0, ZBS_FUNCT6_BCLRI_BEXTI, 0b001, 40, 0, "bclri"),
            (MASK64, ZBS_FUNCT6_BCLRI_BEXTI, 0b001, 40, MASK64 ^ BIT40, "bclri"),
            (0, ZBS_FUNCT6_BINVI, 0b001, 40, BIT40, "binvi"),
            (BIT40, ZBS_FUNCT6_BINVI, 0b001, 40, 0, "binvi"),
            (BIT40, ZBS_FUNCT6_BCLRI_BEXTI, 0b101, 40, 1, "bexti"),
            (BIT40, ZBS_FUNCT6_BCLRI_BEXTI, 0b101, 0, 0, "bexti"),
            (0, ZBS_FUNCT6_BSETI, 0b001, 63, 0x8000_0000_0000_0000, "bseti"),
        ],
    )
    def test_zbs_itype(  # noqa: PLR0913, PLR0917 — 参数化测试, 每列一个形参
        self,
        hart: Hart,
        rs1: int,
        funct6: int,
        fn3: int,
        shamt: int,
        expect_rd: int,
        instr_name: str,
    ):
        hart.gprs[1] = rs1
        imm = (funct6 << 6) | shamt
        hart.exec_instr(i_type(OP_IMM, 3, fn3, 1, imm))
        assert hart.gprs[3] == expect_rd, (
            f"wrong at instr<{instr_name}>:imm<{imm:#x}>, gpr1<{rs1}>"
        )
