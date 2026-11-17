#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""RISC-V RV64 反汇编器.

将 32-bit / 16-bit 指令字翻译为可读汇编字符串, 覆盖 RV64 I + M + Zicsr + AMO
与 C、F、D 扩展, 与 decoder/ 的 Hart 执行单元对齐.

按指令类别分模块实现: alu、load_store、branch、csr、atom、compressed、fpu.
本模块给出分发表与入口, 并转出 common 的公开定义.
"""

from collections.abc import Callable

from pyremu.disasm.alu import (
    dis_auipc,
    dis_itype,
    dis_lui,
    dis_op32,
    dis_op_imm32,
    dis_rtype,
)
from pyremu.disasm.atom import dis_amo
from pyremu.disasm.branch import dis_branch, dis_jal, dis_jalr
from pyremu.disasm.common import (
    AMOF5_MAP,
    AmoFunct5,
    AMOW_MAP,
    AmoWidth,
    BrFn3,
    BrFn3_MAP,
    decode_c_sdsp,
    decode_sd_sp,
    fmt_addr,
    fmt_imm,
    LdFn3,
    LdFn3_MAP,
    Opc,
    parse_compressed,
    parse_func3,
    parse_func6,
    parse_func7,
    parse_func12,
    parse_imm12_raw,
    parse_imm12_se,
    parse_imm20_raw,
    parse_imm_b,
    parse_imm_j,
    parse_imm_s,
    parse_opcode,
    parse_rd,
    parse_rs1,
    parse_rs2,
    rd_name,
    rs1_name,
    rs2_name,
    StFn3,
    StFn3_MAP,
    SysFn12,
    UNKNOWN,
)
from pyremu.disasm.compressed import dis_compressed
from pyremu.disasm.csr import dis_csr, dis_fence, dis_priv
from pyremu.disasm.fpu import dis_fp_fma, dis_fp_load, dis_fp_op, dis_fp_store
from pyremu.disasm.load_store import dis_load, dis_store

__all__ = [
    "AMOF5_MAP",
    "AMOW_MAP",
    "BrFn3",
    "BrFn3_MAP",
    "LdFn3",
    "LdFn3_MAP",
    "Opc",
    "StFn3",
    "StFn3_MAP",
    "SysFn12",
    "UNKNOWN",
    "AmoFunct5",
    "AmoWidth",
    "decode_c_sdsp",
    "decode_sd_sp",
    "disasm",
    "fmt_addr",
    "fmt_imm",
    "parse_compressed",
    "parse_func3",
    "parse_func6",
    "parse_func7",
    "parse_func12",
    "parse_imm_b",
    "parse_imm_j",
    "parse_imm_s",
    "parse_imm12_raw",
    "parse_imm12_se",
    "parse_imm20_raw",
    "parse_opcode",
    "parse_rd",
    "parse_rs1",
    "parse_rs2",
    "rd_name",
    "rs1_name",
    "rs2_name",
]


#  主入口


_DISASM_HANDLERS: dict[Opc, Callable[[int], str]] = {
    Opc.op: dis_rtype,
    Opc.op_imm: dis_itype,
    Opc.op_imm32: dis_op_imm32,
    Opc.op32: dis_op32,
    Opc.ld: dis_load,
    Opc.st: dis_store,
    Opc.jalr: dis_jalr,
    Opc.lui: dis_lui,
    Opc.auipc: dis_auipc,
    Opc.fence: dis_fence,
    Opc.amo: dis_amo,
    Opc.ld_fp: dis_fp_load,
    Opc.stfp: dis_fp_store,
    Opc.fp_op: dis_fp_op,
    Opc.fmadd: dis_fp_fma,
    Opc.fmsub: dis_fp_fma,
    Opc.fnmsub: dis_fp_fma,
    Opc.fnmadd: dis_fp_fma,
}

# 分支与跳转的助记符需要 pc 计算目标地址, 故单独一张表.
_DISASM_PC_HANDLERS: dict[Opc, Callable[[int, int], str]] = {
    Opc.br: dis_branch,
    Opc.jal: dis_jal,
}


def _dis_unknown(instr: int) -> str:
    return UNKNOWN


def disasm(
    instr: int,
    pc: int,
) -> str:
    """反汇编一条 RISC-V 指令.

    Args:
        instr: 4 字节指令字 (小端).
        pc: 当前指令的虚拟地址 (用于计算分支/跳转目标).

    Returns:
        反汇编字符串 ("mnemonic     operands").
        未知指令返回 "<unk-op>".
        16-bit 压缩指令返回解码后的汇编字符串.
    """
    if parse_compressed(instr):
        return dis_compressed(instr & 0xFFFF, pc)

    try:
        opc = Opc(parse_opcode(instr))
    except ValueError:
        # op_imm32 (0b00110_11) 不在 Opc enum 中, 单独处理
        return (
            dis_op_imm32(instr)
            if parse_opcode(instr) == 0b00110_11
            else UNKNOWN
        )

    if opc == Opc.sys:
        return (
            dis_priv(instr) if parse_func3(instr) == 0b000 else dis_csr(instr)
        )
    pc_handler = _DISASM_PC_HANDLERS.get(opc)
    if pc_handler is not None:
        return pc_handler(instr, pc)
    return _DISASM_HANDLERS.get(opc, _dis_unknown)(instr)
