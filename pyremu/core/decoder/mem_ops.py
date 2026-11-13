# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""访存指令的操作数解码与取值辅助.

包括 c.sdsp / sd rs2, imm(sp) 的编码识别、按加载类型读取与符号扩展、
原子操作的宽度与结果计算.
"""

from pyremu.utils.disassem import AmoFunct5, AmoWidth, LdFn3
from pyremu.utils.mask import (
    MASK32,
    MASK64,
    sext,
    sext8,
    sext16,
    sext32,
    sint64,
)


def decode_c_sdsp(half: int) -> tuple[int, int] | None:
    """If *half* is ``c.sdsp rs2, uimm(sp)``, return ``(rs2, uimm)``; else None.

    C.SDSP encoding (C2 quadrant, RV64 only):
        bits[1:0]   = 10
        bits[4:2]   = rs2 (x8--x15 in standard, but we also accept x1)
        bits[6:5]   = uimm[5:3] lower bits
        bits[12:10] = uimm[5:3]
        bits[9:7]   = uimm[8:6]
        bits[15:13] = 111 (funct3)
    The uimm is assembled from {bits[9:7], bits[12:10]} << 3, i.e. 8-byte
    aligned.
    """
    if (half & 0xE003) != 0xE002:  # bits[15:13]=111, bits[1:0]=10
        return None
    rs2 = (half >> 2) & 0x1F
    uimm = ((half >> 7) & 0x7) << 6  # bits[9:7]  -> uimm[8:6]
    uimm |= ((half >> 10) & 0x7) << 3  # bits[12:10] -> uimm[5:3]
    return rs2, uimm


def decode_sd_sp(instr: int) -> tuple[int, int] | None:
    """If *instr* is ``sd rs2, imm(sp)``, return ``(rs2, imm)``; else None.

    S-type encoding:
        opcode (bits[6:0])   = 0b0100011 (STORE)
        funct3 (bits[14:12]) = 0b011     (SD / doubleword store)
        rs1    (bits[19:15]) = 2         (sp)
        rs2    (bits[24:20]) = source register
        imm[4:0]  at bits[11:7], imm[11:5] at bits[31:25]
    """
    if (instr & 0x7F) != 0b0100011:
        return None
    if ((instr >> 12) & 0x7) != 0b011:  # funct3 = SD
        return None
    if ((instr >> 15) & 0x1F) != 2:  # rs1 = sp
        return None
    rs2 = (instr >> 20) & 0x1F
    imm = ((instr >> 25) << 5) | ((instr >> 7) & 0x1F)
    if imm & 0x800:  # 按有符号立即数返回, 供调用方与 sp 相加
        imm -= 0x1000
    return rs2, imm


# ---------------------------------------------------------------
#  加载与原子操作的取值
# ---------------------------------------------------------------


LD_READ_SIZE = {
    LdFn3.lb: 1,
    LdFn3.lbu: 1,
    LdFn3.lh: 2,
    LdFn3.lhu: 2,
    LdFn3.lw: 4,
    LdFn3.lwu: 4,
    LdFn3.ld: 8,
}

_LD_SIGN_EXTEND = {
    LdFn3.lb: sext8,
    LdFn3.lh: sext16,
    LdFn3.lw: sext32,
}


def load_value(kind: LdFn3, mem: bytes) -> int:
    """按加载指令的宽度解码内存字节, 有符号形式做符号扩展."""
    raw = int.from_bytes(mem, "little")
    extend = _LD_SIGN_EXTEND.get(kind)
    return raw if extend is None else extend(raw)


def amo_width(width: AmoWidth) -> tuple[int, int]:
    """返回该 AMO 宽度的字节数与位掩码."""
    return (8, MASK64) if width == AmoWidth.D else (4, MASK32)


def _amo_signed(val: int, width: AmoWidth) -> int:
    """按 AMO 宽度做符号扩展后取有符号值."""
    return sint64(sext(val, 64 if width == AmoWidth.D else 32))


def amo_result(
    op: AmoFunct5,
    mem_val: int,
    op_val: int,
    width: AmoWidth,
    mask: int,
) -> int:
    """按 AMO 子操作计算写回内存的新值."""
    if op == AmoFunct5.SWAP:
        result = op_val
    elif op == AmoFunct5.ADD:
        result = (mem_val + op_val) & mask
    elif op == AmoFunct5.XOR:
        result = mem_val ^ op_val
    elif op == AmoFunct5.AND:
        result = mem_val & op_val
    elif op == AmoFunct5.OR:
        result = mem_val | op_val
    elif op == AmoFunct5.MIN:
        result = min(op_val, mem_val, key=lambda v: _amo_signed(v, width))
    elif op == AmoFunct5.MAX:
        result = max(op_val, mem_val, key=lambda v: _amo_signed(v, width))
    elif op == AmoFunct5.MINU:
        result = op_val if op_val < mem_val else mem_val
    elif op == AmoFunct5.MAXU:
        result = op_val if op_val > mem_val else mem_val
    else:
        raise ValueError(f"unhandled AMO op: {op}")
    return result & mask
