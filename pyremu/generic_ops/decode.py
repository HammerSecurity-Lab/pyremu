# SPDX-LICENSE-IDENTIFIER: MIT
"""指令字段解码 — 有动态链接库时经加速执行引擎, 否则走本模块的纯 Python 实现.

两个入口返回与 Rust ``#[repr(C)]`` 结构体同布局的 ctypes 对象; 纯 Python 实现
以 ``_decode_fields_py`` 与 ``_decode_compressed_py`` 的名字放在同一文件内.
"""

from __future__ import annotations

from pyremu._native import CompressedFields, DecodedFields, loaded_lib
from pyremu.decoder import compressed_imm
from pyremu.utils.mask import (
    creg,
    mask08,
    mask12,
    mask16,
    mask32,
    mask64,
    sext12,
)


def _decode_fields_py(instr: int) -> DecodedFields:
    """Pure-Python equivalent of Rust ``decode_fields()``."""
    f = DecodedFields()
    instr = mask32(instr)

    # Fixed fields
    f.opcode = instr & 0x7F
    f.rd = (instr >> 7) & 0x1F
    f.func3 = (instr >> 12) & 0x7
    f.rs1 = (instr >> 15) & 0x1F
    f.rs2 = (instr >> 20) & 0x1F
    f.func7 = (instr >> 25) & 0x7F
    f.func12 = mask12(instr >> 20)
    f.is_compressed = int((instr & 0x3) != 3)
    # F/D: rs3 = bits[31:27], fmt = bits[26:25]
    f.rs3 = (instr >> 27) & 0x1F
    f.fmt = (instr >> 25) & 0x3

    f.imm12_se = sext12(mask12(instr >> 20))
    f.imm20_raw = (instr >> 12) & 0xF_FFFF

    imm_s = ((instr >> 25) & 0x7F) << 5 | ((instr >> 7) & 0x1F)
    f.imm_s = sext12(imm_s)

    imm_b = ((instr >> 31) & 1) << 12
    imm_b |= ((instr >> 25) & 0x3F) << 5
    imm_b |= (mask08(instr >> 8)) << 1
    imm_b |= ((instr >> 7) & 1) << 11
    f.imm_b = mask12(imm_b) - mask64(imm_b & 0x1000)

    imm_j = ((instr >> 31) & 1) << 20
    imm_j |= ((instr >> 21) & 0x3FF) << 1
    imm_j |= ((instr >> 20) & 1) << 11
    imm_j |= (mask08(instr >> 12)) << 12
    f.imm_j = (imm_j & 0xF_FFFF) - mask64(imm_j & 0x10_0000)

    return f


#  Public decode function


def _decode_compressed_py(half: int) -> CompressedFields:
    """Pure-Python equivalent of Rust ``decode_compressed()``."""
    cf = CompressedFields()
    h = mask16(half)
    cf.quadrant = h & 0x3
    cf.funct3 = (h >> 13) & 0x7

    bit12 = (h >> 12) & 0x1
    cf.bit12 = bit12
    cf.bit65 = (h >> 5) & 0x3
    cf.sf = (h >> 10) & 0x3

    bits_6_2 = (h >> 2) & 0x1F
    bits_11_7 = (h >> 7) & 0x1F

    # ---- register fields ----
    cf.rdp = creg((h >> 2) & 0x7)  # C0 rd/rs2, C1-ALU rs2
    cf.rs1p = creg((h >> 7) & 0x7)  # C0 rs1, C1-ALU rd

    if cf.quadrant == 0:
        cf.rd = cf.rdp
        cf.rs1 = cf.rs1p
        cf.rs2 = cf.rdp
    else:
        cf.rd = bits_11_7
        cf.rs1 = bits_11_7
        cf.rs2 = bits_6_2

    imm, imm2 = compressed_imm.immediates(h, cf.funct3, cf.quadrant)

    cf.imm = mask64(imm)
    cf.imm2 = mask64(imm2)
    return cf


def decode_fields(instr: int) -> DecodedFields:
    """解出 32 位指令的全部字段."""
    lib = loaded_lib()
    if lib is None:
        return _decode_fields_py(instr)
    return lib.decode_fields(instr)


def decode_compressed(half: int) -> CompressedFields:
    """解出 16 位压缩指令的字段."""
    lib = loaded_lib()
    if lib is None:
        return _decode_compressed_py(half)
    return lib.decode_compressed(half)


__all__ = ["decode_compressed", "decode_fields"]
