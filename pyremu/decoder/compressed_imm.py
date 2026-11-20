# SPDX-LICENSE-IDENTIFIER: MIT
"""压缩指令的立即数解码.

按象限解出 16 位压缩指令的偏移; 第二个分量只用于象限 2 的存储类指令. 本模块
"""

from __future__ import annotations

from pyremu.utils.mask import mask64


def immediates(h: int, funct3: int, quadrant: int) -> tuple[int, int]:
    """按象限解码立即数; 第二个分量只用于象限 2 的存储类指令."""
    if quadrant == 0:
        return imm_q0(h, funct3), 0
    if quadrant == 1:
        return imm_q1(h, funct3), 0
    if quadrant == 2:
        return imm_q2(h, funct3)
    return 0, 0


def imm_q0(h: int, funct3: int) -> int:
    """象限 0 的立即数: C.ADDI4SPN / C.LW / C.SW / C.FLD / C.LD /
    C.FSD / C.SD."""
    if funct3 == 0:
        return (
            ((h >> 6) & 0x1) << 2
            | ((h >> 5) & 0x1) << 3
            | ((h >> 11) & 0x1) << 4
            | ((h >> 12) & 0x1) << 5
            | ((h >> 7) & 0xF) << 6
        )
    if funct3 in (2, 6):
        # C.LW / C.SW: uimm[5:3|2|6]
        return (
            ((h >> 6) & 0x1) << 2
            | ((h >> 10) & 0x7) << 3
            | ((h >> 5) & 0x1) << 6
        )
    if funct3 in (1, 3, 5, 7):
        # C.FLD / C.LD / C.FSD / C.SD: uimm[5:3|6|7]
        return ((h >> 5) & 0x3) << 6 | ((h >> 10) & 0x7) << 3
    return 0


def imm_q1_lui(h: int, bit12: int, bits_6_2: int) -> int:
    """funct3=011: C.ADDI16SP (rd=2) 的 10 位 nzimm, 否则 C.LUI 的 6 位
    nzimm."""
    bits_11_7 = (h >> 7) & 0x1F
    if bits_11_7 == 2:
        # C.ADDI16SP: 10-bit signed nzimm
        nz = ((h >> 6) & 0x1) << 4
        nz |= ((h >> 2) & 0x1) << 5
        nz |= ((h >> 5) & 0x1) << 6
        nz |= ((h >> 3) & 0x3) << 7
        nz |= bit12 << 9
        return (nz & 0x1FF) - (nz & 0x200) & 0xFFFF_FFFF_FFFF_FFFF
    # C.LUI: 6-bit signed nzimm (shift-left-12 in caller)
    nz = (bit12 << 5) | bits_6_2
    return (nz & 0x1F) - (nz & 0x20) & 0xFFFF_FFFF_FFFF_FFFF


def imm_q1_shamt(bit12: int, bits_6_2: int) -> int:
    """C.SRLI/C.SRAI/C.ANDI 的 6 位立即数, 由 bit12 与 bits[6:2] 组成.

    funct3=100 的立即数不参与 ``immediates`` 的按象限取值, 故单独给出.
    """
    return (bit12 << 5) | (bits_6_2 & 0x1F)


def imm_q1(h: int, funct3: int) -> int:
    """象限 1 的立即数: 立即数算术、C.ADDI16SP / C.LUI、跳转与分支."""
    bit12 = (h >> 12) & 0x1
    bits_6_2 = (h >> 2) & 0x1F
    if funct3 in (0, 1, 2):
        # C.ADDI / C.ADDIW / C.LI: 6-bit signed imm
        raw = (bit12 << 5) | bits_6_2
        return (raw & 0x1F) - mask64(raw & 0x20)
    if funct3 == 3:
        return imm_q1_lui(h, bit12, bits_6_2)
    if funct3 == 5:
        # C.J: 11-bit signed offset
        off = bit12 << 11
        off |= ((h >> 8) & 0x1) << 10
        off |= ((h >> 9) & 0x3) << 8
        off |= ((h >> 6) & 0x1) << 7
        off |= ((h >> 7) & 0x1) << 6
        off |= ((h >> 2) & 0x1) << 5
        off |= ((h >> 11) & 0x1) << 4
        off |= ((h >> 3) & 0x7) << 1
        return (off & 0x7FF) - mask64(off & 0x800)
    if funct3 in (6, 7):
        # C.BEQZ / C.BNEZ: 9-bit signed offset
        off = bit12 << 8
        off |= ((h >> 10) & 0x3) << 3  # offset[4:3]
        off |= ((h >> 5) & 0x3) << 6  # offset[7:6]
        off |= ((h >> 2) & 0x1) << 5  # offset[5]
        off |= ((h >> 3) & 0x3) << 1  # offset[2:1]
        return (off & 0xFF) - (off & 0x100) & 0xFFFF_FFFF_FFFF_FFFF
    return 0


def imm_q2(h: int, funct3: int) -> tuple[int, int]:
    """象限 2 的立即数: 载入类的偏移写入第一个分量, 存储类的偏移写入第二个."""
    bit12 = (h >> 12) & 0x1
    bits_6_2 = (h >> 2) & 0x1F
    if funct3 == 0:
        return (bit12 << 5) | bits_6_2, 0
    if funct3 == 2:
        return ((h >> 2) & 0x3) << 6 | bit12 << 5 | ((h >> 4) & 0x7) << 2, 0
    if funct3 in (1, 3):
        # C.FLDSP / C.LDSP: uimm[5|4:3|8:6]
        return ((h >> 2) & 0x7) << 6 | bit12 << 5 | ((h >> 5) & 0x3) << 3, 0
    if funct3 == 6:
        return 0, ((h >> 9) & 0xF) << 2 | ((h >> 7) & 0x3) << 6
    if funct3 in (5, 7):
        # C.FSDSP / C.SDSP: uimm[5:3|8:6]
        return 0, ((h >> 7) & 0x7) << 6 | ((h >> 10) & 0x7) << 3
    return 0, 0
