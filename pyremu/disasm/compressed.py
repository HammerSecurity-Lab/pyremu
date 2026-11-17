"""压缩指令 (C 扩展)."""

from collections.abc import Callable

from pyremu.disasm.common import (
    fmt_addr,
)
from pyremu.disasm.regname import gpr_name
from pyremu.utils.mask import mask64

#  压缩指令 (C extension) 反汇编

# 寄存器: x8-x15 使用 3-bit 缩写索引 rd′/rs1′/rs2′.


def _c_x8(idx3: int) -> str:
    """由 3-bit 压缩寄存器索引得到 ABI 名, 即 x8 到 x15."""
    return gpr_name(8 + (idx3 & 0b111))


def dis_compressed(
    c16: int,
    pc: int,
) -> str:
    """反汇编 16-bit RISC-V 压缩指令 (C extension).

    覆盖 RV64C 常用指令: 寄存器操作、立即数、Load/Store、分支、跳转。
    未实现的编码退回 raw hex 显示。
    """
    quad = c16 & 0b11
    if quad == 0b00:
        return _dis_c0(c16)
    if quad == 0b01:
        return _dis_c1(c16, pc)
    if quad == 0b10:
        return _dis_c2(c16, pc)
    return _c_unknown(c16)


def _c_unknown(c16: int) -> str:
    return f"c.?    0x{c16:04x}"


# ---- 象限 0: CIW / CL / CS ----


def _c0_addi4spn(c16: int) -> str:
    rd_p = _c_x8(c16 >> 2)
    # 基址寄存器固定为 sp (x2), bits[9:7] 属于立即数而非 rs1' 字段.
    uimm = (
        ((c16 >> 7) & 0x0F) << 6  # instr[10:7] -> nzuimm[9:6]
        | ((c16 >> 11) & 0x03) << 4  # instr[12:11] -> nzuimm[5:4]
        | ((c16 >> 5) & 1) << 3  # instr[5] -> nzuimm[3]
        | ((c16 >> 6) & 1) << 2  # instr[6] -> nzuimm[2]
    )
    if uimm == 0:
        return f"c.?    0x{c16:04x}  # C.ADDI4SPN nzuimm=0 (reserved)"
    return f"c.addi4spn {rd_p}, sp, {uimm}"


def _c0_fld(c16: int) -> str:
    uimm = ((c16 >> 5) & 0b11) << 6 | ((c16 >> 10) & 0b111) << 3
    fpr_rd = 8 + ((c16 >> 2) & 0b111)
    return f"c.fld        f{fpr_rd}, {uimm}({_c_x8(c16 >> 7)})"


def _c0_lw(c16: int) -> str:
    uimm = (
        ((c16 >> 5) & 1) << 6
        | ((c16 >> 10) & 0b111) << 3
        | ((c16 >> 6) & 1) << 2
    )
    return f"c.lw         {_c_x8(c16 >> 2)}, {uimm}({_c_x8(c16 >> 7)})"


def _c0_ld(c16: int) -> str:
    uimm = ((c16 >> 5) & 0b11) << 6 | ((c16 >> 10) & 0b111) << 3
    return f"c.ld         {_c_x8(c16 >> 2)}, {uimm}({_c_x8(c16 >> 7)})"


def _c0_fsd(c16: int) -> str:
    uimm = ((c16 >> 5) & 0b11) << 6 | ((c16 >> 10) & 0b111) << 3
    fpr_rs2 = 8 + ((c16 >> 2) & 0b111)
    return f"c.fsd        f{fpr_rs2}, {uimm}({_c_x8(c16 >> 7)})"


def _c0_sw(c16: int) -> str:
    uimm = (
        ((c16 >> 5) & 1) << 6
        | ((c16 >> 10) & 0b111) << 3
        | ((c16 >> 6) & 1) << 2
    )
    return f"c.sw         {_c_x8(c16 >> 2)}, {uimm}({_c_x8(c16 >> 7)})"


def _c0_sd(c16: int) -> str:
    uimm = ((c16 >> 5) & 0b11) << 6 | ((c16 >> 10) & 0b111) << 3
    return f"c.sd         {_c_x8(c16 >> 2)}, {uimm}({_c_x8(c16 >> 7)})"


_C0_HANDLERS: dict[int, Callable[[int], str]] = {
    0b000: _c0_addi4spn,
    0b001: _c0_fld,  # C.FLD (RV64DC)
    0b010: _c0_lw,
    0b011: _c0_ld,  # RV64
    0b101: _c0_fsd,  # C.FSD (RV64DC)
    0b110: _c0_sw,
    0b111: _c0_sd,  # RV64
}


def _dis_c0(c16: int) -> str:
    """象限 0: C.ADDI4SPN / C.FLD / C.LW / C.LD / C.FSD / C.SW / C.SD."""
    handler = _C0_HANDLERS.get((c16 >> 13) & 0b111)
    if handler is None:
        return _c_unknown(c16)
    return handler(c16)


# ---- 象限 1: CI / CJ / CB ----


def _c1_imm6(c16: int) -> int:
    """bits[12] 与 bits[6:2] 组成的 6 位立即数, 按 bit 5 符号扩展."""
    imm6 = ((c16 >> 12) & 1) << 5 | ((c16 >> 2) & 0x1F)
    return (imm6 & 0x20) and (imm6 | ~0x3F) or imm6


def _c1_addi(c16: int, pc: int) -> str:
    rd_raw = (c16 >> 7) & 0x1F
    imm6_se = _c1_imm6(c16)
    if imm6_se == 0 and rd_raw == 0:  # rd=x0, imm=0 -> C.NOP
        return "c.nop"
    return f"c.addi       {gpr_name(rd_raw)}, {imm6_se}"


def _c1_addiw(c16: int, pc: int) -> str:
    return f"c.addiw {gpr_name((c16 >> 7) & 0x1F)}, {_c1_imm6(c16)}"


def _c1_li(c16: int, pc: int) -> str:
    return f"c.li         {gpr_name((c16 >> 7) & 0x1F)}, {_c1_imm6(c16)}"


def _c1_addi16sp(c16: int) -> str:
    # nzimm[9:4] encoding per RISC-V spec:
    nzimm = (
        ((c16 >> 12) & 1) << 9  # nzimm[9]
        | ((c16 >> 3) & 0b11) << 7  # nzimm[8:7]
        | ((c16 >> 5) & 1) << 6  # nzimm[6]
        | ((c16 >> 2) & 1) << 5  # nzimm[5]
        | ((c16 >> 6) & 1) << 4  # nzimm[4]
    )
    if nzimm & (1 << 9):
        nzimm |= ~((1 << 10) - 1)
    return f"c.addi16sp sp, {nzimm}"


def _c1_lui(c16: int, pc: int) -> str:
    """C.LUI (rd≠{0,2}) 与 C.ADDI16SP (rd=2) 共用 funct3=0b011."""
    rd_raw = (c16 >> 7) & 0x1F
    if rd_raw == 2:
        return _c1_addi16sp(c16)
    nzuimm = ((c16 >> 12) & 1) << 17 | ((c16 >> 2) & 0x1F) << 12
    # sext from bit 17
    if nzuimm & (1 << 17):
        nzuimm = nzuimm - (1 << 18)
    if nzuimm == 0:
        return f"c.?    0x{c16:04x}  # C.LUI nzuimm=0 (reserved)"
    return f"c.lui        {gpr_name(rd_raw)}, 0x{(nzuimm >> 12) & 0x3F:x}"


_C1_ALU_REG_MNEMONICS: dict[int, str] = {
    0b00: "c.sub",
    0b01: "c.xor",
    0b10: "c.or",
    0b11: "c.and",
}

_C1_ALU_REG_W_MNEMONICS: dict[int, str] = {
    0b00: "c.subw",
    0b01: "c.addw",
}


def _c1_alu(c16: int, pc: int) -> str:
    """C.SRLI / C.SRAI / C.ANDI 与寄存器间的 ALU 运算.

    bits[11:10] 全为 1 时由 bit12 选择 64 位或 32 位运算: bit12 清零取 C.SUB /
    C.XOR / C.OR / C.AND, 由 bits[6:5] 选择; bit12 置位取 C.SUBW / C.ADDW, 由
    bits[6:5] 选择, 其余取值属保留编码.
    """
    rd_p = _c_x8(c16 >> 7)
    b11_10 = (c16 >> 10) & 0b11
    if b11_10 == 0b00:  # C.SRLI
        uimm = ((c16 >> 2) & 0x1F) | ((c16 >> 12) & 1) << 5
        return f"c.srli       {rd_p}, {uimm}"
    if b11_10 == 0b01:  # C.SRAI
        uimm = ((c16 >> 2) & 0x1F) | ((c16 >> 12) & 1) << 5
        return f"c.srai       {rd_p}, {uimm}"
    if b11_10 == 0b10:  # C.ANDI
        return f"c.andi       {rd_p}, {_c1_imm6(c16)}"
    if (c16 >> 12) & 1:
        mn = _C1_ALU_REG_W_MNEMONICS.get((c16 >> 5) & 0b11)
        if mn is None:
            return f"c.?    0x{c16:04x}  # C.SUBW/C.ADDW 的 bits[6:5] 保留"
        return f"{mn:<12} {rd_p}, {_c_x8(c16 >> 2)}"
    mn = _C1_ALU_REG_MNEMONICS[(c16 >> 5) & 0b11]
    return f"{mn:<12} {rd_p}, {_c_x8(c16 >> 2)}"


def _c1_jump(c16: int, pc: int) -> str:
    offset = (
        ((c16 >> 12) & 1) << 11
        | ((c16 >> 8) & 1) << 10
        | ((c16 >> 9) & 0b11) << 8
        | ((c16 >> 6) & 1) << 7
        | ((c16 >> 7) & 1) << 6
        | ((c16 >> 2) & 1) << 5
        | ((c16 >> 11) & 1) << 4
        | ((c16 >> 3) & 0b11) << 1
    )
    # sign extend from bit 11
    if offset & (1 << 11):
        offset |= ~((1 << 12) - 1)
    return f"c.j          {fmt_addr(mask64(pc + offset))}"


def _c1_branch_offset(c16: int) -> int:
    """C.BEQZ 与 C.BNEZ 共用的 9 位分支偏移."""
    offset = (
        ((c16 >> 12) & 1) << 8
        | ((c16 >> 10) & 0b11) << 6
        | ((c16 >> 5) & 0b11) << 4
        | ((c16 >> 3) & 0b11) << 1
    )
    if offset & (1 << 8):
        offset |= ~((1 << 9) - 1)
    return offset


def _c1_beqz(c16: int, pc: int) -> str:
    target = mask64(pc + _c1_branch_offset(c16))
    return f"c.beqz       {_c_x8(c16 >> 7)}, {fmt_addr(target)}"


def _c1_bnez(c16: int, pc: int) -> str:
    target = mask64(pc + _c1_branch_offset(c16))
    return f"c.bnez       {_c_x8(c16 >> 7)}, {fmt_addr(target)}"


_C1_HANDLERS: dict[int, Callable[[int, int], str]] = {
    0b000: _c1_addi,  # C.NOP / C.ADDI
    0b001: _c1_addiw,  # RV64
    0b010: _c1_li,
    0b011: _c1_lui,
    0b100: _c1_alu,  # SRLI / SRAI / ANDI / SUB / XOR / OR / AND
    0b101: _c1_jump,
    0b110: _c1_beqz,
    0b111: _c1_bnez,
}


def _dis_c1(c16: int, pc: int) -> str:
    """象限 1: C.NOP / C.ADDI / C.ADDIW / C.LI / C.LUI / C.ADDI16SP /
    移位与分支."""
    handler = _C1_HANDLERS.get((c16 >> 13) & 0b111)
    if handler is None:
        return _c_unknown(c16)
    return handler(c16, pc)


# ---- 象限 2: CR / CSS ----


def _c2_slli(c16: int, pc: int) -> str:
    # rd=x0 is a HINT (executed as NOP), but display apparent semantics
    shamt = ((c16 >> 2) & 0x1F) | ((c16 >> 12) & 1) << 5
    return f"c.slli       {gpr_name((c16 >> 7) & 0x1F)}, {shamt}"


def _c2_fldsp(c16: int, pc: int) -> str:
    uimm = (
        ((c16 >> 2) & 0b111) << 6
        | ((c16 >> 12) & 1) << 5
        | ((c16 >> 5) & 0b11) << 3
    )
    # rd=0 -> ft0, valid FP destination (unlike GPR loads where x0 is reserved)
    return f"c.fldsp      f{(c16 >> 7) & 0x1F}, {uimm}(sp)"


def _c2_lwsp(c16: int, pc: int) -> str:
    # offset = {inst[3:2], inst[12], inst[6:4], 00} (4 字节对齐)
    uimm = (
        ((c16 >> 2) & 0b11) << 6
        | ((c16 >> 12) & 1) << 5
        | ((c16 >> 4) & 0b111) << 2
    )
    rd_raw = (c16 >> 7) & 0x1F
    if rd_raw == 0:
        return f"c.?    0x{c16:04x}  # C.LWSP rd=0 (reserved)"
    return f"c.lwsp       {gpr_name(rd_raw)}, {uimm}(sp)"


def _c2_ldsp(c16: int, pc: int) -> str:
    # offset = {inst[4:2], inst[12], inst[6:5], 000} (8 字节对齐)
    uimm = (
        ((c16 >> 2) & 0b111) << 6
        | ((c16 >> 12) & 1) << 5
        | ((c16 >> 5) & 0b11) << 3
    )
    rd_raw = (c16 >> 7) & 0x1F
    if rd_raw == 0:
        return f"c.?    0x{c16:04x}  # C.LDSP rd=0 (reserved)"
    return f"c.ldsp       {gpr_name(rd_raw)}, {uimm}(sp)"


def _c2_misc(c16: int, pc: int) -> str:
    """C.JR / C.JALR / C.MV / C.ADD / C.EBREAK."""
    rd_raw = (c16 >> 7) & 0x1F
    rs2_raw = (c16 >> 2) & 0x1F
    if rd_raw == 0:
        return "c.ebreak" if rs2_raw == 0 else _c_unknown(c16)
    rd_name = gpr_name(rd_raw)
    if rs2_raw == 0:  # bit12 区分 C.JR 与 C.JALR
        return (
            f"c.jalr       {rd_name}"
            if c16 & 0x1000
            else f"c.jr         {rd_name}"
        )
    rs2_name = gpr_name(rs2_raw)
    if c16 & 0x1000:  # bit12 区分 C.MV 与 C.ADD
        return f"c.add        {rd_name}, {rs2_name}"
    return f"c.mv         {rd_name}, {rs2_name}"


def _c2_fsdsp(c16: int, pc: int) -> str:
    uimm = ((c16 >> 7) & 0b111) << 6 | ((c16 >> 10) & 0b111) << 3
    return f"c.fsdsp      f{(c16 >> 2) & 0x1F}, {uimm}(sp)"


def _c2_swsp(c16: int, pc: int) -> str:
    # offset = {inst[8:7], inst[12:9], 00}  (4-byte aligned)
    uimm = ((c16 >> 7) & 0b11) << 6 | ((c16 >> 9) & 0b1111) << 2
    return f"c.swsp       {gpr_name((c16 >> 2) & 0x1F)}, {uimm}(sp)"


def _c2_sdsp(c16: int, pc: int) -> str:
    # offset = {inst[9:7], inst[12:10], 000}  (8-byte aligned)
    uimm = ((c16 >> 7) & 0b111) << 6 | ((c16 >> 10) & 0b111) << 3
    return f"c.sdsp       {gpr_name((c16 >> 2) & 0x1F)}, {uimm}(sp)"


_C2_HANDLERS: dict[int, Callable[[int, int], str]] = {
    0b000: _c2_slli,  # RV64C: shamt[5] = bit12
    0b001: _c2_fldsp,  # C.FLDSP (RV64DC)
    0b010: _c2_lwsp,
    0b011: _c2_ldsp,  # RV64
    0b100: _c2_misc,
    0b101: _c2_fsdsp,  # C.FSDSP (RV64DC)
    0b110: _c2_swsp,
    0b111: _c2_sdsp,  # RV64
}


def _dis_c2(c16: int, pc: int) -> str:
    """象限 2: C.SLLI 与 sp 相对的载入/存储, 以及 C.EBREAK 一族."""
    handler = _C2_HANDLERS.get((c16 >> 13) & 0b111)
    if handler is None:
        return _c_unknown(c16)
    return handler(c16, pc)
