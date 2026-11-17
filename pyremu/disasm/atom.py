"""原子内存操作指令."""

from pyremu.disasm.common import (
    AmoFunct5,
    AmoWidth,
    parse_func3,
    rd_name,
    rs1_name,
    rs2_name,
    UNKNOWN,
)

#  AMO


def dis_amo(instr: int) -> str:
    funct5_val = (instr >> 27) & 0x1F
    funct3_val = parse_func3(instr)
    try:
        op = AmoFunct5(funct5_val)
        width = AmoWidth(funct3_val)
    except ValueError:
        return UNKNOWN

    suffix = ".d" if width == AmoWidth.D else ".w"
    # bits[26] 为 aq, bits[25] 为 rl, 两者同时置位时写作 .aqrl
    order = ""
    if (instr >> 26) & 1:
        order += "aq"
    if (instr >> 25) & 1:
        order += "rl"
    if order:
        suffix += "." + order
    base = op.name.lower()
    # LR / SC 不带 amo 前缀, 其余原子操作带
    if op in (AmoFunct5.LR, AmoFunct5.SC):
        mnemonic = base + suffix
    else:
        mnemonic = "amo" + base + suffix
    # LR 的 rs2 字段恒为 0, 不属于操作数
    if op == AmoFunct5.LR:
        operands = f"{rd_name(instr)}, ({rs1_name(instr)})"
    else:
        operands = f"{rd_name(instr)}, {rs2_name(instr)}, ({rs1_name(instr)})"
    return f"{mnemonic:<12} {operands}"
