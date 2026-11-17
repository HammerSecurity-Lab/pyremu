"""加载与存储指令."""

from pyremu.disasm.common import (
    fmt_imm,
    parse_func3,
    parse_imm12_se,
    parse_imm_s,
    rd_name,
    rs1_name,
    rs2_name,
    StFn3,
    UNKNOWN,
)

#  Load / Store


_LD_MNEMONIC: dict[int, str] = {
    0b000: "lb",
    0b001: "lh",
    0b010: "lw",
    0b011: "ld",
    0b100: "lbu",
    0b101: "lhu",
    0b110: "lwu",
}


def dis_load(instr: int) -> str:
    """Load: mnemonic rd, offset(rs1)."""
    f3 = parse_func3(instr)
    mnemonic = _LD_MNEMONIC.get(f3)
    if mnemonic is None:
        return UNKNOWN
    offset = parse_imm12_se(instr)
    return (
        f"{mnemonic:<12} {rd_name(instr)}, {fmt_imm(offset)}({rs1_name(instr)})"
    )


def dis_store(instr: int) -> str:
    """Store: mnemonic rs2, offset(rs1)."""
    f3 = parse_func3(instr)
    try:
        mnemonic = StFn3(f3).name
    except ValueError:
        return UNKNOWN
    offset = parse_imm_s(instr)
    return (
        f"{mnemonic:<12} {rs2_name(instr)}, "
        f"{fmt_imm(offset)}({rs1_name(instr)})"
    )
