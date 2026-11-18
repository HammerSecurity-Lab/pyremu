"""分支与跳转指令."""

from pyremu.disasm.common import (
    BrFn3,
    fmt_imm,
    parse_func3,
    parse_imm12_se,
    parse_imm_b,
    parse_imm_j,
    rd_name,
    rs1_name,
    rs2_name,
    UNKNOWN,
)
from pyremu.utils.mask import mask64
from pyremu.utils.str_aux import fmt_addr


def dis_branch(instr: int, pc: int) -> str:
    """Branch: mnemonic rs1, rs2, target_addr."""
    f3 = parse_func3(instr)
    try:
        mnemonic = BrFn3(f3).name
    except ValueError:
        return UNKNOWN
    offset = parse_imm_b(instr)
    target = mask64((pc + offset))
    return (
        f"{mnemonic:<12} {rs1_name(instr)}, {rs2_name(instr)}, "
        f"{fmt_addr(target)}"
    )


def dis_jal(instr: int, pc: int) -> str:
    """JAL: mnemonic rd, target_addr."""
    offset = parse_imm_j(instr)
    target = mask64((pc + offset))
    return f"jal          {rd_name(instr)}, {fmt_addr(target)}"


def dis_jalr(instr: int) -> str:
    """JALR: mnemonic rd, offset(rs1)."""
    offset = parse_imm12_se(instr)
    return (
        f"jalr         {rd_name(instr)}, {fmt_imm(offset)}({rs1_name(instr)})"
    )
