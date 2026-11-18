"""整数运算指令: R 型、I 型、移位、RV64 32 位运算与 U 型立即数."""

from pyremu.disasm.common import (
    fmt_imm,
    parse_func3,
    parse_func6,
    parse_func7,
    parse_imm12_se,
    parse_imm20_raw,
    rd_name,
    rs1_name,
    rs2_name,
    UNKNOWN,
)
from pyremu.utils.str_aux import fmt_addr

#  R-type 编码表 — funct3 -> (func7 -> mnemonic)


_R_FUNCT3_MAP: dict[int, dict[int, str]] = {
    0b000: {0x00: "add", 0x01: "mul", 0x20: "sub"},
    0b001: {
        0x00: "sll",
        0x01: "mulh",
        0x14: "bset",
        0x24: "bclr",
        0x30: "rol",
        0x34: "binv",
    },
    0b010: {0x00: "slt", 0x01: "mulhsu", 0x10: "sh1add"},
    0b011: {0x00: "sltu", 0x01: "mulhu"},
    0b100: {
        0x00: "xor",
        0x01: "div",
        0x05: "min",
        0x10: "sh2add",
        0x20: "xnor",
    },
    0b101: {
        0x00: "srl",
        0x01: "divu",
        0x05: "minu",
        0x20: "sra",
        0x24: "bext",
        0x30: "ror",
    },
    0b110: {0x00: "or", 0x01: "rem", 0x05: "max", 0x10: "sh3add", 0x20: "orn"},
    0b111: {0x00: "and", 0x01: "remu", 0x05: "maxu", 0x20: "andn"},
}


def dis_rtype(instr: int) -> str:
    """R-type: mnemonic rd, rs1, rs2."""
    f3 = parse_func3(instr)
    f7 = parse_func7(instr)
    mnemonic = _R_FUNCT3_MAP.get(f3, {}).get(f7)
    if mnemonic is None:
        return UNKNOWN
    return (
        f"{mnemonic:<12} {rd_name(instr)}, {rs1_name(instr)}, {rs2_name(instr)}"
    )


#  I-type ALU (op_imm)


_IMM_FUNCT3_MAP: dict[int, str] = {
    0b000: "addi",
    0b010: "slti",
    0b011: "sltiu",
    0b100: "xori",
    0b110: "ori",
    0b111: "andi",
}


def dis_itype(instr: int) -> str:
    """I-type ALU: mnemonic rd, rs1, imm."""
    f3 = parse_func3(instr)
    if f3 in (0b001, 0b101):  # SLLI / SRLI / SRAI
        return _dis_shift_imm(instr, f3)

    mnemonic = _IMM_FUNCT3_MAP.get(f3)
    if mnemonic is None:
        return UNKNOWN
    imm = parse_imm12_se(instr)
    return f"{mnemonic:<12} {rd_name(instr)}, {rs1_name(instr)}, {fmt_imm(imm)}"


# funct3=001 中由 funct6 确定助记符的立即数指令
_SHIFT_IMM_SLL: dict[int, str] = {
    0x00: "slli",
    0x0A: "bseti",
    0x12: "bclri",
    0x1A: "binvi",
}

# funct3=101 中由 funct6 确定助记符, 并由 shamt 给出移位量的立即数指令
_SHIFT_IMM_SRL: dict[int, str] = {
    0x00: "srli",
    0x10: "srai",
    0x12: "bexti",
    0x18: "rori",
}

# funct3=101 中立即数固定的指令: funct6 -> (助记符, 12 位立即数)
_SHIFT_IMM_FIXED: dict[int, tuple[str, int]] = {
    0x0A: ("orc.b", 0x287),
    0x1A: ("rev8", 0x6B8),
}

# Zbb 单目立即数子指令: shamt -> 助记符
_ZBB_UNARY_IMM: dict[int, str] = {
    0: "clz",
    1: "ctz",
    2: "cpop",
    4: "sext.b",
    5: "sext.h",
}


def _dis_shift_imm(instr: int, f3: int) -> str:
    """移位与位操作立即数: 由 funct6 与 shamt 判别.

    bit 25 属于 shamt, 故移位类指令不按 funct7 判别.
    """
    shamt = (instr >> 20) & 0x3F
    f6 = parse_func6(instr)
    rd, rs1 = rd_name(instr), rs1_name(instr)
    if f3 == 0b001:
        return _dis_shift_imm_sll(f6, shamt, rd, rs1)
    return _dis_shift_imm_srl(instr, f6, shamt, rd, rs1)


def _dis_shift_imm_sll(f6: int, shamt: int, rd: str, rs1: str) -> str:
    """funct3=001: SLLI 与 Zbs、Zbb 的立即数形式."""
    if f6 == 0x18:
        mnemonic = _ZBB_UNARY_IMM.get(shamt)
        if mnemonic is None:
            return UNKNOWN
        return f"{mnemonic:<12} {rd}, {rs1}"
    mnemonic = _SHIFT_IMM_SLL.get(f6)
    if mnemonic is None:
        return UNKNOWN
    return f"{mnemonic:<12} {rd}, {rs1}, {shamt}"


def _dis_shift_imm_srl(
    instr: int,
    f6: int,
    shamt: int,
    rd: str,
    rs1: str,
) -> str:
    """funct3=101: SRLI、SRAI、RORI、BEXTI、ORC.B 与 REV8."""
    fixed = _SHIFT_IMM_FIXED.get(f6)
    if fixed is not None:
        mnemonic, imm = fixed
        if parse_imm12_se(instr) != imm:
            return UNKNOWN
        return f"{mnemonic:<12} {rd}, {rs1}"
    mnemonic = _SHIFT_IMM_SRL.get(f6)
    if mnemonic is None:
        return UNKNOWN
    return f"{mnemonic:<12} {rd}, {rs1}, {shamt}"


# funct3 为 010 与 011 的编码未定义; funct3 为 100 / 110 / 111 时只有
# funct7=1 的除法与取余形式.
_OP32_FUNCT3_MAP: dict[int, dict[int, str]] = {
    0b000: {0x00: "addw", 0x01: "mulw", 0x04: "add.uw", 0x20: "subw"},
    0b001: {0x00: "sllw", 0x30: "rolw"},
    0b010: {0x10: "sh1add.uw"},
    0b100: {0x01: "divw", 0x10: "sh2add.uw"},
    0b101: {0x00: "srlw", 0x01: "divuw", 0x20: "sraw", 0x30: "rorw"},
    0b110: {0x01: "remw", 0x10: "sh3add.uw"},
    0b111: {0x01: "remuw"},
}


def dis_op32(instr: int) -> str:
    """RV64 32-bit R-type: mnemonic rd, rs1, rs2."""
    f3 = parse_func3(instr)
    f7 = parse_func7(instr)
    mnemonic = _OP32_FUNCT3_MAP.get(f3, {}).get(f7)
    if mnemonic is None:
        return UNKNOWN
    return (
        f"{mnemonic:<12} {rd_name(instr)}, {rs1_name(instr)}, {rs2_name(instr)}"
    )


# funct3=001 的 32 位字立即数单目子指令: shamt -> 助记符
_ZBB_UNARY_IMM32: dict[int, str] = {
    0: "clzw",
    1: "ctzw",
    2: "cpopw",
}


def dis_op_imm32(instr: int) -> str:
    """RV64 32-bit I-type: ADDIW / SLLIW / SRLIW / SRAIW
    与 Zba、Zbb 的立即数形式."""
    f3 = parse_func3(instr)
    f7 = parse_func7(instr)
    rd, rs1 = rd_name(instr), rs1_name(instr)
    if f3 == 0b000:
        return f"addiw        {rd}, {rs1}, {fmt_imm(parse_imm12_se(instr))}"
    if f3 == 0b001:
        return _dis_op_imm32_sll(instr, f7, rd, rs1)
    if f3 == 0b101:
        shamt = (instr >> 20) & 0x1F
        if f7 == 0x00:
            return f"srliw        {rd}, {rs1}, {shamt}"
        if f7 == 0x20:
            return f"sraiw        {rd}, {rs1}, {shamt}"
        if f7 == 0x30:
            return f"roriw        {rd}, {rs1}, {shamt}"
    return UNKNOWN


def _dis_op_imm32_sll(instr: int, f7: int, rd: str, rs1: str) -> str:
    """funct3=001: SLLIW、SLLI.UW 与 Zbb 的 clzw、ctzw、cpopw."""
    shamt = (instr >> 20) & 0x3F
    if f7 >> 1 == 0x02:  # slli.uw, 移位量为 6 位
        return f"slli.uw      {rd}, {rs1}, {shamt}"
    if f7 == 0x00:
        return f"slliw        {rd}, {rs1}, {shamt}"
    if f7 == 0x30:
        mnemonic = _ZBB_UNARY_IMM32.get(shamt)
        if mnemonic is None:
            return UNKNOWN
        return f"{mnemonic:<12} {rd}, {rs1}"
    return UNKNOWN


#  LUI / AUIPC


def dis_lui(instr: int) -> str:
    # LUI 的 20-bit 立即数为地址高位常量 (实际值 = imm << 12), 用 hex 更直观
    imm = parse_imm20_raw(instr)
    return f"lui          {rd_name(instr)}, {fmt_addr(imm)}"


def dis_auipc(instr: int) -> str:
    # AUIPC 同上, upper immediate 用 hex 表示
    imm = parse_imm20_raw(instr)
    return f"auipc        {rd_name(instr)}, {fmt_addr(imm)}"
