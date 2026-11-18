"""F/D 浮点指令."""

from collections.abc import Callable

from pyremu.disasm.common import (
    fmt_imm,
    parse_func3,
    parse_func7,
    parse_imm12_se,
    parse_imm_s,
    parse_opcode,
    parse_rd,
    parse_rs1,
    parse_rs2,
    rd_name,
    rs1_name,
    UNKNOWN,
)

_FP_LOAD_MNEMONIC = {0b010: "flw", 0b011: "fld"}
_FP_STORE_MNEMONIC = {0b010: "fsw", 0b011: "fsd"}
# OP-FP funct7[6:2] ->助记符基名 (S/D 后缀由 fmt 决定)
_FP_ARITH = {0x00: "fadd", 0x01: "fsub", 0x02: "fmul", 0x03: "fdiv"}
_FP_SGNJ = {0: "fsgnj", 1: "fsgnjn", 2: "fsgnjx"}
_FP_MINMAX = {0: "fmin", 1: "fmax"}
_FP_CMP = {0: "fle", 1: "flt", 2: "feq"}
_FP_FMA_MNEMONIC = {
    0b10000_11: "fmadd",
    0b10001_11: "fmsub",
    0b10010_11: "fnmsub",
    0b10011_11: "fnmadd",
}


def _fpr_name(idx: int) -> str:
    return f"f{idx}"


def _fsuffix(fmt: int) -> str:
    return "d" if fmt == 1 else "s"


def dis_fp_load(instr: int) -> str:
    """FLW / FLD: mnemonic frd, offset(rs1)."""
    m = _FP_LOAD_MNEMONIC.get(parse_func3(instr))
    if m is None:
        return UNKNOWN
    off = parse_imm12_se(instr)
    return (
        f"{m:<12} {_fpr_name(parse_rd(instr))}, "
        f"{fmt_imm(off)}({rs1_name(instr)})"
    )


def dis_fp_store(instr: int) -> str:
    """FSW / FSD: mnemonic frs2, offset(rs1)."""
    m = _FP_STORE_MNEMONIC.get(parse_func3(instr))
    if m is None:
        return UNKNOWN
    off = parse_imm_s(instr)
    return (
        f"{m:<12} {_fpr_name(parse_rs2(instr))}, "
        f"{fmt_imm(off)}({rs1_name(instr)})"
    )


def dis_fp_fma(instr: int) -> str:
    """FMADD/FMSUB/FNMSUB/FNMADD: mnemonic.fmt frd, frs1, frs2, frs3."""
    base = _FP_FMA_MNEMONIC.get(parse_opcode(instr))
    if base is None:
        return UNKNOWN
    fmt = (instr >> 25) & 0x3
    rs3 = (instr >> 27) & 0x1F
    m = f"{base}.{_fsuffix(fmt)}"
    return (
        f"{m:<12} {_fpr_name(parse_rd(instr))}, {_fpr_name(parse_rs1(instr))}, "
        f"{_fpr_name(parse_rs2(instr))}, {_fpr_name(rs3)}"
    )


def _fp_operands(instr: int) -> tuple[str, str, str]:
    """OP-FP 的目的与两个源浮点寄存器名."""
    return (
        _fpr_name(parse_rd(instr)),
        _fpr_name(parse_rs1(instr)),
        _fpr_name(parse_rs2(instr)),
    )


def _fp_arith(instr: int) -> str:
    funct7 = parse_func7(instr)
    m = f"{_FP_ARITH[funct7 >> 2]}.{_fsuffix(funct7 & 0x3)}"
    frd, frs1, frs2 = _fp_operands(instr)
    return f"{m:<12} {frd}, {frs1}, {frs2}"


def _fp_sqrt(instr: int) -> str:
    funct7 = parse_func7(instr)
    frd, frs1, _ = _fp_operands(instr)
    return f"{'fsqrt.' + _fsuffix(funct7 & 0x3):<12} {frd}, {frs1}"


def _fp_sgnj(instr: int) -> str:
    fmt = parse_func7(instr) & 0x3
    m = _FP_SGNJ.get(parse_func3(instr), "fsgnj?")
    frd, frs1, frs2 = _fp_operands(instr)
    return f"{m + '.' + _fsuffix(fmt):<12} {frd}, {frs1}, {frs2}"


def _fp_minmax(instr: int) -> str:
    fmt = parse_func7(instr) & 0x3
    m = _FP_MINMAX.get(parse_func3(instr), "fmin?")
    frd, frs1, frs2 = _fp_operands(instr)
    return f"{m + '.' + _fsuffix(fmt):<12} {frd}, {frs1}, {frs2}"


def _fp_cmp(instr: int) -> str:
    """FCMP 类指令的结果写入整数寄存器."""
    funct7 = parse_func7(instr)
    m = _FP_CMP.get(parse_func3(instr), "fcmp?")
    _, frs1, frs2 = _fp_operands(instr)
    mnemonic = m + "." + _fsuffix(funct7 & 0x3)
    return f"{mnemonic:<12} {rd_name(instr)}, {frs1}, {frs2}"


def _fp_cvt_f2i(instr: int) -> str:
    """浮点到整数的转换, 结果写入整数寄存器."""
    funct7 = parse_func7(instr)
    w = {0: "w", 1: "wu", 2: "l", 3: "lu"}.get(parse_rs2(instr), "?")
    frs1 = _fpr_name(parse_rs1(instr))
    mnemonic = "fcvt." + w + "." + _fsuffix(funct7 & 0x3)
    return f"{mnemonic:<12} {rd_name(instr)}, {frs1}"


def _fp_cvt_i2f(instr: int) -> str:
    """整数到浮点的转换, 源为整数寄存器."""
    funct7 = parse_func7(instr)
    w = {0: "w", 1: "wu", 2: "l", 3: "lu"}.get(parse_rs2(instr), "?")
    frd = _fpr_name(parse_rd(instr))
    mnemonic = "fcvt." + _fsuffix(funct7 & 0x3) + "." + w
    return f"{mnemonic:<12} {frd}, {rs1_name(instr)}"


def _fp_cvt_sd(instr: int) -> str:
    """FCVT.S.D 与 FCVT.D.S 之间的精度转换."""
    m = "fcvt.d.s" if parse_func7(instr) & 0x3 == 1 else "fcvt.s.d"
    frd, frs1, _ = _fp_operands(instr)
    return f"{m:<12} {frd}, {frs1}"


def _fp_class_mvx(instr: int) -> str:
    """FMV.X.W / FMV.X.D 与 FCLASS, 结果写入整数寄存器."""
    is_single = parse_func7(instr) & 0x3 == 0
    if parse_func3(instr) == 0:
        m = "fmv.x.w" if is_single else "fmv.x.d"
    else:
        m = "fclass.s" if is_single else "fclass.d"
    frs1 = _fpr_name(parse_rs1(instr))
    return f"{m:<12} {rd_name(instr)}, {frs1}"


def _fp_mvfx(instr: int) -> str:
    """FMV.W.X / FMV.D.X, 源为整数寄存器."""
    m = "fmv.w.x" if parse_func7(instr) & 0x3 == 0 else "fmv.d.x"
    frd = _fpr_name(parse_rd(instr))
    return f"{m:<12} {frd}, {rs1_name(instr)}"


_FP_OP_HANDLERS: dict[int, Callable[[int], str]] = {
    0x00: _fp_arith,
    0x01: _fp_arith,
    0x02: _fp_arith,
    0x03: _fp_arith,
    0x04: _fp_sgnj,  # FSGNJ*
    0x05: _fp_minmax,  # FMIN/FMAX
    0x08: _fp_cvt_sd,  # FCVT.S.D / FCVT.D.S
    0x0B: _fp_sqrt,  # FSQRT
    0x14: _fp_cmp,  # FCMP -> GPR rd
    0x18: _fp_cvt_f2i,  # float -> int
    0x1A: _fp_cvt_i2f,  # int -> float
    0x1C: _fp_class_mvx,  # FMV.X.* / FCLASS -> GPR rd
    0x1E: _fp_mvfx,  # FMV.*.X (GPR rs1 -> FPR)
}


def dis_fp_op(instr: int) -> str:
    """OP-FP: 算术/转换/比较/符号/分类/移动."""
    handler = _FP_OP_HANDLERS.get(parse_func7(instr) >> 2)
    if handler is None:
        return UNKNOWN
    return handler(instr)
