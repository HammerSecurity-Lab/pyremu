# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""按平台声明的扩展判定一条指令能否被解码执行.

每条指令先由编码得到所属扩展的开关名, 取值为 ``IsaExts`` 的字段名, 如 ``is_m``
与 ``is_zbb``, 再取该 hart 的扩展开关. 基础整数指令与特权指令不属于可选扩展,
不受扩展声明约束.

压缩指令与全部 32 位指令都在此处判定; 同一份编码到扩展的对应关系在加速执行
引擎的 ``check_ext_isa.rs`` 中另有一份实现, 两侧必须逐一对应.
"""

from pyremu._native import DecodedFields

# OP (0x33): funct7 取 1 的 8 条指令都属于 M 扩展; 其余按 (funct3, funct7) 判定.
_OP_ISA: dict[tuple[int, int], str] = {
    (0b010, 0x10): "is_zba",  # sh1add
    (0b100, 0x10): "is_zba",  # sh2add
    (0b110, 0x10): "is_zba",  # sh3add
    (0b001, 0x14): "is_zbs",  # bset
    (0b001, 0x24): "is_zbs",  # bclr
    (0b101, 0x24): "is_zbs",  # bext
    (0b001, 0x34): "is_zbs",  # binv
    (0b001, 0x30): "is_zbb",  # rol
    (0b101, 0x30): "is_zbb",  # ror
    (0b100, 0x20): "is_zbb",  # xnor
    (0b110, 0x20): "is_zbb",  # orn
    (0b111, 0x20): "is_zbb",  # andn
    (0b100, 0x05): "is_zbb",  # min
    (0b101, 0x05): "is_zbb",  # minu
    (0b110, 0x05): "is_zbb",  # max
    (0b111, 0x05): "is_zbb",  # maxu
}

# OP-32 (0x3B): funct7 取 1 的指令属于 M 扩展; 其余按 (funct3, funct7) 判定.
_OP32_ISA: dict[tuple[int, int], str] = {
    (0b000, 0x04): "is_zba",  # add.uw
    (0b010, 0x10): "is_zba",  # sh1add.uw
    (0b100, 0x10): "is_zba",  # sh2add.uw
    (0b110, 0x10): "is_zba",  # sh3add.uw
    (0b001, 0x30): "is_zbb",  # rolw
    (0b101, 0x30): "is_zbb",  # rorw
}

# OP-IMM (0x13): funct3 取 001 与 101 的移位类指令按 funct6 判定.
# funct6 为 funct7 右移一位的结果, 移位量取 6 位时 funct7 的最低位一并归入.
_OP_IMM_SHIFT_ISA: dict[tuple[int, int], str] = {
    (0b001, 0x0A): "is_zbs",  # bseti
    (0b001, 0x12): "is_zbs",  # bclri
    (0b001, 0x1A): "is_zbs",  # binvi
    (0b001, 0x18): "is_zbb",  # clz / ctz / cpop / sext.b / sext.h
    (0b101, 0x12): "is_zbs",  # bexti
    (0b101, 0x0A): "is_zbb",  # orc.b
    (0b101, 0x18): "is_zbb",  # rori
    (0b101, 0x1A): "is_zbb",  # rev8
}

# OP-IMM-32 (0x1B): 移位类指令按 (funct3, funct7) 判定, 其余 funct3 取基础指令.
_OP_IMM32_ISA: dict[tuple[int, int], str] = {
    (0b001, 0x04): "is_zba",  # slli.uw
    (0b001, 0x05): "is_zba",  # slli.uw
    (0b001, 0x30): "is_zbb",  # clzw / ctzw / cpopw
    (0b101, 0x30): "is_zbb",  # roriw
}

# 浮点加载与存储的 funct3: 001 为半精度, 本模拟器未实现, 由处理器拒绝编码.
_FP_MEM_ISA: dict[int, str] = {
    0b010: "is_f",  # FLW / FSW
    0b011: "is_d",  # FLD / FSD
}

# OP-FP 与 FMA 按 fmt (bits[26:25]) 判定: 0 为单精度, 1 为双精度.
_FP_FMT_ISA: dict[int, str] = {
    0: "is_f",
    1: "is_d",
}

# SYSTEM (0x73) 中 funct3 非 0 的 6 条指令为 CSR 指令.
_ZICSR_FUNC3 = frozenset({1, 2, 3, 5, 6, 7})


def _check_op_isa(
    func3: int,
    func7: int,
) -> str | None:
    """R 型指令所属扩展的开关名."""
    if func7 == 0x01:
        return "is_m"
    return _OP_ISA.get((func3, func7))


def _check_op_imm_isa(
    func3: int,
    func7: int,
) -> str | None:
    """I 型立即数指令所属扩展的开关名."""
    return _OP_IMM_SHIFT_ISA.get((func3, func7 >> 1))


def _check_op32_isa(
    func3: int,
    func7: int,
) -> str | None:
    """RV64 32 位字运算指令所属扩展的开关名."""
    if func7 == 0x01:
        return "is_m"
    return _OP32_ISA.get((func3, func7))


def _check_integer_isa(
    f: DecodedFields,
) -> str | None:
    """整数运算指令所属扩展的开关名; 不属于本组时返回 None."""
    opcode = f.opcode
    if opcode == 0b01100_11:  # OP
        return _check_op_isa(f.func3, f.func7)
    if opcode == 0b00100_11:  # OP-IMM
        return _check_op_imm_isa(f.func3, f.func7)
    if opcode == 0b01110_11:  # OP-32
        return _check_op32_isa(f.func3, f.func7)
    if opcode == 0b00110_11:  # OP-IMM-32
        return _OP_IMM32_ISA.get((f.func3, f.func7))
    if opcode == 0b01011_11:  # AMO
        return "is_a"
    return None


def _check_fp_isa(
    f: DecodedFields,
) -> str | None:
    """浮点指令所属扩展的开关名; 不属于本组时返回 None."""
    opcode = f.opcode
    if opcode in (0b00001_11, 0b01001_11):  # 浮点加载与存储
        return _FP_MEM_ISA.get(f.func3)
    if opcode in (
        0b10100_11,  # OP-FP
        0b10000_11,  # FMADD
        0b10001_11,  # FMSUB
        0b10010_11,  # FNMSUB
        0b10011_11,  # FNMADD
    ):
        return _FP_FMT_ISA.get(f.fmt)
    return None


def _check_priv_isa(
    f: DecodedFields,
) -> str | None:
    """特权指令所属扩展的开关名; 不属于本组时返回 None."""
    if f.opcode == 0b11100_11:  # SYSTEM
        return "is_zicsr" if f.func3 in _ZICSR_FUNC3 else None
    if f.opcode == 0b00011_11:  # MISC-MEM
        return "is_zifencei" if f.func3 == 0b001 else None
    return None


# 按指令组依次判定, 第一个给出开关名的组即为该指令所属的扩展
_ISA_CHECKS = (_check_integer_isa, _check_fp_isa, _check_priv_isa)


def _check_instr_isa(
    f: DecodedFields,
) -> str | None:
    """返回该指令所属扩展的开关名, 不属于可选扩展时返回 None."""
    if f.is_compressed:
        return "is_c"
    for check in _ISA_CHECKS:
        name = check(f)
        if name is not None:
            return name
    return None


def check_ext_isa(
    f: DecodedFields,
    switches: dict[str, bool],
) -> bool:
    """判定该指令所属扩展的开关是否打开.

    Args:
        f: 已解码的指令字段.
        switches: 该 hart 的扩展开关, 键为 ``IsaExts`` 的字段名.

    Returns:
        True 表示可以解码执行; 所属扩展关闭时返回 False. 基础指令恒为 True.
    """
    name = _check_instr_isa(f)
    if name is None:
        return True
    return switches.get(name, False)
