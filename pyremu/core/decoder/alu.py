# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""纯 Python 的算术指令实现.

op / op_imm / op32 / op_imm32 四类指令各有一张以 funct3 为索引的函数表, 加速执行
引擎不可用时由本模块计算. 对外只暴露 exec_alu / exec_op_imm / exec_op32 /
exec_op_imm32 四个入口, 是否调用加速执行引擎的判断也在本模块内完成.
"""

from pyremu import _native
from pyremu._native import native_available
from pyremu.utils.mask import (
    mask32,
    mask64,
    rol32,
    rol64,
    ror32,
    ror64,
    sext8,
    sext16,
    sext32,
    sint64,
)

"""
mul      有符号 x 有符号    取 低 64 位
mulh     有符号 x 有符号    取 高 64 位
mulhsu   有符号 x 无符号    取 高 64 位
mulhu    无符号 x 无符号    取 高 64 位
"""


def _trunc_div(a: int, b: int) -> int:
    """Integer division truncating toward zero (C99 / RISC-V semantics)."""
    if b == 0:
        return -1  # RISC-V: all-bits-1 on division by zero
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q


def _trunc_rem(a: int, b: int) -> int:
    """Integer remainder with same sign as dividend (RISC-V semantics)."""
    if b == 0:
        return a  # RISC-V: dividend on division by zero
    return a - _trunc_div(a, b) * b


#  Zba / Zbb / Zbs 位操作辅助函数


def _zbb_unary(
    v: int,
    shamt: int,
) -> int:
    """funct7=0x30 且 funct3=001 的单目子指令, 由 shamt 选择.

    shamt 取值: 0 = clz, 1 = ctz, 2 = cpop, 4 = sext.b, 5 = sext.h.
    """
    u = mask64(v)
    if shamt == 0:  # clz
        return 64 - u.bit_length()
    if shamt == 1:  # ctz
        return (u & -u).bit_length() - 1 if u else 64
    if shamt == 2:  # cpop
        return u.bit_count()
    if shamt == 4:  # sext.b
        return sext8(u)
    if shamt == 5:  # sext.h
        return sext16(u)
    raise ValueError(f"invalid Zbb unary shamt={shamt}")


def _zbb_unary32(
    v: int,
    shamt: int,
) -> int:
    """funct7=0x30 且 funct3=001 的 32 位字单目子指令, 由 shamt 选择.

    shamt 取值: 0 = clzw, 1 = ctzw, 2 = cpopw.
    """
    u = mask32(v)
    if shamt == 0:  # clzw
        return 32 - u.bit_length()
    if shamt == 1:  # ctzw
        return (u & -u).bit_length() - 1 if u else 32
    if shamt == 2:  # cpopw
        return u.bit_count()
    raise ValueError(f"invalid Zbb unary32 shamt={shamt}")


def _zbb_orc_b(v: int) -> int:
    """orc.b: 对每个字节, 若任一 bit 为 1 则该字节全 1, 否则全 0."""
    result = 0
    for i in range(8):
        byte = (v >> (i * 8)) & 0xFF
        if byte:
            result |= 0xFF << (i * 8)
    return result


def _zbb_rev8(v: int) -> int:
    """rev8.d (RV64): 字节序反转."""
    result = 0
    for i in range(8):
        result |= ((mask64(v) >> (i * 8)) & 0xFF) << ((7 - i) * 8)
    return result


def _bset(v1: int, shamt: int) -> int:
    """bset 与 bseti: 把 shamt 指定的位写为 1."""
    return mask64(v1 | (1 << shamt))


def _bclr(v1: int, shamt: int) -> int:
    """bclr 与 bclri: 把 shamt 指定的位写为 0."""
    return mask64(v1 & ~(1 << shamt))


def _binv(v1: int, shamt: int) -> int:
    """binv 与 binvi: 把 shamt 指定的位取反."""
    return mask64(v1 ^ (1 << shamt))


def _bext(v1: int, shamt: int) -> int:
    """bext 与 bexti: 读出 shamt 指定的位."""
    return (mask64(v1) >> shamt) & 1


#  R 型 ALU 的纯 Python 计算, 按 funct3 分组


def _alu_py_000(funct7: int, v1: int, v2: int) -> int:
    """funct3=000: add / mul / sub."""
    if funct7 == 0:
        return mask64(v1 + v2)
    if funct7 == 1:
        return mask64(v1 * v2)
    if funct7 == 0x20:
        return mask64(v1 - v2)
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=000")


def _alu_py_001(funct7: int, v1: int, v2: int) -> int:
    """funct3=001: sll / mulh / rol / bset / bclr / binv."""
    shamt = v2 & 0x3F
    if funct7 == 0:
        return mask64(v1 << shamt)
    if funct7 == 1:
        s1 = sint64(v1)
        s2 = sint64(v2)
        return mask64(sint64((s1 * s2) >> 64))
    if funct7 == 0x14:  # bset
        return _bset(v1, shamt)
    if funct7 == 0x24:  # bclr
        return _bclr(v1, shamt)
    if funct7 == 0x30:  # rol
        return rol64(v1, shamt)
    if funct7 == 0x34:  # binv
        return _binv(v1, shamt)
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=001")


def _alu_py_010(funct7: int, v1: int, v2: int) -> int:
    """funct3=010: slt / mulhsu / sh1add."""
    if funct7 == 0:
        return 1 if sint64(v1) < sint64(v2) else 0
    if funct7 == 1:
        s1 = sint64(v1)
        u2 = mask64(v2)
        return mask64(sint64((s1 * u2) >> 64))
    if funct7 == 0x10:  # sh1add
        return mask64((v1 << 1) + v2)
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=010")


def _alu_py_011(funct7: int, v1: int, v2: int) -> int:
    """funct3=011: sltu / mulhu."""
    if funct7 == 0:
        return 1 if mask64(v1) < mask64(v2) else 0
    if funct7 == 1:
        u1 = mask64(v1)
        u2 = mask64(v2)
        return mask64((u1 * u2) >> 64)
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=011")


def _alu_py_100(funct7: int, v1: int, v2: int) -> int:
    """funct3=100: xor / div / min / sh2add / xnor."""
    if funct7 == 0:
        return v1 ^ v2
    if funct7 == 1:
        return mask64(_trunc_div(sint64(v1), sint64(v2)))
    if funct7 == 0x05:  # min
        return mask64(min(sint64(v1), sint64(v2)))
    if funct7 == 0x10:  # sh2add
        return mask64((v1 << 2) + v2)
    if funct7 == 0x20:  # xnor
        return mask64(~(v1 ^ v2))
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=100")


def _alu_py_101(funct7: int, v1: int, v2: int) -> int:
    """funct3=101: srl / divu / minu / sra / bext / ror."""
    shamt = v2 & 0x3F
    if funct7 == 0:
        return mask64(mask64(v1) >> shamt)
    if funct7 == 1:
        return mask64(_trunc_div(mask64(v1), mask64(v2)))
    if funct7 == 0x05:  # minu
        return min(mask64(v1), mask64(v2))
    if funct7 == 0x20:
        return mask64(sint64(sint64(v1) >> shamt))
    if funct7 == 0x24:  # bext
        return _bext(v1, shamt)
    if funct7 == 0x30:  # ror
        return ror64(v1, shamt)
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=101")


def _alu_py_110(funct7: int, v1: int, v2: int) -> int:
    """funct3=110: or / rem / max / sh3add / orn."""
    if funct7 == 0:
        return v1 | v2
    if funct7 == 1:
        return mask64(_trunc_rem(sint64(v1), sint64(v2)))
    if funct7 == 0x05:  # max
        return mask64(max(sint64(v1), sint64(v2)))
    if funct7 == 0x10:  # sh3add
        return mask64((v1 << 3) + v2)
    if funct7 == 0x20:  # orn
        return mask64(v1 | ~v2)
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=110")


def _alu_py_111(funct7: int, v1: int, v2: int) -> int:
    """funct3=111: and / remu / maxu / andn."""
    if funct7 == 0:
        return v1 & v2
    if funct7 == 1:
        return mask64(_trunc_rem(mask64(v1), mask64(v2)))
    if funct7 == 0x05:  # maxu
        return max(mask64(v1), mask64(v2))
    if funct7 == 0x20:  # andn
        return mask64(v1 & ~v2)
    raise ValueError(f"invalid funct7={funct7:#x} for funct3=111")


_ALU_PY_OPS = {
    0b000: _alu_py_000,
    0b001: _alu_py_001,
    0b010: _alu_py_010,
    0b011: _alu_py_011,
    0b100: _alu_py_100,
    0b101: _alu_py_101,
    0b110: _alu_py_110,
    0b111: _alu_py_111,
}


def _exec_alu_via_native(fields, v1: int, v2: int) -> int:
    """经加速执行引擎计算 R 型 ALU 指令."""
    r = _native.exec_alu_op(fields.func3, fields.func7, v1, v2)
    if r.trap:
        raise ValueError(
            f"invalid funct3={fields.func3:#b} funct7={fields.func7:#x}"
        )
    return r.value


#  I 型立即数 ALU 的纯 Python 计算, 按 funct3 分组
#
#  各函数的 funct6 为 funct7 右移一位的结果; shamt 为立即数的低 6 位.


def _op_imm_py_000(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=000: addi."""
    return mask64(v1 + imm)


def _op_imm_py_001(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=001: slli / bseti / bclri / Zbb 单目子指令 / binvi."""
    if funct6 == 0:
        return mask64(v1 << shamt)
    if funct6 == 0x0A:  # bseti
        return _bset(v1, shamt)
    if funct6 == 0x12:  # bclri
        return _bclr(v1, shamt)
    if funct6 == 0x18:  # clz / ctz / cpop / sext.b / sext.h
        return _zbb_unary(v1, shamt)
    if funct6 == 0x1A:  # binvi
        return _binv(v1, shamt)
    raise ValueError(f"invalid funct6={funct6:#x} for SLLI")


def _op_imm_py_010(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=010: slti."""
    return 1 if sint64(v1) < imm else 0


def _op_imm_py_011(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=011: sltiu."""
    return 1 if mask64(v1) < mask64(imm) else 0


def _op_imm_py_100(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=100: xori."""
    return v1 ^ imm


def _op_imm_py_101(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=101: srli / srai / rori / bexti / orc.b / rev8."""
    if funct6 == 0:
        return mask64(mask64(v1) >> shamt)
    if funct6 == 0x0A:  # orc.b, 立即数固定为 0x287
        if imm != 0x287:
            raise ValueError(f"invalid orc.b immediate={imm:#x}")
        return _zbb_orc_b(v1)
    if funct6 == 0x10:
        return mask64(sint64(sint64(v1) >> shamt))
    if funct6 == 0x12:  # bexti
        return _bext(v1, shamt)
    if funct6 == 0x18:  # rori
        return ror64(v1, shamt)
    if funct6 == 0x1A:  # rev8, 立即数固定为 0x6B8
        if imm != 0x6B8:
            raise ValueError(f"invalid rev8 immediate={imm:#x}")
        return _zbb_rev8(v1)
    raise ValueError(f"invalid funct6={funct6:#x} for SRLI/SRAI")


def _op_imm_py_110(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=110: ori."""
    return v1 | imm


def _op_imm_py_111(funct6: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=111: andi."""
    return v1 & imm


_OP_IMM_PY_OPS = {
    0b000: _op_imm_py_000,
    0b001: _op_imm_py_001,
    0b010: _op_imm_py_010,
    0b011: _op_imm_py_011,
    0b100: _op_imm_py_100,
    0b101: _op_imm_py_101,
    0b110: _op_imm_py_110,
    0b111: _op_imm_py_111,
}


def _exec_op_imm_via_native(fields, v1: int) -> int:
    """经加速执行引擎计算 I 型立即数 ALU 指令."""
    r = _native.exec_op_imm(fields.func3, fields.func7, v1, fields.imm12_se)
    if r.trap:
        raise ValueError(
            f"invalid funct3={fields.func3:#b} funct7={fields.func7:#x}"
        )
    return r.value


#  RV64 32 位字运算的纯 Python 计算, 按 funct3 分组
#
#  各函数收到的 v1 与 v2 已截断为 32 位.


def _op32_py_000(funct7: int, v1: int, v2: int) -> int:
    """funct3=000: addw / mulw / subw."""
    if funct7 == 0:
        return sext32(mask32(v1 + v2))
    if funct7 == 1:
        return sext32(mask32(v1 * v2))
    if funct7 == 0x20:
        return sext32(mask32(v1 - v2))
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=000")


def _op32_py_001(funct7: int, v1: int, v2: int) -> int:
    """funct3=001: sllw / mulw 的高 32 位 / rolw."""
    if funct7 == 0:
        return sext32(mask32(v1 << (v2 & 0x1F)))
    if funct7 == 1:
        s1 = sint64(sext32(v1))
        s2 = sint64(sext32(v2))
        return mask64(sint64((s1 * s2) >> 32))
    if funct7 == 0x30:  # rolw
        return sext32(rol32(v1, v2 & 0x1F))
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=001")


def _op32_py_010(funct7: int, v1: int, v2: int) -> int:
    """funct3=010: sltw / mulhsuw."""
    if funct7 == 0:
        return 1 if sint64(sext32(v1)) < sint64(sext32(v2)) else 0
    if funct7 == 1:
        s1 = sint64(sext32(v1))
        u2 = mask64(v2)
        return mask64(sint64((s1 * u2) >> 32))
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=010")


def _op32_py_011(funct7: int, v1: int, v2: int) -> int:
    """funct3=011: sltuw / mulhuw."""
    if funct7 == 0:
        return 1 if v1 < v2 else 0
    if funct7 == 1:
        return mask64((v1 * v2) >> 32)
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=011")


def _op32_py_100(funct7: int, v1: int, v2: int) -> int:
    """funct3=100: xorw / divw."""
    if funct7 == 0:
        return sext32(mask32(v1 ^ v2))
    if funct7 == 1:
        return sext32(
            mask32(_trunc_div(sint64(sext32(v1)), sint64(sext32(v2))))
        )
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=100")


def _op32_py_101(funct7: int, v1: int, v2: int) -> int:
    """funct3=101: srlw / sraw / divuw / rorw."""
    if funct7 == 0:
        return sext32(mask32(v1 >> (v2 & 0x1F)))
    if funct7 == 1:
        return sext32(mask32(_trunc_div(v1, v2)))
    if funct7 == 0x20:
        return sext32(mask32(sint64(sext32(v1) >> (v2 & 0x1F))))
    if funct7 == 0x30:  # rorw
        return sext32(ror32(v1, v2 & 0x1F))
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=101")


def _op32_py_110(funct7: int, v1: int, v2: int) -> int:
    """funct3=110: orw / remw."""
    if funct7 == 0:
        return sext32(mask32(v1 | v2))
    if funct7 == 1:
        return sext32(
            mask32(_trunc_rem(sint64(sext32(v1)), sint64(sext32(v2))))
        )
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=110")


def _op32_py_111(funct7: int, v1: int, v2: int) -> int:
    """funct3=111: andw / remuw."""
    if funct7 == 0:
        return sext32(mask32(v1 & v2))
    if funct7 == 1:
        return sext32(mask32(_trunc_rem(v1, v2)))
    raise ValueError(f"invalid funct7={funct7:#x} for op32 funct3=111")


_OP32_PY_OPS = {
    0b000: _op32_py_000,
    0b001: _op32_py_001,
    0b010: _op32_py_010,
    0b011: _op32_py_011,
    0b100: _op32_py_100,
    0b101: _op32_py_101,
    0b110: _op32_py_110,
    0b111: _op32_py_111,
}

# Zba 的 uw 形式: 键为 (funct3, funct7), 值为 rs1 左移的位数
_OP32_UW_SHIFT = {
    (0b000, 0x04): 0,  # add.uw
    (0b010, 0x10): 1,  # sh1add.uw
    (0b100, 0x10): 2,  # sh2add.uw
    (0b110, 0x10): 3,  # sh3add.uw
}


def _op32_py(
    func3: int,
    funct7: int,
    v1: int,
    v2: int,
) -> int:
    """按 funct3 分发 32 位字运算.

    Zba 的 uw 形式只把 rs1 截断为 32 位, rs2 取完整的 64 位参与加法.
    """
    shift = _OP32_UW_SHIFT.get((func3, funct7))
    if shift is not None:
        return mask64((mask32(v1) << shift) + v2)
    return _OP32_PY_OPS[func3](funct7, mask32(v1), mask32(v2))


def _exec_op32_via_native(fields, v1: int, v2: int) -> int:
    """经加速执行引擎计算 RV64 32 位字运算指令."""
    r = _native.exec_op32(fields.func3, fields.func7, v1, v2)
    if r.trap:
        raise ValueError(
            f"invalid funct3={fields.func3:#b} funct7={fields.func7:#x}"
        )
    return r.value


#  I 型 32 位字立即数运算的纯 Python 计算, 按 funct3 分组


def _op_imm32_py_000(funct7: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=000: addiw."""
    return sext32(mask32(v1 + imm))


def _op_imm32_py_001(funct7: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=001: slliw / slli.uw / Zbb 的 clzw、ctzw、cpopw."""
    if funct7 == 0:  # slliw, 移位量取 5 位
        return sext32(mask32(mask32(v1) << (shamt & 0x1F)))
    if funct7 in (0x04, 0x05):  # slli.uw, 移位量取 6 位
        return mask64(mask32(v1) << shamt)
    if funct7 == 0x30:
        return _zbb_unary32(v1, shamt)
    raise ValueError(f"invalid funct7={funct7:#x} for SLLIW")


def _op_imm32_py_101(funct7: int, v1: int, imm: int, shamt: int) -> int:
    """funct3=101: srliw / sraiw / roriw."""
    shamt &= 0x1F
    if funct7 == 0:
        return sext32(mask32(mask32(v1) >> shamt))
    if funct7 == 0x20:
        return sext32(mask32(sint64(sext32(mask32(v1)) >> shamt)))
    if funct7 == 0x30:  # roriw
        return sext32(ror32(v1, shamt))
    raise ValueError(f"invalid funct7={funct7:#x} for SRLIW/SRAIW")


_OP_IMM32_PY_OPS = {
    0b000: _op_imm32_py_000,
    0b001: _op_imm32_py_001,
    0b101: _op_imm32_py_101,
}


def _op_imm32_py(func3: int, funct7: int, v1: int, imm: int, shamt: int) -> int:
    """按 funct3 分发 I 型 32 位字立即数运算."""
    op = _OP_IMM32_PY_OPS.get(func3)
    if op is None:
        raise ValueError(f"invalid funct3={func3:#x} for op_imm32")
    return op(funct7, v1, imm, shamt)


def _exec_op_imm32_via_native(fields, v1: int) -> int:
    """经加速执行引擎计算 I 型 32 位字立即数运算."""
    r = _native.exec_op_imm32(fields.func3, fields.func7, v1, fields.imm12_se)
    if r.trap:
        raise ValueError(
            f"invalid funct3={fields.func3:#b} funct7={fields.func7:#x}"
        )
    return r.value


#  对外入口: 加速执行引擎可用时经其计算, 否则查纯 Python 表


def exec_alu(fields, v1: int, v2: int) -> int:
    """计算 R 型 ALU 指令."""
    if native_available():
        return _exec_alu_via_native(fields, v1, v2)
    return _ALU_PY_OPS[fields.func3](fields.func7, v1, v2)


def exec_op_imm(fields, v1: int) -> int:
    """计算 I 型立即数 ALU 指令."""
    if native_available():
        return _exec_op_imm_via_native(fields, v1)
    return _OP_IMM_PY_OPS[fields.func3](
        fields.func7 >> 1, v1, fields.imm12_se, fields.imm12_se & 0x3F
    )


def exec_op32(fields, v1: int, v2: int) -> int:
    """计算 RV64 的 32 位字运算指令."""
    if native_available():
        return _exec_op32_via_native(fields, v1, v2)
    return _op32_py(fields.func3, fields.func7, v1, v2)


def exec_op_imm32(fields, v1: int) -> int:
    """计算 I 型 32 位字立即数运算指令."""
    if native_available():
        return _exec_op_imm32_via_native(fields, v1)
    return _op_imm32_py(
        fields.func3, fields.func7, v1, fields.imm12_se, fields.imm12_se & 0x3F
    )
