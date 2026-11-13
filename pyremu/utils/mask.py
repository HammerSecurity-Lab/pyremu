# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""位宽掩码 — 将任意精度 Python int 截断为硬件位宽.

Python 的任意精度整数在右移等运算中可能产生超大值,
与 64-bit / 32-bit 硬件语义不一致。
本模块提供 ``mask64`` / ``mask32`` 作为统一截断点,
替代散落各处的 ``& 0xFFFF_FFFF_FFFF_FFFF`` / ``& 0xFFFF_FFFF``.

Usage::

    from pyremu.utils.mask import mask64, mask32

    result = mask64(v1 + v2)   # 等价于 (v1 + v2) & 0xFFFF_FFFF_FFFF_FFFF
    lo = mask32(value)         # 等价于 value & 0xFFFF_FFFF
"""

MASK04: int = 0xF
MASK08: int = (MASK04 << 4) | MASK04
MASK12: int = (MASK08 << 4) | MASK04
MASK16: int = (MASK12 << 4) | MASK04
MASK32: int = (MASK16 << 16) | MASK16
MASK48: int = (MASK32 << 16) | MASK16
MASK64: int = (MASK32 << 32) | MASK32


def mask64(val: int) -> int:
    return val & MASK64


def mask48(val: int) -> int:
    return val & MASK48


def mask32(val: int) -> int:
    return val & MASK32


def mask16(val: int) -> int:
    return val & MASK16


def mask12(val: int) -> int:
    return val & MASK12


def mask08(val: int) -> int:
    return val & MASK08


def mask04(val: int) -> int:
    return val & MASK04


def is_power_of_two_in(value: int, minimum: int, maximum: int) -> bool:
    """判定 *value* 是 2 的幂且落在 [minimum, maximum] 内."""
    return minimum <= value <= maximum and (value & (value - 1)) == 0


# ---------------------------------------------------------------
#  64 位寄存器的字节窗口 — 按小端字节序读出与写入
# ---------------------------------------------------------------


def read_u64_bytes(val: int, byte_off: int, size: int) -> bytes:
    """从 64 位寄存器的第 byte_off 个字节起取出 size 个字节.

    取值先经 mask64 截断; 越过寄存器末尾的部分读为 0.
    """
    raw = mask64(val).to_bytes(8, "little", signed=False)
    chunk = raw[byte_off : byte_off + size]
    return chunk + b"\x00" * (size - len(chunk))


def write_u64_bytes(cur: int, byte_off: int, data: bytes) -> int | None:
    """把 data 自 64 位寄存器的第 byte_off 个字节起写入, 返回合并后的值.

    写入越过寄存器末尾时返回 None, 调用方据此丢弃该次写入.
    """
    if byte_off + len(data) > 8:
        return None
    raw = bytearray(mask64(cur).to_bytes(8, "little", signed=False))
    raw[byte_off : byte_off + len(data)] = data
    return int.from_bytes(raw, "little", signed=False)


# ---------------------------------------------------------------
#  循环移位 — 移位量取以位宽为模的余数
# ---------------------------------------------------------------


def rol64(val: int, shamt: int) -> int:
    """64 位循环左移, 移位量为 shamt 以 64 为模的余数."""
    v = mask64(val)
    s = shamt & 0x3F
    return mask64((v << s) | (v >> (64 - s))) if s else v


def ror64(val: int, shamt: int) -> int:
    """64 位循环右移, 移位量为 shamt 以 64 为模的余数."""
    v = mask64(val)
    s = shamt & 0x3F
    return mask64((v >> s) | (v << (64 - s))) if s else v


def rol32(val: int, shamt: int) -> int:
    """32 位循环左移, 移位量为 shamt 以 32 为模的余数, 结果截断为 32 位."""
    v = mask32(val)
    s = shamt & 0x1F
    return mask32((v << s) | (v >> (32 - s))) if s else v


def ror32(val: int, shamt: int) -> int:
    """32 位循环右移, 移位量为 shamt 以 32 为模的余数, 结果截断为 32 位."""
    v = mask32(val)
    s = shamt & 0x1F
    return mask32((v >> s) | (v << (32 - s))) if s else v


# ---------------------------------------------------------------
#  Sign-extend helpers (moved from disassem.py to break circular import)
# ---------------------------------------------------------------


def sext(val: int, bits: int) -> int:
    """Sign-extend *val* from *bits* width to a canonical 64-bit unsigned
    Python int.

    Python's arbitrary-precision integers behave differently from finite-width
    hardware in bitwise operations (|, &, ^, <<, >>) when values are negative.
    Canonicalizing to [0, 2^64) ensures consistent behaviour regardless of
    whether the value was built via sign-extend, zero-extend, or arithmetic.
    """
    sign_bit = 1 << (bits - 1)
    result = (val & (sign_bit - 1)) - (val & sign_bit)
    if bits <= 64:
        result = mask64(result)
    return result


def sext8(val: int) -> int:
    """Sign-extend from 8 bits -> canonical 64-bit unsigned."""
    return mask64((val & 0x7F) - (val & 0x80))


def sext12(val: int) -> int:
    """Sign-extend from 12 bits -> canonical 64-bit unsigned."""
    return mask64((val & 0x7FF) - (val & 0x800))


def sext16(val: int) -> int:
    """Sign-extend from 16 bits -> canonical 64-bit unsigned."""
    return mask64((val & 0x7FFF) - (val & 0x8000))


def sext32(val: int) -> int:
    """Sign-extend from 32 bits -> canonical 64-bit unsigned."""
    return mask64((val & 0x7FFF_FFFF) - (val & 0x8000_0000))


def sint64(val: int) -> int:
    """把 64 位无符号值按二进制补码解释为有符号整数, 取值范围 [-2^63, 2^63).

    有符号比较、算术右移与有符号乘法的取高位都要先取得该解释, 与 ``mask64``
    互为反向操作。
    """
    v = val & MASK64
    return v - (1 << 64) if v >> 63 else v
