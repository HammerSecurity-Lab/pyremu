# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""整数运算辅助 — 对齐与 2 的幂判定.

与位宽掩码区分开: 掩码负责按位宽截断, 本模块负责与具体位宽无关的整数性质.

Usage::

    from pyremu.utils.math import align_up, is_power_of_two_in

    base = align_up(0x1234, 0x1000)   # 0x2000
"""


def is_power_of_two_in(value: int, minimum: int, maximum: int) -> bool:
    """判定 *value* 是 2 的幂且属于区间 [minimum, maximum]."""
    return minimum <= value <= maximum and (value & (value - 1)) == 0


def align_up(value: int, align: int) -> int:
    """value 向上对齐到 align 的整数倍。align 须为正数."""
    return (value + align - 1) // align * align


def trunc_div(a: int, b: int) -> int:
    """截断除法: 商向零取整; 除数为零时返回全 1.

    不使用 ``int(a / b)``: 真除法先把商舍入到双精度的 53 位有效位, 商的绝对值
    达到 2**53 之后该舍入改变结果.
    """
    if b == 0:
        return 0xFFFF_FFFF_FFFF_FFFF
    quotient = abs(a) // abs(b)
    return -quotient if (a < 0) != (b < 0) else quotient


def trunc_rem(a: int, b: int) -> int:
    """截断取余: 余数符号与被除数一致; 除数为零时返回被除数."""
    return a if b == 0 else a - trunc_div(a, b) * b
