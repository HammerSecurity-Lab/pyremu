# SPDX-LICENSE-IDENTIFIER: MIT
"""算术指令的入口 — 有动态链接库时经加速执行引擎, 否则走纯 Python 实现.

纯 Python 实现在 ``pyremu.decoder.alu``; 本模块只负责选择与把 Ops 返回的
陷态标记换算为 ``ValueError``, 由 ``Hart.exec_instr`` 统一转为 IllInstr 陷态.
"""

from __future__ import annotations

from pyremu import _native
from pyremu._native import loaded_lib
from pyremu.decoder import alu


def _value_or_raise(result, func3: int, func7: int) -> int:
    """取出加速执行引擎的计算结果; 陷态标记置位时抛出 ``ValueError``."""
    if result.trap:
        raise ValueError(f"invalid funct3={func3:#b} funct7={func7:#x}")
    return result.value


def exec_alu(fields, v1: int, v2: int) -> int:
    """计算 R 型 ALU 指令."""
    if _native.loaded_lib() is None:
        return alu.exec_alu(fields, v1, v2)
    result = loaded_lib().exec_alu_op(fields.func3, fields.func7, v1, v2)
    return _value_or_raise(result, fields.func3, fields.func7)


def exec_op_imm(fields, v1: int) -> int:
    """计算 I 型立即数 ALU 指令."""
    if _native.loaded_lib() is None:
        return alu.exec_op_imm(fields, v1)
    result = loaded_lib().exec_op_imm(
        fields.func3, fields.func7, v1, fields.imm12_se
    )
    return _value_or_raise(result, fields.func3, fields.func7)


def exec_op32(fields, v1: int, v2: int) -> int:
    """计算 RV64 的 32 位字运算指令."""
    if _native.loaded_lib() is None:
        return alu.exec_op32(fields, v1, v2)
    result = loaded_lib().exec_op32(fields.func3, fields.func7, v1, v2)
    return _value_or_raise(result, fields.func3, fields.func7)


def exec_op_imm32(fields, v1: int) -> int:
    """计算 I 型 32 位字立即数运算指令."""
    if _native.loaded_lib() is None:
        return alu.exec_op_imm32(fields, v1)
    result = loaded_lib().exec_op_imm32(
        fields.func3, fields.func7, v1, fields.imm12_se
    )
    return _value_or_raise(result, fields.func3, fields.func7)
