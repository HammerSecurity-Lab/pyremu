# SPDX-License-Identifier: MIT
"""浮点计算 — 目前只有动态链接库实现, 库不可用时由调用方转为 IllInstr."""

from __future__ import annotations

from pyremu._native import FpOut, loaded_lib, native_available


def fp_exec_op(
    funct7: int,
    funct3: int,
    rs2: int,
    src_bits: tuple[int, int],
    frm: int,
) -> FpOut:
    """OP-FP compute via native softfloat.  Requires the native library.

    *src_bits* 为 (rs1 的位模式, rs2 的位模式); 整数源与浮点源都由调用方按
    指令语义取好.

    Raises NotImplementedError if ``.so`` is unavailable (caller converts
    to IllInstr) — there is no pure-Python floating-point fallback.
    """
    if not native_available():
        raise NotImplementedError("FPU requires native library (libdecode.so)")
    rs1_bits, rs2_bits = src_bits
    return loaded_lib().fp_exec_op(funct7, funct3, rs2, rs1_bits, rs2_bits, frm)


def fp_exec_fma(
    opcode: int,
    rm: int,
    fmt: int,
    src_bits: tuple[int, int, int],
    frm: int,
) -> FpOut:
    """FMA compute via native softfloat.  Requires the native library.

    *src_bits* 为 (rs1, rs2, rs3) 三个浮点源操作数的位模式.
    """
    if not native_available():
        raise NotImplementedError("FPU requires native library (libdecode.so)")
    rs1, rs2, rs3 = src_bits
    return loaded_lib().fp_exec_fma(opcode, rm, fmt, rs1, rs2, rs3, frm)


__all__ = ["fp_exec_fma", "fp_exec_op"]
