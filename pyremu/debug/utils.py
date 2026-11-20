#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""调试器无状态工具 — 输入校验、常量与调试器侧的读取辅助.

所有函数均为模块级, 不依赖 Debugger 实例. 通用的格式化与解析工具位于
``pyremu.utils.str_aux``.
"""

from typing import TYPE_CHECKING

from pyremu.core import trap_def
from pyremu.core.hart import RiscvMode
from pyremu.debug.exception import UsageError
from pyremu.disasm import Opc

if TYPE_CHECKING:
    from pyremu.core.hart import HartWithRegs
    from pyremu.memory.bus import Bus

EXC_NAMES: dict[int, str] = {
    0: "InstrAddrMisaligned",
    1: "InstrAccessFault",
    2: "IllInstr",
    3: "Breakpoint",
    4: "LdAddrMisaligned",
    5: "LdAccessFault",
    6: "StAddrMisaligned",
    7: "StAccessFault",
    8: "Ecall from U",
    9: "Ecall from S",
    11: "Ecall from M",
    12: "InstrPageFault",
    13: "LdPageFault",
    15: "StPageFault",
}

IRQ_NAMES: dict[int, str] = {
    1: "SSIP (S 模式软件中断)",
    3: "MSIP (M 模式软件中断)",
    5: "STIP (S 模式定时器中断)",
    7: "MTIP (M 模式定时器中断)",
    9: "SEIP (S 模式外部中断)",
    11: "MEIP (M 模式外部中断)",
}

INSTR_BP_NAMES: dict[str, int] = {
    "ecall": 0x000,
    "ebreak": 0x001,
    "mret": 0x302,
    "sret": 0x102,
    "wfi": 0x105,
}

KNOWN_OPCODES: frozenset[int] = frozenset(o.value for o in Opc)
MAX_ADDR = (1 << 64) - 1
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def check_rv64_addr(v: int) -> bool:
    """校验 *v* 是否在 RV64 地址范围 [0, 2^64) 内."""
    return 0 <= v < (1 << 64)


def parse_addr_literal(text: str) -> int | None:
    """解析数值字面量; 超出 RV64 范围或非整数时返回 None."""
    try:
        value = int(text, 0)
    except ValueError:
        return None
    return value if check_rv64_addr(value) else None


def parse_hex_addr(text: str) -> int:
    """解析十六进制地址, 前缀 0x 可省略.

    Raises:
        UsageError: 内容不是十六进制, 或数值超出 64 位.
    """
    body = text[2:] if text.lower().startswith("0x") else text
    if not body or any(ch not in _HEX_DIGITS for ch in body):
        raise UsageError(f"非16进制值: {text}")
    value = int(body, 16)
    if value > MAX_ADDR:
        raise UsageError(f"超出64位: {text}")
    return value


def trap_cause_name(mcause_val: int) -> str:
    """将 mcause 寄存器值翻译为可读的 trap 类型名称."""
    return trap_def.trap_cause_name(mcause_val)


#  虚拟地址读取


def read_pa_bytes(
    bus: Bus,
    pa: int,
    size: int,
) -> bytes | None:
    """从物理地址读取内存, 只读取主存与已注册设备的地址范围.

    Returns:
        读到的字节; 地址不是整数, 超出 64 位范围或落在未定义的物理空间时
        返回 None.
    """
    if not isinstance(pa, int) or pa < 0 or pa > MAX_ADDR:
        return None
    if not bus.is_valid_addr(pa):
        return None
    return bus.try_read(pa, size)


def read_va_bytes(
    bus: Bus,
    hart: HartWithRegs,
    va: int,
    size: int,
) -> bytes | None:
    """从虚拟地址读取内存, 跨越页边界时逐页翻译.

    翻译是调试器查询, 只做地址换算, 不判定页权限位.

    Returns:
        读到的字节; 翻译失败或读取失败时返回 None.
    """
    if size <= 0 or size > 4096:
        return None
    if hart.mmu_mode == 0 or hart.mode == RiscvMode.M:
        return read_pa_bytes(bus, va, size)
    result = bytearray()
    remain = size
    cur = va
    while remain > 0:
        page_off = cur & 0xFFF
        chunk = min(remain, 0x1000 - page_off)
        ok, pa = hart.translate_addr(cur, is_hart_access=False)
        if not ok:
            return None
        data = read_pa_bytes(bus, pa, chunk)
        if data is None:
            return None
        result.extend(data)
        remain -= chunk
        cur += chunk
    return bytes(result)


def ip_bits() -> list[tuple[str, int, str]]:
    """mip/mie/sip/sie 位域描述."""
    return [
        ("USIP", 0, "U 模式软件中断挂起"),
        ("SSIP", 1, "S 模式软件中断挂起"),
        ("MSIP", 3, "M 模式软件中断挂起"),
        ("UTIP", 4, "U 模式定时器中断挂起"),
        ("STIP", 5, "S 模式定时器中断挂起"),
        ("MTIP", 7, "M 模式定时器中断挂起"),
        ("UEIP", 8, "U 模式外部中断挂起"),
        ("SEIP", 9, "S 模式外部中断挂起"),
        ("MEIP", 11, "M 模式外部中断挂起"),
    ]
