#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""调试器无状态工具 — 格式化、校验、常量.

所有函数均为模块级, 不依赖 Debugger 实例.
"""

from pathlib import Path
from typing import TYPE_CHECKING
import unicodedata

from pyremu.configs_aux import cfg_str
from pyremu.core import trap_def
from pyremu.core.hart import RiscvMode
from pyremu.debug.exception import UsageError
from pyremu.utils.disassem import Opc
from pyremu.utils.mask import mask64

if TYPE_CHECKING:
    from pyremu.core.hart import HartWithRegs
    from pyremu.memory.bus import Bus

# ============================================================
#  格式化
# ============================================================

MAX_INSTR_COUNT = 100_000  # 指令条数上限
_TRI_SPLIT = ["", "K", "M", "B", "T", "P", "E"]

SIZE_UNITS: tuple[tuple[str, int], ...] = (
    ("EB", 1 << 60),
    ("PB", 1 << 50),
    ("TB", 1 << 40),
    ("GB", 1 << 30),
    ("MB", 1 << 20),
    ("KB", 1 << 10),
    ("B", 1),
)

# ============================================================
#  异常/中断名称表
# ============================================================

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

# ============================================================
#  断点常量
# ============================================================

INSTR_BP_NAMES: dict[str, int] = {
    "ecall": 0x000,
    "ebreak": 0x001,
    "mret": 0x302,
    "sret": 0x102,
    "wfi": 0x105,
}

KNOWN_OPCODES: frozenset[int] = frozenset(o.value for o in Opc)
# ============================================================
#  历史文件
# ============================================================
MAX_ADDR = (1 << 64) - 1
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# 未配置路径时使用的文件名, 位于用户主目录下.
HISTORY_FILE_NAME = ".pyremu_history"


def hex_addr(v: int, styled: bool = True) -> str:
    """格式化为 16 位 hex: ``0x0000000080000000``.

    *styled* 为 True 时, 虚地址以蓝色高亮 (Rich tag).
    """
    raw = f"0x{mask64(v):016x}"
    if styled:
        return f"[bright_blue]{raw}[/]"
    return raw


def fmt_size(n: int) -> str:
    """human-readable 尺寸, 超出最大单位时落到最远单位."""
    for name, threshold in SIZE_UNITS:
        if n >= threshold:
            return f"{n / threshold:.3f} {name}"
    return f"{n} B"


def parse_size(text: str) -> int:
    """解析带单位的大小, 返回字节数.

    单位取 SIZE_UNITS 的写法或其中单个字母, 单位后的 B 可省略; 无单位时按字节计,
    如 ``128M`` 与 ``128MB`` 都表示 128 MiB.

    Raises:
        ValueError: 内容不是整数与单位的组合.
    """
    s = text.upper().rstrip("B")
    for name, mul in SIZE_UNITS:
        # 多字母单位写作字母加 B, 去掉 B 后按该字母匹配.
        if len(name) > 1 and s.endswith(name[0]):
            return int(s[:-1]) * mul
    return int(s)


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


def _escape_nonprintable(ch: str) -> str:
    """把控制字符、格式字符与代理字符写成反斜杠转义形式."""
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def fmt_display_name(text: str) -> str:
    """把文件名或路径写成可直接复制的形式.

    不可打印的字符写成转义形式; 结果含空白或已发生转义时用引号包围,
    使含空白的文件名在 ``sym load`` 中仍可作为单个参数给出.
    """
    escaped = "".join(
        _escape_nonprintable(ch) if unicodedata.category(ch).startswith("C") else ch
        for ch in text
    )
    if escaped == text and not any(ch.isspace() for ch in text):
        return text
    if '"' not in escaped:
        return f'"{escaped}"'
    if "'" not in escaped:
        return f"'{escaped}'"
    return '"' + escaped.replace("\\", "\\\\").replace('"', '\\"') + '"'


def fmt_instr_count(n: int) -> str:
    nn = float(n)
    for idx, val in enumerate(_TRI_SPLIT):
        if nn < 1000:
            return f"{nn:.3f}{val}"
        nn /= 1000.0
    return f"{n:.3f}?"


def trap_cause_name(mcause_val: int) -> str:
    """将 mcause 寄存器值翻译为可读的 trap 类型名称."""
    return trap_def.trap_cause_name(mcause_val)


# ============================================================
#  虚拟地址读取
# ============================================================


def read_pa_bytes(
    bus: Bus,
    pa: int,
    size: int,
) -> bytes | None:
    """从物理地址读取内存, 只读取主存与已注册设备的地址范围.

    Returns:
        读到的字节; 地址不是整数, 超出 64 位范围或落在未定义的物理空间时返回 None.
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


# ============================================================
#  校验
# ============================================================


def check_rv64_addr(v: int) -> bool:
    """校验 *v* 是否在 RV64 地址范围 [0, 2^64) 内."""
    return 0 <= v < (1 << 64)


# ============================================================
#  中断/IP 位描述
# ============================================================


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


def history_file_path() -> Path:
    """命令历史文件的路径.

    取环境变量 PYREMU_HISTORY_FILE 或 configs_gen 中的同名配置; 两者都没有时取用户
    主目录下的 HISTORY_FILE_NAME.
    """
    configured = cfg_str("PYREMU_HISTORY_FILE")
    if len(configured) > 0:
        return Path(configured).expanduser()
    return Path.home() / HISTORY_FILE_NAME


def trim_history(max_entries: int = 10000) -> None:
    """若历史文件超过 *max_entries* 行, 仅保留最近一半."""
    hist_path = history_file_path()
    if not hist_path.is_file():
        return
    try:
        lines = hist_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) <= max_entries:
            return
        keep = max_entries // 2
        hist_path.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")
    except OSError:
        pass  # 文件被锁或权限不足时静默跳过


def group_order(key: str) -> tuple[int, str]:
    """字典序排序: 字母先 (a-z), 再数字, 再下划线, 再点, 最后其他."""
    c = key.lower()
    if "a" <= c <= "z":
        return (0, c)
    if "0" <= c <= "9":
        return (1, c)
    if c == "_":
        return (2, c)
    if c == ".":
        return (3, c)
    return (4, c)
