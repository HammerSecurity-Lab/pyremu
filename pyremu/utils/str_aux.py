#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""字符串格式化与解析辅助 — 地址、尺寸、文件名、hexdump 等可复用文本格式."""

import unicodedata

from pyremu.utils.mask import mask64

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


def join_names(names: list[str], *, empty: str = "-") -> str:
    """把名称列表以逗号分隔连接; 列表为空时返回 *empty*."""
    return ", ".join(names) if names else empty


def flag_names(value: int, table: tuple[tuple[int, str], ...]) -> list[str]:
    """按位取出 *table* 中登记的名称; 未登记的高位以十六进制附在末尾."""
    names = [name for bit, name in table if value & bit]
    known = 0
    for bit, _name in table:
        known |= bit
    unknown = value & ~known
    if unknown:
        names.append(f"unknown=0x{unknown:x}")
    return names


def bytes_to_utf8(raw: bytes) -> str:
    """按第一个 0 字节截断, 再以 UTF-8 解码, 无法解码的字节替换为 U+FFFD."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def uuid_text(raw: bytes) -> str:
    """把 16 字节标识按其自然分段写成带连字符的十六进制文本."""
    text = raw.hex()
    parts = (text[:8], text[8:12], text[12:16], text[16:20], text[20:])
    return "-".join(parts)


def fmt_addr(addr: int) -> str:
    """
    默认情况下假设处在64位表示
    故仅固定 16 位并返回带 0x 前缀的十六进制字符串.
    """
    return f"0x{addr:016x}"


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


def fmt_instr_count(n: int) -> str:
    """把指令条数写成带 K/M/B 等后缀的三位小数形式."""
    nn = float(n)
    for idx, val in enumerate(_TRI_SPLIT):
        if nn < 1000:
            return f"{nn:.3f}{val}"
        nn /= 1000.0
    return f"{n:.3f}?"


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
        _escape_nonprintable(ch)
        if unicodedata.category(ch).startswith("C")
        else ch
        for ch in text
    )
    if escaped == text and not any(ch.isspace() for ch in text):
        return text
    if '"' not in escaped:
        return f'"{escaped}"'
    if "'" not in escaped:
        return f"'{escaped}'"
    return '"' + escaped.replace("\\", "\\\\").replace('"', '\\"') + '"'


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


def fmt_hexdump(data: bytes, addr: int = 0, *, columns: int = 16) -> str:
    """把字节序列转换为经典 hexdump 文本, 依次为地址列、十六进制列与 ASCII 列.

    Args:
        data: 原始字节.
        addr: 起始地址, 用于地址列显示.
        columns: 每行字节数, 默认为 16.
    """
    lines: list[str] = []
    for offset in range(0, len(data), columns):
        chunk = data[offset : offset + columns]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(
            f"  {fmt_addr(addr + offset)}  {hex_part:<{columns * 3 - 1}s}  "
            f"|{ascii_part}|"
        )
    return "\n".join(lines)


def dye_hexdump(data: bytes, addr: int = 0, *, columns: int = 16) -> str:
    """把字节序列转换为带 Rich 样式标记的 hexdump 文本.

    地址列用亮蓝色, ASCII 列用暗灰色.

    Args:
        data: 原始字节.
        addr: 起始地址, 用于地址列显示.
        columns: 每行字节数, 默认为 16.
    """
    lines: list[str] = []
    for offset in range(0, len(data), columns):
        chunk = data[offset : offset + columns]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        # ASCII 列写成 '[[' 后输出, 使 Rich 按字面显示该字符, 不把它解析为
        # 样式标记的开头.
        ascii_part = ascii_part.replace("[", "[[")
        lines.append(
            f"  [bright_blue]{fmt_addr(addr + offset)}[/]  "
            f"{hex_part:<{columns * 3 - 1}s}  [dim]|{ascii_part}|[/]"
        )
    return "\n".join(lines)
