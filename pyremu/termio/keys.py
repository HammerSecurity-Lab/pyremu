#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""宿主终端按键编码到受调试程序终端编码的改写."""

from __future__ import annotations

# 宿主终端的按键编码到受调试程序终端编码的对照, 与 Rust 侧 translate_key
# 的对照一致. 受调试程序终端取 xterm 系列, 其 terminfo 的 khome 与 kend 为
# ESC O H 与 ESC O F; Ctrl 加左右键取行编辑器中按词移动的序列, Ctrl 加上下键
# 去掉修饰键, 与上键和下键相同.
_HOST_KEY_TO_GUEST: dict[bytes, bytes] = {
    b"\x1b[H": b"\x1bOH",
    b"\x1b[1~": b"\x1bOH",
    b"\x1b[7~": b"\x1bOH",
    b"\x1b[F": b"\x1bOF",
    b"\x1b[4~": b"\x1bOF",
    b"\x1b[8~": b"\x1bOF",
    b"\x1b[1;5C": b"\x1bf",
    b"\x1b[5C": b"\x1bf",
    b"\x1bOc": b"\x1bf",
    b"\x1b[1;5D": b"\x1bb",
    b"\x1b[5D": b"\x1bb",
    b"\x1bOd": b"\x1bb",
    b"\x1b[1;5A": b"\x1bOA",
    b"\x1b[5A": b"\x1bOA",
    b"\x1b[1;5B": b"\x1bOB",
    b"\x1b[5B": b"\x1bOB",
}


def _match_host_key(
    data: bytes,
    idx: int,
) -> tuple[bytes, int] | None:
    """取 idx 处匹配的宿主按键编码, 返回改写序列与源序列长度."""
    for seq, repl in _HOST_KEY_TO_GUEST.items():
        if data.startswith(seq, idx):
            return repl, len(seq)
    return None


def translate_host_keys(data: bytes) -> bytes:
    """把宿主终端的按键编码改写为受调试程序终端使用的编码.

    未列入对照的字节原样保留. 一个按键的编码若被拆分到两次读取中, 两段都不
    匹配对照, 原样转发.
    """
    if b"\x1b" not in data:
        return data
    out = bytearray()
    idx = 0
    while idx < len(data):
        matched = _match_host_key(data, idx) if data[idx] == 0x1B else None
        if matched is None:
            out.append(data[idx])
            idx += 1
            continue
        repl, length = matched
        out += repl
        idx += length
    return bytes(out)
