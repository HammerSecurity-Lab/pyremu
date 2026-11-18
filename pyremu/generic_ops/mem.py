# SPDX-LICENSE-IDENTIFIER: MIT
"""主存直接读写 — 有动态链接库时直读 RAM 缓冲区, 否则由调用方走 Python 路径."""

from __future__ import annotations

from pyremu import _native
from pyremu._native import loaded_lib


def bus_read_ram(ram_range, pa: int, size: int, out_buf) -> int:
    """从物理地址 *pa* 读出 *size* 个字节到 *out_buf*, 命中主存时返回 1.

    *ram_range* 为 (RAM 缓冲区首地址, 字节数, 基址, 影子基址, 影子字节数);
    返回 0 表示地址不在主存范围内或未装载动态库, 调用方转 Python 路径.
    """
    if _native.loaded_lib() is None:
        return 0
    return loaded_lib().bus_read_ram(*ram_range, pa, size, out_buf)


def bus_write_ram(ram_range, pa: int, data, size: int) -> int:
    """向物理地址 *pa* 写入 *data*, 命中主存时返回 1."""
    if _native.loaded_lib() is None:
        return 0
    return loaded_lib().bus_write_ram(*ram_range, pa, data, size)


def read_ram(
    lib_available: bool,
    ram: bytearray,
    ram_offset: int,
    size: int,
) -> bytes:
    """从主存读出 *size* 个字节.

    动态库可用时由调用方另行走 ``bus_read_ram``; 本函数给出纯 Python 结果.
    """
    del lib_available
    return bytes(ram[ram_offset : ram_offset + size])


def write_ram(ram: bytearray, ram_offset: int, data: bytes) -> None:
    """把 *data* 写入主存的纯 Python 路径."""
    ram[ram_offset : ram_offset + len(data)] = data


__all__ = ["bus_read_ram", "bus_write_ram", "read_ram", "write_ram"]
