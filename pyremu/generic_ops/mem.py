# SPDX-LICENSE-IDENTIFIER: MIT
"""主存直接读写 — 有动态链接库时直读 RAM 缓冲区, 否则由调用方走 Python 路径."""

from __future__ import annotations

import ctypes

from pyremu._native import loaded_lib, native_available

# 加速执行引擎一次读写的宽度: 读取结果暂存在一个 64 位单元格中,
# 更宽的访问 (例如 64 字节的缓存行填充) 由调用方走 Python 路径.
_ACCESS_SIZES = (1, 2, 4, 8)


class RamView:
    """主存缓冲区在加速执行引擎一侧的视图.

    持有 RAM 缓冲区首地址、读取结果的暂存单元格与传给 bus_read_ram 和
    bus_write_ram 的区间元组; 区间元组的五项依次为缓冲区首地址、字节数、
    基址、PIE 链接基址与其字节数. 未装载动态链接库时首地址为 0, read 与
    write 均报告未处理, 调用方改走 Python 路径.
    """

    def __init__(
        self,
        ram: bytearray,
        ram_size: int,
        ram_base: int,
    ) -> None:
        self._ram_size = ram_size
        self._ram_base = ram_base
        self._read_out = ctypes.c_uint64(0)
        self._read_out_ptr: int = ctypes.addressof(self._read_out)
        self._ram_ptr: int = 0
        self._ram_range: tuple[int, int, int, int, int] = (
            0,
            ram_size,
            ram_base,
            0,
            0,
        )
        if native_available():
            # 首地址用 ctypes.addressof 取得; 取地址不用 ctypes.cast,
            # 后者会与所转换的对象构成引用环.
            self._ram_ptr = ctypes.addressof(ctypes.c_uint8.from_buffer(ram))
            self._ram_range = (
                self._ram_ptr,
                ram_size,
                ram_base,
                0,
                0,
            )

    @property
    def native_ptr(self) -> int:
        """RAM 缓冲区首地址; 未装载动态链接库时为 0."""
        return self._ram_ptr

    def set_pie_ofs(self, link_base: int, link_size: int) -> None:
        """登记 PIE 链接地址区间 [link_base, link_base + link_size).

        引擎把落在该区间内的地址换算为主存偏移后访问同一段字节.
        """
        self._ram_range = (
            self._ram_ptr,
            self._ram_size,
            self._ram_base,
            link_base,
            link_size,
        )

    def read(self, addr: int, size: int) -> bytes | None:
        """经加速执行引擎读出 *size* 个字节.

        返回 None 表示未装载动态链接库、访问宽度不是 1/2/4/8 字节之一,
        或地址不在主存范围内, 调用方应走 Python 路径.
        """
        if not self._ram_ptr or size not in _ACCESS_SIZES:
            return None
        if not bus_read_ram(self._ram_range, addr, size, self._read_out_ptr):
            return None
        return ctypes.string_at(self._read_out_ptr, size)

    def write(self, addr: int, data: bytes) -> bool:
        """经加速执行引擎写入 *data*; 返回是否已写入.

        与 read 同理, 宽度不受支持、未装载动态链接库或地址不在主存范围内时
        返回 False, 调用方应走 Python 路径.
        """
        data_len = len(data)
        if not self._ram_ptr or data_len not in _ACCESS_SIZES:
            return False
        return bool(bus_write_ram(self._ram_range, addr, data, data_len))


def bus_read_ram(ram_range, pa: int, size: int, out_buf) -> int:
    """从物理地址 *pa* 读出 *size* 个字节到 *out_buf*, 命中主存时返回 1.

    *ram_range* 为 (RAM 缓冲区首地址, 字节数, 基址, 影子基址, 影子字节数);
    返回 0 表示地址不在主存范围内或未装载动态链接库, 调用方转 Python 路径.
    """
    if not native_available():
        return 0
    return loaded_lib().bus_read_ram(*ram_range, pa, size, out_buf)


def bus_write_ram(ram_range, pa: int, data, size: int) -> int:
    """向物理地址 *pa* 写入 *data*, 命中主存时返回 1."""
    if not native_available():
        return 0
    return loaded_lib().bus_write_ram(*ram_range, pa, data, size)


def read_ram(
    lib_available: bool,
    ram: bytearray,
    ram_offset: int,
    size: int,
) -> bytes:
    """从主存读出 *size* 个字节.

    动态链接库可用时由调用方另行走 ``bus_read_ram``; 本函数给出纯 Python 结果.
    """
    del lib_available
    return bytes(ram[ram_offset : ram_offset + size])


def write_ram(ram: bytearray, ram_offset: int, data: bytes) -> None:
    """把 *data* 写入主存的纯 Python 路径."""
    ram[ram_offset : ram_offset + len(data)] = data


__all__ = [
    "RamView",
    "bus_read_ram",
    "bus_write_ram",
    "read_ram",
    "write_ram",
]
