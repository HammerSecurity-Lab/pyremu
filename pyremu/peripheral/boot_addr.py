#!/usr/bin/env python3
# -*- coding: utf-8
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""启动地址寄存器 — 每个 hart 一个 64 位寄存器, 偏移 ``8 * hartid``.

hart 复位后在引导只读存储器内取指, 其中的代码读取本寄存器取得下一级程序的入口
地址. 寄存器可读可写; 窗口内不属于任何 hart 的字节读回零, 写入丢弃.

设备树中该节点不带 compatible, 按节点名称 ``boot-address-reg`` 识别.
"""

from __future__ import annotations

from pyremu.memory.bus import Device
from pyremu.utils.mask import mask08, mask64

# 每个 hart 的寄存器占用 8 字节.
ENTRY_BYTES = 8


class BootAddrReg(Device):
    """每个 hart 一个 64 位启动地址寄存器."""

    def __init__(
        self,
        num_harts: int,
        base: int = 0x1000,
        size: int = 0x1000,
    ) -> None:
        assert num_harts > 0, f"num_harts={num_harts} 须大于 0"
        assert size >= ENTRY_BYTES * num_harts, (
            f"窗口大小 0x{size:x} 不足以容纳 {num_harts} 个 hart 的寄存器"
        )
        self.base_addr = base
        self.size = size
        self._entries = [0] * num_harts

    def entry(
        self,
        hart_id: int,
    ) -> int:
        """读取该 hart 的启动地址."""
        return self._entries[hart_id]

    def set_entry(
        self,
        hart_id: int,
        addr: int,
    ) -> None:
        """直接写入该 hart 的启动地址, 不经总线写路径."""
        self._entries[hart_id] = mask64(addr)

    def read(
        self,
        offset: int,
        size: int,
    ) -> bytes:
        """按字节读取; 越出各 hart 寄存器范围的字节读回零."""
        out = bytearray(max(0, size))
        for index in range(len(out)):
            pos = offset + index
            if pos < 0:
                continue
            hart_id, byte_index = divmod(pos, ENTRY_BYTES)
            if hart_id >= len(self._entries):
                continue
            out[index] = mask08(self._entries[hart_id] >> (byte_index * 8))
        return bytes(out)

    def write(
        self,
        offset: int,
        data: bytes,
    ) -> None:
        """按字节写入; 越出各 hart 寄存器范围的字节丢弃."""
        for index, byte in enumerate(data):
            pos = offset + index
            if pos < 0:
                continue
            hart_id, byte_index = divmod(pos, ENTRY_BYTES)
            if hart_id >= len(self._entries):
                continue
            shift = byte_index * 8
            mask = 0xFF << shift
            self._entries[hart_id] = (self._entries[hart_id] & ~mask) | (
                byte << shift
            )
