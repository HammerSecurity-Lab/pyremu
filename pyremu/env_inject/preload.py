#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""
预加载注入器 — 将外部提供的载荷写入物理内存.

载荷来源:
- RISC-V 指令流, 类似 objcopy -O binary 产物
- 或手动定义的字节序列

注入后 Emulator 将从载荷的入口开始执行, 载荷负责设置环境并跳转到目标程序入口.

默认内存布局 (以 ram_base=0x80000000, ram_size=128 MiB 为例):

  OpenSBI:   0x80000000 - 0x8003ebb0  (PIE 搬迁后, ~251 KiB)
  DTB:       0x87ff0000 - 0x87ff046c  (ram_base + ram_size - RAM_DTB_OFFSET)
  Preload:   0x87fe0000 - 0x87fe008c  (ram_base + ram_size - RAM_PRELOAD_OFFSET)
"""

from pathlib import Path

from pyremu import configs_gen
from pyremu.emulator import Emulator
from pyremu.memory.bus import ranges_overlap


class Preloader:
    """将外部载荷注入物理内存并返回入口地址.

    Usage:
        p = Preloader(emu)
        entry = p.inject(code_bytes)                # 从 bytes
        entry = p.inject_file("/path/to/crt0.bin")  # 从文件
        emu.harts[0].pc = entry
    """

    def __init__(
        self,
        emu: Emulator,
    ) -> None:
        self._emu = emu

    def inject(
        self,
        code: bytes,
        addr: int | None = None,
    ) -> int:
        """将载荷字节写入物理内存.

        Args:
            code: 原始 RISC-V 机器码字节.
            addr: 写入地址 (None = 自动选择 RAM 窗口内的默认位置).

        Returns:
            载荷的起始物理地址, 即入口地址.

        Raises:
            ValueError: 载荷的区间范围不在 RAM 窗口或引导只读存储器窗口内, 或与
                已装载的设备树、initramfs 的区间范围重叠.
        """
        emu = self._emu
        if addr is None:
            # 默认注入位置: 自 RAM 窗口 [ram_base, ram_base + ram_size) 的上界往下
            # RAM_PRELOAD_OFFSET 字节, 该存储位置在设备树的默认位置之下, 见 mk/memory.mk.
            addr = (
                emu.bus.ram_base + emu.bus.ram_size - configs_gen.RAM_PRELOAD_OFFSET
            ) & ~0xF

        bus = emu.bus
        start, end = addr, addr + len(code)
        if not (bus.is_ram_range(start, len(code)) or bus.is_rom_range(start, len(code))):
            raise ValueError(
                f"载荷的区间范围 [0x{start:x}, 0x{end:x}) 不在 RAM 窗口"
                f" [0x{bus.ram_base:x}, 0x{bus.ram_base + bus.ram_size:x}) 或"
                f"引导只读存储器的窗口内"
            )
        dtb_addr = emu.dtb_addr
        if dtb_addr is not None and ranges_overlap(
            start, end, dtb_addr, dtb_addr + emu.dtb_size
        ):
            raise ValueError(
                f"载荷的区间范围 [0x{start:x}, 0x{end:x}) 与设备树的区间范围"
                f" [0x{dtb_addr:x}, 0x{dtb_addr + emu.dtb_size:x}) 重叠"
            )
        initrd = emu.initrd
        if initrd is not None and ranges_overlap(start, end, initrd.start, initrd.end):
            raise ValueError(
                f"载荷的区间范围 [0x{start:x}, 0x{end:x}) 与 initramfs 的区间范围"
                f" [0x{initrd.start:x}, 0x{initrd.end:x}) 重叠"
            )

        emu.load_code(addr, code)
        return addr

    def inject_file(
        self,
        path: str,
        addr: int | None = None,
    ) -> int:
        """从文件读取载荷并注入物理内存.

        Args:
            path: 载荷文件路径 (裸二进制).
            addr: 写入地址 (None = 自动选择).

        Returns:
            载荷的入口地址.
        """
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"preload payload file not found: {p}")
        code = p.read_bytes()
        return self.inject(code, addr)
