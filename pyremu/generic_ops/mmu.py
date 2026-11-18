# SPDX-LICENSE-IDENTIFIER: MIT
"""Sv39 页表项拆解、合成与页大小查询 — 按后端选择实现."""

from __future__ import annotations

from pyremu import _native
from pyremu._native import loaded_lib
from pyremu.memory import mmu


def sv39_decompose_va(va: int):
    """把 39 位虚拟地址分解为带字段的 Sv39Vpn 结构体."""
    if _native.loaded_lib() is None:
        return mmu.sv39_vpn_fields(va)
    return loaded_lib().sv39_decompose_va(va)


def pte_parse(raw: int):
    """把 64 位页表项原值拆成 PteFields."""
    if _native.loaded_lib() is None:
        return mmu.pte_parse(raw)
    return loaded_lib().pte_parse(raw)


def pte_assemble_pa(ppn: int, va: int, level: int) -> int:
    """由叶子页表项的 PPN、原虚拟地址与页级别合成物理地址."""
    if _native.loaded_lib() is None:
        return mmu.pte_assemble_pa(ppn, va, level)
    return loaded_lib().pte_assemble_pa(ppn, va, level)


def sv39_page_size(level: int) -> int:
    """返回 Sv39 叶子页的字节数."""
    if _native.loaded_lib() is None:
        return mmu.sv39_page_size(level)
    return loaded_lib().sv39_page_size(level)


__all__ = [
    "pte_assemble_pa",
    "pte_parse",
    "sv39_decompose_va",
    "sv39_page_size",
]
