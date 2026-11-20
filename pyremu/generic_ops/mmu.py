# SPDX-LICENSE-IDENTIFIER: MIT
"""Sv39 页表项拆解、合成与页大小查询 — 按后端选择实现."""

from __future__ import annotations

from pyremu._native import loaded_lib, native_available, PteFields, Sv39Vpn


def _vpn_fields(va: int) -> Sv39Vpn:
    """把 39 位虚拟地址分解为带字段的 Sv39Vpn 结构体."""
    vpn = Sv39Vpn()
    va &= 0xFFFF_FFFF_FFFF_FFFF
    vpn.vpn2 = (va >> 30) & 0x1FF
    vpn.vpn1 = (va >> 21) & 0x1FF
    vpn.vpn0 = (va >> 12) & 0x1FF
    vpn.offset = va & 0xFFF
    return vpn


def _pte_parse_fields(raw: int) -> PteFields:
    """把 64 位页表项原值拆成 PteFields."""
    raw &= 0xFFFF_FFFF_FFFF_FFFF
    # 叶子页表项要求 R、W、X 中至少一位置位; W 置位而 R 清零属保留编码,
    # 仍按叶子项处理, 由权限检查投递缺页.
    rwx = raw & 0b1110
    f = PteFields()
    f.ppn = (raw >> 10) & 0xFFF_FFFF_FFFF
    f.perm = raw & 0x1E
    f.v = 1 if raw & 0x1 else 0
    f.is_leaf = 1 if f.v and rwx else 0
    f.is_ptr = 1 if f.v and not rwx else 0
    return f


def _assemble_pa(ppn: int, va: int, level: int) -> int:
    """由叶子页表项的 PPN、原虚拟地址与页级别合成物理地址."""
    if level == 1:
        vpn0 = (va >> 12) & 0x1FF
        ppn = (ppn & 0xFFFF_FFFF_FFFF_FE00) | vpn0
    return ((ppn << 12) | (va & 0xFFF)) & 0xFFFF_FFFF_FFFF_FFFF


def _page_size(level: int) -> int:
    """返回 Sv39 叶子页的字节数."""
    return 2 * 1024 * 1024 if level == 1 else 4096


def sv39_decompose_va(va: int):
    """把 39 位虚拟地址分解为带字段的 Sv39Vpn 结构体."""
    if not native_available():
        return _vpn_fields(va)
    return loaded_lib().sv39_decompose_va(va)


def pte_parse(raw: int):
    """把 64 位页表项原值拆成 PteFields."""
    if not native_available():
        return _pte_parse_fields(raw)
    return loaded_lib().pte_parse(raw)


def pte_assemble_pa(ppn: int, va: int, level: int) -> int:
    """由叶子页表项的 PPN、原虚拟地址与页级别合成物理地址."""
    if not native_available():
        return _assemble_pa(ppn, va, level)
    return loaded_lib().pte_assemble_pa(ppn, va, level)


def sv39_page_size(level: int) -> int:
    """返回 Sv39 叶子页的字节数."""
    if not native_available():
        return _page_size(level)
    return loaded_lib().sv39_page_size(level)


__all__ = [
    "pte_assemble_pa",
    "pte_parse",
    "sv39_decompose_va",
    "sv39_page_size",
]
