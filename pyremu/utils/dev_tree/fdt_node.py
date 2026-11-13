#!/usr/bin/env python3
# -*- coding: utf-8
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""设备树节点的读写 — 在 pyfdt 的节点树上读取与改写属性, 编解码 32 位单元格.

节点与属性的查找按名称进行; 改写属性的过程中节点的位置与其余属性保持不变.
单元格是设备树中地址与大小的编码单位, 每格 32 位,
高位在前的格子序列表示一个取值.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from pyfdt.pyfdt import (
    FdtNode,
    FdtProperty,
    FdtPropertyStrings,
    FdtPropertyWords,
)

# 规范对未声明 #address-cells 与 #size-cells 的节点的缺省取值.
DEFAULT_ADDR_CELLS = 2
DEFAULT_SIZE_CELLS = 1


def node_property(
    node: FdtNode,
    name: str,
) -> FdtProperty | None:
    """取名为 name 的属性; 不存在时为 None."""
    for sub in node.subdata:
        if isinstance(sub, FdtProperty) and sub.get_name() == name:
            return sub
    return None


def set_property(
    node: FdtNode,
    prop: FdtProperty,
) -> None:
    """用 prop 取代 node 上的同名属性; 该属性不存在时插在最后一个属性之后.

    设备树要求属性排在子节点之前. 追加到末尾时该属性落在子节点之后, 按结构块顺序
    扫描属性的读取方看不到它.
    """
    last_prop = -1
    for index, sub in enumerate(node.subdata):
        if not isinstance(sub, FdtProperty):
            continue
        if sub.get_name() == prop.get_name():
            node[index] = prop
            return
        last_prop = index
    node.insert(last_prop + 1, prop)


def child_node(
    node: FdtNode,
    name: str,
) -> FdtNode | None:
    """取第一个名为 name 的子节点; 不存在时为 None."""
    for sub in node.subdata:
        if isinstance(sub, FdtNode) and sub.get_name() == name:
            return sub
    return None


def iter_nodes(
    root: FdtNode,
) -> Iterator[FdtNode]:
    """先序遍历 root 及其全部子节点."""
    yield root
    for sub in root.subdata:
        if isinstance(sub, FdtNode):
            yield from iter_nodes(sub)


def parent_of(
    root: FdtNode,
    target: FdtNode,
) -> FdtNode | None:
    """target 的父节点; target 就是 root 时返回 None."""
    for node in iter_nodes(root):
        if any(sub is target for sub in node.subdata):
            return node
    return None


def has_compatible(
    node: FdtNode,
    compatibles: Sequence[str],
) -> bool:
    """节点的 compatible 属性与给定取值有交集."""
    prop = node_property(node, "compatible")
    if not isinstance(prop, FdtPropertyStrings):
        return False
    return any(item in compatibles for item in prop.strings)


def find_node(
    root: FdtNode,
    compatibles: Sequence[str],
) -> FdtNode | None:
    """取第一个有效且 compatible 命中给定取值的节点."""
    for node in iter_nodes(root):
        if is_enabled_node(node) and has_compatible(node, compatibles):
            return node
    return None


def phandle_of(
    node: FdtNode,
) -> int:
    """节点的 phandle 取值.

    Raises:
        ValueError: 节点没有 phandle.
    """
    for name in ("phandle", "linux,phandle"):
        prop = node_property(node, name)
        if isinstance(prop, FdtPropertyWords) and prop.words:
            return prop.words[0]
    raise ValueError(f"{node.get_name()} 节点没有 phandle")


def cells_of_node(
    node: FdtNode,
    name: str,
    default: int,
) -> int:
    """取属性给出的一格单元格数; 属性不存在或不是单格格子时取 default."""
    prop = node_property(node, name)
    if isinstance(prop, FdtPropertyWords) and len(prop.words) == 1:
        return prop.words[0]
    return default


def is_enabled_node(
    node: FdtNode,
) -> bool:
    """不带 status 属性或 status 取值为 okay 时, 节点有效."""
    prop = node_property(node, "status")
    if not isinstance(prop, FdtPropertyStrings) or not prop.strings:
        return True
    return prop.strings[0] in ("okay", "ok")


def cells_for(
    value: int,
) -> int:
    """描述 value 所需的单元格数, 至少 1."""
    return max(1, (value.bit_length() + 31) // 32)


def encode_cells(
    value: int,
    cells: int,
) -> list[int]:
    """按 cells 个 32 位单元格编码 value, 高位在前."""
    if cells_for(value) > cells:
        raise ValueError(f"取值 0x{value:x} 超出 {cells} 个单元格的可表示范围")
    return [
        (value >> (32 * (cells - 1 - index))) & 0xFFFFFFFF
        for index in range(cells)
    ]


def decode_cells(
    words: Sequence[int],
) -> int:
    """把高位在前的若干 32 位单元格合为一个取值."""
    value = 0
    for word in words:
        value = (value << 32) | word
    return value


def reg_words(
    base: int,
    size: int,
    addr_cells: int,
    size_cells: int,
) -> list[int]:
    """按地址与大小的单元格数编码一段区间范围."""
    return encode_cells(base, addr_cells) + encode_cells(size, size_cells)
