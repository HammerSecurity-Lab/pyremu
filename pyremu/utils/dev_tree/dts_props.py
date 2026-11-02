#!/usr/bin/env python3
# -*- coding: utf-8
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""DTS 源文本解析树上的属性取值与节点判定.

与 fdt_node 的分工: fdt_node 读写 pyfdt 的 FdtNode, 即已编译的 DTB 的节点树;
本模块读取内置解析器的 Node, 即 DTS 源文本解析后的节点树.
"""

from __future__ import annotations

from collections.abc import Sequence

from pyremu.utils.dev_tree.parser import DTError, Node


def strings_of(
    node: Node,
    name: str,
) -> list[str]:
    """取字符串类属性的全部取值; 属性不存在或类型不符时返回空列表."""
    prop = node.props.get(name)
    if prop is None:
        return []
    try:
        return prop.to_strings()
    except DTError:
        return []


def cells_of(
    node: Node,
    name: str,
) -> list[int] | None:
    """取格子类属性的取值; 属性不存在或类型不符时返回 None."""
    prop = node.props.get(name)
    if prop is None:
        return None
    try:
        return prop.to_nums()
    except DTError:
        return None


def first_cell(
    node: Node,
    name: str,
) -> int | None:
    """取格子类属性的第一格; 属性不存在或为空时返回 None."""
    cells = cells_of(node, name)
    if cells:
        return cells[0]
    return None


def cell_count(
    node: Node | None,
    name: str,
    default: int,
) -> int:
    """取 #address-cells 或 #size-cells 的取值, 缺失时取 default."""
    if node is None:
        return default
    value = first_cell(node, name)
    return default if value is None else value


def is_enabled(
    node: Node,
) -> bool:
    """不带 status 属性或 status 取值为 okay 时, 节点有效."""
    status = strings_of(node, "status")
    if not status:
        return True
    return status[0] in ("okay", "ok")


def has_compat(
    node: Node,
    compatibles: Sequence[str],
) -> bool:
    """节点的 compatible 属性与给定取值有交集."""
    return any(item in compatibles for item in strings_of(node, "compatible"))


def base_name(
    node: Node,
) -> str:
    """节点名称中 '@' 之前的部分."""
    return node.name.partition("@")[0]


def node_named(
    nodes: Sequence[Node],
    name: str,
) -> Node | None:
    """取名称与给定值相同的第一个节点."""
    for node in nodes:
        if base_name(node) == name:
            return node
    return None
