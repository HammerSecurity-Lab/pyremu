#!/usr/bin/env python3
# -*- coding: utf-8
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""设备树的读取、改写与生成.

各模块的分工: chip 从芯片 DTS 文本读出平台参数, rewrite 把已解析的芯片树改写为
交给受调试程序的 DTB, build 按平台配置生成 DTB, fdt_node 提供 pyfdt 节点树上的
读写与单元格编解码, parser 是由 Zephyr Project 的 python-devicetree 拆分而来的
DTS 解析器.
"""

from pyremu.utils.dev_tree.build import build_default_dtb, DefaultDtbDev, Initrd
from pyremu.utils.dev_tree.chip import (
    ChipDt,
    ChipIrq,
    ChipPeriph,
    DtDeviceNode,
    DtDeviceRequest,
    DtRegion,
    parse_chip_dts,
    parse_chip_dts_text,
    region_text,
)
from pyremu.utils.dev_tree.fdt_node import (
    cells_for,
    cells_of_node,
    child_node,
    decode_cells,
    DEFAULT_ADDR_CELLS,
    DEFAULT_SIZE_CELLS,
    encode_cells,
    find_node,
    has_compatible,
    is_enabled_node,
    iter_nodes,
    node_property,
    parent_of,
    phandle_of,
    reg_words,
    set_property,
)
from pyremu.utils.dev_tree.parser import DT, DTError, Node, Property, to_num, to_nums, Type
from pyremu.utils.dev_tree.rewrite import chip_dt_to_dtb, DeliveredTree

__all__ = [
    "DEFAULT_ADDR_CELLS",
    "DEFAULT_SIZE_CELLS",
    "ChipDt",
    "ChipIrq",
    "ChipPeriph",
    "DT",
    "DTError",
    "DefaultDtbDev",
    "DeliveredTree",
    "DtDeviceNode",
    "DtDeviceRequest",
    "DtRegion",
    "Initrd",
    "Node",
    "Property",
    "Type",
    "build_default_dtb",
    "cells_for",
    "cells_of_node",
    "child_node",
    "chip_dt_to_dtb",
    "decode_cells",
    "encode_cells",
    "find_node",
    "has_compatible",
    "is_enabled_node",
    "iter_nodes",
    "node_property",
    "parent_of",
    "parse_chip_dts",
    "parse_chip_dts_text",
    "phandle_of",
    "reg_words",
    "region_text",
    "set_property",
    "to_num",
    "to_nums",
]
