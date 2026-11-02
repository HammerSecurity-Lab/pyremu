# Copyright (c) 2019, Nordic Semiconductor
# SPDX-License-Identifier: BSD-3-Clause
#
# 本包由 Zephyr Project 的 python-devicetree 包中的 dtlib.py 拆分而来,
# 版权声明与许可条款见同目录下的 LICENSE.

"""设备树解析器 — 对外给出入口类 DT 与解析结果的数据模型.

词法单元、词法分析、语法分析与节点模型分别位于 tokens, lexer, syntax 与 model 模块.
"""

from pyremu.utils.dev_tree.parser.model import (
    DTError,
    Node,
    Property,
    to_num,
    to_nums,
    Type,
)
from pyremu.utils.dev_tree.parser.syntax import DT

__all__ = [
    "DT",
    "DTError",
    "Node",
    "Property",
    "Type",
    "to_num",
    "to_nums",
]
