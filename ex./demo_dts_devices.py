#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按芯片设备树装配平台, 用调试器的 devices 命令列出设备地址区间.

输入为 DTS 源文件路径; 平台配置由 ``PlatformConfig.from_chip`` 按该树构造,
区间的输出复用调试器的 ``devices`` 命令.

运行:
    uv run python examples/demo_dts_devices.py <芯片.dts>
"""

from __future__ import annotations

from pathlib import Path
import sys

from pyremu.debug import Debugger
from pyremu.emulator import Emulator
from pyremu.platform import PlatformConfig
from pyremu.utils.dev_tree import parse_chip_dts

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"uv run python {__file__} /path/to/chip.dts")
        sys.exit(1)
    chip_def = parse_chip_dts(Path(sys.argv[1]))
    Debugger(Emulator(PlatformConfig.from_chip(chip_def))).cmd_devices()
