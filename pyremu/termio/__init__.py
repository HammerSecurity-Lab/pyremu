#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""终端 I/O 桥接 — 宿主 stdin/stdout 与 UART 之间的转发.

本包不实现 Device 接口, 不属于内存映射外设: 由 Emulator 创建并注入 UART.
"""

from pyremu.termio.bridge import TerminalIO
from pyremu.termio.keys import translate_host_keys

__all__ = ["TerminalIO", "translate_host_keys"]
