#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""
环境注入包 — 将外部载荷注入 RAM 作为目标程序的预加载运行时.

snippets.py  提供可复用的 RISC-V 指令片段, 由使用者自行组装,
preload.py   负责将外部提供的载荷字节流写入 RAM 并返回入口地址.

Usage:
    from pyremu.env_inject import Preloader
    from pyremu.env_inject.snippets import set_sp, set_gp

    # 使用者自行组装载荷:
    payload = b"".join(w.to_bytes(4, "little") for w in set_sp(0x7FFF000).words)
    payload += ...  # 更多片段 + 跳转到 main 的指令

    # 注入:
    p = Preloader(emu)
    entry = p.inject(payload)
"""

from pyremu.env_inject.preload import Preloader

__all__ = ["Preloader"]
