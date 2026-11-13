#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""运行统计 — 按环境变量打开, 在进程退出时把汇总写入标准错误.

- batch.py     — 加速执行每轮的批次数、退出原因、每批指令数与三段耗时
- recording.py — 记录入口与 ``PYREMU_BATCH_STATS`` 的判定

统计关闭时 ``begin_round``、``mark_phase`` 与 ``end_round`` 均为空操作,
调用方直接调用.
"""

from pyremu.stat.batch import BatchStats
from pyremu.stat.recording import (
    begin_round,
    end_round,
    get_batch_stats,
    mark_phase,
)

__all__ = [
    "BatchStats",
    "begin_round",
    "end_round",
    "get_batch_stats",
    "mark_phase",
]
