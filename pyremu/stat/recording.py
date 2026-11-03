#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""加速执行统计的记录入口; 统计关闭时全部函数为空操作.

由环境变量 ``PYREMU_BATCH_STATS`` 决定是否评估统计, 取值 "0" 或空串表示关闭.
"""

import atexit
import functools
import sys

from pyremu.configs_aux import cfg_bool
from pyremu.stat.batch import BatchStats


@functools.cache
def _resolve_stats() -> BatchStats | None:
    """判定开关并创建本进程唯一的统计对象, 未打开时返回 ``None``."""
    if not cfg_bool("PYREMU_BATCH_STATS"):
        return None
    stats = BatchStats()
    atexit.register(_report_at_exit)
    return stats


def get_batch_stats() -> BatchStats | None:
    """取本进程的统计对象; ``PYREMU_BATCH_STATS`` 未打开时返回 ``None``."""
    return _resolve_stats()


def begin_round() -> None:
    """开始记录一轮加速执行."""
    stats = _resolve_stats()
    if stats is not None:
        stats.begin()


def mark_phase(phase: str) -> None:
    """结束当前阶段, 开始下一阶段."""
    stats = _resolve_stats()
    if stats is not None:
        stats.mark(phase)


def end_round(
    exit_reason: int,
    instrs: int,
    exit_instr: int = 0,
    exit_pc: int = 0,
    exit_hart_id: int = 0,
) -> None:
    """登记本轮的退出原因、退出指令、退出地址与指令数."""
    stats = _resolve_stats()
    if stats is not None:
        stats.end(exit_reason, instrs, exit_instr, exit_pc, exit_hart_id)


def _report_at_exit() -> None:
    stats = _resolve_stats()
    if stats is None or stats.batch_count == 0:
        return
    print(stats.report(), file=sys.stderr, flush=True)
