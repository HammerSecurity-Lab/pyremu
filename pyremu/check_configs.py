#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""对 mk/ 传递给 pyremu 的配置常量做合法性检查与设备区间分配.

检查不依赖平台对象, 只接收数值参数与设备区间列表, 便于单独测试:

- 运行环境的内存上界: 取物理内存与 ``RLIMIT_AS`` 中较小者, 物理 RAM 不得超过它;
- PMP 条目数: 规范允许至多 64 条;
- 设备区间: RAM、引导只读存储器与各设备的地址区间两两不重叠. 发生重叠时按区间的
  请求基址升序重新分配, 找不到可容纳的地址则以 ``SystemExit`` 报错退出.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import os
import resource
import sys

from pyremu.utils.math import align_up

# PMP 条目数的硬件上界.
MAX_PMP_ENTRIES = 64

# 地址区间的默认对齐字节数.
DEFAULT_ALIGN = 0x1000

# 重新分配可用的地址上界, 超过视为没有可用的分配方案.
RANGE_LIMIT = 1 << 40


@dataclass(frozen=True)
class DevRange:
    """一段物理地址区间.

    字段:
        name: 区间名称, 用于报错与重分配提示.
        base: 请求的起始地址; 取 0 表示该区间未启用.
        size: 字节数.
        align: 起始地址的对齐字节数.
        is_fixed: 真表示该区间不参与重新分配.
    """

    name: str
    base: int
    size: int
    align: int = DEFAULT_ALIGN
    is_fixed: bool = False


def host_memory_limit() -> int | None:
    """运行环境可提供的内存上界, 取物理内存与 RLIMIT_AS 中较小者.

    两者都取不到时返回 None, 调用方据此跳过该项检查.
    """
    limits: list[int] = []
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and page_size > 0:
            limits.append(pages * page_size)
    except OSError, ValueError:
        pass
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
        if soft != resource.RLIM_INFINITY and soft > 0:
            limits.append(soft)
    except OSError, ValueError:
        pass
    return min(limits) if limits else None


def check_limits(
    *,
    ram_size: int,
    pmp_entries: int,
    num_harts: int,
    memory_limit: int | None = None,
) -> None:
    """检查与地址布局无关的配置取值.

    *memory_limit* 给出可用的内存上界; 省略时按 :func:`host_memory_limit` 取.
    任一项不合法时抛出 ``SystemExit``, 消息指出不合法项与允许范围.
    """
    if num_harts < 1:
        raise SystemExit(f"NUM_HARTS={num_harts} 须大于等于 1")
    if not 0 <= pmp_entries <= MAX_PMP_ENTRIES:
        raise SystemExit(
            f"PMP_ENTRIES={pmp_entries} 超出允许范围 0..{MAX_PMP_ENTRIES}"
        )
    limit = host_memory_limit() if memory_limit is None else memory_limit
    if limit is not None and ram_size > limit:
        raise SystemExit(
            f"RAM_SIZE=0x{ram_size:x} 超出当前运行环境可用的内存 "
            f"0x{limit:x}; 请检查 mk/ 下的内存配置或提高宿主限额"
        )


def check_reserved_ranges(
    ram_base: int,
    ram_size: int,
    ranges: Sequence[tuple[int, int]],
) -> None:
    """保留内存区间须落在主存之内.

    保留区间经设备树交给受调试程序; 落在主存之外时, 固件按该区间访问内存会
    触发存储访问故障. 不一致时抛出 ``SystemExit``, 消息指出越界区间与主存范围.
    """
    ram_end = ram_base + ram_size
    for base, size in ranges:
        if size == 0:
            continue
        if base < ram_base or base + size > ram_end:
            raise SystemExit(
                f"保留内存区间 [0x{base:x}, 0x{base + size:x}) 超出主存 "
                f"[0x{ram_base:x}, 0x{ram_end:x}); "
                "请增大 RAM 或调整 RESERVED_MEM_*"
            )


def _find_free_base(
    dev_range: DevRange,
    placed: Sequence[DevRange],
) -> int:
    """为一处冲突的区间寻找可容纳的起始地址.

    从请求的基址向上按对齐推进, 每次越过一个冲突区间的末尾; 超过
    :data:`RANGE_LIMIT` 时抛出 ``SystemExit``.
    """
    base = dev_range.base
    while True:
        base = align_up(base, dev_range.align)
        end = base + dev_range.size
        if base >= RANGE_LIMIT or end > RANGE_LIMIT:
            raise SystemExit(
                f"{dev_range.name} 没有可用的地址空间: 请求 "
                f"[0x{dev_range.base:x}, "
                f"0x{dev_range.base + dev_range.size:x}), "
                f"上界 0x{RANGE_LIMIT:x}"
            )
        conflict = next(
            (
                other
                for other in placed
                if base < other.base + other.size and other.base < end
            ),
            None,
        )
        if conflict is None:
            return base
        base = conflict.base + conflict.size


def parse_dev_range(ranges: Sequence[DevRange]) -> list[DevRange]:
    """按请求基址升序放置各区间, 冲突者重新分配并打印提示.

    固定区间先放置, 其余按请求基址升序放置; 与已放置区间重叠的区间从请求基址
    向上寻找第一个可容纳的对齐空位. 找不到时由 :func:`_find_free_base` 报错退出.
    返回与入参同序的区间列表, 重新分配过的区间基址已更新.
    """
    result = list(ranges)
    placed: list[DevRange] = []
    order = sorted(
        range(len(result)),
        key=lambda i: (not result[i].is_fixed, result[i].base),
    )
    for index in order:
        dev_range = result[index]
        if dev_range.base == 0 or dev_range.size == 0:
            continue
        base = _find_free_base(dev_range, placed)
        if base != dev_range.base:
            print(
                f"警告: {dev_range.name} 的基址 0x{dev_range.base:x} "
                f"与其他区间冲突, 重新分配到 0x{base:x}",
                file=sys.stderr,
            )
            dev_range = DevRange(
                name=dev_range.name,
                base=base,
                size=dev_range.size,
                align=dev_range.align,
                is_fixed=dev_range.is_fixed,
            )
            result[index] = dev_range
        placed.append(dev_range)
    return result
