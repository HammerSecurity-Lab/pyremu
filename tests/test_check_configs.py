#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""mk/ 传递给 pyremu 的配置常量的合法性检查与设备区间分配."""

from __future__ import annotations

import pytest

from pyremu.check_configs import (
    check_limits,
    check_reserved_ranges,
    DevRange,
    MAX_PMP_ENTRIES,
    parse_dev_range,
    RANGE_LIMIT,
)
from pyremu.platform import PlatformConfig
from pyremu.utils import dev_tree


@pytest.mark.parametrize(
    ("kwargs", "config_kwargs", "raises"),
    [
        # 取值合法
        (
            {
                "ram_size": 0x1000,
                "pmp_entries": 8,
                "num_harts": 1,
                "memory_limit": 0x1_0000,
            },
            None,
            None,
        ),
        # PMP 条目数取上界
        (
            {
                "ram_size": 0x1000,
                "pmp_entries": MAX_PMP_ENTRIES,
                "num_harts": 1,
                "memory_limit": 0x1_0000,
            },
            None,
            None,
        ),
        # RAM 恰好等于可用内存
        (
            {
                "ram_size": 0x1_0000,
                "pmp_entries": 8,
                "num_harts": 1,
                "memory_limit": 0x1_0000,
            },
            None,
            None,
        ),
        # PMP 条目数超过硬件上界
        (
            {
                "ram_size": 0x1000,
                "pmp_entries": MAX_PMP_ENTRIES + 1,
                "num_harts": 1,
                "memory_limit": 0x1_0000,
            },
            None,
            "PMP_ENTRIES",
        ),
        # PMP 条目数为 0 表示不实现 PMP, 属合法配置
        (
            {
                "ram_size": 0x1000,
                "pmp_entries": 0,
                "num_harts": 1,
                "memory_limit": 0x1_0000,
            },
            None,
            None,
        ),
        # hart 数为 0
        (
            {
                "ram_size": 0x1000,
                "pmp_entries": 8,
                "num_harts": 0,
                "memory_limit": 0x1_0000,
            },
            None,
            "NUM_HARTS",
        ),
        # RAM 超过可用内存
        (
            {
                "ram_size": 0x2_0000,
                "pmp_entries": 8,
                "num_harts": 1,
                "memory_limit": 0x1_0000,
            },
            None,
            "RAM_SIZE",
        ),
        # PlatformConfig 构造路径同样受检
        (None, {"pmp_entries": MAX_PMP_ENTRIES + 1}, "PMP_ENTRIES"),
        (None, {"num_harts": 0}, "NUM_HARTS"),
    ],
)
def test_config_limits(kwargs, config_kwargs, raises) -> None:
    """配置取值的检查: 合法值放行, 越界值以 SystemExit 报错.

    ``kwargs`` 非空时直接调用 ``check_limits``; 为空时按 ``config_kwargs``
    构造 ``PlatformConfig``, 核对构造路径同样执行检查.
    """
    if raises is None:
        check_limits(**kwargs)
        return
    with pytest.raises(SystemExit, match=raises):
        if kwargs is not None:
            check_limits(**kwargs)
        else:
            PlatformConfig(**config_kwargs)


@pytest.mark.parametrize(
    ("ranges", "expected_bases", "raises"),
    [
        # 互不冲突, 基址保持
        (
            [
                DevRange("ram", 0x8000_0000, 0x1_0000, is_fixed=True),
                DevRange("uart", 0x1000_0000, 0x1000),
            ],
            (0x8000_0000, 0x1000_0000),
            None,
        ),
        # 与 RAM 重叠, 移到 RAM 之后
        (
            [
                DevRange("ram", 0x8000_0000, 0x1_0000, is_fixed=True),
                DevRange("uart", 0x8000_0000, 0x1000),
            ],
            (0x8000_0000, 0x8001_0000),
            None,
        ),
        # 两设备重叠, 后者顺延一页
        (
            [
                DevRange("uart", 0x1000_0000, 0x1000),
                DevRange("spi", 0x1000_0000, 0x1000),
            ],
            (0x1000_0000, 0x1000_1000),
            None,
        ),
        # 固定区间不参与重新分配
        (
            [
                DevRange("rom", 0x4000_0000, 0x1_0000, is_fixed=True),
                DevRange("uart", 0x4000_0000, 0x1000),
            ],
            (0x4000_0000, 0x4001_0000),
            None,
        ),
        # 基址取 0 的区间跳过, 不占地址
        (
            [
                DevRange("ram", 0x8000_0000, 0x1000, is_fixed=True),
                DevRange("uart", 0, 0x1000),
                DevRange("spi", 0x8000_0000, 0x1000),
            ],
            (0x8000_0000, 0, 0x8000_1000),
            None,
        ),
        # 重新分配时遵守对齐
        (
            [
                DevRange("ram", 0x8000_0000, 0x1_0000, is_fixed=True),
                DevRange("imsic", 0x8000_0001, 0x2000, align=0x2000),
            ],
            (0x8000_0000, 0x8001_0000),
            None,
        ),
        # 地址上界内没有空位, 报错退出
        (
            [
                DevRange("ram", RANGE_LIMIT - 0x1000, 0x1000, is_fixed=True),
                DevRange("uart", RANGE_LIMIT - 0x1000, 0x2000),
            ],
            None,
            "没有可用的地址空间",
        ),
    ],
)
def test_parse_dev_range(ranges, expected_bases, raises) -> None:
    """设备区间的冲突检测: 无冲突保持原基址, 冲突者重新分配, 无空位报错."""
    if raises is not None:
        with pytest.raises(SystemExit, match=raises):
            parse_dev_range(ranges)
        return
    got = parse_dev_range(ranges)
    assert tuple(r.base for r in got) == expected_bases


@pytest.mark.parametrize(
    ("ranges", "raises"),
    [
        ([(0x8000_0000, 0x1000)], None),
        ([(0x8000_0000, 0x0800_0000)], None),
        ([(0x8000_0000, 0x0800_0001)], SystemExit),
        ([(0x7FFF_FFFF, 0x1000)], SystemExit),
        ([(0, 0)], None),
    ],
)
def test_check_reserved_ranges(ranges, raises) -> None:
    """保留区间须落在主存之内, 越界或低于基址时以 SystemExit 报错."""
    if raises is None:
        check_reserved_ranges(0x8000_0000, 0x0800_0000, ranges)
        return
    with pytest.raises(SystemExit):
        check_reserved_ranges(0x8000_0000, 0x0800_0000, ranges)


def test_default_dtb_rejects_reserved_pool_outside_ram() -> None:
    """默认主存 128 MiB 放不下 2.25 GiB 的飞地内存池, 生成设备树必须报错.

    默认配置把内存池列为保留区间, 而 RAM_SIZE 的默认值只覆盖
    [0x8000_0000, 0x8800_0000), 交付出去就是一份区间越界的设备树;
    固件按池的地址清零内存时在主存上界触发存储访问故障.
    """
    cfg = PlatformConfig()
    with pytest.raises(SystemExit):
        dev_tree.build_default_dtb(
            cfg, reserved_ranges=cfg.reserved_memory_ranges
        )
