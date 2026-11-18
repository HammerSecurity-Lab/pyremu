#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""tests/test_native 共用的夹具."""

from __future__ import annotations

from unittest import mock

import pytest


@pytest.fixture
def no_native():
    """关闭加速执行, 使指令执行走纯 Python 路径.

    后端选择在 ``pyremu.generic_ops`` 内完成,
    依据是 ``pyremu._native._lib`` 是否为空;
    把该句柄置空即退回纯 Python 实现, 无须卸载动态库.
    """
    with (
        mock.patch("pyremu._native.native_available", return_value=False),
        mock.patch(
            "pyremu._native.loaded_lib", return_value=None
        ) as avail_lib,
    ):
        yield avail_lib


@pytest.fixture
def pure_python():
    """使 pyremu._native 的各个入口走纯 Python 回退分支。"""
    with mock.patch("pyremu._native._lib", None):
        yield
