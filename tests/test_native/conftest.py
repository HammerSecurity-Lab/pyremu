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

    ``handle_alu`` / ``handle_op_imm`` / ``handle_op32`` / ``handle_op_imm32``
    以 ``native_available()`` 的返回值判断是否调用加速执行库, 故替换该函数返回
    False 即退回纯 Python 实现, 无须触及动态库的装载状态。
    """
    with mock.patch(
        "pyremu.core.decoder.alu.native_available", return_value=False
    ) as gate:
        yield gate


@pytest.fixture
def pure_python():
    """使 pyremu._native 的各个入口走纯 Python 回退分支。"""
    with mock.patch("pyremu._native._lib", None):
        yield
