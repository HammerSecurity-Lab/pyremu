#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026


class Counter:
    """计数器: 每次调用返回自增前的取值, 随后自增."""

    def __init__(
        self,
        val: int = 0,
    ) -> None:
        self._cnt_val = val

    def __call__(self) -> int:
        value = self._cnt_val
        self._cnt_val += 1
        return value

    def reset(self) -> None:
        """清零."""
        self._cnt_val = 0

    def set_to(
        self,
        val: int,
    ) -> None:
        """把计数设置为 val."""
        self._cnt_val = val
