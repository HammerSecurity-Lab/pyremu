#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""顺序编号计数器的用例."""

from pyremu.utils.counter import Counter


class TestCounter:
    """每次调用返回自增前的取值."""

    def test_call_returns_value_before_increment(self):
        counter = Counter(3)
        assert [counter() for _ in range(3)] == [3, 4, 5]

    def test_call_starts_at_zero_by_default(self):
        counter = Counter()
        assert counter() == 0

    def test_reset_clears_to_zero(self):
        counter = Counter(5)
        counter()
        counter.reset()
        assert counter() == 0

    def test_set_to_sets_given_value(self):
        counter = Counter()
        counter.set_to(7)
        assert counter() == 7
