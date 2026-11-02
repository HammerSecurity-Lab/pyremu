#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.utils."""

from pathlib import Path

import pytest

from pyremu.debug import utils
from pyremu.debug.utils import (
    check_rv64_addr,
    EXC_NAMES,
    fmt_instr_count,
    fmt_size,
    group_order,
    hex_addr,
    ip_bits,
    IRQ_NAMES,
    MAX_INSTR_COUNT,
    parse_size,
    trap_cause_name,
)


class TestHexAddr:
    def test_basic(self):
        assert hex_addr(0, styled=False) == "0x0000000000000000"
        assert hex_addr(0x80000000, styled=False) == "0x0000000080000000"

    def test_mask_upper_bits(self):
        """Python int 无位宽限制, 超出 64-bit 的部分应被掩码清除."""
        assert hex_addr(0x1_0000_0000_0000_0001, styled=False) == "0x0000000000000001"

    def test_negative_value(self):
        """负值在补码下转换为 64-bit 无符号."""
        assert hex_addr(-1, styled=False) == "0xffffffffffffffff"


class TestFmtSize:
    def test_bytes(self):
        assert fmt_size(0) == "0 B"
        assert fmt_size(512) == "512.000 B"

    def test_kb(self):
        assert fmt_size(2048) == "2.000 KB"

    def test_mb(self):
        assert fmt_size(2 * 1024 * 1024) == "2.000 MB"

    def test_gb(self):
        assert fmt_size(3 * 1024**3) == "3.000 GB"


class TestParseSize:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("1024", 1024),
            ("512B", 512),
            ("64K", 64 << 10),
            ("64KB", 64 << 10),
            ("128m", 128 << 20),
            ("128M", 128 << 20),
            ("128MB", 128 << 20),
            ("2G", 2 << 30),
            ("2GB", 2 << 30),
            ("1T", 1 << 40),
        ],
    )
    def test_suffixes(self, text, expected):
        assert parse_size(text) == expected

    def test_unknown_unit_raises(self):
        with pytest.raises(ValueError):
            parse_size("128X")


class TestFmtInstrCount:
    def test_small(self):
        assert fmt_instr_count(0) == "0.000"
        assert fmt_instr_count(999) == "999.000"

    def test_k(self):
        assert fmt_instr_count(1000) == "1.000K"
        assert fmt_instr_count(999999) == "999.999K"

    def test_m(self):
        assert fmt_instr_count(1_000_000) == "1.000M"

    def test_b(self):
        assert fmt_instr_count(1_000_000_000) == "1.000B"


class TestTrapCauseName:
    def test_known(self):
        name = trap_cause_name(0x8000_0000_0000_0003)  # MSIP
        assert len(name) > 0

    def test_unknown(self):
        name = trap_cause_name(0xDEAD)
        # 未知 cause code 格式: "异常#57005" (中文"异常" + 编号)
        assert "#" in name


class TestCheckRv64Addr:
    def test_valid(self):
        assert check_rv64_addr(0) is True
        assert check_rv64_addr(0xFFFFFFFFFFFFFFFF) is True
        assert check_rv64_addr(0x80000000) is True

    def test_invalid(self):
        assert check_rv64_addr(-1) is False
        assert check_rv64_addr(1 << 64) is False

    @pytest.mark.parametrize("v", [2**64, -(2**63)])
    def test_boundary_invalid(self, v):
        assert check_rv64_addr(v) is False


class TestIpBits:
    def test_returns_list(self):
        bits = ip_bits()
        assert len(bits) == 9
        assert bits[0] == ("USIP", 0, "U 模式软件中断挂起")
        assert bits[-1] == ("MEIP", 11, "M 模式外部中断挂起")


class TestExcIrqNames:
    def test_exc_names_coverage(self):
        assert EXC_NAMES[2] == "IllInstr"
        assert EXC_NAMES[12] == "InstrPageFault"

    def test_irq_names_coverage(self):
        assert IRQ_NAMES[5] == "STIP (S 模式定时器中断)"


class TestGroupOrder:
    def test_alpha_first(self):
        assert group_order("a") < group_order("1")
        assert group_order("z") < group_order("0")

    def test_digit_before_underscore(self):
        assert group_order("0") < group_order("_")

    def test_underscore_before_dot(self):
        assert group_order("_") < group_order(".")


class TestHistoryFilePath:
    def test_unconfigured_path_falls_back_to_home(self, monkeypatch):
        monkeypatch.setattr(utils, "cfg_str", lambda name: "")
        assert utils.history_file_path() == Path.home() / ".pyremu_history"

    def test_environment_path_is_expanded(self, monkeypatch):
        monkeypatch.setenv("PYREMU_HISTORY_FILE", "~/logs/hist")
        assert utils.history_file_path() == Path.home() / "logs" / "hist"

    def test_absolute_path_is_used_as_given(self, monkeypatch):
        monkeypatch.setenv("PYREMU_HISTORY_FILE", "/var/tmp/pyremu_history")
        assert utils.history_file_path() == Path("/var/tmp/pyremu_history")


class TestMaxInstrCount:
    def test_value(self):
        assert MAX_INSTR_COUNT == 100_000
