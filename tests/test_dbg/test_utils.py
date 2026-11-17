#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.utils."""

import pytest

from pyremu.debug.utils import (
    check_rv64_addr,
    EXC_NAMES,
    fmt_instr_count,
    fmt_size,
    group_order,
    hex_addr,
    ip_bits,
    IRQ_NAMES,
    parse_size,
    trap_cause_name,
)
from pyremu.debugger import Debugger


class TestHexAddr:
    def test_basic(self):
        assert hex_addr(0, styled=False) == "0x0000000000000000"
        assert hex_addr(0x80000000, styled=False) == "0x0000000080000000"

    def test_mask_upper_bits(self):
        """Python int 无位宽限制, 超出 64-bit 的部分应被掩码清除."""
        assert (
            hex_addr(0x1_0000_0000_0000_0001, styled=False)
            == "0x0000000000000001"
        )

    def test_negative_value(self):
        """负值在补码下转换为 64-bit 无符号."""
        assert hex_addr(-1, styled=False) == "0xffffffffffffffff"


class TestFmtSize:
    @pytest.mark.parametrize(
        "val, fmt_str",
        [
            (0, "0 B"),
            (512, "512.000 B"),
            (2048, "2.000 KB"),
            (2 << 20, "2.000 MB"),
            (3 << 30, "3.000 GB"),
        ],
    )
    def test_fmt_size(self, val: int, fmt_str: str) -> None:
        assert fmt_size(val) == fmt_str


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
    @pytest.mark.parametrize(
        "val, fmt_str",
        [
            (0, "0.000"),
            (999, "999.000"),
            (1000, "1.000K"),
            (999999, "999.999K"),
            (1_000_000, "1.000M"),
            (1_000_000_000, "1.000B"),
        ],
    )
    def test_fmt_inst_cnt(self, val: int, fmt_str: str):
        assert fmt_instr_count(val) == fmt_str


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

    def test_returns_correct_count(self):
        bits = Debugger._ip_bits()
        assert len(bits) == 9

    def test_all_bit_numbers_unique(self):
        bits = Debugger._ip_bits()
        bit_nums = {b[1] for b in bits}
        assert len(bit_nums) == 9

    def test_msip_at_bit3(self):
        bits = Debugger._ip_bits()
        msip = next(b for b in bits if b[0] == "MSIP")
        assert msip[1] == 3


class TestExcIrqNames:
    def test_exc_names_coverage(self):
        assert EXC_NAMES[2] == "IllInstr"
        assert EXC_NAMES[12] == "InstrPageFault"

    def test_irq_names_coverage(self):
        assert IRQ_NAMES[5] == "STIP (S 模式定时器中断)"


class TestGroupOrder:
    def test_orders(self):
        assert group_order("a") < group_order("1")
        assert (
            group_order("z")
            < group_order("0")
            < group_order("_")
            < group_order(".")
        )
