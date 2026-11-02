#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.status — Hart 状态/CSR Bitfield."""

import io

from rich.console import Console

from pyremu.debug.status import StatusOps
from pyremu.emulator import Emulator
from tests.conftest import DbgTestBase

# ============================================================
#  Mini 测试类
# ============================================================


class _TestStatusDbg(DbgTestBase, StatusOps):
    """最小聚合类供 StatusOps 测试."""

    def __init__(self, emu, hart_id=0):
        super().__init__(emu, hart_id)
        self._instr_count = 0


def _make_sdbg(num_harts=1, ram_size=0x10000):
    emu = Emulator(num_harts=num_harts, ram_size=ram_size, prog_cnt=0x1000)
    emu.load_code(0x1000, b"\x13\x00\x00\x00")  # NOP
    return _TestStatusDbg(emu, hart_id=0)


# ============================================================
#  模式 / mstatus
# ============================================================


class TestCmdMode:
    def test_shows_mode(self):
        dbg = _make_sdbg()
        dbg.cmd_mode()


class TestCmdMstatus:
    def test_shows_bitfields(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["mstatus"].val = 0x1800
        dbg.cmd_mstatus()


# ============================================================
#  mcause / scause
# ============================================================


class TestCmdMcause:
    def test_shows_decomposed(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["mcause"].val = 11  # Ecall from M
        dbg.cmd_mcause()


class TestCmdScause:
    def test_shows_decomposed(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["scause"].val = 8  # Ecall from U
        dbg.cmd_scause()


# ============================================================
#  mtvec / stvec
# ============================================================


class TestCmdMtvec:
    def test_direct_mode(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["mtvec"].val = 0x80000000  # Direct
        dbg.cmd_mtvec()

    def test_vectored_mode(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["mtvec"].val = 0x80000001  # Vectored
        dbg.cmd_mtvec()


class TestCmdStvec:
    def test_shows(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["stvec"].val = 0x80200000
        dbg.cmd_stvec()


# ============================================================
#  mip / mie / sip / sie
# ============================================================


class TestCmdMip:
    def test_shows_bits(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["mip"].val = 1 << 7  # MTIP
        dbg.cmd_mip()


class TestCmdMie:
    def test_shows_bits(self):
        dbg = _make_sdbg()
        dbg.cmd_mie()


class TestCmdSip:
    def test_shows_bits(self):
        dbg = _make_sdbg()
        dbg.cmd_sip()


class TestCmdSie:
    def test_shows_bits(self):
        dbg = _make_sdbg()
        dbg.cmd_sie()

    def test_reports_the_mie_view(self):
        """sie 是 mie 按 mideleg 取出的视图, 显示值须与 csrr sie 一致."""
        dbg = _make_sdbg()
        dbg.hart.write_csr(0x303, 0x22)  # mideleg = SSI | STI
        dbg.hart.write_csr(0x304, 0x22)  # mie = SSI | STI
        buf = io.StringIO()
        dbg._console = Console(file=buf, highlight=False, width=200)
        dbg.cmd_sie()
        assert "0x0000000000000022" in buf.getvalue()


# ============================================================
#  medeleg / mideleg
# ============================================================


class TestCmdMedeleg:
    def test_shows_delegation(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["medeleg"].val = 1 << 8  # Ecall from U
        dbg.cmd_medeleg()


class TestCmdMideleg:
    def test_shows_delegation(self):
        dbg = _make_sdbg()
        dbg.hart.csrs["mideleg"].val = 1 << 5  # STIP
        dbg.cmd_mideleg()


# ============================================================
#  status
# ============================================================


class TestCmdStatus:
    def test_overview_single_hart(self):
        dbg = _make_sdbg()
        dbg.cmd_status()

    def test_overview_multi_hart(self):
        dbg = _make_sdbg(num_harts=4)
        dbg.cmd_status()

    def test_detail(self):
        dbg = _make_sdbg()
        dbg.cmd_status("0")

    def test_detail_out_of_range(self):
        dbg = _make_sdbg()
        dbg.cmd_status("99")

    def test_detail_invalid_id(self):
        dbg = _make_sdbg()
        dbg.cmd_status("abc")
