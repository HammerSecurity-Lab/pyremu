#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.exec — 快照、回滚、写监控."""

from pyremu.core.hart import RiscvMode
from pyremu.debug.exec import ExecutionOps
from pyremu.debug.types import MemoryChange
from pyremu.emulator import Emulator
from pyremu.peripheral.power_ctrl import PowerRequest
from tests.conftest import DbgTestBase

POWER_BASE = 0x0010_0000


def _request_shutdown(emu: Emulator) -> None:
    """经总线写入关机请求."""
    emu.bus.write(POWER_BASE, PowerRequest.SHUTDOWN.to_bytes(4, "little"))


# ============================================================
#  Mini 测试类
# ============================================================


class _TestExecDbg(DbgTestBase, ExecutionOps):
    """最小聚合类供 ExecutionOps 测试."""

    def __init__(self, emu, hart_id=0):
        super().__init__(emu, hart_id)
        self._instr_count = 0
        self._snapshot = None
        self._mem_changes = []
        self._watch_ranges = []
        self._watch_hit = None
        self._paused = False
        self._hart_paused: set[int] = set()
        self._bp_hit_this_run: set[int] = set()

    # Stubs for step_one dependencies (not testing breakpoints here)
    def _try_read_va(self, va, size):
        return self._emu.bus.try_read(va, size)

    def _check_breakpoints(self, h, pc, instr):
        return False  # never stop

    def _show_trap_context(self, h):
        pass

    def _enter_run_mode(self):
        pass

    def _enter_repl_mode(self):
        pass

    def _check_multi_hart_bp(self):
        pass

    def cmd_pc(self, addr=None):
        pass

    def _resolve_addr(self, arg):
        try:
            return int(arg, 0)
        except ValueError, TypeError:
            return None


def _make_edbg(num_harts=1, ram_size=0x10000):
    emu = Emulator(num_harts=num_harts, ram_size=ram_size, prog_cnt=0x8000_0000)
    emu.load_code(0x8000_0000, b"\x13\x00\x00\x00")  # NOP
    return _TestExecDbg(emu)


# ============================================================
#  快照
# ============================================================


class TestSnapshot:
    """快照保存 / 恢复."""

    def test_save_restore_preserves_pc(self):
        edbg = _make_edbg()
        edbg.hart.pc = 0x80000000
        snap = edbg._save_snapshot()
        edbg.hart.pc = 0xDEAD
        edbg._restore_snapshot(snap)
        assert edbg.hart.pc == 0x80000000

    def test_save_restore_preserves_gprs(self):
        edbg = _make_edbg()
        edbg.hart.gprs[10] = 0xCAFE  # a0
        edbg.hart.gprs[11] = 0xBEEF  # a1
        snap = edbg._save_snapshot()
        edbg.hart.gprs[10] = 0
        edbg.hart.gprs[11] = 0
        edbg._restore_snapshot(snap)
        assert edbg.hart.gprs[10] == 0xCAFE
        assert edbg.hart.gprs[11] == 0xBEEF

    def test_save_restore_preserves_csrs(self):
        edbg = _make_edbg()
        edbg.hart.csrs["mstatus"].val = 0x1800
        snap = edbg._save_snapshot()
        edbg.hart.csrs["mstatus"].val = 0
        edbg._restore_snapshot(snap)
        assert edbg.hart.csrs["mstatus"].val == 0x1800

    def test_save_restore_preserves_mode(self):
        edbg = _make_edbg()
        edbg.hart.mode = RiscvMode.S
        snap = edbg._save_snapshot()
        edbg.hart.mode = RiscvMode.M
        edbg._restore_snapshot(snap)
        assert edbg.hart.mode == RiscvMode.S

    def test_save_restore_reservation(self):
        edbg = _make_edbg()
        edbg.hart.set_reservation(0x80001000)
        assert edbg.hart.reservation_valid
        snap = edbg._save_snapshot()
        edbg.hart.clear_reservation()
        assert not edbg.hart.reservation_valid
        edbg._restore_snapshot(snap)
        assert edbg.hart.reservation_valid
        assert edbg.hart.reservation_addr == 0x80001000

    def test_save_all_gprs_count(self):
        edbg = _make_edbg()
        snap = edbg._save_snapshot()
        assert len(snap.gpr_vals) == 32

    def test_save_csr_vals_not_empty(self):
        edbg = _make_edbg()
        snap = edbg._save_snapshot()
        assert len(snap.csr_vals) > 0
        assert "mstatus" in snap.csr_vals


# ============================================================
#  回滚
# ============================================================


class TestRollback:
    """rollback — 撤销最近一条指令."""

    def test_rollback_no_snapshot_warns(self):
        edbg = _make_edbg()
        edbg.rollback()  # 应不抛异常

    def test_rollback_restores_state(self):
        edbg = _make_edbg()
        edbg.hart.pc = 0x1000
        edbg.hart.gprs[10] = 0xAAAA
        snap = edbg._save_snapshot()
        edbg.hart.pc = 0x2000
        edbg.hart.gprs[10] = 0xBBBB
        edbg._snapshot = snap
        edbg._instr_count = 5
        edbg.rollback()
        assert edbg.hart.pc == 0x1000
        assert edbg.hart.gprs[10] == 0xAAAA
        assert edbg._instr_count == 4

    def test_rollback_reverts_memory_changes(self):
        edbg = _make_edbg()
        addr = 0x80000800
        old_val = b"\x00" * 8
        new_val = b"\xff" * 8
        edbg._emu.bus.write_ram_direct(addr, new_val)
        edbg._mem_changes = [MemoryChange(addr=addr, old=old_val)]
        edbg._snapshot = edbg._save_snapshot()
        edbg._instr_count = 10
        edbg.rollback()
        restored = edbg._emu.bus.try_read(addr, 8)
        assert restored == old_val


# ============================================================
#  单步执行
# ============================================================


class TestStepOne:
    """step_one — 基本执行."""

    def test_step_one_advances_pc(self):
        edbg = _make_edbg()
        edbg.hart.pc = 0x8000_0000
        edbg.step_one()
        # NOP at 0x8000_0000 advances PC by 4
        assert edbg.hart.pc == 0x8000_0004

    def test_step_one_increments_instr_count(self):
        edbg = _make_edbg()
        edbg.hart.pc = 0x8000_0000
        before = edbg._instr_count
        edbg.step_one()
        assert edbg._instr_count == before + 1

    def test_step_one_halted_hart_skips(self):
        edbg = _make_edbg()
        edbg.hart._halted = True
        edbg.hart.pc = 0x8000_0000
        edbg.step_one()
        assert edbg.hart.pc == 0x8000_0000  # unchanged

    def test_step_one_saves_snapshot(self):
        edbg = _make_edbg()
        edbg.hart.pc = 0x8000_0000
        edbg.step_one()
        assert edbg._snapshot is not None
        assert edbg._snapshot.pc == 0x8000_0000

    def test_step_one_after_shutdown_skips(self):
        """关机请求置位后单步不执行指令."""
        edbg = _make_edbg()
        _request_shutdown(edbg._emu)
        edbg.hart.pc = 0x8000_0000
        edbg.step_one()
        assert edbg.hart.pc == 0x8000_0000
        assert edbg._instr_count == 0
        assert edbg._snapshot is None

    def test_step_one_instr_page_fault(self):
        """不可读的地址应触发 InstrPageFault."""
        edbg = _make_edbg()
        edbg.hart.pc = 0xFFFFFFFF  # 无效地址
        edbg.step_one()
        # hart 应进入 trap 状态 (mcause 非零)
        assert edbg.hart.mcause_val != 0


# ============================================================
#  写监控
# ============================================================


class TestCmdWatch:
    """cmd_watch — 内存写监控."""

    def test_watch_off_clears_ranges(self):
        edbg = _make_edbg()
        edbg._watch_ranges = [(0x80000000, 0x80001000)]
        edbg.cmd_watch("off")
        assert edbg._watch_ranges == []

    def test_watch_none_clears(self):
        edbg = _make_edbg()
        edbg._watch_ranges = [(0x80000000, 0x80001000)]
        edbg.cmd_watch("none")
        assert edbg._watch_ranges == []

    def test_watch_adds_range(self):
        edbg = _make_edbg()
        edbg.cmd_watch("0x80001000", "16")
        assert len(edbg._watch_ranges) == 1
        assert edbg._watch_ranges[0] == (0x80001000, 0x80001010)


# ============================================================
#  重启
# ============================================================


class TestCmdRestart:
    """cmd_restart — 设备树按装载时的内容重写."""

    def test_restart_rewrites_loaded_dtb_blob(self):
        """重启重写装载时的 blob, 不重新生成默认设备树."""
        edbg = _make_edbg()
        emu = edbg._emu
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        addr = emu.config.ram_base + 0x2000
        emu.load_dtb_blob(addr, b"TREE")
        emu.bus.write_ram_direct(addr, b"ZZZZ")
        edbg.cmd_restart()
        assert emu.bus.try_read(addr, 4) == b"TREE"
        assert emu.dtb_addr == addr

    def test_restart_clears_power_request(self):
        """重启撤销关机请求, 之后可以继续执行."""
        edbg = _make_edbg()
        emu = edbg._emu
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        _request_shutdown(emu)
        assert emu.power_request is PowerRequest.SHUTDOWN
        edbg.cmd_restart()
        assert emu.power_request is None
        pc_before = edbg.hart.pc
        assert emu.step() == 1
        assert edbg.hart.pc == pc_before + 4

    def test_restart_without_dtb_writes_nothing(self):
        """未装载设备树的重启不写入设备树, 地址仍为 None."""
        edbg = _make_edbg()
        emu = edbg._emu
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        edbg.cmd_restart()
        assert emu.dtb_addr is None
        assert emu.dtb_blob is None
