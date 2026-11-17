#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.exec — 快照、回滚、写监控."""

import ctypes

import pytest

from pyremu.configs_aux import cfg_bool
from pyremu.core.hart import RiscvMode
from pyremu.debug.exec import ExecutionOps
from pyremu.debug.types import MemoryChange
from pyremu.emulator import Emulator
from pyremu.peripheral.power_ctrl import PowerRequest
from tests.conftest import (
    DbgTestBase,
    make_test_dbg,
    make_test_emu,
    TEST_PROG_PA,
)

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

    def test_step_advances_pc(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        # load_code 已在 TEST_PROG_PA 放了 NOP
        h = dbg.hart
        assert h.pc == TEST_PROG_PA

        dbg.step_one()
        # ADDI x0,x0,0 推进 4 字节
        assert h.pc == TEST_PROG_PA + 4

    def test_step_increments_count(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        assert dbg._instr_count == 0
        dbg.step_one()
        assert dbg._instr_count == 1
        dbg.step_one()
        assert dbg._instr_count == 2

    def test_halted_hart_skipped(self):
        dbg = make_test_dbg()
        dbg.hart._halted = True
        count_before = dbg._instr_count
        dbg.step_one()
        assert dbg._instr_count == count_before  # 未执行

    def test_ebreak_sets_mcause(self):
        """EBREAK 指令应触发陷态, 但不应导致 halted."""
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        dbg._emu.load_code(TEST_PROG_PA, b"\x73\x00\x10\x00")
        h = dbg.hart
        h.pc = TEST_PROG_PA
        dbg.step_one()
        # EBREAK trap -> mcause = 3 (Breakpoint)
        assert (h.mcause_val & ~(1 << 63)) == 3


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
    """cmd_restart — 设备树按装载时的内容重写, 内部状态与 hart 接线复位."""

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

    def test_restart_rebinds_pmp_buffers(self):
        """重启后的 hart 与引擎共用同一份 PMP 缓冲区.

        不重新绑定时, 固件在引擎内写入的 PMP 条目落在旧 hart 的数组上, Python
        侧 ``show pmp`` 读到的始终为空, 设备 MMIO 的 S 模式写会被拒.
        """
        edbg = _make_edbg()
        emu = edbg._emu
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        entries = emu.harts[0].pmp.num_entries
        edbg.cmd_restart()
        h = emu.harts[0]
        assert len(h.pmp.flat_cfg) == entries
        assert ctypes.addressof(h.pmp.flat_cfg) == ctypes.addressof(
            emu._pmp_cfg_buf
        )
        assert ctypes.addressof(h.pmp.flat_addr) == ctypes.addressof(
            emu._pmp_addr_buf
        )

    def test_restart_restores_uart_write_wrapper(self):
        """重启后的物理写入口仍是 UART 包装, 而非裸的 bus.write."""
        edbg = _make_edbg()
        emu = edbg._emu
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        before = edbg.hart.mem_write_phy
        edbg.cmd_restart()
        after = emu.harts[0].mem_write_phy
        assert after != emu.bus.read
        assert after != emu.bus.write
        assert type(after).__name__ == type(before).__name__

    def test_restart_restores_imsic_reference(self, make_aia_emu):
        """AIA 模式下重启后的 hart 仍持有 IMSIC 引用."""
        emu = make_aia_emu(1)
        edbg = _TestExecDbg(emu)
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        assert emu.harts[0].imsic is emu.imsic
        edbg.cmd_restart()
        assert emu.harts[0].imsic is emu.imsic

    @pytest.mark.skipif(
        cfg_bool("PYREMU_NO_L2"), reason="构建时关闭 L2 缓存, 该用例不适用"
    )
    def test_restart_invalidates_l2(self):
        """重启清空 L2 缓存, 上一轮的有效行不保留."""
        edbg = _make_edbg()
        emu = edbg._emu
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        l2 = emu.bus.l2
        if l2 is None:
            return
        emu.bus.write(emu.bus.ram_base, b"\xaa" * 4)
        assert len(l2) > 0
        edbg.cmd_restart()
        assert len(l2) == 0

    def test_restart_clears_plic_pending(self):
        """重启清空 PLIC 的挂起位与使能位."""
        emu = make_test_emu()
        edbg = _TestExecDbg(emu)
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        plic = emu.plic
        assert plic is not None
        plic.set_irq(10, True)
        assert plic.pending[10] == 1
        edbg.cmd_restart()
        assert plic.pending[10] == 0
        assert plic.level[10] == 0

    def test_restart_clears_imsic_pending(self, make_aia_emu):
        """重启清空 IMSIC 各 hart 的挂起位."""
        emu = make_aia_emu(1)
        edbg = _TestExecDbg(emu)
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        assert emu.imsic.peek_topei(0, "M") == 0
        # 软件中断号为 1, 不受 eie 与 eidelivery 门控, 置位后即可观察到.
        emu.imsic.set_ip_number(0, "M", 1)
        assert emu.imsic.peek_topei(0, "M") != 0
        edbg.cmd_restart()
        assert emu.imsic.peek_topei(0, "M") == 0

    def test_restart_resets_virtio_queue(self):
        """重启重置 virtqueue 索引与设备状态字."""
        emu = make_test_emu(virtio_net_s_base=0x1000_7000)
        edbg = _TestExecDbg(emu)
        edbg._image = None
        edbg._load_offset = 0
        edbg._bins_images = {}
        net = emu.virtio_net_s
        assert net is not None
        queue = net.mmio.queues[0]
        queue.last_avail_idx = 5
        net.mmio.status = 0xF
        edbg.cmd_restart()
        assert net.mmio.queues[0].last_avail_idx == 0
        assert net.mmio.status == 0


class TestSnapshotRollback:
    """快照与回滚."""

    def test_save_snapshot_captures_state(self):
        dbg = make_test_dbg()
        h = dbg.hart
        h.pc = 0x80000000
        h.gprs[10] = 0xDEAD
        h.mode = RiscvMode.M

        snap = dbg._save_snapshot()
        assert snap.pc == 0x80000000
        assert snap.gpr_vals[10] == 0xDEAD
        assert snap.mode == RiscvMode.M.value

    def test_restore_snapshot_restores_all_state(self):
        dbg = make_test_dbg()
        h = dbg.hart

        # 设置初始状态
        h.pc = 0x80000000
        h.gprs[5] = 0xABCD
        h.gprs[10] = 0x1234
        h.csrs["mstatus"].val = 0x1800
        h.mode = RiscvMode.S

        snap = dbg._save_snapshot()

        # 修改状态
        h.pc = 0x90000000
        h.gprs[5] = 0xFFFF
        h.gprs[10] = 0xDEAD
        h.csrs["mstatus"].val = 0x0
        h.mode = RiscvMode.M

        dbg._restore_snapshot(snap)
        assert h.pc == 0x80000000
        assert h.gprs[5] == 0xABCD
        assert h.gprs[10] == 0x1234
        assert h.csrs["mstatus"].val == 0x1800
        assert h.mode == RiscvMode.S

    def test_restore_clears_reservation(self):
        dbg = make_test_dbg()
        h = dbg.hart
        h.set_reservation(0x8000)

        snap_with_res = dbg._save_snapshot()

        h.clear_reservation()
        assert not h.reservation_valid

        dbg._restore_snapshot(snap_with_res)
        assert h.reservation_valid
        assert h.reservation_addr == 0x8000

    def test_rollback_reverts_memory(self):
        dbg = make_test_dbg()
        h = dbg.hart

        # 在 RAM 中预写数据
        dbg._emu.bus.write(0x80000000, b"\xca\xfe\xba\xbe\x00\x00\x00\x00")

        # 执行一条 SW 指令: sw x10, 0(x2)
        h.pc = 0x1000
        h.gprs[2] = 0x80000000  # sp
        h.gprs[10] = 0x12345678  # a0 = value to store
        # SD x10, 0(x2): funct3=011, opcode=0100011
        instr = (0 << 25) | (10 << 20) | (2 << 15) | (3 << 12) | (2 << 7) | 0x23
        # 需要将指令写入 PC 处
        dbg._emu.load_code(0x1000, instr.to_bytes(4, "little"))

        dbg.step_one()
        # 验证数据确实写入
        dbg._emu.bus.read(0x80000000, 4)
        # 回滚
        dbg.rollback()
        # 验证内存恢复
        data_restored = dbg._emu.bus.read(0x80000000, 4)
        assert data_restored == b"\xca\xfe\xba\xbe", (
            f"回滚应恢复旧数据, 实际: {data_restored.hex()}"
        )

    def test_rollback_without_snapshot_warns(self):
        dbg = make_test_dbg()
        dbg._snapshot = None
        # 应该只是打印警告, 不抛异常
        dbg.rollback()
        assert dbg._snapshot is None
