#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.mmu_view — PMP/SATP/页表."""

from pyremu.debug.mmu_view import MmuViewOps
from pyremu.emulator import Emulator
from pyremu.memory.mmu import PTE
from pyremu.memory.pmp import PMP_A_TOR, PMP_R, PMP_W, PMP_X
from tests.conftest import (
    DbgTestBase,
    make_test_dbg,
    TEST_PT_L1_BASE,
    TEST_PT_L2_BASE,
    TEST_PT_L3_BASE,
)

# ============================================================
#  Mini 测试类
# ============================================================


class _TestMmuDbg(DbgTestBase, MmuViewOps):
    """最小聚合类供 MmuViewOps 测试."""

    def _resolve_addr(self, arg):
        try:
            return int(arg, 0)
        except ValueError, TypeError:
            return None


def _make_mmudbg(**kwargs):
    emu = Emulator(prog_cnt=0x1000, **kwargs)
    emu.load_code(0x1000, b"\x13\x00\x00\x00")  # NOP
    return _TestMmuDbg(emu)


# ============================================================
#  PMP cfg 解码
# ============================================================


class TestDecodePmpCfgByte:
    """_decode_pmp_cfg_byte — 从 pmpcfgN 提取条目配置."""

    def test_entry_0(self):
        val = MmuViewOps._decode_pmp_cfg_byte(0x000000000000001F, 0)
        assert val == 0x1F  # L+R+W+X

    def test_entry_7(self):
        """最后一个条目在 pmpcfg0 中."""
        cfg_val = 0xFF00000000000000  # entry 7 = 0xFF
        val = MmuViewOps._decode_pmp_cfg_byte(cfg_val, 7)
        assert val == 0xFF

    def test_entry_8(self):
        """第一个条目在 pmpcfg2 中."""
        cfg_val = 0x000000000000001F  # entry 8 = 0x1F
        val = MmuViewOps._decode_pmp_cfg_byte(cfg_val, 0)  # local idx 0
        assert val == 0x1F

    def test_entry_15(self):
        """最后一个条目在 pmpcfg2 中."""
        cfg_val = 0xFF00000000000000
        val = MmuViewOps._decode_pmp_cfg_byte(cfg_val, 7)
        assert val == 0xFF


# ============================================================
#  PMP / SATP / PT 命令
# ============================================================


class TestCmdPmp:
    """cmd_pmp — PMP 条目显示."""

    def test_no_pmp(self):
        """无 PMP 条目时显示提示."""
        dbg = _make_mmudbg(pmp_entries=0)
        dbg.cmd_pmp()

    def test_with_pmp_entries(self):
        dbg = _make_mmudbg()
        dbg.cmd_pmp()

    def _set_pmp_entry(self, dbg, idx: int, cfg: int, addr: int) -> None:
        group = idx // 8
        reg = f"pmpcfg{group * 2}"
        val = dbg.hart.csrs[reg].val
        shift = (idx & 7) * 8
        val = (val & ~(0xFF << shift)) | (cfg << shift)
        dbg.hart.csrs[reg].val = val
        dbg.hart.csrs[f"pmpaddr{idx}"].val = addr

    def test_na4_entry(self):
        """NA4 条目按 4 字节区域显示."""
        dbg = _make_mmudbg()
        self._set_pmp_entry(dbg, 0, 0x17, 0x8000_0000 >> 2)
        dbg.cmd_pmp()

    def test_napot_entry(self):
        """NAPOT 条目按解码后的区域显示."""
        dbg = _make_mmudbg()
        self._set_pmp_entry(dbg, 0, 0x1F, (0x8000_0000 >> 2) | 0x1FF)
        dbg.cmd_pmp()

    def test_tor_lower_entry_uses_previous_address(self):
        """非零编号的 TOR 条目下界取前一条目的 pmpaddr."""
        dbg = _make_mmudbg()
        self._set_pmp_entry(dbg, 0, 0x0D, 0x4000 >> 2)
        self._set_pmp_entry(dbg, 1, 0x0D, 0x8000 >> 2)
        dbg.cmd_pmp()

    def test_no_pmp_entries(self):
        """PMP 未配置时显示提示."""
        dbg = make_test_dbg()
        dbg.cmd_pmp()  # 不应抛异常

    def test_pmp_with_entries(self):
        """PMP 有配置条目时正常显示."""
        dbg = make_test_dbg()
        h = dbg.hart
        # 配置一条 TOR entry
        pmp = h._pmp
        if pmp is not None:
            # pmpcfg0: entry 0 = TOR, R/W/X
            h.csrs["pmpcfg0"].val = PMP_A_TOR | PMP_R | PMP_W | PMP_X
            h.csrs["pmpaddr0"].val = 0x20000000 >> 2  # TOR hi bound
            dbg.cmd_pmp()  # 不应抛异常


class TestCmdSatp:
    """cmd_satp — SATP 解码."""

    def test_bare_mode(self):
        dbg = _make_mmudbg()
        dbg.hart.satp_val = 0
        dbg.cmd_satp()

    def test_sv39_mode(self):
        dbg = _make_mmudbg()
        dbg.hart.satp_val = (8 << 60) | 0x80000
        dbg.cmd_satp()


def _make_pt_dbg():
    """RAM 从物理地址 0 起的调试器实例, 供页表构造使用."""
    emu = Emulator(ram_base=0, ram_size=0x100000, prog_cnt=0x1000)
    emu.load_code(0x1000, b"\x13\x00\x00\x00")
    return _TestMmuDbg(emu)


def _pointer_pte(next_table_pa: int) -> int:
    """指向下一级页表的页表项: V=1, R=W=X=0."""
    return ((next_table_pa >> 12) << 10) | 0x01


def _leaf_pte(pa: int) -> int:
    """叶子页表项: V=1, R=1, W=1, X=1."""
    return ((pa >> 12) << 10) | 0x0F


def _write_pte(dbg, table_pa: int, index: int, pte: int) -> None:
    dbg._emu.bus.write_ram_direct(
        table_pa + index * 8, pte.to_bytes(8, "little")
    )


def _build_three_level(dbg) -> None:
    """构造 VA 0x1000 -> PA 0x1000 的三级页表, 根表在 0x8000."""
    _write_pte(dbg, 0x8000, 0, _pointer_pte(0x9000))
    _write_pte(dbg, 0x9000, 0, _pointer_pte(0xA000))
    _write_pte(dbg, 0xA000, 1, _leaf_pte(0x1000))
    dbg.hart.satp_val = (8 << 60) | 0x8


class TestCmdPt:
    """cmd_pt — 页表遍历."""

    def test_bare_mode_warns(self):
        dbg = _make_mmudbg()
        dbg.hart.satp_val = 0  # Bare
        dbg.cmd_pt("0x1000")  # 应不抛异常

    def test_sv39_no_page_table(self):
        """Sv39 模式但根页表不可读."""
        dbg = _make_mmudbg()
        dbg.hart.satp_val = (8 << 60) | 0x100  # Sv39, 根 PPN 指向无效区域
        dbg.cmd_pt("0x1000")  # 应不抛异常

    def test_with_valid_sv39_table(self):
        """三级页表遍历到 4 KiB 叶子页."""
        dbg = _make_pt_dbg()
        _build_three_level(dbg)
        dbg.cmd_pt("0x1000")

    def test_defaults_to_sepc(self):
        """未给 VA 时取 sepc."""
        dbg = _make_pt_dbg()
        _build_three_level(dbg)
        dbg.hart.sepc_val = 0x1000
        dbg.cmd_pt()

    def test_defaults_to_mepc(self):
        """sepc 为零时取 mepc."""
        dbg = _make_pt_dbg()
        _build_three_level(dbg)
        dbg.hart.sepc_val = 0
        dbg.hart.mepc_val = 0x1000
        dbg.cmd_pt()

    def test_no_default_va_warns(self):
        """sepc 与 mepc 均为零时不遍历."""
        dbg = _make_pt_dbg()
        dbg.hart.satp_val = (8 << 60) | 0x8  # Sv39, 否则在 Bare 判定处提前返回
        dbg.hart.sepc_val = 0
        dbg.hart.mepc_val = 0
        dbg.cmd_pt()

    def test_invalid_va_warns(self):
        """地址无法解析时给出提示."""
        dbg = _make_pt_dbg()
        dbg.hart.satp_val = (8 << 60) | 0x8
        dbg.cmd_pt("not-an-address")

    def test_l1_leaf_superpage(self):
        """L1 叶子项直接给出 1 GiB 超级页的最终地址."""
        dbg = _make_pt_dbg()
        _write_pte(dbg, 0x8000, 0, _leaf_pte(0x1000))
        dbg.hart.satp_val = (8 << 60) | 0x8
        dbg.cmd_pt("0x1000")

    def test_l2_leaf_megapage(self):
        """L2 叶子项给出 2 MiB 超级页的最终地址."""
        dbg = _make_pt_dbg()
        _write_pte(dbg, 0x8000, 0, _pointer_pte(0x9000))
        _write_pte(dbg, 0x9000, 0, _leaf_pte(0x2000))
        dbg.hart.satp_val = (8 << 60) | 0x8
        dbg.cmd_pt("0x1000")

    def test_three_level_walk(self):
        """三级遍历到 4 KiB 叶子页."""
        dbg = _make_pt_dbg()
        _build_three_level(dbg)
        dbg.cmd_pt("0x1000")

    def test_invalid_l1_pte_stops_walk(self):
        """L1 页表项无效时停止遍历."""
        dbg = _make_pt_dbg()
        _write_pte(dbg, 0x8000, 0, 0)
        dbg.hart.satp_val = (8 << 60) | 0x8
        dbg.cmd_pt("0x1000")

    def test_invalid_l2_pte_stops_walk(self):
        """L2 页表项无效时停止遍历."""
        dbg = _make_pt_dbg()
        _write_pte(dbg, 0x8000, 0, _pointer_pte(0x9000))
        _write_pte(dbg, 0x9000, 0, 0)
        dbg.hart.satp_val = (8 << 60) | 0x8
        dbg.cmd_pt("0x1000")

    def test_invalid_l3_pte_stops_walk(self):
        """L3 页表项无效时停止遍历."""
        dbg = _make_pt_dbg()
        _write_pte(dbg, 0x8000, 0, _pointer_pte(0x9000))
        _write_pte(dbg, 0x9000, 0, _pointer_pte(0xA000))
        _write_pte(dbg, 0xA000, 1, 0)
        dbg.hart.satp_val = (8 << 60) | 0x8
        dbg.cmd_pt("0x1000")

    def test_pt_bare_mode(self):
        """Bare 模式下 pt 显示相应信息."""
        dbg = make_test_dbg()
        dbg.hart.csrs["satp"].val = 0  # Bare mode
        # 在 Bare 模式下 sv39_walk 会失败, cmd_pt 应妥善处理
        dbg.cmd_pt("0x1000")  # 不应抛异常

    def test_pt_with_table(self):
        """Sv39 模式下 pt 遍历显示."""
        dbg = make_test_dbg()
        h = dbg.hart
        # 构建三级页表 (identity map 0x1000 -> 0x80001000)
        # 写入 L1 (根页表) -> L2
        l2_pte = PTE()
        l2_pte.v = True
        l2_pte.ppn = TEST_PT_L2_BASE >> 12  # 软件 PPN
        dbg._emu.bus.write(
            TEST_PT_L1_BASE, l2_pte.to_int().to_bytes(8, "little")
        )

        # 写入 L2 -> L3 (4 KiB page)
        l3_pte = PTE()
        l3_pte.v = True
        l3_pte.ppn = TEST_PT_L3_BASE >> 12
        dbg._emu.bus.write(
            TEST_PT_L2_BASE, l3_pte.to_int().to_bytes(8, "little")
        )

        # 写入 L3 -> 目标页 (R/W/X)
        leaf = PTE()
        leaf.v = True
        leaf.r = True
        leaf.w = True
        leaf.x = True
        leaf.ppn = 0x80001  # -> PA 0x80001000
        dbg._emu.bus.write(TEST_PT_L3_BASE, leaf.to_int().to_bytes(8, "little"))

        # 设置 satp
        h.csrs["satp"].val = (8 << 60) | (TEST_PT_L1_BASE >> 12)
        dbg.cmd_pt("0x1000")  # 不应抛异常
