#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.sym — 符号解析、内核符号加载、段查找与代码地址校验."""

from pathlib import Path

import pytest

from pyremu import configs_gen
from pyremu.core.hart import RiscvMode
from pyremu.core.mem_check_aux import MemoryAccessOps
from pyremu.debug import sym
from pyremu.debug.sym import model
from pyremu.debug.sym.model import SymAvailItem
from pyremu.utils.parse_bin import FirmwareImage, FirmwareSegment
from tests.conftest import (
    make_test_dbg,
    make_test_dbg_buffered,
    make_test_image,
)

RAM_BASE = 0x8000_0000
RAM_SIZE = 0x0004_0000
HOLE_ADDR = 0x9000_0000
SATP_SV39 = 8 << 60
KERNEL_VA = 0xFFFF_FFC0_0000_1000
USER_VA = 0x0000_0000_8000_1000
NON_CANONICAL_VA = 0x0000_0100_0000_0000
# 管理器把自身 .text 映射到的虚拟地址与部署的物理地址
MODULE_VA = 0xFFFF_FFE0_0000_0000
MODULE_PA = 0x8300_0000


def _fw_image(
    entry_point: int = 0x1000,
    symbols: dict | None = None,
    symbol_ranges: list | None = None,
    fmt: str = "elf",
    segments: list | None = None,
) -> FirmwareImage:
    return FirmwareImage(
        entry_point=entry_point,
        segments=list(segments or []),
        format=fmt,
        symbols=dict(symbols or {}),
        symbol_ranges=list(symbol_ranges or []),
    )


def _many_symbols(prefix: str, count: int) -> dict:
    """构造以 *prefix* 开头的 *count* 个符号, 地址自 0x1000 起递增."""
    return {f"{prefix}{i}": 0x1000 + 4 * i for i in range(count)}


class _FakeSymIndex:
    """按链接地址给出符号名的索引替身; 未登记的链接地址没有符号名."""

    def __init__(self, names: dict[int, str]) -> None:
        self._names = names

    def resolve_addr(self, link: int) -> str | None:
        return self._names.get(link)

    def close(self) -> None:
        pass


def _deployed_module(name: str) -> model.SymMod:
    """以物理地址部署的符号模块, 覆盖 [0x0, 0x2000) 且只登记链接地址 0x0."""
    return model.SymMod(
        file_name="sittim",
        path="/tmp/sittim",
        pa_base=MODULE_PA,
        va_base=None,
        cover_start=0x0,
        cover_end=0x2000,
        sym_count=1,
        is_verified=False,
        load_order=0,
        verify_epoch=0,
        index=_FakeSymIndex({0x0: name}),
    )


# 加载路径先核对文件是否存在, 再调用 parse_firmware; 后者由替身给出,
# 故此处只需要一个确实存在的路径.
EXISTING_PATH = sym.__file__


# ============================================================
#  按名称读取寄存器
# ============================================================


class TestReadByName:
    def test_gpr_is_read_by_number_name(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        emu.harts[0].write_gpr(12, 0xDEAD)
        assert dbg._read_gpr_by_name("x12") == 0xDEAD

    def test_gpr_is_read_by_alias(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        emu.harts[0].write_gpr(10, 0x1234)
        assert dbg._read_gpr_by_name("a0") == 0x1234

    def test_unknown_gpr_name_yields_zero(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        emu.harts[0].write_gpr(0, 0xFFFF)
        assert dbg._read_gpr_by_name("x99") == 0

    def test_csr_is_read_by_name(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        emu.harts[0].write_csr(0x305, 0x8000_1234)
        assert dbg._read_csr_by_name("mtvec") == 0x8000_1234

    def test_unknown_csr_name_yields_zero(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg._read_csr_by_name("nosuchcsr") == 0


# ============================================================
#  _resolve_symbol
# ============================================================


class TestResolveSymbol:
    def test_range_containing_address_wins(self):
        ranges = [(0x1000, 0x1100, "probe"), (0x2000, 0x2100, "echo")]
        assert sym.SymLookupOps._resolve_symbol({}, 0x1050, ranges) == "probe"

    def test_second_range_is_selected(self):
        ranges = [(0x1000, 0x1100, "probe"), (0x2000, 0x2100, "echo")]
        assert sym.SymLookupOps._resolve_symbol({}, 0x2000, ranges) == "echo"

    def test_range_end_is_exclusive(self):
        """区间右端不包含: 命中落在 end 的地址须回退到后续判定."""
        ranges = [(0x1000, 0x1100, "probe")]
        assert sym.SymLookupOps._resolve_symbol({}, 0x1100, ranges) is None

    def test_exact_match_is_used_without_ranges(self):
        assert (
            sym.SymLookupOps._resolve_symbol({"main": 0x8000}, 0x8000) == "main"
        )

    def test_exact_match_runs_before_predecessor_fallback(self):
        """无区间信息时精确匹配优先于最近前驱."""
        symbols = {"_start": 0x7000, "main": 0x8000}
        assert sym.SymLookupOps._resolve_symbol(symbols, 0x8000) == "main"

    def test_gap_inside_range_span_yields_none(self):
        """地址落在区间跨度之内但不在任何区间内时放弃匹配."""
        ranges = [(0x1000, 0x1100, "probe"), (0x2000, 0x2100, "echo")]
        assert (
            sym.SymLookupOps._resolve_symbol({"mid": 0x1500}, 0x1800, ranges)
            is None
        )

    def test_address_before_range_span_falls_back_to_predecessor(self):
        ranges = [(0x1000, 0x1100, "probe")]
        assert (
            sym.SymLookupOps._resolve_symbol({"head": 0x0F00}, 0x0F00, ranges)
            == "head"
        )

    def test_address_after_range_span_falls_back_to_predecessor(self):
        ranges = [(0x1000, 0x1100, "probe")]
        assert (
            sym.SymLookupOps._resolve_symbol({"tail": 0x3000}, 0x3000, ranges)
            == "tail"
        )

    @pytest.mark.parametrize("name", ["$x", ".L0"])
    def test_assembler_local_names_are_skipped(self, name):
        symbols = {name: 0x1000}
        assert sym.SymLookupOps._resolve_symbol(symbols, 0x2000) is None

    def test_local_name_does_not_shadow_visible_predecessor(self):
        symbols = {".L0": 0x1800, "func": 0x1000}
        assert sym.SymLookupOps._resolve_symbol(symbols, 0x2000) == "func"

    def test_predecessor_beyond_limit_yields_none(self):
        """最近前驱相距超过 64 KiB 时不视为匹配."""
        assert (
            sym.SymLookupOps._resolve_symbol({"far": 0x1000}, 0x1000 + 0x10001)
            is None
        )

    def test_predecessor_at_limit_is_accepted(self):
        assert (
            sym.SymLookupOps._resolve_symbol({"far": 0x1000}, 0x1000 + 0x10000)
            == "far"
        )

    def test_empty_symbols_yield_none(self):
        assert sym.SymLookupOps._resolve_symbol({}, 0x1000) is None

    def test_successor_only_yields_none(self):
        assert (
            sym.SymLookupOps._resolve_symbol({"later": 0x2000}, 0x1000) is None
        )


# ============================================================
#  load_kernel_symbols
# ============================================================


class TestLoadKernelSymbols:
    def test_missing_file_reports_error(self, tmp_path):
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        missing = tmp_path / "vmlinux"
        assert dbg.load_kernel_symbols(str(missing)) is False
        assert "符号文件不存在" in buf.getvalue()

    def test_unparsable_file_reports_error(self, tmp_path, monkeypatch):
        src = tmp_path / "vmlinux"
        src.write_bytes(b"\x00")
        monkeypatch.setattr(sym.lookup, "parse_firmware", lambda *a, **k: None)
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg.load_kernel_symbols(str(src)) is False
        assert "无法解析符号文件" in buf.getvalue()

    def test_non_elf_file_reports_error(self, tmp_path, monkeypatch):
        src = tmp_path / "kernel.bin"
        src.write_bytes(b"\x00")
        monkeypatch.setattr(
            sym.lookup,
            "parse_firmware",
            lambda *a, **k: _fw_image(fmt="raw"),
        )
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg.load_kernel_symbols(str(src)) is False
        assert "需为 ELF" in buf.getvalue()

    def test_missing_symbol_table_reports_warning(self, tmp_path, monkeypatch):
        src = tmp_path / "vmlinux"
        src.write_bytes(b"\x00")
        monkeypatch.setattr(
            sym.lookup, "parse_firmware", lambda *a, **k: _fw_image()
        )
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg.load_kernel_symbols(str(src)) is False
        assert "未找到符号表" in buf.getvalue()

    def test_default_base_address_is_reserved_mem_top(self, monkeypatch):
        image = _fw_image(
            entry_point=0x1000,
            symbols={"main": 0x1000},
            symbol_ranges=[(0x1000, 0x1100, "main")],
        )
        monkeypatch.setattr(sym.lookup, "parse_firmware", lambda *a, **k: image)
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg.load_kernel_symbols(EXISTING_PATH) is True
        expected_base = RAM_BASE + configs_gen.FW_RESERVED_MEM_SIZE
        assert dbg._sym_load_offset == (
            (expected_base - 0x1000) & ((1 << 64) - 1)
        )
        assert dbg._sym_symbols_pa["main"] == (
            (0x1000 + dbg._sym_load_offset) & ((1 << 64) - 1)
        )

    def test_explicit_base_address_is_used(self, monkeypatch):
        image = _fw_image(entry_point=0x2000, symbols={"main": 0x2000})
        monkeypatch.setattr(sym.lookup, "parse_firmware", lambda *a, **k: image)
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg.load_kernel_symbols(EXISTING_PATH, base_pa=0x9000) is True
        assert dbg._sym_load_offset == 0x7000
        assert dbg._sym_symbols_pa["main"] == 0x9000

    def test_loaded_state_is_recorded(self, monkeypatch):
        image = _fw_image(
            entry_point=0x1000,
            symbols={"main": 0x1000, "echo": 0x1200},
            symbol_ranges=[(0x1000, 0x1100, "main"), (0x1200, 0x1300, "echo")],
        )
        monkeypatch.setattr(sym.lookup, "parse_firmware", lambda *a, **k: image)
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg.load_kernel_symbols(EXISTING_PATH) is True
        assert dbg._sym_symbols == {"main": 0x1000, "echo": 0x1200}
        assert dbg._sym_path == EXISTING_PATH
        assert dbg._sym_symbols_pa["echo"] == 0x1200 + dbg._sym_load_offset
        assert dbg._pa_to_va[dbg._sym_symbols_pa["echo"]] == 0x1200
        assert dbg._sym_ranges_pa[0] == (
            0x1000 + dbg._sym_load_offset,
            0x1100 + dbg._sym_load_offset,
            "main",
        )
        assert "已加载" in buf.getvalue()

    def test_physical_ranges_are_sorted_by_start(self, monkeypatch):
        """范围表按物理起始地址升序排列, 供二分查找使用."""
        image = _fw_image(
            entry_point=0x1000,
            symbols={"main": 0x1000},
            symbol_ranges=[(0x2000, 0x2100, "echo"), (0x1000, 0x1100, "main")],
        )
        monkeypatch.setattr(sym.lookup, "parse_firmware", lambda *a, **k: image)
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg.load_kernel_symbols(EXISTING_PATH, base_pa=0x4000)
        starts = [r[0] for r in dbg._sym_ranges_pa]
        assert starts == sorted(starts)
        assert [r[2] for r in dbg._sym_ranges_pa] == ["main", "echo"]

    def test_reload_clears_previous_tables(self, monkeypatch):
        first = _fw_image(entry_point=0x1000, symbols={"old": 0x1000})
        second = _fw_image(entry_point=0x1000, symbols={"new": 0x1000})
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        monkeypatch.setattr(sym.lookup, "parse_firmware", lambda *a, **k: first)
        dbg.load_kernel_symbols(EXISTING_PATH)
        monkeypatch.setattr(
            sym.lookup, "parse_firmware", lambda *a, **k: second
        )
        assert dbg.load_kernel_symbols(EXISTING_PATH) is True
        assert dbg._sym_symbols == {"new": 0x1000}
        assert "old" not in dbg._sym_symbols_pa


# ============================================================
#  地址解析
# ============================================================


class TestResolveSymAddr:
    def test_without_symbols_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg._resolve_sym_addr(0x1000) is None

    def test_bare_mode_adds_load_offset(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"main": 0x1000}
        dbg._sym_load_offset = 0x2000
        assert dbg._resolve_sym_addr(0x1000) == 0x3000

    def test_bare_mode_wraps_around_64_bits(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"main": 0x1000}
        dbg._sym_load_offset = (1 << 64) - 0x1000
        assert dbg._resolve_sym_addr(0x2000) == 0x1000

    def test_translation_result_is_returned(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"main": 0x1000}
        dbg._sym_load_offset = 0x2000
        emu.harts[0].satp_val = SATP_SV39
        monkeypatch.setattr(
            MemoryAccessOps,
            "translate_addr",
            lambda *a, **k: (True, 0x4000),
        )
        assert dbg._resolve_sym_addr(KERNEL_VA) == 0x4000

    def test_original_address_is_kept_when_translation_fails(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"main": 0x1000}
        dbg._sym_load_offset = 0x2000
        emu.harts[0].satp_val = SATP_SV39
        monkeypatch.setattr(
            MemoryAccessOps,
            "translate_addr",
            lambda *a, **k: (False, 0),
        )
        assert dbg._resolve_sym_addr(KERNEL_VA) == KERNEL_VA


class TestSymLookupName:
    def test_without_symbols_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg._sym_lookup_name(0x1000) is None

    def test_bare_mode_with_physical_table_uses_physical(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"va_name": 0x1000}
        dbg._sym_symbols_pa = {"pa_name": 0x2000}
        dbg._sym_ranges_pa = [(0x2000, 0x2100, "pa_name")]
        assert dbg._sym_lookup_name(0x2050) == "pa_name"

    def test_bare_mode_without_physical_table_falls_back_to_va(self):
        """未建立物理表时沿用类 VA 表."""
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"va_name": 0x1000}
        dbg._sym_ranges = [(0x1000, 0x1100, "va_name")]
        assert dbg._sym_lookup_name(0x1050) == "va_name"

    def test_translated_mode_uses_va_table(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"va_name": 0x1000}
        dbg._sym_symbols_pa = {"pa_name": 0x2000}
        emu.harts[0].satp_val = SATP_SV39
        dbg._sym_ranges = [(0x1000, 0x1100, "va_name")]
        assert dbg._sym_lookup_name(0x1050) == "va_name"

    def test_address_far_from_any_symbol_returns_none(self):
        """最近前驱相距超过 64 KiB 时不给出名称."""
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"va_name": 0x1000}
        dbg._sym_ranges = [(0x1000, 0x1100, "va_name")]
        assert dbg._sym_lookup_name(0x1000 + 0x10001) is None


class TestResolveAnySymbolName:
    def test_without_firmware_image_uses_kernel_symbols(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"kern": 0x1000}
        dbg._sym_ranges = [(0x1000, 0x1100, "kern")]
        assert dbg._resolve_any_symbol_name(0x1050) == "kern"

    def test_firmware_symbol_wins(self):
        image = _fw_image(
            symbols={"fw_main": 0x1000},
            symbol_ranges=[(0x1000, 0x1100, "fw_main")],
        )
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE, image=image)
        dbg._sym_symbols = {"kern": 0x1000}
        assert dbg._resolve_any_symbol_name(0x1050) == "fw_main"

    def test_kernel_symbols_are_consulted_after_firmware_miss(self):
        image = _fw_image(
            symbols={"fw_main": 0x1000},
            symbol_ranges=[(0x1000, 0x1100, "fw_main")],
        )
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE, image=image)
        dbg._sym_symbols = {"kern": 0x50000}
        dbg._sym_ranges = [(0x50000, 0x50100, "kern")]
        assert dbg._resolve_any_symbol_name(0x50050) == "kern"

    def test_firmware_load_offset_is_subtracted(self):
        image = _fw_image(
            symbols={"fw_main": 0x1000},
            symbol_ranges=[(0x1000, 0x1100, "fw_main")],
        )
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE, image=image)
        dbg._load_offset = 0x8000_0000
        assert dbg._resolve_any_symbol_name(0x8000_1050) == "fw_main"

    def test_image_without_symbols_uses_kernel_symbols(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE, image=_fw_image())
        dbg._sym_symbols = {"kern": 0x1000}
        assert dbg._resolve_any_symbol_name(0x1000) == "kern"


# ============================================================
#  符号模块查找
# ============================================================


class TestModuleNameAt:
    @staticmethod
    def _make_dbg():
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_mods = [_deployed_module("sittim::fault")]
        hart = emu.harts[0]
        hart.mode = RiscvMode.S
        hart.satp_val = SATP_SV39
        return dbg, hart

    def test_deployed_physical_address_resolves(self):
        dbg, _ = self._make_dbg()
        assert dbg._module_name_at(MODULE_PA) == "sittim::fault"

    def test_translated_address_resolves_module(self, monkeypatch):
        """按物理地址部署的模块经调试翻译的物理地址命中符号.

        该模块没有虚拟区间, S 模式的虚拟地址只能经翻译命中.
        """
        dbg, _ = self._make_dbg()
        seen: dict = {}

        def translate(h, va, **kwargs):
            seen.update(kwargs)
            return True, MODULE_PA

        monkeypatch.setattr(MemoryAccessOps, "translate_addr", translate)
        assert dbg._module_name_at(MODULE_VA) == "sittim::fault"
        assert seen.get("is_hart_access") is False

    def test_untranslatable_address_returns_none(self, monkeypatch):
        dbg, _ = self._make_dbg()
        monkeypatch.setattr(
            MemoryAccessOps,
            "translate_addr",
            lambda *a, **k: (False, 0),
        )
        assert dbg._module_name_at(MODULE_VA) is None


# ============================================================
#  段查找
# ============================================================


class TestFindSegment:
    def test_without_image_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg._find_segment(0x1000) is None

    def test_containing_segment_is_returned(self):
        segs = [
            FirmwareSegment(
                vaddr=0x1000, data=b"\x00", memsz=0x100, name=".text"
            ),
            FirmwareSegment(
                vaddr=0x2000, data=b"\x00", memsz=0x100, name=".data"
            ),
        ]
        dbg, _, _ = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(segments=segs)
        )
        assert dbg._find_segment(0x2050).name == ".data"

    def test_bss_tail_is_inside_segment(self):
        """memsz 大于文件内容时, 零填充部分仍属该段."""
        segs = [
            FirmwareSegment(
                vaddr=0x1000, data=b"\x00", memsz=0x1000, name=".bss"
            )
        ]
        dbg, _, _ = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(segments=segs)
        )
        assert dbg._find_segment(0x1F00).name == ".bss"

    def test_address_at_segment_end_is_outside(self):
        segs = [
            FirmwareSegment(
                vaddr=0x1000, data=b"\x00", memsz=0x100, name=".text"
            )
        ]
        dbg, _, _ = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(segments=segs)
        )
        assert dbg._find_segment(0x1100) is None

    def test_address_in_no_segment_returns_none(self):
        segs = [
            FirmwareSegment(
                vaddr=0x1000, data=b"\x00", memsz=0x100, name=".text"
            )
        ]
        dbg, _, _ = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(segments=segs)
        )
        assert dbg._find_segment(0x9000) is None


# ============================================================
#  代码地址校验
# ============================================================


class TestIsValidCodeVa:
    def test_bare_mode_accepts_ram_address(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg._is_valid_code_va(RAM_BASE) is True

    def test_bare_mode_rejects_hole_address(self):
        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        assert dbg._is_valid_code_va(HOLE_ADDR) is False

    def test_machine_mode_falls_back_to_physical_check(self):
        """M 模式恒用 Bare 语义, 即使 satp 已设定翻译模式."""
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        hart = emu.harts[0]
        hart.satp_val = SATP_SV39
        hart.mode = RiscvMode.M
        assert dbg._is_valid_code_va(RAM_BASE) is True
        assert dbg._is_valid_code_va(KERNEL_VA) is False

    @pytest.mark.parametrize("mode", [RiscvMode.S, RiscvMode.D])
    def test_supervisor_mode_accepts_kernel_va(self, mode):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        hart = emu.harts[0]
        hart.satp_val = SATP_SV39
        hart.mode = mode
        assert dbg._is_valid_code_va(KERNEL_VA) is True

    @pytest.mark.parametrize("mode", [RiscvMode.S, RiscvMode.D])
    def test_supervisor_mode_rejects_user_va(self, mode):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        hart = emu.harts[0]
        hart.satp_val = SATP_SV39
        hart.mode = mode
        assert dbg._is_valid_code_va(USER_VA) is False

    def test_user_mode_accepts_user_va(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        hart = emu.harts[0]
        hart.satp_val = SATP_SV39
        hart.mode = RiscvMode.U
        assert dbg._is_valid_code_va(USER_VA) is True

    def test_user_mode_rejects_kernel_va(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        hart = emu.harts[0]
        hart.satp_val = SATP_SV39
        hart.mode = RiscvMode.U
        assert dbg._is_valid_code_va(KERNEL_VA) is False

    def test_non_canonical_address_is_rejected(self):
        dbg, emu, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        hart = emu.harts[0]
        hart.satp_val = SATP_SV39
        hart.mode = RiscvMode.S
        assert dbg._is_valid_code_va(NON_CANONICAL_VA) is False


# ============================================================
#  cmd_symbols
# ============================================================


class TestCmdSymbols:
    def test_without_image_reports_warning(self):
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg.cmd_symbols()
        assert "无可用的符号表" in buf.getvalue()

    def test_empty_symbol_table_is_reported(self):
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image()
        )
        dbg.cmd_symbols()
        assert "符号表为空" in buf.getvalue()

    def test_grouping_counts_symbols_by_first_character(self):
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE,
            image=_fw_image(symbols={"alpha": 1, "beta": 2, "ax": 3}),
        )
        dbg.cmd_symbols()
        text = buf.getvalue()
        assert "符号分组 (3 项, 2 组)" in text
        assert "a..." in text
        assert "b..." in text
        assert "sym <prefix>" in text

    def test_prefix_filter_lists_matching_addresses(self):
        image = _fw_image(
            symbols={"alpha": 0x1000, "ax": 0x1004, "beta": 0x2000}
        )
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE, image=image)
        dbg.cmd_symbols("a")
        text = buf.getvalue()
        assert "alpha" in text
        assert "ax" in text
        assert "beta" not in text

    def test_prefix_filter_is_case_insensitive(self):
        image = _fw_image(symbols={"Alpha": 0x1000})
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE, image=image)
        dbg.cmd_symbols("aL")
        assert "Alpha" in buf.getvalue()

    def test_unmatched_prefix_reports_nothing_found(self):
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(symbols={"alpha": 0x1000})
        )
        dbg.cmd_symbols("zz")
        assert "无以前缀 'zz' 开头的符号" in buf.getvalue()

    def test_many_matches_are_split_into_subgroups(self):
        """超过 50 项时按 filter 之后的一位再分组."""
        symbols = {"f": 0x1000}
        symbols.update(_many_symbols("f", 60))
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(symbols=symbols)
        )
        dbg.cmd_symbols("f")
        text = buf.getvalue()
        assert "子组" in text
        assert "f0..." in text
        assert "sym f0" in text

    def test_single_subgroup_repeats_its_own_name_in_hint(self):
        """只分出一个子组时提示中两次给出同一名称."""
        symbols = _many_symbols("zzz", 60)
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(symbols=symbols)
        )
        dbg.cmd_symbols("zz")
        assert "sym zzz, sym zzz" in buf.getvalue()

    def test_list_all(self):
        dbg = make_test_dbg()
        dbg._image = make_test_image()
        dbg.cmd_symbols()

    def test_filter(self):
        dbg = make_test_dbg()
        dbg._image = make_test_image()
        dbg.cmd_symbols("main")

    def test_no_match(self):
        dbg = make_test_dbg()
        dbg._image = make_test_image()
        dbg.cmd_symbols("nonexistent")

    def test_no_image(self):
        dbg = make_test_dbg()
        dbg._image = None
        dbg.cmd_symbols()

    def test_resolve_symbol(self):
        dbg = make_test_dbg()
        syms = {"main": 0x2000, "_start": 0x1000}
        name = dbg._resolve_symbol(syms, 0x2000)
        assert name == "main"

    def test_resolve_symbol_not_found(self):
        dbg = make_test_dbg()
        name = dbg._resolve_symbol({}, 0x9999)
        assert name is None

    def test_resolve_symbol_closest_predecessor(self):
        """最近前驱符号匹配: PC 在函数中间时返回所在函数名."""
        dbg = make_test_dbg()
        syms = {"_start": 0x1000, "main": 0x2000, "init_warmboot": 0xE000}
        assert dbg._resolve_symbol(syms, 0x2004) == "main"  # 中间
        assert dbg._resolve_symbol(syms, 0x2000) == "main"  # 精确
        assert dbg._resolve_symbol(syms, 0x100C) == "_start"  # 中间
        assert dbg._resolve_symbol(syms, 0xE670) == "init_warmboot"  # 中间

    def test_resolve_symbol_far_away_returns_none(self):
        """距离 > 64 KiB 视为不在任何函数内."""
        dbg = make_test_dbg()
        syms = {"main": 0x2000}
        # 0x12000 - 0x2000 = 0x10000 (64 KiB) 仍在范围内
        # 0x12001 - 0x2000 = 0x10001 > 64 KiB -> None
        assert dbg._resolve_symbol(syms, 0x12001) is None

    def test_resolve_symbol_with_pie_offset_applied(self):
        """调用方已减去 _load_offset, 传入链接时地址能正确匹配."""
        dbg = make_test_dbg()
        dbg._load_offset = 0x80000000
        syms = {"fdt_next_tag": 0x21D58}
        # _fn_name 传运行时 PC, 内部减去 _load_offset
        runtime_pc = 0x80021EC4  # fdt_next_tag 内部
        name = dbg._resolve_symbol(syms, runtime_pc - dbg._load_offset)
        assert name == "fdt_next_tag"

    def test_resolve_symbol_range_exact_match(self):
        """范围匹配: start <= addr < end -> 返回正确的包含符号."""
        dbg = make_test_dbg()
        # 模拟 vmlinux 中的场景: aio_complete_rw 和 vfs_coredump 距离 60KB+
        syms = {"aio_complete_rw": 0x1000, "vfs_coredump": 0x11000}
        ranges = [
            (0x1000, 0x1080, "aio_complete_rw"),
            (0x11000, 0x12000, "vfs_coredump"),
        ]
        # 0x1060 在 aio_complete_rw 范围内 — 旧算法会错误返回 vfs_coredump
        assert dbg._resolve_symbol(syms, 0x1060, ranges) == "aio_complete_rw"
        # 0x1000 精确起始
        assert dbg._resolve_symbol(syms, 0x1000, ranges) == "aio_complete_rw"
        # 0x107F 刚好在边界内
        assert dbg._resolve_symbol(syms, 0x107F, ranges) == "aio_complete_rw"
        # 0x1080 = end — 不在任何范围内, ranges 存在时返回 None
        # (不回退到最近前驱: 错误的函数名比无符号名更有害)
        assert dbg._resolve_symbol(syms, 0x1080, ranges) is None

    def test_resolve_symbol_range_no_match_returns_none(self):
        """ranges 存在但地址不在任何范围内 -> 返回 None (不回退猜测)."""
        dbg = make_test_dbg()
        syms = {"func_a": 0x1000, "func_b": 0x1200}
        ranges = [(0x1000, 0x1080, "func_a"), (0x1200, 0x1280, "func_b")]
        # 0x1100 不在任何范围内, ranges 存在 -> 返回 None
        # (旧行为: 返回 "func_a" 作为最近前驱. 这在 kernel 中会错误将
        #  静态函数内的 PC 挂到前一个 GLOBAL 符号名下)
        assert dbg._resolve_symbol(syms, 0x1100, ranges) is None

    def test_resolve_symbol_no_ranges_still_works(self):
        """无 ranges 参数时回退到旧的前驱算法 (向后兼容)."""
        dbg = make_test_dbg()
        syms = {"main": 0x2000}
        assert dbg._resolve_symbol(syms, 0x2004) == "main"  # 中间
        assert dbg._resolve_symbol(syms, 0x2000) == "main"  # 精确

    def test_resolve_symbol_local_func_correctly_resolved(self):
        """LOCAL 静态函数内的 PC 正确解析, 不挂到前驱 GLOBAL 符号上.

        真实回追溯源 (2026-07-04, Linux vmlinux bt):
          workqueue_sysfs_register (GLOBAL): 0x80045664, size=254
          process_scheduled_works (LOCAL): 0x8004604c, size=912 ← PC=0x800461c6
          worker_thread (LOCAL): 0x80047a94, size=638 ← PC=0x80047c38
          kthread_blkcg           (GLOBAL): 0x8004d770, size=34
          kthread (LOCAL): 0x8004d794, size=256 ← PC=0x8004d870

        旧行为: LOCAL 符号被 skip_local 过滤, ranges 中缺失, PC 经二分查找
        未命中后回退到最近前驱 GLOBAL, 导致 #03~#05 帧函数名全错.
        """
        dbg = make_test_dbg()
        syms = {
            "workqueue_sysfs_register": 0x80045664,
            "process_scheduled_works": 0x8004604C,
            "worker_thread": 0x80047A94,
            "kthread_blkcg": 0x8004D770,
            "kthread": 0x8004D794,
        }
        ranges = [
            (0x80045664, 0x80045762, "workqueue_sysfs_register"),
            (0x8004604C, 0x800463DC, "process_scheduled_works"),
            (0x80047A94, 0x80047D12, "worker_thread"),
            (0x8004D770, 0x8004D792, "kthread_blkcg"),
            (0x8004D794, 0x8004D894, "kthread"),
        ]
        # 旧行为 (无 ranges): 前驱匹配 -> workqueue_sysfs_register (错误!)
        # 新行为 (有 ranges): 精确包含 -> process_scheduled_works
        assert (
            dbg._resolve_symbol(syms, 0x800461C6, ranges)
            == "process_scheduled_works"
        )
        assert dbg._resolve_symbol(syms, 0x80047C38, ranges) == "worker_thread"
        assert dbg._resolve_symbol(syms, 0x8004D870, ranges) == "kthread"
        # GLOBAL 函数仍正常匹配
        assert (
            dbg._resolve_symbol(syms, 0x80045664, ranges)
            == "workqueue_sysfs_register"
        )

    def test_resolve_symbol_gap_between_funcs_returns_none(self):
        """两函数间空隙地址: ranges 存在 -> 返回 None, 不猜测.

        kthread_blkcg 结束于 0x8004D792, kthread 始于 0x8004D794.
        间隙 [0x8004D792, 0x8004D794) 2 字节 — 既不属于前者也不属于后者.
        """
        dbg = make_test_dbg()
        syms = {"kthread_blkcg": 0x8004D770, "kthread": 0x8004D794}
        ranges = [
            (0x8004D770, 0x8004D792, "kthread_blkcg"),
            (0x8004D794, 0x8004D894, "kthread"),
        ]
        assert dbg._resolve_symbol(syms, 0x8004D792, ranges) is None  # end 排除
        assert dbg._resolve_symbol(syms, 0x8004D793, ranges) is None  # 间隙中
        # 边界内
        assert dbg._resolve_symbol(syms, 0x8004D794, ranges) == "kthread"

    def test_find_segment_with_pie_offset(self):
        """_find_segment 传入链接时地址 (已减 _load_offset) 匹配段."""
        image = FirmwareImage(
            entry_point=0x0,
            format="elf",
            segments=[
                FirmwareSegment(
                    vaddr=0x0, data=b"", memsz=0x3EBB0, name=".text"
                ),
            ],
            symbols={},
        )
        dbg = make_test_dbg()
        dbg._image = image
        dbg._load_offset = 0x80000000
        # 运行时地址 0x80021ec4, 减 _load_offset 后 = 0x21ec4 在 .text 范围内
        seg = dbg._find_segment(0x21EC4)
        assert seg is not None
        assert seg.name == ".text"

    def test_find_segment_miss_far_address(self):
        """不落在任何段内返回 None (远地址)."""
        dbg = make_test_dbg()
        seg = dbg._find_segment(0xFFFF_FFFF)
        assert seg is None

    def test_find_segment_gap_between_segments_returns_none(self):
        """段间空隙中的地址返回 None — 不做最近前驱猜测.

        模拟真实固件布局: .text 在 VA 0x0, .sittim 在 VA 0x180000.
        内核 Image 加载在 VA 0x200000 (fw_jump 模式), 无对应固件段.
        VA 0x201048 在 .sittim 之后 0x72e23 字节 — 距离足够近
        (在旧实现的 1 MiB 阈值内) 会触发错误猜测, 返回 .sittim.
        修复后应返回 None.
        """
        image = FirmwareImage(
            entry_point=0x0,
            format="elf",
            segments=[
                FirmwareSegment(
                    vaddr=0x0, data=b"", memsz=0x3F260, name=".text"
                ),
                FirmwareSegment(
                    vaddr=0x180000, data=b"", memsz=0xE225, name=".sittim"
                ),
            ],
            symbols={},
        )
        dbg = make_test_dbg()
        dbg._image = image
        dbg._load_offset = 0x80000000
        # 内核 Image 区域 (fw_jump): VA 0x200000 起, 无对应段
        seg = dbg._find_segment(0x201048)
        assert seg is None, (
            f"段间空隙地址不应匹配任何段, 但返回了 {seg.name if seg else None}"
        )

    def test_find_segment_gap_just_after_segment_returns_none(self):
        """紧接段末尾之后的地址返回 None.

        旧实现会在距离 <= 1 MiB 时返回最近前驱段,
        这对栈回溯是有害的 — 返回错误的段名比无段名更误导.
        """
        image = FirmwareImage(
            entry_point=0x0,
            format="elf",
            segments=[
                FirmwareSegment(
                    vaddr=0x1000, data=b"", memsz=0x100, name=".text"
                ),
                FirmwareSegment(
                    vaddr=0x2000, data=b"", memsz=0x80, name=".rodata"
                ),
            ],
            symbols={},
        )
        dbg = make_test_dbg()
        dbg._image = image
        # .text 结束于 0x1100, .rodata 开始于 0x2000
        # 0x1100 在 1 MiB 内且紧接 .text — 旧实现会返回 .text
        seg = dbg._find_segment(0x1100)
        assert seg is None, (
            f"段间空隙 0x1100 不应匹配 .text, "
            f"但返回了 {seg.name if seg else None}"
        )
        # 0x1FFF 紧接 .rodata 之前 — 同样不应匹配
        seg = dbg._find_segment(0x1FFF)
        assert seg is None, (
            f"段间空隙 0x1FFF 不应匹配 .rodata, "
            f"但返回了 {seg.name if seg else None}"
        )


# ============================================================
#  cmd_sym
# ============================================================


class TestCmdSym:
    @staticmethod
    def _with_candidate(dbg, tmp_path) -> Path:
        """在候选清单中放入一个真实存在的文件."""
        target = tmp_path / "app.elf"
        target.write_bytes(b"\x00")
        dbg._sym_mod_dir = str(tmp_path)
        dbg._sym_avail_items = [
            SymAvailItem(
                number=1,
                name="app.elf",
                path=str(target),
                size=1,
                is_readable=True,
                is_loaded=False,
            ),
        ]
        return target

    def test_load_without_path_reports_usage(self):
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg.cmd_sym("load")
        assert (
            "用法: sym load <#n|文件名> [pa:<addr>|va:<addr>]" in buf.getvalue()
        )

    @pytest.mark.parametrize(
        ("spec", "space", "base"),
        [
            ("", None, None),
            ("pa:0x80200000", "pa", 0x8020_0000),
            ("va:0x40000000", "va", 0x4000_0000),
        ],
    )
    def test_load_forwards_candidate_and_address(
        self, monkeypatch, tmp_path, spec, space, base
    ):
        recorded = {}

        def fake_load(dbg, path, space_arg, base_arg):
            recorded["path"] = path
            recorded["space"] = space_arg
            recorded["base"] = base_arg

        dbg, _, _ = make_test_dbg_buffered(ram_size=RAM_SIZE)
        target = self._with_candidate(dbg, tmp_path)
        monkeypatch.setattr(
            sym.cmd_files.loader, "load_symbol_module", fake_load
        )
        dbg.cmd_sym(f"load #1 {spec}")
        assert recorded == {"path": str(target), "space": space, "base": base}

    def test_load_without_address_prefix_reports_usage(self, tmp_path):
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        self._with_candidate(dbg, tmp_path)
        dbg.cmd_sym("load #1 0x80200000")
        assert sym.cmd_files.ADDR_USAGE in buf.getvalue()

    def test_load_rejects_filesystem_path(self):
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg.cmd_sym("load /tmp/vmlinux")
        assert "只接受候选清单" in buf.getvalue()

    def test_info_without_symbols_is_reported(self):
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg.cmd_sym("info")
        assert "未加载外部调试符号" in buf.getvalue()

    def test_info_summarises_loaded_symbols(self):
        dbg, _, buf = make_test_dbg_buffered(ram_size=RAM_SIZE)
        dbg._sym_symbols = {"main": 0x1000, "echo": 0x2000}
        dbg._sym_path = "/tmp/vmlinux"
        dbg._sym_load_offset = 0x8000
        dbg.cmd_sym("info")
        text = buf.getvalue()
        assert "/tmp/vmlinux" in text
        assert "符号数: 2" in text
        assert "0x1000" in text
        assert "load_offset: 0x8000" in text

    def test_list_subcommand_filters_symbols(self):
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(symbols={"alpha": 0x1000})
        )
        dbg.cmd_sym("list a")
        assert "alpha" in buf.getvalue()

    def test_empty_argument_lists_all_symbols(self):
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(symbols={"alpha": 0x1000})
        )
        dbg.cmd_sym("")
        assert "符号分组" in buf.getvalue()

    def test_unknown_subcommand_falls_back_to_prefix_filter(self):
        """非子命令的关键字整串作为前缀过滤."""
        dbg, _, buf = make_test_dbg_buffered(
            ram_size=RAM_SIZE, image=_fw_image(symbols={"alpha": 0x1000})
        )
        dbg.cmd_sym("alpha")
        assert "alpha" in buf.getvalue()


# ============================================================
#  目录约定
# ============================================================


def test_module_file_exists():
    """测试对象为 pyremu/debug/sym/__init__.py, 避免导入到同名替身."""
    module_path = Path(sym.__file__)
    assert module_path.name == "__init__.py"
    assert module_path.parent.name == "sym"
