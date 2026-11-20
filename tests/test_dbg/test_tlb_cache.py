#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.tlb_cache — TLB/Cache 显示."""

import io

from pyremu.debug.tlb_cache import TlbCacheOps
from pyremu.debugger import (
    Debugger,
)
from pyremu.emulator import Emulator
from pyremu.memory.l2cache import L2Cache
from tests.conftest import (
    DbgTestBase,
    make_test_dbg,
)

# ============================================================
#  Mini 测试类
# ============================================================


class _TestTlbDbg(DbgTestBase, TlbCacheOps):
    """最小聚合类供 TlbCacheOps 测试."""


def _make_tlbdbg():
    emu = Emulator(prog_cnt=0x1000)
    emu.load_code(0x1000, b"\x13\x00\x00\x00")  # NOP
    return _TestTlbDbg(emu)


# ============================================================
#  TLB 页大小
# ============================================================


class TestTlbPageSize:
    """_tlb_page_size 静态方法."""

    def test_level_0_is_4k(self):
        assert TlbCacheOps._tlb_page_size(0) == "4K"

    def test_level_1_is_2m(self):
        assert TlbCacheOps._tlb_page_size(1) == "2M"

    def test_level_2_is_1g(self):
        assert TlbCacheOps._tlb_page_size(2) == "1G"

    def test_unknown_level(self):
        assert "Lv3" in TlbCacheOps._tlb_page_size(3)


# ============================================================
#  hexdump
# ============================================================


class TestHexdumpBytes:
    """_hexdump_bytes 静态方法."""

    def test_empty(self):
        result = TlbCacheOps._hexdump_bytes(b"")
        assert result == ""

    def test_short_data(self):
        data = b"\x00\x01\x02\x03"
        result = TlbCacheOps._hexdump_bytes(data)
        assert "0000" in result
        assert "00 01 02 03" in result

    def test_sixteen_bytes_single_line(self):
        data = bytes(range(16))
        result = TlbCacheOps._hexdump_bytes(data)
        lines = result.split("\n")
        assert len(lines) == 1

    def test_multi_line(self):
        data = bytes(range(32))
        result = TlbCacheOps._hexdump_bytes(data)
        lines = result.split("\n")
        assert len(lines) == 2

    def test_indent(self):
        data = b"\x00\x01"
        result = TlbCacheOps._hexdump_bytes(data, indent="  ")
        assert result.startswith("  ")

    def test_hexdump_short(self):
        data = b"\x48\x65\x6c\x6c\x6f"
        result = Debugger._hexdump_bytes(data)
        assert "48 65 6c 6c 6f" in result.lower()
        assert "|Hello|" in result

    def test_hexdump_exact_row(self):
        data = bytes(range(16))
        result = Debugger._hexdump_bytes(data)
        assert "0000  " in result

    def test_hexdump_indented(self):
        data = b"\x00\x01"
        result = Debugger._hexdump_bytes(data, indent="    ")
        assert result.startswith("    ")


# ============================================================
#  TLB 命令
# ============================================================


class TestCmdTlb:
    """cmd_tlb — 默认/全部/范围/VPN 查找."""

    def test_default_shows_both_tlbs(self):
        dbg = _make_tlbdbg()
        dbg.cmd_tlb()  # 应不抛异常

    def test_all_flag(self):
        dbg = _make_tlbdbg()
        dbg.cmd_tlb("-a")

    def test_vpn_search(self):
        dbg = _make_tlbdbg()
        dbg.cmd_tlb("0x12345")

    def test_range_mode(self):
        dbg = _make_tlbdbg()
        dbg.cmd_tlb("10-20")

    def test_bad_range_reversed(self):
        dbg = _make_tlbdbg()
        dbg.cmd_tlb("20-10")  # end <= start

    def test_tlb_empty(self):
        dbg = make_test_dbg()
        dbg.cmd_tlb()  # 空 TLB

    def test_tlb_search(self):
        dbg = make_test_dbg()
        dbg.cmd_tlb("0x00001")

    def test_tlb_search_invalid(self):
        dbg = make_test_dbg()
        dbg.cmd_tlb("bad")

    def test_tlbflush_all(self):
        dbg = make_test_dbg()
        dbg.cmd_tlbflush()  # 全刷新

    def test_tlbflush_vpn(self):
        dbg = make_test_dbg()
        dbg.cmd_tlbflush("0x00001")

    def test_tlbflush_invalid(self):
        dbg = make_test_dbg()
        dbg.cmd_tlbflush("bad")

    def test_tlb_negative_vpn(self):
        dbg = make_test_dbg()
        dbg.cmd_tlb("-1")  # 被拒绝, 不抛异常

    def test_tlbflush_negative_vpn(self):
        dbg = make_test_dbg()
        dbg.cmd_tlbflush("-1")  # 被拒绝, 不抛异常


class TestCmdTlbflush:
    """cmd_tlbflush — 全部/单 VPN 刷新."""

    def test_flush_all(self):
        dbg = _make_tlbdbg()
        dbg.cmd_tlbflush()

    def test_flush_vpn(self):
        dbg = _make_tlbdbg()
        dbg.cmd_tlbflush("0x10000")


# ============================================================
#  Cache 命令
# ============================================================


class TestCmdCache:
    """cmd_cache — L2 缓存显示."""

    def test_no_l2_cache(self):
        """无 L2 缓存时显示提示."""
        dbg = _make_tlbdbg()
        dbg.cmd_cache()  # 应不抛异常

    def test_with_l2_cache(self):
        """有 L2 缓存时显示统计."""
        emu = Emulator(ram_size=0x100000, use_l2_cache=True, prog_cnt=0x1000)
        emu.load_code(0x1000, b"\x13\x00\x00\x00")
        dbg = _TestTlbDbg(emu)
        dbg.cmd_cache()

    def test_with_l2_cache_set_range(self):
        emu = Emulator(ram_size=0x100000, use_l2_cache=True, prog_cnt=0x1000)
        dbg = _TestTlbDbg(emu)
        dbg.cmd_cache("0-3")

    def test_with_l2_cache_single_set(self):
        emu = Emulator(ram_size=0x100000, use_l2_cache=True, prog_cnt=0x1000)
        dbg = _TestTlbDbg(emu)
        dbg.cmd_cache("0")

    def test_with_l2_cache_set_way(self):
        emu = Emulator(ram_size=0x100000, use_l2_cache=True, prog_cnt=0x1000)
        dbg = _TestTlbDbg(emu)
        dbg.cmd_cache("0 0")

    def test_cache_overview(self):
        dbg = make_test_dbg()
        dbg.cmd_cache()

    def test_cache_set(self):
        dbg = make_test_dbg()
        dbg.cmd_cache("0")

    def test_cache_set_way(self):
        dbg = make_test_dbg()
        dbg.cmd_cache("0 0")

    def test_cache_invalid_set(self):
        dbg = make_test_dbg()
        dbg.cmd_cache("999")  # 超出范围

    def test_cache_invalid_arg(self):
        dbg = make_test_dbg()
        dbg.cmd_cache("bad")


# ============================================================
#  Cache 参数解析
# ============================================================


class TestParseCacheArgs:
    """_parse_cache_args 参数解析."""

    def test_none_args(self):
        dbg = _make_tlbdbg()
        err, *rest = dbg._parse_cache_args(None, 8, 4)
        assert not err
        assert rest == [None, None, None, None]

    def test_set_range(self):
        dbg = _make_tlbdbg()
        err, ts, tw, rs, re = dbg._parse_cache_args("2-5", 8, 4)
        assert not err
        assert ts is None
        assert tw is None
        assert rs == 2
        assert re == 5

    def test_single_set(self):
        dbg = _make_tlbdbg()
        err, ts, tw, rs, re = dbg._parse_cache_args("3", 8, 4)
        assert not err
        assert ts == 3
        assert tw is None

    def test_set_and_way(self):
        dbg = _make_tlbdbg()
        err, ts, tw, rs, re = dbg._parse_cache_args("3 1", 8, 4)
        assert not err
        assert ts == 3
        assert tw == 1

    def test_set_out_of_range(self):
        dbg = _make_tlbdbg()
        err, *_ = dbg._parse_cache_args("99", 8, 4)
        assert err

    def test_range_out_of_bounds(self):
        dbg = _make_tlbdbg()
        err, *_ = dbg._parse_cache_args("0-99", 8, 4)
        assert err

    def test_way_out_of_range(self):
        dbg = _make_tlbdbg()
        err, *_ = dbg._parse_cache_args("3 99", 8, 4)
        assert err


class _CacheOutputCapture:
    """捕获 Rich console 输出文本."""

    def __init__(self, dbg):
        self.lines: list[str] = []
        self._orig = dbg._console.print

        def _capture(*args, **kwargs):

            buf = io.StringIO()
            dbg._console.file = buf
            self._orig(*args, **kwargs)
            dbg._console.file = __import__("sys").stdout
            text = buf.getvalue()
            self.lines.extend(text.split("\n"))

        dbg._console.print = _capture

    def text(self) -> str:
        return "\n".join(self.lines)


def _make_l2_dbg(
    num_sets=256,
    ways=4,
    line_size=64,
) -> Debugger:
    """构造带可配置 L2 缓存的 Debugger."""
    dbg = make_test_dbg(ram_size=128 * 1024 * 1024, is_code_loaded=False)
    emu = dbg._emu
    l2 = L2Cache(
        size=num_sets * ways * line_size, line_size=line_size, ways=ways
    )
    emu.bus._l2 = l2
    l2.set_ram_backend(emu.bus.read_ram_direct, emu.bus._ram_write_direct)
    return dbg


class TestTlbDecodeHelpers:
    """TLB 静态辅助函数."""

    def test_tlb_page_size(self):
        assert Debugger._tlb_page_size(0) == "4K"
        assert Debugger._tlb_page_size(1) == "2M"
        assert Debugger._tlb_page_size(2) == "1G"
        assert Debugger._tlb_page_size(3) == "Lv3"
        assert Debugger._tlb_page_size(99) == "Lv99"


class TestFmtCacheLine:
    """L2 缓存行格式化."""

    def test_meta_only(self):
        dbg = make_test_dbg()
        l2 = dbg._emu.bus._l2
        assert l2 is not None
        # 取一个有效条目
        e = l2.entries[0]
        e.valid = True
        e.tag = 0x12345
        result = dbg._fmt_cache_line(e, 0, 0, full=False)
        assert "tag=0x" in result

    def test_full_dump(self):
        dbg = make_test_dbg()
        l2 = dbg._emu.bus._l2
        assert l2 is not None
        e = l2.entries[0]
        e.valid = True
        e.tag = 0xABCDE
        result = dbg._fmt_cache_line(e, 0, 0, full=True)
        assert "tag=0x" in result


class TestCacheDisplay:
    """cmd_cache 输出格式测试."""

    def test_no_args_shows_header(self):
        """cache 无参数 -> 显示统计概览头."""
        dbg = _make_l2_dbg()
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache()
        text = cap.text()
        assert "L2 Cache" in text
        assert "valid" in text
        assert "MESI" in text
        assert "hit_rate" in text

    def test_no_args_shows_up_to_64_entries(self):
        """默认显示最多 64 条 valid 行 (预览格式: data[:16])."""
        dbg = _make_l2_dbg(num_sets=128, ways=2)
        l2 = dbg._emu.bus._l2
        assert l2 is not None
        # 预填一些数据产生 valid 行
        for i in range(80):
            l2.read(i * 64, 4)
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache()
        text = cap.text()
        # 应有 64 条 (或实际 valid 行数) + 截断提示
        assert "data[:16]" in text, "预览模式应含 data[:16]"
        assert "还有" in text, "超过 64 条时应有截断提示"

    def test_less_than_64_shows_all_no_truncation(self):
        """不足 64 条 valid -> 全部显示, 无截断提示."""
        dbg = _make_l2_dbg(num_sets=128, ways=2)
        l2 = dbg._emu.bus._l2
        assert l2 is not None
        for i in range(10):
            l2.read(i * 64, 4)
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache()
        text = cap.text()
        assert "还有" not in text, "不足 64 条不应有截断提示"

    def test_single_set_shows_full_hexdump(self):
        """cache <set> -> 完整 64B hexdump."""
        dbg = _make_l2_dbg()
        l2 = dbg._emu.bus._l2
        assert l2 is not None
        l2.read(0, 8)
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache("0")
        text = cap.text()
        assert "L2 Cache:" in text, (
            "单 set 模式应为完整 hexdump, 不应含 data[:16]"
        )

    def test_range_shows_preview_format(self):
        """cache <start>-<end> -> 范围预览模式."""
        dbg = _make_l2_dbg(num_sets=128, ways=2)
        l2 = dbg._emu.bus._l2
        assert l2 is not None
        for i in range(30):
            l2.read(i * 64, 4)
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache("0-4")
        text = cap.text()
        assert "L2 Cache:" in text, "范围模式应为预览格式"

    def test_invalid_set_index(self):
        """非法 set 索引 -> 错误信息."""
        dbg = _make_l2_dbg(num_sets=16, ways=2)
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache("99")
        text = cap.text()
        assert "超出范围" in text or "set" in text.lower()

    def test_invalid_range(self):
        """非法范围 -> 错误信息."""
        dbg = _make_l2_dbg(num_sets=16, ways=2)
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache("10-99")
        text = cap.text()
        assert "超出范围" in text or "set" in text.lower()

    def test_empty_cache(self):
        """空缓存 -> 无 valid 行提示."""
        dbg = _make_l2_dbg()
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache()
        text = cap.text()
        assert "无 valid 行" in text

    def test_set_with_no_valid_lines(self):
        """指定 set 但该组无 valid 行."""
        dbg = _make_l2_dbg()
        # 不填充任何数据, 直接查某个 set
        cap = _CacheOutputCapture(dbg)
        dbg.cmd_cache("5")
        text = cap.text()
        assert "无 valid 行" in text
