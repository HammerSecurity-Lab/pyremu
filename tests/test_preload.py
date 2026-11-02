#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.env_inject.preload — 载荷的注入位置与文件读取."""

import pytest

from pyremu import configs_gen
from pyremu.env_inject.preload import Preloader
from tests.conftest import make_test_emu

RAM_BASE = 0x8000_0000
RAM_SIZE = 0x0004_0000
PAYLOAD = b"\x13\x00\x00\x00\x73\x00\x10\x00"


class TestInject:
    def test_default_address_sits_below_ram_top(self):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        entry = Preloader(emu).inject(PAYLOAD)
        expected = RAM_BASE + RAM_SIZE - configs_gen.RAM_PRELOAD_OFFSET
        assert entry == expected & ~0xF
        assert emu.bus.try_read(entry, len(PAYLOAD)) == PAYLOAD

    def test_explicit_address_is_used_verbatim(self):
        """显式地址不做对齐处理, 按调用方给定值写入."""
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        addr = RAM_BASE + 0x1002
        entry = Preloader(emu).inject(PAYLOAD, addr)
        assert entry == addr
        assert emu.bus.try_read(addr, len(PAYLOAD)) == PAYLOAD

    def test_every_hart_is_untouched_by_injection(self):
        """注入只写内存, 不改变 hart 的程序计数器."""
        emu = make_test_emu(num_harts=2, ram_size=RAM_SIZE, uart_base=0)
        for hart in emu.harts:
            hart.pc = RAM_BASE
        Preloader(emu).inject(PAYLOAD)
        assert [h.pc for h in emu.harts] == [RAM_BASE, RAM_BASE]

    def test_empty_payload_returns_address(self):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        entry = Preloader(emu).inject(b"")
        expected = RAM_BASE + RAM_SIZE - configs_gen.RAM_PRELOAD_OFFSET
        assert entry == expected & ~0xF


class TestInjectFile:
    def test_file_contents_are_injected(self, tmp_path):
        src = tmp_path / "crt0.bin"
        src.write_bytes(PAYLOAD)
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        entry = Preloader(emu).inject_file(str(src))
        expected = RAM_BASE + RAM_SIZE - configs_gen.RAM_PRELOAD_OFFSET
        assert entry == expected & ~0xF
        assert emu.bus.try_read(entry, len(PAYLOAD)) == PAYLOAD

    def test_explicit_address_is_forwarded(self, tmp_path):
        src = tmp_path / "crt0.bin"
        src.write_bytes(PAYLOAD)
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        addr = RAM_BASE + 0x2000
        assert Preloader(emu).inject_file(str(src), addr) == addr

    def test_missing_file_raises(self, tmp_path):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        missing = tmp_path / "none.bin"
        with pytest.raises(FileNotFoundError) as exc_info:
            Preloader(emu).inject_file(str(missing))
        assert str(missing) in str(exc_info.value)

    def test_directory_is_rejected(self, tmp_path):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        with pytest.raises(FileNotFoundError):
            Preloader(emu).inject_file(str(tmp_path))


class TestPlacementValidation:
    """注入位置的窗口归属与区间范围重叠判定."""

    def test_address_below_ram_window_is_rejected(self):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        with pytest.raises(ValueError) as exc_info:
            Preloader(emu).inject(PAYLOAD, RAM_BASE - 0x1000)
        assert "RAM" in str(exc_info.value)

    def test_payload_crossing_ram_top_is_rejected(self):
        """最后一个字节越出窗口上界时拒绝, 不能只检查起始地址."""
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        with pytest.raises(ValueError):
            Preloader(emu).inject(PAYLOAD, RAM_BASE + RAM_SIZE - 1)

    def test_payload_touching_ram_top_is_accepted(self):
        """区间范围的上界等于窗口上界时仍落在窗口内."""
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        addr = RAM_BASE + RAM_SIZE - len(PAYLOAD)
        assert Preloader(emu).inject(PAYLOAD, addr) == addr
        assert emu.bus.try_read(addr, len(PAYLOAD)) == PAYLOAD

    def test_payload_overlapping_dtb_is_rejected(self):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        dtb_addr = RAM_BASE + 0x1000
        emu.load_dtb_blob(dtb_addr, b"DTBSTUB0")
        with pytest.raises(ValueError) as exc_info:
            Preloader(emu).inject(PAYLOAD, dtb_addr + 4)
        assert "设备树" in str(exc_info.value)

    def test_payload_touching_dtb_start_is_accepted(self):
        """端点相接不算重叠."""
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        dtb_addr = RAM_BASE + 0x1000
        emu.load_dtb_blob(dtb_addr, b"DTBSTUB0")
        addr = dtb_addr - len(PAYLOAD)
        assert Preloader(emu).inject(PAYLOAD, addr) == addr

    def test_payload_overlapping_initrd_is_rejected(self, tmp_path):
        src = tmp_path / "initrd.cpio"
        src.write_bytes(b"\x00" * 0x1000)
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        initrd = emu.load_initrd(str(src), RAM_BASE + 0x4000)
        with pytest.raises(ValueError) as exc_info:
            Preloader(emu).inject(PAYLOAD, initrd.start + 0x100)
        assert "initramfs" in str(exc_info.value)
