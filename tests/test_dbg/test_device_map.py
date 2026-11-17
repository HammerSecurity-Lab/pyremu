#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.device_map — 物理地址区间列表."""

import io
from types import SimpleNamespace

from rich.console import Console

from pyremu.debug.device_map import DeviceMapOps
from pyremu.debug.utils import hex_addr
from pyremu.memory.bus import Bus
from pyremu.peripheral.virtio_net import VirtIONet
from tests.conftest import DbgTestBase, make_test_dbg_buffered, make_test_emu


class _TestDeviceDbg(DbgTestBase, DeviceMapOps):
    """最小聚合类供 DeviceMapOps 测试."""


def _capture(dbg) -> str:
    buf = io.StringIO()
    dbg._console = Console(file=buf, highlight=False, width=200)
    dbg.cmd_devices()
    return buf.getvalue()


def _make_dbg(**periph):
    return _TestDeviceDbg(make_test_emu(**periph))


class TestCmdDevices:
    def test_lists_main_memory(self):
        out = _capture(_make_dbg())
        assert "主存" in out

    def test_lists_registered_devices(self):
        """默认配置注册了 CLINT 与 UART, 两者都出现在列表中."""
        out = _capture(_make_dbg())
        assert "CLINT" in out
        assert "UART" in out

    def test_omits_unregistered_device(self):
        """uart_base 取 0 时 UART 不注册, 列表中不出现."""
        out = _capture(_make_dbg(uart_base=0))
        assert "UART" not in out

    def test_reports_range_bounds(self):
        """列表给出主存基址与区间上界."""
        dbg = _make_dbg()
        out = _capture(dbg)
        base = dbg._emu.bus.ram_base
        size = dbg._emu.bus.ram_size
        assert hex_addr(base, styled=False) in out
        assert hex_addr(base + size, styled=False) in out

    def test_boot_rom_listed_once_as_storage(self):
        """引导只读存储器同时在设备表中, 只按存储区间列出一次."""
        out = _capture(_make_dbg())
        assert out.count("引导只读存储器") == 1
        assert "BootRom" not in out

    def test_reports_no_device_message(self):
        """总线未注册设备时在表下列出说明."""
        bus = Bus()
        assert bus.device_entries() == ()
        out = _capture(_TestDeviceDbg(SimpleNamespace(bus=bus)))
        assert "未注册任何虚拟设备" in out

    def test_shows_irq_of_device_holding_one(self):
        """virtio-net 持有中断源编号, 中断源一列给出该编号."""
        emu = make_test_emu()
        net = VirtIONet(
            mem_read=emu.bus.read,
            mem_write=emu.bus.write,
            irq_sink=(2, lambda _src, _pending: None),
        )
        emu.bus.add_device(0x1000_7000, net)
        out = _capture(_TestDeviceDbg(emu))
        assert net.irq == 2
        assert "VirtIONet" in out
        assert hex_addr(0x1000_7000, styled=False) in out

    def test_rows_sorted_by_base(self):
        """主存 (0x8000_0000) 排在全部低位设备之后."""
        out = _capture(_make_dbg())
        first = hex_addr(0x100000, styled=False)
        ram = hex_addr(0x8000_0000, styled=False)
        assert out.index(first) < out.index(ram)


class TestCommandDispatch:
    def test_dispatches_devices_command(self):
        dbg, _emu, buf = make_test_dbg_buffered()
        assert dbg._dispatch(["devices"]) is True
        assert "主存" in buf.getvalue()

    def test_help_lists_devices(self):
        dbg, _emu, buf = make_test_dbg_buffered()
        dbg._print_help()
        assert "devices/dev" in buf.getvalue()
