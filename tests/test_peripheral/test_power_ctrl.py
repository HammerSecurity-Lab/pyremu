#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""关机与复位请求设备的用例."""

import ctypes
import struct
import threading

import libfdt
import pytest

from pyremu.emu.run import RunStopReason
from pyremu.peripheral.power_ctrl import PowerCtrl, PowerRequest
from tests.conftest import make_test_emu

POWER_BASE = 0x0010_0000
CTRL_SIZE = 0x1000


def _ctrl_val(val: int) -> bytes:
    """控制寄存器的 4 字节小端编码."""
    return val.to_bytes(4, "little")


def _prop_u32(
    fdt: libfdt.Fdt,
    node: int,
    prop: str,
) -> int:
    """读取 32 位大端属性."""
    return struct.unpack(">I", bytes(fdt.getprop(node, prop)))[0]


class TestPowerCtrlRegister:
    """控制寄存器的读写."""

    def test_read_returns_zero(self):
        dev = PowerCtrl(base=POWER_BASE)
        assert dev.read(0x00, 4) == b"\x00" * 4
        assert dev.read(0x04, 8) == b"\x00" * 8

    def test_shutdown_request_notifies(self):
        stop_flag = ctypes.c_uint8(0)
        wake_event = threading.Event()
        dev = PowerCtrl(
            base=POWER_BASE, stop_flag=stop_flag, wake_event=wake_event
        )
        dev.write(0x00, _ctrl_val(PowerRequest.SHUTDOWN))
        assert dev.request is PowerRequest.SHUTDOWN
        assert stop_flag.value == 1
        assert wake_event.is_set()

    def test_reboot_request_notifies(self):
        stop_flag = ctypes.c_uint8(0)
        wake_event = threading.Event()
        dev = PowerCtrl(
            base=POWER_BASE, stop_flag=stop_flag, wake_event=wake_event
        )
        dev.write(0x00, _ctrl_val(PowerRequest.REBOOT))
        assert dev.request is PowerRequest.REBOOT
        assert stop_flag.value == 1
        assert wake_event.is_set()

    def test_other_value_ignored(self):
        stop_flag = ctypes.c_uint8(0)
        dev = PowerCtrl(base=POWER_BASE, stop_flag=stop_flag)
        dev.write(0x00, _ctrl_val(0x1234))
        assert dev.request is None
        assert stop_flag.value == 0

    def test_write_to_other_offset_ignored(self):
        dev = PowerCtrl(base=POWER_BASE)
        dev.write(0x04, _ctrl_val(PowerRequest.SHUTDOWN))
        assert dev.request is None

    def test_request_latches(self):
        dev = PowerCtrl(base=POWER_BASE)
        dev.write(0x00, _ctrl_val(PowerRequest.SHUTDOWN))
        dev.write(0x00, _ctrl_val(PowerRequest.REBOOT))
        assert dev.request is PowerRequest.SHUTDOWN

    def test_request_without_notify_hooks(self):
        dev = PowerCtrl(base=POWER_BASE)
        dev.write(0x00, _ctrl_val(PowerRequest.REBOOT))
        assert dev.request is PowerRequest.REBOOT


class TestEmulatorPowerCtrl:
    """模拟器装配与执行循环的停止."""

    def test_device_registered_by_default(self):
        emu = make_test_emu(uart_base=0)
        assert emu.power_ctrl is not None
        assert emu.bus.is_device_addr(POWER_BASE)
        assert "power_ctrl" in emu.peripherals

    def test_base_zero_disables_device(self):
        emu = make_test_emu(uart_base=0, power_base=0)
        assert emu.power_ctrl is None
        assert not emu.bus.is_device_addr(POWER_BASE)
        assert "power_ctrl" not in emu.peripherals

    def test_bus_write_sets_stop_flag(self):
        emu = make_test_emu(uart_base=0)
        emu.bus.write(POWER_BASE, _ctrl_val(PowerRequest.SHUTDOWN))
        assert emu.power_ctrl.request is PowerRequest.SHUTDOWN
        assert emu._native_stop_flag.value == 1

    def test_run_stops_on_shutdown(self):
        emu = make_test_emu(uart_base=0)
        emu.bus.write(POWER_BASE, _ctrl_val(PowerRequest.SHUTDOWN))
        assert emu.run(timeout=1) == 0
        assert emu._run_stop_reason == RunStopReason.SHUTDOWN

    def test_run_stops_on_reboot(self):
        emu = make_test_emu(uart_base=0)
        emu.bus.write(POWER_BASE, _ctrl_val(PowerRequest.REBOOT))
        assert emu.run(timeout=1) == 0
        assert emu._run_stop_reason == RunStopReason.REBOOT


class TestPostPowerRequestExecution:
    """请求置位后的执行状态."""

    @pytest.mark.parametrize(
        "power_req", [PowerRequest.SHUTDOWN, PowerRequest.REBOOT]
    )
    def test_step_does_not_execute(self, power_req):
        emu = make_test_emu(uart_base=0)
        emu.load_code(emu.prog_cnt, b"\x13\x00\x00\x00")
        emu.bus.write(POWER_BASE, _ctrl_val(power_req))
        pc_before = emu.harts[0].pc
        assert emu.step() == 0
        assert emu.harts[0].pc == pc_before
        assert emu.total_instructions == 0

    def test_step_executes_without_request(self):
        """对照: 没有请求时同一条 NOP 正常执行."""
        emu = make_test_emu(uart_base=0)
        emu.load_code(emu.prog_cnt, b"\x13\x00\x00\x00")
        pc_before = emu.harts[0].pc
        assert emu.step() == 1
        assert emu.harts[0].pc == pc_before + 4

    def test_clear_request_resumes_execution(self):
        emu = make_test_emu(uart_base=0)
        emu.load_code(emu.prog_cnt, b"\x13\x00\x00\x00")
        emu.bus.write(POWER_BASE, _ctrl_val(PowerRequest.SHUTDOWN))
        assert emu.step() == 0
        emu.power_ctrl.clear_request()
        assert emu.power_request is None
        assert emu.step() == 1


class TestPowerCtrlDtb:
    """设备树节点."""

    def test_dtb_contains_syscon_and_reset_nodes(self):
        emu = make_test_emu(uart_base=0)
        fdt = libfdt.Fdt(emu.build_default_dtb())
        node = fdt.path_offset(f"/soc/syscon@{POWER_BASE:x}")
        assert node >= 0
        assert bytes(fdt.getprop(node, "compatible")) == b"syscon\x00"
        base_hi, base_lo, size_hi, size_lo = struct.unpack(
            ">IIII", bytes(fdt.getprop(node, "reg"))
        )
        assert (base_hi << 32) | base_lo == POWER_BASE
        assert (size_hi << 32) | size_lo == CTRL_SIZE
        phandle = _prop_u32(fdt, node, "phandle")

        for name, compatible, value in (
            ("poweroff", b"syscon-poweroff\x00", PowerRequest.SHUTDOWN),
            ("reboot", b"syscon-reboot\x00", PowerRequest.REBOOT),
        ):
            child = fdt.path_offset(f"/soc/{name}")
            assert child >= 0
            assert bytes(fdt.getprop(child, "compatible")) == compatible
            assert _prop_u32(fdt, child, "regmap") == phandle
            assert _prop_u32(fdt, child, "offset") == 0
            assert _prop_u32(fdt, child, "value") == value

    def test_dtb_omits_nodes_when_disabled(self):
        emu = make_test_emu(uart_base=0, power_base=0)
        fdt = libfdt.Fdt(emu.build_default_dtb())
        syscon_path = f"/soc/syscon@{POWER_BASE:x}"
        assert fdt.path_offset(syscon_path, libfdt.QUIET_NOTFOUND) < 0
        assert fdt.path_offset("/soc/poweroff", libfdt.QUIET_NOTFOUND) < 0
        assert fdt.path_offset("/soc/reboot", libfdt.QUIET_NOTFOUND) < 0
