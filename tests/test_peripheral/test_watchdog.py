#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""多 hart 看门狗测试.

覆盖: 每 hart 寄存器块的读写 / 按宿主时钟递减计数与自动重装 / 到期经中断投递目标
拉高中断线 / 到期不写 CLINT 的 msip / 守护线程 / Emulator 装配与 DTB 节点.
时间由注入的 clock_ns 与直接调用 tick 给出, 用例不睡眠.
"""

import struct
import threading
import time

import libfdt
import pytest

from pyremu import configs_gen
from pyremu.configs_gen import TIMER_FREQ
from pyremu.emulator import Emulator
from pyremu.peripheral.watchdog import HartWatchdog, WATCHDOG_IRQ
from pyremu.platform import PeripheralConfig, PlatformConfig
from tests.conftest import make_test_config

WDOG_CTRL = 0x00
WDOG_TIMEOUT = 0x04
WDOG_COUNT = 0x08
WDOG_KICK = 0x0C
WDOG_STRIDE = 0x10
CTRL_ENABLE = 1 << 0
CTRL_AUTORELOAD = 1 << 1

WDOG_BASE = 0x1000_4000
MSIP_STRIDE = 4
# 用例的默认超时周期, 单位 tick, 即 10 毫秒
TEST_TIMEOUT = TIMER_FREQ // 100


@pytest.fixture(autouse=True)
def _disable_aia_compile_override(monkeypatch):
    """用例按 legacy 模式构造平台, 不随 PYREMU_AIA 编译选项变化."""
    monkeypatch.setattr(configs_gen, "PYREMU_AIA", False)


class FakeClock:
    """可推进的注入时钟, 返回纳秒."""

    def __init__(self, now_ns: int = 0) -> None:
        self._now_ns = now_ns

    def __call__(self) -> int:
        return self._now_ns

    def advance_ns(self, ns: int) -> None:
        self._now_ns += ns


class IrqRecorder:
    """记录投递目标收到的 (中断源编号, 电平) 序列."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, bool]] = []

    def __call__(self, source: int, pending: bool = True) -> None:
        self.calls.append((source, pending))


def _u32(dev: HartWatchdog, offset: int) -> int:
    """按 32 位宽读取一个寄存器."""
    return int.from_bytes(dev.read(offset, 4), "little", signed=False)


def _write_u32(dev: HartWatchdog, offset: int, val: int) -> None:
    dev.write(offset, struct.pack("<I", val))


def _elapse_ns(dev: HartWatchdog, clock: FakeClock, ns: int) -> None:
    """推进注入时钟, 并按新时刻调用一次 tick."""
    clock.advance_ns(ns)
    dev.tick(clock())


def _make_dev(
    clock: FakeClock,
    recorder: IrqRecorder,
    num_harts: int = 1,
    timeout: int = 3 * TIMER_FREQ,
) -> HartWatchdog:
    return HartWatchdog(
        irq_sink=(WATCHDOG_IRQ, recorder),
        num_harts=num_harts,
        timeout=timeout,
        clock_ns=clock,
    )


def _make_enabled(
    clock: FakeClock,
    recorder: IrqRecorder,
    num_harts: int = 1,
    timeout: int = 3 * TIMER_FREQ,
) -> HartWatchdog:
    """构造设备并打开 hart 0 的使能位, 使计数装载为超时周期."""
    dev = _make_dev(clock, recorder, num_harts=num_harts, timeout=timeout)
    _write_u32(dev, WDOG_CTRL, CTRL_ENABLE)
    return dev


def _emu_cfg(num_harts: int, watchdog_base: int) -> PlatformConfig:
    """不配置串口的平台, 以免构造 Emulator 时启动终端线程."""
    return make_test_config(
        num_harts=num_harts,
        uart_base=0,
        spi_base=0,
        i2c_base=0,
        gpio_base=0,
        crng_base=0,
        virtio_blk_base=0,
        virtio_net_s_base=0,
        virtio_net_m_base=0,
        watchdog_base=watchdog_base,
    )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def recorder() -> IrqRecorder:
    return IrqRecorder()


@pytest.fixture
def wdog(clock, recorder) -> HartWatchdog:
    return _make_dev(clock, recorder, num_harts=2, timeout=TEST_TIMEOUT)


class TestWatchdogRegisters:
    """每 hart 寄存器块的读写."""

    def test_reset_state_is_disabled(self, wdog):
        """复位后不使能, 计数为 0, 超时周期取构造参数."""
        assert _u32(wdog, WDOG_CTRL) == 0
        assert _u32(wdog, WDOG_COUNT) == 0
        assert _u32(wdog, WDOG_TIMEOUT) == TEST_TIMEOUT

    def test_size_covers_all_harts(self, wdog):
        """设备大小为 hart 数乘以寄存器块间距."""
        assert wdog.size == 2 * WDOG_STRIDE
        assert wdog.num_harts == 2

    def test_register_block_per_hart(self, wdog):
        """第 1 个 hart 的寄存器块从偏移 0x10 起, 与第 0 个互不影响."""
        _write_u32(wdog, WDOG_CTRL, CTRL_ENABLE)
        _write_u32(wdog, WDOG_STRIDE + WDOG_TIMEOUT, 77)
        assert _u32(wdog, WDOG_TIMEOUT) == TEST_TIMEOUT
        assert _u32(wdog, WDOG_COUNT) == TEST_TIMEOUT
        assert _u32(wdog, WDOG_STRIDE + WDOG_TIMEOUT) == 77
        assert _u32(wdog, WDOG_STRIDE + WDOG_CTRL) == 0
        assert _u32(wdog, WDOG_STRIDE + WDOG_COUNT) == 0

    def test_unaligned_and_out_of_range_read_zero(self, wdog):
        """未落在 4 字节边界上的读与超出 hart 数的读都返回零."""
        assert wdog.read(0x01, 4) == b"\x00" * 4
        assert wdog.read(2 * WDOG_STRIDE, 4) == b"\x00" * 4
        assert wdog.read(3 * WDOG_STRIDE + WDOG_COUNT, 8) == b"\x00" * 8

    def test_kick_reads_zero(self, wdog):
        """写踢狗寄存器只改状态, 该偏移读出为 0."""
        assert wdog.read(WDOG_KICK, 4) == b"\x00" * 4
        assert wdog.read(WDOG_KICK, 8) == b"\x00" * 8

    def test_write_beyond_hart_count_is_ignored(self, wdog):
        """写超出覆盖范围的 hart 无副作用."""
        _write_u32(wdog, 2 * WDOG_STRIDE + WDOG_TIMEOUT, 9)
        assert wdog.read(2 * WDOG_STRIDE + WDOG_TIMEOUT, 4) == b"\x00" * 4

    def test_count_is_read_only(self, wdog):
        """写计数寄存器被忽略."""
        _write_u32(wdog, WDOG_CTRL, CTRL_ENABLE)
        _write_u32(wdog, WDOG_COUNT, 1)
        assert _u32(wdog, WDOG_COUNT) == TEST_TIMEOUT

    def test_enable_bit_loads_and_clears_count(self, wdog):
        """使能位由 0 变为 1 时装载计数, 由 1 变为 0 时清零."""
        _write_u32(wdog, WDOG_CTRL, CTRL_ENABLE)
        assert _u32(wdog, WDOG_COUNT) == TEST_TIMEOUT
        _write_u32(wdog, WDOG_CTRL, 0)
        assert _u32(wdog, WDOG_COUNT) == 0


class TestWatchdogCounting:
    """按宿主时钟递减计数."""

    def test_count_follows_clock_with_remainder_carried(self, recorder):
        """两次各推进 0.6 秒与一次推进 1.2 秒的计数相同, 余数不丢."""
        split_clock = FakeClock()
        split = _make_enabled(split_clock, recorder)
        _elapse_ns(split, split_clock, 600_000_007)
        _elapse_ns(split, split_clock, 600_000_000)

        whole_clock = FakeClock()
        whole = _make_enabled(whole_clock, recorder)
        _elapse_ns(whole, whole_clock, 1_200_000_007)

        assert _u32(split, WDOG_COUNT) == 3 * TIMER_FREQ - 120_000
        assert _u32(whole, WDOG_COUNT) == _u32(split, WDOG_COUNT)

    def test_disabled_hart_is_not_counted_down(self, clock, recorder):
        """未使能的 hart 计数不递减, 也不置到期标志."""
        dev = _make_dev(clock, recorder, num_harts=2, timeout=TEST_TIMEOUT)
        _write_u32(dev, WDOG_CTRL, CTRL_ENABLE)
        _elapse_ns(dev, clock, 2 * TEST_TIMEOUT * 10_000)
        assert _u32(dev, WDOG_COUNT) == 0
        assert _u32(dev, WDOG_STRIDE + WDOG_COUNT) == 0
        assert recorder.calls == [(WATCHDOG_IRQ, True)]

    def test_kick_reloads_count_and_clears_expired(self, clock, recorder):
        """写踢狗寄存器重装计数并撤销到期标志."""
        dev = _make_enabled(clock, recorder)
        _elapse_ns(dev, clock, 3_000_000_000)
        assert recorder.calls == [(WATCHDOG_IRQ, True)]
        _write_u32(dev, WDOG_KICK, 1)
        assert _u32(dev, WDOG_COUNT) == 3 * TIMER_FREQ
        assert recorder.calls == [(WATCHDOG_IRQ, True), (WATCHDOG_IRQ, False)]

    def test_timeout_write_does_not_reload_count(self, clock, recorder):
        """写超时周期只改周期, 不回装当前计数."""
        dev = _make_enabled(clock, recorder)
        _elapse_ns(dev, clock, 1_000_000_000)
        before = _u32(dev, WDOG_COUNT)
        _write_u32(dev, WDOG_TIMEOUT, 7)
        assert before == 2 * TIMER_FREQ
        assert _u32(dev, WDOG_COUNT) == before
        assert _u32(dev, WDOG_TIMEOUT) == 7


class TestWatchdogIrq:
    """到期经中断投递目标拉高中断线."""

    def test_no_irq_without_expiry(self, clock, recorder):
        """未使能的设备连续推进多个周期也不调用投递目标."""
        dev = _make_dev(clock, recorder, timeout=TEST_TIMEOUT)
        for _ in range(5):
            _elapse_ns(dev, clock, TEST_TIMEOUT * 10_000)
        assert recorder.calls == []

    def test_expiry_records_single_rising_edge(self, clock, recorder):
        """到期时计数归 0 并记录一次拉高; 再推进不再重复."""
        dev = _make_enabled(clock, recorder)
        _elapse_ns(dev, clock, 3_000_000_000)
        assert _u32(dev, WDOG_COUNT) == 0
        assert recorder.calls == [(WATCHDOG_IRQ, True)]
        _elapse_ns(dev, clock, 3_000_000_000)
        assert recorder.calls == [(WATCHDOG_IRQ, True)]

    def test_irq_sink_reading_registers_does_not_deadlock(self, clock):
        """投递目标在回调内读本设备的寄存器时, tick 仍能在限定时间内返回."""
        holder: dict[str, HartWatchdog] = {}

        def sink(source: int, pending: bool = True) -> None:
            holder["dev"].read(WDOG_CTRL, 4)

        dev = HartWatchdog(
            irq_sink=(WATCHDOG_IRQ, sink),
            num_harts=1,
            timeout=1,
            clock_ns=clock,
        )
        holder["dev"] = dev
        _write_u32(dev, WDOG_CTRL, CTRL_ENABLE)
        clock.advance_ns(1_000_000)
        done = threading.Event()

        def _tick() -> None:
            dev.tick(clock())
            done.set()

        threading.Thread(target=_tick, daemon=True).start()
        assert done.wait(2.0)

    def test_first_expired_hart_raises_level(self, clock, recorder):
        """任一 hart 到期即拉高, 另一未到期的 hart 继续递减."""
        dev = _make_dev(clock, recorder, num_harts=2, timeout=TEST_TIMEOUT)
        _write_u32(dev, WDOG_STRIDE + WDOG_TIMEOUT, 3 * TEST_TIMEOUT)
        _write_u32(dev, WDOG_CTRL, CTRL_ENABLE)
        _write_u32(dev, WDOG_STRIDE + WDOG_CTRL, CTRL_ENABLE)
        _elapse_ns(dev, clock, TEST_TIMEOUT * 10_000)
        assert recorder.calls == [(WATCHDOG_IRQ, True)]
        assert _u32(dev, WDOG_STRIDE + WDOG_COUNT) == 2 * TEST_TIMEOUT

    def test_autoreload_keeps_level_high(self, clock, recorder):
        """bit1 置位时到期后自动重装, 电平保持为高, 周期按超时周期重复."""
        dev = _make_dev(clock, recorder, timeout=TEST_TIMEOUT)
        _write_u32(dev, WDOG_CTRL, CTRL_ENABLE | CTRL_AUTORELOAD)
        _elapse_ns(dev, clock, TEST_TIMEOUT * 10_000)
        assert _u32(dev, WDOG_COUNT) == TEST_TIMEOUT
        assert recorder.calls == [(WATCHDOG_IRQ, True)]
        _elapse_ns(dev, clock, TEST_TIMEOUT * 10_000)
        assert _u32(dev, WDOG_COUNT) == TEST_TIMEOUT
        assert recorder.calls == [(WATCHDOG_IRQ, True)]

    def test_level_stays_high_until_kick(self, clock, recorder):
        """bit1 清零时到期后计数停在 0, 电平保持为高直至撤销到期标志."""
        dev = _make_enabled(clock, recorder)
        _elapse_ns(dev, clock, 3_000_000_000)
        _elapse_ns(dev, clock, 3_000_000_000)
        assert _u32(dev, WDOG_COUNT) == 0
        assert recorder.calls == [(WATCHDOG_IRQ, True)]
        _write_u32(dev, WDOG_KICK, 1)
        assert recorder.calls == [(WATCHDOG_IRQ, True), (WATCHDOG_IRQ, False)]

    def test_disable_clears_expired_and_level(self, clock, recorder):
        """关闭使能撤销到期标志并拉低电平."""
        dev = _make_enabled(clock, recorder)
        _elapse_ns(dev, clock, 3_000_000_000)
        _write_u32(dev, WDOG_CTRL, 0)
        assert _u32(dev, WDOG_COUNT) == 0
        assert recorder.calls == [(WATCHDOG_IRQ, True), (WATCHDOG_IRQ, False)]


class TestWatchdogNoMsip:
    """到期不写 CLINT 的 msip — 旧实现向等待中的 hart 注入核间中断."""

    def test_expiry_leaves_clint_msip_clear(self, monkeypatch):
        """到期只拉高中断线, 各 hart 的 msip 保持为 0, 也不调用 send_ipi."""
        cfg = _emu_cfg(2, WDOG_BASE)
        emu = Emulator(cfg, bootargs="console=ttySIF0")
        try:
            wdog = emu.watchdog
            assert wdog is not None
            wdog.stop()
            ipis: list[int] = []
            msip_writes: list[int] = []
            monkeypatch.setattr(emu.clint, "send_ipi", ipis.append)
            monkeypatch.setattr(
                emu.clint,
                "write",
                lambda offset, data: msip_writes.append(offset),
            )
            emu.bus.write(WDOG_BASE + WDOG_TIMEOUT, struct.pack("<I", 1))
            emu.bus.write(WDOG_BASE + WDOG_CTRL, struct.pack("<I", CTRL_ENABLE))
            wdog.tick(time.monotonic_ns() + 1_000_000)
            assert ipis == []
            assert msip_writes == []
            for hart_id in range(cfg.num_harts):
                msip = emu.clint.read(hart_id * MSIP_STRIDE, 4)
                assert not int.from_bytes(msip, "little") & 1
            assert not hasattr(wdog, "_clint")
        finally:
            emu.close()


class TestWatchdogThread:
    """守护线程的启动与停止."""

    def test_start_is_idempotent_and_stop_ends_thread(self, clock, recorder):
        """start 两次只有一个线程, stop 之后线程不再存活, 重复 stop 无作用."""
        dev = _make_dev(clock, recorder, timeout=3 * TIMER_FREQ)
        dev.start()
        try:
            assert dev.is_running
            thread = dev._thread
            dev.start()
            assert dev._thread is thread
        finally:
            dev.stop()
        assert not dev.is_running
        dev.stop()
        assert not dev.is_running

    def test_emulator_close_stops_thread(self):
        """Emulator.close 停止看门狗线程."""
        emu = Emulator(_emu_cfg(1, WDOG_BASE), bootargs="console=ttySIF0")
        assert emu.watchdog is not None
        emu.close()
        assert not emu.watchdog.is_running


class TestWatchdogAssembly:
    """Emulator 装配与 DTB 节点."""

    def test_emulator_registers_device(self):
        """基址非 0 时经 Bus 读写落到设备."""
        emu = Emulator(_emu_cfg(1, WDOG_BASE), bootargs="console=ttySIF0")
        try:
            assert emu.watchdog is not None
            assert emu.bus.is_device_addr(WDOG_BASE)
            emu.bus.write(WDOG_BASE + WDOG_TIMEOUT, struct.pack("<I", 12))
            assert emu.bus.read(WDOG_BASE + WDOG_TIMEOUT, 4) == struct.pack(
                "<I", 12
            )
        finally:
            emu.close()

    def test_zero_base_disables_device(self):
        """基址为 0 时不创建设备, 设备树中也没有对应节点."""
        emu = Emulator(_emu_cfg(1, 0), bootargs="console=ttySIF0")
        try:
            assert emu.watchdog is None
            assert "watchdog" not in emu.peripherals
            assert not emu.bus.is_device_addr(0)
            fdt = libfdt.Fdt(emu.build_default_dtb())
            with pytest.raises(libfdt.FdtException):
                fdt.path_offset(f"/soc/watchdog@{WDOG_BASE:x}")
        finally:
            emu.close()

    def test_dtb_node_describes_device(self):
        """节点含 compatible、status、reg、clock-frequency 与 hart 数."""
        emu = Emulator(_emu_cfg(2, WDOG_BASE), bootargs="console=ttySIF0")
        try:
            fdt = libfdt.Fdt(emu.build_default_dtb())
            node = fdt.path_offset(f"/soc/watchdog@{WDOG_BASE:x}")
            assert node >= 0
            assert bytes(fdt.getprop(node, "compatible")) == (
                b"pyremu,hart-watchdog-1.0\x00"
            )
            assert bytes(fdt.getprop(node, "status")) == b"okay\x00"
            base_hi, base_lo, size_hi, size_lo = struct.unpack(
                ">IIII", bytes(fdt.getprop(node, "reg"))
            )
            assert (base_hi << 32) | base_lo == WDOG_BASE
            assert (size_hi << 32) | size_lo == 2 * WDOG_STRIDE
            clock = int.from_bytes(
                bytes(fdt.getprop(node, "clock-frequency")), "big"
            )
            assert clock == TIMER_FREQ
            nums = int.from_bytes(
                bytes(fdt.getprop(node, "pyremu,num-harts")), "big"
            )
            assert nums == 2
        finally:
            emu.close()

    def test_dtb_interrupts_extended_legacy(self):
        """legacy 模式下中断父节点后接一个单元格的中断源编号."""
        emu = Emulator(_emu_cfg(1, WDOG_BASE), bootargs="console=ttySIF0")
        try:
            fdt = libfdt.Fdt(emu.build_default_dtb())
            node = fdt.path_offset(f"/soc/watchdog@{WDOG_BASE:x}")
            cells = struct.unpack(
                ">II", bytes(fdt.getprop(node, "interrupts-extended"))
            )
            assert cells[1] == WATCHDOG_IRQ
        finally:
            emu.close()

    def test_dtb_interrupts_extended_aia(self, make_aia_config):
        """AIA 模式下中断父节点后接中断源编号与电平触发标志."""
        cfg = make_aia_config()
        cfg.periph.uart_base = 0
        cfg.periph.watchdog_base = WDOG_BASE
        emu = Emulator(cfg, bootargs="console=ttySIF0")
        try:
            fdt = libfdt.Fdt(emu.build_default_dtb())
            node = fdt.path_offset(f"/soc/watchdog@{WDOG_BASE:x}")
            cells = struct.unpack(
                ">III", bytes(fdt.getprop(node, "interrupts-extended"))
            )
            assert cells[1] == WATCHDOG_IRQ
            assert cells[2] == 0x4
        finally:
            emu.close()

    def test_default_watchdog_base_follows_build_config(self):
        """默认基址取自按项目编译选项生成的常量, 取 0 即默认不注册该设备."""
        assert PeripheralConfig().watchdog_base == configs_gen.WATCHDOG_BASE
