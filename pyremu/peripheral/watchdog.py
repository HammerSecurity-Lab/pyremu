#!/usr/bin/env python3
"""多 hart 看门狗虚拟设备.

MMIO 寄存器布局, 每个 hart 一段, stride 0x10:
  0x00 WDOG_CTRL    控制寄存器: bit0 使能, bit1 到期后自动重装
  0x04 WDOG_TIMEOUT 到期 tick 数, 时钟频率取 TIMER_FREQ
  0x08 WDOG_COUNT   剩余 tick, 只读
  0x0C WDOG_KICK    写入任意值: 重装该 hart 的计数并撤销其到期标志

计数依据宿主单调时钟. 守护线程等待至最早的到期时刻, 寄存器写入与停止请求唤醒它
重算. 任一 hart 到期时经中断投递目标拉高中断线, 由 PLIC 或 APLIC 投递; 设备不写
CLINT 的 MSIP.

DTB 绑定:
  compatible = "pyremu,hart-watchdog-1.0"
"""

from __future__ import annotations

import atexit
import threading
import time
from typing import Callable

from pyremu.configs_gen import TIMER_FREQ
from pyremu.memory.bus import Device
from pyremu.utils.mask import mask32
from pyremu.utils.tick import ns_to_ticks, ticks_to_ns

# 中断源编号: 1、2、3 与 10 已由块设备、两块网卡与串口占用
WATCHDOG_IRQ = 4

# 寄存器偏移
_WDOG_CTRL = 0x00
_WDOG_TIMEOUT = 0x04
_WDOG_COUNT = 0x08
_WDOG_KICK = 0x0C
_WDOG_STRIDE = 0x10  # 每个 hart 寄存器块间隔

_CTRL_ENABLE = 1 << 0
_CTRL_AUTORELOAD = 1 << 1


class HartWatchdog(Device):
    """多 hart 看门狗 — 每个 hart 一段倒计数器, 到期经中断控制器投递中断."""

    def __init__(
        self,
        irq_sink: tuple[int, Callable[[int, bool], None]],
        base: int = 0x1000_4000,
        num_harts: int = 2,
        timeout: int = TIMER_FREQ,
        clock_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        """按中断源编号、投递目标与 hart 数构造.

        ``irq_sink`` 取 ``(中断源编号, 投递目标)`` 二元组.
        投递目标取设备中断投递目标对象, 不取 Emulator 的绑定方法,
        理由见 DeviceIrqSink. ``clock_ns`` 给出当前时刻的纳秒数,
        用例据此注入可控时钟.
        """
        self.base_addr = base
        self._num_harts = num_harts
        self._irq, self._irq_sink = irq_sink
        self._clock_ns = clock_ns

        # _lock 保护下列寄存器状态与中断线电平, 覆盖 MMIO 读写与 tick.
        self._lock = threading.Lock()
        self._ctrl: list[int] = [0] * num_harts
        self._timeout_val: list[int] = [timeout] * num_harts
        self._count: list[int] = [0] * num_harts
        self._is_expired: list[bool] = [False] * num_harts
        self._last_ns = clock_ns()
        self._is_irq_high = False

        # start / stop 的幂等判定另用一把锁: 在 _lock 内 join 会与等待 _lock
        # 的守护线程互相等待.
        self._lifecycle_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        # 寄存器写入置位本事件, 使守护线程按新状态重算等待时长.
        self._rearm_event = threading.Event()
        self._is_atexit_registered = False

    # ---- Device interface ----

    @property
    def size(self) -> int:
        return self._num_harts * _WDOG_STRIDE

    @property
    def num_harts(self) -> int:
        return self._num_harts

    def read(self, offset: int, size: int) -> bytes:
        # 寄存器按 4 字节对齐访问; 未对齐的读返回零.
        if offset % 4 != 0:
            return b"\x00" * size
        out = bytearray(size)
        with self._lock:
            for i in range(0, size, 4):
                word = self._read_at(offset + i).to_bytes(4, "little")
                out[i : i + 4] = word[: size - i]
        return bytes(out)

    def _read_at(self, offset: int) -> int:
        """读取 *offset* 所在的 32 位寄存器; 超出设备范围时返回 0."""
        hart, reg = divmod(offset, _WDOG_STRIDE)
        return 0 if hart >= self._num_harts else self._read_word(hart, reg)

    def write(self, offset: int, data: bytes) -> None:
        # 寄存器按 4 字节对齐访问; 未对齐的写不落到任何字段.
        if not data or offset % 4 != 0:
            return
        val = int.from_bytes(data, "little", signed=False)
        with self._lock:
            for i in range(0, len(data), 4):
                hart, reg = divmod(offset + i, _WDOG_STRIDE)
                if hart < self._num_harts:
                    self._write_word(hart, reg, mask32(val >> (8 * i)))
            level = self._sync_level()
        self._publish(level)
        self._rearm_event.set()

    def _read_word(self, hart: int, reg: int) -> int:
        """读取一个 32 位寄存器; 调用方持有 _lock."""
        if reg == _WDOG_CTRL:
            return self._ctrl[hart]
        if reg == _WDOG_TIMEOUT:
            return self._timeout_val[hart]
        if reg == _WDOG_COUNT:
            return self._count[hart]
        return 0  # KICK 读出为 0, 其余偏移无字段

    def _write_word(self, hart: int, reg: int, val: int) -> None:
        """写入一个 32 位寄存器; 调用方持有 _lock."""
        if reg == _WDOG_CTRL:
            self._write_ctrl(hart, val)
        elif reg == _WDOG_TIMEOUT:
            # 只改周期, 不回装当前计数.
            self._timeout_val[hart] = mask32(val)
        elif reg == _WDOG_KICK:
            if self._ctrl[hart] & _CTRL_ENABLE:
                self._count[hart] = self._timeout_val[hart]
            self._is_expired[hart] = False
        # COUNT 只读, 其余偏移无字段

    def _write_ctrl(self, hart: int, val: int) -> None:
        """使能位由 0 变为 1 时装载计数, 由 1 变为 0 时清零;
        两种变化都撤销到期标志."""
        was_enabled = bool(self._ctrl[hart] & _CTRL_ENABLE)
        self._ctrl[hart] = val
        is_enabled = bool(val & _CTRL_ENABLE)
        if was_enabled == is_enabled:
            return
        self._count[hart] = self._timeout_val[hart] if is_enabled else 0
        self._is_expired[hart] = False

    # ---- 计数与中断 ----

    def tick(self, now_ns: int) -> None:
        """按 ``now_ns`` 与上次推进时刻之差递减各使能 hart 的计数.

        只把已计入的整数个 tick 对应的纳秒计入 ``_last_ns``, 余数留到下一次,
        长期不产生累计偏差.
        """
        with self._lock:
            ticks = ns_to_ticks(now_ns - self._last_ns, TIMER_FREQ)
            if ticks <= 0:
                return
            self._last_ns += ticks_to_ns(ticks, TIMER_FREQ)
            for i in range(self._num_harts):
                self._tick_hart(i, ticks)
            level = self._sync_level()
        self._publish(level)

    def _tick_hart(self, hart: int, ticks: int) -> None:
        """递减一个 hart 的计数, 归零时置到期标志并按需自动重装;
        调用方持有 _lock."""
        if not self._ctrl[hart] & _CTRL_ENABLE:
            return
        self._count[hart] -= ticks
        if self._count[hart] > 0:
            return
        self._is_expired[hart] = True
        timeout = self._timeout_val[hart]
        if not self._ctrl[hart] & _CTRL_AUTORELOAD or timeout <= 0:
            self._count[hart] = 0
            return
        # 自动重装把超出量带到下一周期; TIMEOUT 取 0 时每个 tick 都到期, 不回装.
        while self._count[hart] <= 0:
            self._count[hart] += timeout

    def _sync_level(self) -> bool | None:
        """按各 hart 的到期标志更新中断线电平;
        电平变化时返回新电平, 否则返回 None."""
        level = any(self._is_expired)
        if level == self._is_irq_high:
            return None
        self._is_irq_high = level
        return level

    def _publish(self, level: bool | None) -> None:
        """在 _lock 之外调用投递目标: 后者会写 PLIC 或 APLIC 并置轮次通知位."""
        if level is not None:
            self._irq_sink(self._irq, level)

    def _next_wait_s(self) -> float | None:
        """距最早到期时刻的秒数; 没有待检测的到期时刻时返回 None, 即等到被唤醒.

        调用方持有 _lock.
        """
        now_ns = self._clock_ns()
        deadlines = [
            self._last_ns + ticks_to_ns(self._count[i], TIMER_FREQ)
            for i in range(self._num_harts)
            if self._ctrl[i] & _CTRL_ENABLE and self._count[i] > 0
        ]
        if not deadlines:
            return None
        return max(0, min(deadlines) - now_ns) / 1_000_000_000

    # ---- 线程 ----

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """幂等启动守护线程, 并按 ``clock_ns`` 置计数基准时刻."""
        with self._lifecycle_lock:
            if self.is_running:
                return
            self._reset_time_base()
            self._stop_event.clear()
            self._rearm_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="pyremu-watchdog",
                daemon=True,
            )
            self._thread.start()
            if not self._is_atexit_registered:
                atexit.register(self.stop)
                self._is_atexit_registered = True

    def _reset_time_base(self) -> None:
        with self._lock:
            self._last_ns = self._clock_ns()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            with self._lock:
                wait_s = self._next_wait_s()
            if self._rearm_event.wait(wait_s) and self._stop_event.is_set():
                return
            self._rearm_event.clear()
            self.tick(self._clock_ns())

    def stop(self) -> None:
        """幂等停止守护线程; 由守护线程自身调用时直接返回."""
        if threading.current_thread() is self._thread:
            return
        with self._lifecycle_lock:
            thread = self._thread
            if thread is None:
                return
            self._stop_event.set()
            self._rearm_event.set()
            # join 不带超时: 线程只有 wait 与 tick 两个阻塞点, 前者因上面置位
            # 重算事件而立即返回. join 在生命周期锁内完成, 否则并发的 start 会在
            # 旧线程退出前清掉停止事件, 使两个线程同时推进同一份计数.
            thread.join()
            self._thread = None
            if self._is_atexit_registered:
                atexit.unregister(self.stop)
                self._is_atexit_registered = False
