#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.base — 输出、信号处理、终端模式与 stdin 转发."""

import os
from pathlib import Path
import select
import signal
import termios
import types

import pytest

from pyremu.debug import base, Debugger
from pyremu.debug.utils import trap_cause_name
from pyremu.peripheral.uart import RX_FIFO_SIZE
from pyremu.utils.parse_bin import FirmwareSegment
from tests.conftest import (
    make_test_dbg,
    make_test_dbg_buffered,
    make_test_emu,
    make_test_image,
    TEST_PROG_PA,
)

# 关机与复位请求设备的 MMIO 基址.
POWER_BASE = 0x0010_0000

# ============================================================
#  测试装置
# ============================================================


class _FakeTermio:
    """TerminalIO 替身 — 记录 start/stop 与 RX 排空调用."""

    def __init__(self, native_active: bool = True) -> None:
        self.native_active = native_active
        self.start_calls = 0
        self.stop_calls = 0
        self.drain_calls = 0
        self.drain_rx_value = False
        self.drain_feed_value = False
        self._rx_wr = types.SimpleNamespace(value=0)
        self._rx_rd = types.SimpleNamespace(value=0)
        self._rx_notify = types.SimpleNamespace(value=1)

    def start(self) -> None:
        self.start_calls += 1

    def stop(self) -> None:
        self.stop_calls += 1

    def drain_rx(self) -> bool:
        self.drain_calls += 1
        return self.drain_rx_value

    def drain_rx_feed_uart(self) -> bool:
        self.drain_calls += 1
        return self.drain_feed_value


class _Recorder:
    """记录调用次数的可调用对象."""

    def __init__(self, ret=None) -> None:
        self.calls = 0
        self.ret = ret

    def __call__(self, *args, **kwargs):
        self.calls += 1
        self.last = (args, kwargs)
        return self.ret


# ============================================================
#  输出
# ============================================================


class TestOutput:
    def test_warn_marks_message(self):
        dbg, _, buf = make_test_dbg_buffered()
        dbg._warn("磁盘镜像只读")
        text = buf.getvalue()
        assert "警告:" in text
        assert "磁盘镜像只读" in text

    def test_err_marks_message(self):
        dbg, _, buf = make_test_dbg_buffered()
        dbg._err("符号不存在")
        text = buf.getvalue()
        assert "错误:" in text
        assert "符号不存在" in text

    def test_uart_tx_writes_and_flushes(self, capsys):
        Debugger._uart_tx("abc")
        captured = capsys.readouterr()
        assert captured.out == "abc"


# ============================================================
#  信号处理
# ============================================================


class TestSigint:
    def test_repl_handler_raises_keyboard_interrupt(self):
        dbg, _, _ = make_test_dbg_buffered()
        with pytest.raises(KeyboardInterrupt):
            dbg._sigint_repl(signal.SIGINT, None)

    def test_run_handler_requests_pause(self, monkeypatch):
        dbg, emu, buf = make_test_dbg_buffered()
        notify = _Recorder()
        monkeypatch.setattr(emu, "notify_processor", notify)
        dbg._sigint_run(signal.SIGINT, None)
        assert notify.calls == 1
        assert "暂停请求" in buf.getvalue()

    def test_run_handler_swallows_failure(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()

        def boom() -> None:
            raise RuntimeError("处理器未就绪")

        monkeypatch.setattr(emu, "notify_processor", boom)
        dbg._sigint_run(signal.SIGINT, None)


# ============================================================
#  运行模式与 REPL 模式的切换
# ============================================================


class TestEnterRunMode:
    def test_disabled_forward_returns_immediately(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        dbg._stdin_forward = False
        started = _Recorder()
        monkeypatch.setattr(dbg, "_start_stdin_daemon", started)
        monkeypatch.setattr(signal, "signal", _Recorder())
        dbg._enter_run_mode()
        assert started.calls == 0
        assert emu._stdin_forward_callback is None

    def test_non_tty_starts_python_daemon(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        started = _Recorder()
        clear_rx = _Recorder()
        monkeypatch.setattr(dbg, "_start_stdin_daemon", started)
        monkeypatch.setattr(emu.uart, "clear_rx", clear_rx)
        monkeypatch.setattr(os, "isatty", lambda _fd: False)
        monkeypatch.setattr(signal, "signal", _Recorder())
        dbg._enter_run_mode()
        assert clear_rx.calls == 1
        assert emu._stdin_forward_callback == dbg._idle_poll
        assert started.calls == 1
        assert dbg._saved_term_attrs is None

    def test_tty_is_switched_to_raw_mode(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        saved = [
            0x1234,
            0,
            0,
            termios.ECHO | termios.ICANON | termios.ISIG,
            0,
            0,
            {termios.VMIN: 0, termios.VTIME: 0},
        ]
        applied: list = []
        monkeypatch.setattr(dbg, "_start_stdin_daemon", _Recorder())
        monkeypatch.setattr(os, "isatty", lambda _fd: True)
        monkeypatch.setattr(termios, "tcgetattr", lambda _fd: list(saved))
        monkeypatch.setattr(
            termios,
            "tcsetattr",
            lambda fd, when, attrs: applied.append((fd, when, attrs)),
        )
        monkeypatch.setattr(signal, "signal", _Recorder())
        dbg._enter_run_mode()
        assert dbg._saved_term_attrs == saved
        assert len(applied) == 1
        attrs = applied[0][2]
        assert attrs[2] & termios.CSIZE == termios.CS8
        assert attrs[2] & termios.PARENB == 0
        assert (
            attrs[3]
            & (
                termios.ECHO
                | termios.ECHONL
                | termios.ICANON
                | termios.IEXTEN
                | termios.ISIG
            )
            == 0
        )
        assert attrs[0] & termios.ICRNL == termios.ICRNL
        assert attrs[6][termios.VMIN] == 1
        assert attrs[6][termios.VTIME] == 0

    def test_native_termio_takes_over_stdin(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        termio = _FakeTermio(native_active=True)
        emu._termio = termio
        started = _Recorder()
        monkeypatch.setattr(dbg, "_start_stdin_daemon", started)
        monkeypatch.setattr(os, "isatty", lambda _fd: False)
        monkeypatch.setattr(signal, "signal", _Recorder())
        dbg._enter_run_mode()
        assert termio.start_calls == 1
        assert started.calls == 0

    def test_fallback_termio_still_starts_daemon(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        termio = _FakeTermio(native_active=False)
        emu._termio = termio
        started = _Recorder()
        monkeypatch.setattr(dbg, "_start_stdin_daemon", started)
        monkeypatch.setattr(os, "isatty", lambda _fd: False)
        monkeypatch.setattr(signal, "signal", _Recorder())
        dbg._enter_run_mode()
        assert termio.start_calls == 1
        assert started.calls == 1


class TestRestoreTerm:
    def test_saved_attributes_are_restored(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        saved = [0, 0, 0, 0, 0, 0, {}]
        applied: list = []
        dbg._saved_term_attrs = saved
        monkeypatch.setattr(
            termios,
            "tcsetattr",
            lambda fd, when, attrs: applied.append((fd, when, attrs)),
        )
        dbg._restore_term()
        assert applied == [(dbg._stdin_fd, termios.TCSANOW, saved)]
        assert dbg._saved_term_attrs is None

    def test_no_saved_attributes_is_noop(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        applied: list = []
        monkeypatch.setattr(termios, "tcsetattr", lambda *a: applied.append(a))
        dbg._restore_term()
        assert applied == []

    def test_termios_failure_is_swallowed(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        dbg._saved_term_attrs = [0, 0, 0, 0, 0, 0, {}]

        def boom(*_args):
            raise termios.error("not a tty")

        monkeypatch.setattr(termios, "tcsetattr", boom)
        dbg._restore_term()


class TestEnterReplMode:
    def test_stops_daemon_and_restores_terminal(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        order: list[str] = []
        emu._stdin_forward_callback = dbg._idle_poll
        monkeypatch.setattr(
            dbg, "_stop_stdin_daemon", lambda: order.append("daemon")
        )
        monkeypatch.setattr(dbg, "_restore_term", lambda: order.append("term"))
        monkeypatch.setattr(signal, "signal", _Recorder())
        dbg._enter_repl_mode()
        assert order == ["daemon", "term"]
        assert emu._stdin_forward_callback is None

    def test_termio_is_stopped(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        termio = _FakeTermio()
        emu._termio = termio
        monkeypatch.setattr(dbg, "_stop_stdin_daemon", _Recorder())
        monkeypatch.setattr(dbg, "_restore_term", _Recorder())
        monkeypatch.setattr(signal, "signal", _Recorder())
        dbg._enter_repl_mode()
        assert termio.stop_calls == 1


# ============================================================
#  stdin daemon 线程
# ============================================================


class TestStdinDaemonLoop:
    def test_missing_uart_returns(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        emu.uart = None
        monkeypatch.setattr(select, "select", _Recorder())
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()

    def test_read_bytes_reach_uart(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        reads = [b"ab", b""]
        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", lambda _fd, _n: reads.pop(0))
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()
        assert bytes(emu.uart._rx_fifo) == b"ab"
        assert dbg._stdin_daemon_running is True

    def test_ctrl_q_stops_simulation(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", lambda _fd, _n: b"x\x11y")
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()
        assert emu._native_stop_flag.value == 1
        assert dbg._stdin_daemon_running is False
        assert bytes(emu.uart._rx_fifo) == b"x"

    def test_not_ready_select_loops_until_stop(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()

        def idle_select(*_args):
            dbg._stdin_daemon_running = False
            return ([], [], [])

        monkeypatch.setattr(select, "select", idle_select)
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()
        assert bytes(emu.uart._rx_fifo) == b""

    def test_not_ready_select_continues_until_stop(self, monkeypatch):
        """select 报告无输入且 daemon 仍在运行时进入下一轮等待."""
        dbg, emu, _ = make_test_dbg_buffered()
        calls: list = []

        def idle_select(*_args):
            calls.append(1)
            if len(calls) >= 2:
                dbg._stdin_daemon_running = False
            return ([], [], [])

        monkeypatch.setattr(select, "select", idle_select)
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()
        assert len(calls) == 2
        assert bytes(emu.uart._rx_fifo) == b""

    def test_select_failure_breaks(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()

        def boom(*_args):
            raise OSError("监视目标无效")

        monkeypatch.setattr(select, "select", boom)
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()

    def test_read_failure_breaks(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()

        def boom(_fd, _n):
            raise OSError("读取失败")

        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", boom)
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()

    def test_eof_breaks(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", lambda _fd, _n: b"")
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()

    def test_preload_failure_is_swallowed(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        reads = [b"ab", b""]

        def boom(_data):
            raise ValueError("FIFO 拒绝")

        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", lambda _fd, _n: reads.pop(0))
        monkeypatch.setattr(emu.uart, "preload", boom)
        dbg._stdin_daemon_running = True
        dbg._stdin_daemon_loop()


class TestStdinDaemonLifecycle:
    def test_start_skipped_without_uart(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        emu.uart = None
        dbg._start_stdin_daemon()
        assert dbg._stdin_daemon_thread is None

    def test_start_skipped_when_already_running(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        dbg._stdin_daemon_running = True
        dbg._start_stdin_daemon()
        assert dbg._stdin_daemon_thread is None
        dbg._stdin_daemon_running = False

    def test_start_and_stop_thread(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        monkeypatch.setattr(dbg, "_stdin_daemon_loop", lambda: None)
        dbg._start_stdin_daemon()
        assert dbg._stdin_daemon_thread is not None
        assert dbg._stdin_daemon_running is True
        dbg._stop_stdin_daemon()
        assert dbg._stdin_daemon_running is False
        assert dbg._stdin_daemon_thread is None

    def test_stop_without_thread_is_noop(self):
        dbg, _, _ = make_test_dbg_buffered()
        dbg._stop_stdin_daemon()
        assert dbg._stdin_daemon_thread is None


# ============================================================
#  stdin 转发
# ============================================================


class TestFeedUartStdin:
    def test_native_termio_path_reports_input(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        termio = _FakeTermio()
        termio.drain_feed_value = True
        emu._termio = termio
        assert dbg._feed_uart_stdin() is True
        assert termio.drain_calls == 1

    def test_missing_uart_reports_none(self):
        dbg, emu, _ = make_test_dbg_buffered()
        emu.uart = None
        assert dbg._feed_uart_stdin() is False

    def test_daemon_running_without_pending_does_not_read(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        read = _Recorder(ret=b"z")
        monkeypatch.setattr(os, "read", read)
        dbg._stdin_daemon_running = True
        assert dbg._feed_uart_stdin() is False
        assert read.calls == 0

    def test_daemon_running_drains_pending(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        dbg._stdin_daemon_running = True
        dbg._stdin_pending = b"A" * (RX_FIFO_SIZE + 2)
        assert dbg._feed_uart_stdin() is True
        assert len(emu.uart._rx_fifo) == RX_FIFO_SIZE
        assert dbg._stdin_pending == b"AA"
        assert emu._native_ext_irq.pending == 1

    def test_daemon_running_pending_rejection_is_swallowed(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()

        def boom(_data):
            raise OSError("接收缓冲区拒绝")

        monkeypatch.setattr(emu.uart, "preload", boom)
        dbg._stdin_daemon_running = True
        dbg._stdin_pending = b"AB"
        assert dbg._feed_uart_stdin() is False
        assert dbg._stdin_pending == b"AB"

    def test_pending_rejection_reports_none(self, monkeypatch):
        """待转发数据被拒绝时不再读取 stdin."""
        dbg, emu, _ = make_test_dbg_buffered()
        select_calls = _Recorder()

        def boom(_data):
            raise ValueError("接收缓冲区拒绝")

        monkeypatch.setattr(select, "select", select_calls)
        monkeypatch.setattr(emu.uart, "preload", boom)
        dbg._stdin_pending = b"AB"
        assert dbg._feed_uart_stdin() is False
        assert select_calls.calls == 0
        assert dbg._stdin_pending == b"AB"

    def test_partial_pending_keeps_remainder_and_wakes(self, monkeypatch):
        """待转发数据只能部分容纳时, 余下部分留在待转发数据内并唤醒等待者."""
        dbg, emu, _ = make_test_dbg_buffered()
        select_calls = _Recorder()
        monkeypatch.setattr(select, "select", select_calls)
        dbg._stdin_pending = b"B" * (RX_FIFO_SIZE + 4)
        assert dbg._feed_uart_stdin() is True
        assert len(emu.uart._rx_fifo) == RX_FIFO_SIZE
        assert dbg._stdin_pending == b"B" * 4
        assert emu._wake_event.is_set() is True
        assert select_calls.calls == 0

    def test_pending_accepted_then_select_idle(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        dbg._stdin_pending = b"AB"
        monkeypatch.setattr(select, "select", lambda *a: ([], [], []))
        assert dbg._feed_uart_stdin() is True
        assert bytes(emu.uart._rx_fifo) == b"AB"
        assert dbg._stdin_pending == b""

    def test_select_ready_reads_bytes(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()
        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", lambda _fd, _n: b"abc")
        assert dbg._feed_uart_stdin() is True
        assert bytes(emu.uart._rx_fifo) == b"abc"
        assert emu._native_ext_irq.pending == 1

    def test_partial_accept_keeps_remainder(self, monkeypatch):
        """接收缓冲区装满后剩余的字节留在待转发数据内."""
        dbg, emu, _ = make_test_dbg_buffered()
        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(
            os, "read", lambda _fd, _n: b"B" * (RX_FIFO_SIZE + 4)
        )
        assert dbg._feed_uart_stdin() is True
        assert len(emu.uart._rx_fifo) == RX_FIFO_SIZE
        assert dbg._stdin_pending == b"B" * 4

    def test_idle_select_reports_none(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        monkeypatch.setattr(select, "select", lambda *a: ([], [], []))
        assert dbg._feed_uart_stdin() is False

    def test_select_failure_reports_none(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()

        def boom(*_args):
            raise OSError("监视目标无效")

        monkeypatch.setattr(select, "select", boom)
        assert dbg._feed_uart_stdin() is False

    def test_read_failure_reports_none(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()

        def boom(_fd, _n):
            raise OSError("读取失败")

        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", boom)
        assert dbg._feed_uart_stdin() is False

    def test_eof_reports_none(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", lambda _fd, _n: b"")
        assert dbg._feed_uart_stdin() is False

    def test_preload_rejection_reports_none(self, monkeypatch):
        dbg, emu, _ = make_test_dbg_buffered()

        def boom(_data):
            raise ValueError("FIFO 拒绝")

        monkeypatch.setattr(select, "select", lambda *a: ([0], [], []))
        monkeypatch.setattr(os, "read", lambda _fd, _n: b"abc")
        monkeypatch.setattr(emu.uart, "preload", boom)
        assert dbg._feed_uart_stdin() is False


class TestIdlePoll:
    def test_idle_poll_delegates_to_stdin_forward(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        monkeypatch.setattr(dbg, "_feed_uart_stdin", lambda: True)
        assert dbg._idle_poll() is True

    def test_idle_poll_termio_drains_ring_buffer(self):
        dbg, emu, _ = make_test_dbg_buffered()
        termio = _FakeTermio()
        termio._rx_wr.value = 3
        termio._rx_rd.value = 3
        termio.drain_rx_value = True
        emu._termio = termio
        assert dbg._idle_poll_termio() is True
        assert termio._rx_notify.value == 0

    def test_idle_poll_termio_without_termio(self):
        dbg, _, _ = make_test_dbg_buffered()
        assert dbg._idle_poll_termio() is False

    def test_idle_poll_flush_yields_control(self):
        dbg, _, _ = make_test_dbg_buffered()
        assert dbg._idle_poll_flush() is False


# ============================================================
#  陷态上下文与补全
# ============================================================


class TestHartAccess:
    def test_hart_property_follows_active_hart(self):
        dbg, emu, _ = make_test_dbg_buffered(num_harts=2)
        dbg._hart_id = 1
        assert dbg.hart is emu.harts[1]


class TestShowTrapContext:
    def test_exception_is_labelled(self):
        dbg, emu, buf = make_test_dbg_buffered()
        hart = emu.harts[0]
        hart.csrs["mcause"].val = 2
        hart.csrs["mepc"].val = 0x1000
        hart.csrs["mtval"].val = 0xB622
        dbg._show_trap_context(hart)
        text = buf.getvalue()
        assert "异常" in text
        assert "IllInstr" in text

    def test_interrupt_is_labelled(self):
        dbg, emu, buf = make_test_dbg_buffered()
        hart = emu.harts[0]
        hart.csrs["mcause"].val = (1 << 63) | 7
        dbg._show_trap_context(hart)
        text = buf.getvalue()
        assert "中断" in text
        assert trap_cause_name((1 << 63) | 7) in text


class TestBuildCompleter:
    def test_words_cover_commands_and_registers(self):
        dbg, _, _ = make_test_dbg_buffered()
        words = set(dbg._build_completer().words)
        assert {"step", "continue", "disasm", "quit"} <= words
        assert {"sp", "mstatus", "satp", "ft0"} <= words
        assert "list" in words


# ============================================================
#  REPL 主循环
# ============================================================


class _ScriptedSession:
    """按脚本返回输入的 PromptSession 替身.

    ``DispatchOps.repl`` 传给 ``prompt`` 的是 (样式, 文本) 二元组的列表,
    此处原样记录, 使提示符的内容可被断言.
    """

    def __init__(self, items: list) -> None:
        self._items = list(items)
        self.prompts: list = []

    def prompt(self, prompt) -> str:
        self.prompts.append(prompt)
        item = self._items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _ending_dispatch(stop: str = "quit", log: list | None = None):
    """返回在 ``stop`` 上结束循环的分发替身, 并把每次参数追加到 ``log``."""

    def dispatch(parts: list) -> bool:
        if log is not None:
            log.append(parts)
        return parts[0] != stop

    return dispatch


def _prepare_repl(dbg, items, monkeypatch, dispatch=None, signals=None):
    """装好提示符输入、分发与信号注册的替身, 返回脚本化的会话对象."""
    session = _ScriptedSession(items)
    monkeypatch.setattr(dbg, "_enter_repl_mode", _Recorder())
    monkeypatch.setattr(dbg, "_session", session)
    monkeypatch.setattr(dbg, "_dispatch", dispatch or _Recorder(ret=True))
    monkeypatch.setattr(signal, "signal", signals or _Recorder())
    return session


class TestRepl:
    def test_banner_reports_harts_and_fdt(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        dbg._fdt_addr = 0x800F0000
        _prepare_repl(dbg, [EOFError()], monkeypatch)
        dbg.repl()
        text = buf.getvalue()
        assert "RISC-V Interactive Debugger" in text
        assert "Harts: 1" in text
        assert "Active Hart(s): 0" in text
        assert "0x800f0000" in text

    def test_banner_marks_missing_fdt(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        _prepare_repl(dbg, [EOFError()], monkeypatch)
        dbg.repl()
        assert "FDT: —" in buf.getvalue()

    def test_prompt_carries_hart_number(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        session = _prepare_repl(dbg, [EOFError()], monkeypatch)
        dbg.repl()
        assert session.prompts[0][-1] == ("class:prompt", "rvdbg[0] ")

    def test_eof_prints_exit_and_footer(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        _prepare_repl(dbg, [EOFError()], monkeypatch)
        dbg.repl()
        text = buf.getvalue()
        assert "退出" in text
        assert "调试器已退出" in text

    def test_oserror_prints_disconnect_message(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        _prepare_repl(dbg, [OSError("终端已关闭")], monkeypatch)
        dbg.repl()
        assert "终端断开, 退出" in buf.getvalue()

    def test_keyboard_interrupt_at_prompt_continues(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        log: list = []
        session = _prepare_repl(
            dbg,
            [KeyboardInterrupt(), "quit"],
            monkeypatch,
            _ending_dispatch(log=log),
        )
        dbg.repl()
        assert len(session.prompts) == 2
        assert log == [["quit"]]
        assert "Traceback" not in buf.getvalue()

    def test_leading_empty_input_is_ignored(self, monkeypatch):
        """首条输入为空时不执行任何命令."""
        dbg, _, buf = make_test_dbg_buffered()
        log: list = []
        _prepare_repl(
            dbg, ["", "status", "quit"], monkeypatch, _ending_dispatch(log=log)
        )
        dbg.repl()
        assert log == [["status"], ["quit"]]
        assert dbg._last_command == "status"

    def test_whitespace_only_input_is_ignored(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        log: list = []
        _prepare_repl(
            dbg,
            ["   ", "  status  ", "quit"],
            monkeypatch,
            _ending_dispatch(log=log),
        )
        dbg.repl()
        assert log == [["status"], ["quit"]]

    def test_empty_input_repeats_last_command(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        log: list = []
        _prepare_repl(
            dbg, ["status", "", "quit"], monkeypatch, _ending_dispatch(log=log)
        )
        dbg.repl()
        assert log == [["status"], ["status"], ["quit"]]

    def test_empty_input_repeats_disasm_with_next_address(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        dbg._last_command = "disasm 0x1000"
        dbg._disasm_next_addr = 0x1004
        log: list = []
        _prepare_repl(dbg, ["", "quit"], monkeypatch, _ending_dispatch(log=log))
        dbg.repl()
        assert log == [["disasm", "0x1004"], ["quit"]]

    def test_empty_input_repeats_vdisasm_with_next_address(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        dbg._last_command = "vdisasm 0x1000"
        dbg._vdisasm_next_addr = 0x1008
        log: list = []
        _prepare_repl(dbg, ["", "quit"], monkeypatch, _ending_dispatch(log=log))
        dbg.repl()
        assert log == [["vdisasm", "0x1008"], ["quit"]]

    def test_empty_input_without_next_address_keeps_command(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        dbg._last_command = "disasm 0x1000"
        log: list = []
        _prepare_repl(dbg, ["", "quit"], monkeypatch, _ending_dispatch(log=log))
        dbg.repl()
        assert log == [["disasm", "0x1000"], ["quit"]]

    def test_command_failure_prints_traceback_and_keeps_loop(self, monkeypatch):
        dbg, _, buf = make_test_dbg_buffered()
        log: list = []

        def dispatch(parts: list) -> bool:
            log.append(parts)
            if parts[0] == "status":
                raise RuntimeError("命令执行失败")
            return False

        _prepare_repl(dbg, ["status", "quit"], monkeypatch, dispatch)
        dbg.repl()
        text = buf.getvalue()
        assert "命令执行失败" in text
        assert "RuntimeError" in text
        assert log == [["status"], ["quit"]]
        assert dbg._last_command is None

    def test_failed_command_does_not_overwrite_last_command(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()

        def dispatch(parts: list) -> bool:
            if parts[0] == "bad":
                raise RuntimeError("命令执行失败")
            return parts[0] != "quit"

        _prepare_repl(dbg, ["status", "bad", "quit"], monkeypatch, dispatch)
        dbg.repl()
        assert dbg._last_command == "status"

    def test_sigint_handler_is_restored_after_exit(self, monkeypatch):
        dbg, _, _ = make_test_dbg_buffered()
        signals = _Recorder()
        _prepare_repl(dbg, [EOFError()], monkeypatch, signals=signals)
        dbg.repl()
        assert signals.last[0] == (signal.SIGINT, signal.SIG_DFL)


# ============================================================
#  命令历史文件
# ============================================================


class TestHistoryFilePath:
    def test_unconfigured_path_falls_back_to_home(self, monkeypatch):
        monkeypatch.setattr(base, "cfg_str", lambda name: "")
        assert base.history_file_path() == Path.home() / ".pyremu_history"

    def test_environment_path_is_expanded(self, monkeypatch):
        monkeypatch.setenv("PYREMU_HISTORY_FILE", "~/logs/hist")
        assert base.history_file_path() == Path.home() / "logs" / "hist"

    def test_absolute_path_is_used_as_given(self, monkeypatch):
        monkeypatch.setenv("PYREMU_HISTORY_FILE", "/var/tmp/pyremu_history")
        assert base.history_file_path() == Path("/var/tmp/pyremu_history")


class TestDebuggerInit:
    """调试器初始化."""

    def test_default_hart_id(self):
        emu = make_test_emu(num_harts=2, prog_cnt=0x1000)
        dbg = Debugger(emulator=emu)
        assert dbg._hart_id == 0

    def test_explicit_hart_id(self):
        emu = make_test_emu(num_harts=4, prog_cnt=0x1000)
        dbg = Debugger(emulator=emu, hart_id=2)
        assert dbg._hart_id == 2

    def test_hart_property(self):
        emu = make_test_emu(num_harts=3, prog_cnt=0x1000)
        dbg = Debugger(emulator=emu, hart_id=1)
        assert dbg.hart is emu.harts[1]

    def test_with_image(self):
        emu = make_test_emu(prog_cnt=0x1000)
        img = make_test_image()
        dbg = Debugger(emulator=emu, hart_id=0, image=img)
        assert dbg._image is img

    def test_build_completer_includes_commands_and_regs(self):
        dbg = make_test_dbg()
        c = dbg._build_completer()
        # WordCompleter.words 是 Sequence[str] | (() -> Sequence[str]) 联合类型
        words = c.words() if callable(c.words) else c.words
        # 包含命令
        for cmd in ["step", "continue", "regs", "pc", "quit", "help"]:
            assert cmd in words, f"缺少命令: {cmd}"
        # 包含 GPR ABI 名称
        for abi in ["zero", "ra", "sp", "t0", "a0", "s0"]:
            assert abi in words, f"缺少 GPR: {abi}"
        # 包含 CSR 名称
        for csr in ["mstatus", "mtvec", "mepc", "mcause"]:
            assert csr in words, f"缺少 CSR: {csr}"


class TestDebuggerHelpers:
    """辅助方法."""

    @pytest.mark.parametrize(
        "v, expected",
        [
            (0, "0x0000000000000000"),
            (0xDEADBEEF, "0x00000000deadbeef"),
            (0xFFFFFFFFFFFFFFFF, "0xffffffffffffffff"),
            (-1, "0xffffffffffffffff"),  # 负值被掩码为 64-bit
        ],
    )
    def test_hex(self, v, expected):
        assert Debugger._hex(v) == expected

    @pytest.mark.parametrize(
        "n, expected",
        [
            (0, "0 B"),
            (512, "512.000 B"),
            (1024, "1.000 KB"),
            (1536, "1.500 KB"),
            (1048576, "1.000 MB"),
            (1073741824, "1.000 GB"),
            (1099511627776, "1.000 TB"),
            (1125899906842624, "1.000 PB"),
            # 超出最大单位: 落到 EB, 不退回 B
            (2**70 * 12, "12288.000 EB"),  # 12 ZB -> 最远单位 EB
        ],
    )
    def test_fmt_size(self, n, expected):
        assert Debugger._fmt_size(n) == expected

    def test_trap_cause_name(self):
        dbg = make_test_dbg()
        # mcause=3 应为断点异常
        name = dbg._trap_cause_name(3)
        assert "breakpoint" in name.lower() or "Breakpoint" in name

    def test_trap_cause_name_interrupt(self):
        dbg = make_test_dbg()
        # MSI: bit63=1, code=3
        irq_mcause = (1 << 63) | 3
        name = dbg._trap_cause_name(irq_mcause)
        assert name == "MmodeSoftInterrupt"

    def test_warn_prints(self, capsys):
        dbg = make_test_dbg()
        dbg._warn("test warning")
        # Rich 输出到 stderr, 我们只验证不抛异常

    def test_err_prints(self, capsys):
        dbg = make_test_dbg()
        dbg._err("test error")


class TestPostPowerRequest:
    """关机与复位请求置位后的命令行为."""

    def test_cmd_step_reports_and_skips(self):
        """单步不执行指令, 并报告关机请求."""
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=TEST_PROG_PA, is_code_loaded=False
        )
        emu.load_code(TEST_PROG_PA, b"\x13\x00\x00\x00" * 2)
        emu.bus.write(POWER_BASE, (0x5555).to_bytes(4, "little"))
        dbg.cmd_step(1)
        assert dbg.hart.pc == TEST_PROG_PA
        assert "关机" in buf.getvalue()

    def test_cmd_run_reports_and_skips(self):
        """按周期执行不推进 PC, 并报告关机请求."""
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=TEST_PROG_PA, is_code_loaded=False
        )
        emu.load_code(TEST_PROG_PA, b"\x13\x00\x00\x00" * 2)
        emu.bus.write(POWER_BASE, (0x5555).to_bytes(4, "little"))
        dbg.cmd_run(2)
        assert dbg.hart.pc == TEST_PROG_PA
        assert "关机" in buf.getvalue()

    def test_status_overview_shows_off(self):
        """概览的 State 列为 off."""
        dbg, emu, buf = make_test_dbg_buffered(num_harts=2)
        emu.bus.write(POWER_BASE, (0x7777).to_bytes(4, "little"))
        dbg.cmd_status()
        assert "off" in buf.getvalue()

    def test_status_detail_reports_request(self):
        """详情标题给出复位请求."""
        dbg, emu, buf = make_test_dbg_buffered()
        emu.bus.write(POWER_BASE, (0x7777).to_bytes(4, "little"))
        dbg.cmd_status("0")
        assert "复位" in buf.getvalue()


class TestPrivilegeBoundary:
    """特权级边界帧解析."""

    def test_resolve_mmode_frame(self):
        """_resolve_boundary_frame 对 M 模式返回 M."""
        dbg = make_test_dbg()
        boundary = dbg._resolve_boundary_frame(0x80000000, "M")
        assert boundary is not None
        assert boundary[0] == "M"  # (label, boundary_mode)

    def test_is_valid_mmode_code_true(self):
        """M 模式代码段判断 (需要 _image 中 .text 段名)."""
        dbg = make_test_dbg()
        # 注入 image 使 _is_valid_mmode_code 能检查段名
        img = make_test_image()
        img.segments = [
            FirmwareSegment(
                vaddr=0x80000000,
                memsz=0x10000,
                data=b"\x00" * 0x10000,
                name=".text",
            )
        ]
        dbg._image = img
        assert dbg._is_valid_mmode_code(0x80000000) is True

    def test_is_valid_mmode_code_false(self):
        """非 M 模式代码段判断."""
        dbg = make_test_dbg()
        # 任意地址不在 RAM 内
        assert dbg._is_valid_mmode_code(0x1000) is False


@pytest.mark.parametrize(
    "val, expected_str",
    [
        (0, "0.000"),
        (99, "99.000"),
        (999, "999.000"),
        (1000, "1.000K"),
        (500000, "500.000K"),
        (999999, "999.999K"),
        (1_000_000, "1.000M"),
        (1_999_000, "1.999M"),
        (1_999_400, "1.999M"),
        (1_999_500, "2.000M"),
        (1_999_999, "2.000M"),
        (500_000_000, "500.000M"),
        (1_000_000_000, "1.000B"),
    ],
)
def test_fmt_instr_cnt(val: int, expected_str: str):
    assert Debugger._fmt_instr_count(val) == expected_str
