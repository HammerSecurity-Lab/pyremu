#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Terminal I/O 后台线程.

独立于 CPU 模拟单轮加速执行循环, 以 Rust 后台线程持续把 stdin 转发到 RX 环形缓冲
并把 TX 环形缓冲转发到 stdout。:

- **单一所有者**: 线程运行期间, Rust 线程是唯一的控制台写者, 对照
  ``fd_chr_write`` 是唯一 TX 出口。UART 行缓冲仅归档 hart 日志文件,
  控制台回显经 ``UART.set_console_echo(False)`` 关闭,
  使 stdout 只由 Rust 线程写。
- **单写者索引**: ``tx_drain`` 由 Rust 线程独占; Python 日志消费者维护
  独立的 ``_tx_log_rd``; ``rx_wr`` 由 Rust 写, ``rx_rd`` 由 Python 写,
  该索引发布消费进度供 Rust 做容量控制 — 缓冲满时 Rust 停止读取 stdin。
- **终端属性**: Rust 侧保存/设置/恢复 termios 与 fcntl 阻塞标志, 对照
  term_init/term_exit, Ctrl+Z 挂起恢复经 SIGCONT handler 重设 raw。

libtermio.so 不可用时降级为 Python ``select`` 轮询线程, 此时不设终端属性,
cbreak 由 Debugger 负责。

Usage:
    term = TerminalIO(uart, wake_event, stdio_fds=(stdin_fd, stdout_fd))
    native = term.start()  # True: Rust 线程接管终端; False: Python 回退
    # 把 RX 环形缓冲的字节写入 UART RX buffer, 每单轮加速执行前调用
    term.drain_rx()
    # 把 TX 环形缓冲的条目写入 UART 行缓冲/日志, 每单轮加速执行后调用
    term.drain_tx_logs()
    term.stop()            # 停止线程 + 恢复终端 + 读出残留数据
"""

from __future__ import annotations

import atexit
import ctypes
import fcntl
import os
import select
import threading
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from pyremu.peripheral.uart import UART

from pyremu._native import (
    termio_attach,
    termio_available,
    termio_is_running,
    termio_stop,
    TermIoHandle,
)
from pyremu.utils.mask import mask32

# 宿主终端的按键编码到受调试程序终端编码的对照, 与 Rust 侧 translate_key
# 的对照一致. 受调试程序终端取 xterm 系列, 其 terminfo 的 khome 与 kend 为
# ESC O H 与 ESC O F; Ctrl 加左右键取行编辑器中按词移动的序列, Ctrl 加上下键
# 去掉修饰键, 与上键和下键相同.
_HOST_KEY_TO_GUEST: dict[bytes, bytes] = {
    b"\x1b[H": b"\x1bOH",
    b"\x1b[1~": b"\x1bOH",
    b"\x1b[7~": b"\x1bOH",
    b"\x1b[F": b"\x1bOF",
    b"\x1b[4~": b"\x1bOF",
    b"\x1b[8~": b"\x1bOF",
    b"\x1b[1;5C": b"\x1bf",
    b"\x1b[5C": b"\x1bf",
    b"\x1bOc": b"\x1bf",
    b"\x1b[1;5D": b"\x1bb",
    b"\x1b[5D": b"\x1bb",
    b"\x1bOd": b"\x1bb",
    b"\x1b[1;5A": b"\x1bOA",
    b"\x1b[5A": b"\x1bOA",
    b"\x1b[1;5B": b"\x1bOB",
    b"\x1b[5B": b"\x1bOB",
}


def translate_host_keys(data: bytes) -> bytes:
    """把宿主终端的按键编码改写为受调试程序终端使用的编码.

    未列入对照的字节原样保留. 一个按键的编码若被拆分到两次读取中, 两段都不
    匹配对照, 原样转发.
    """
    if b"\x1b" not in data:
        return data
    out = bytearray()
    idx = 0
    while idx < len(data):
        if data[idx] == 0x1B:
            for seq, repl in _HOST_KEY_TO_GUEST.items():
                if data.startswith(seq, idx):
                    out += repl
                    idx += len(seq)
                    break
            else:
                out.append(data[idx])
                idx += 1
            continue
        out.append(data[idx])
        idx += 1
    return bytes(out)


class TerminalIO:
    """终端 I/O 管理器 — 封装 Rust 后台线程的启动/停止与环形缓冲区数据的读出.

    设计为 UART 外设的可选组件, 由 Emulator 在初始化时创建并注入。
    Debugger 在运行/REPL 模式切换时通过 Emulator 引用调用 start/stop。
    """

    # 环形缓冲容量必须为 2 的幂: 索引按 u32 单调环绕, 槽位 = 索引 % 容量,
    # 容量需整除 2^32, 否则索引跨 u32 环绕时槽位错位。
    RX_CAP = 0x10000  # 64 KiB — 容纳批量粘贴/快速输入突发
    TX_CAP = 0x40000  # 256 KiB 字节容量 (条目容量 = TX_CAP // 2)

    def __init__(
        self,
        uart: UART,
        wake_event: threading.Event,
        stdio_fds: tuple[int, int] = (0, 1),
        ext_irq: Any = None,
        on_irq: Callable[[int, bool], None] | None = None,
    ) -> None:
        """stdio_fds 为 (stdin 文件描述符, stdout 文件描述符)."""
        self._uart = uart
        self._wake_event = wake_event
        self._stdin_fd, self._stdout_fd = stdio_fds
        self._ext_irq = ext_irq  # FfiExtIrqCtx or None
        # 设备中断注入回调 (``DeviceIrqSink``): 同步 PLIC 挂起状态并写穿
        # 持久数组, 使 batch 内 Rust 内联仲裁能立即看到新到达的 UART 数据。
        # 为 None 时退化为仅置 ext_irq 通知位, 供独立使用场景。
        self._on_irq = on_irq

        # 发送环形缓冲区 — CPU hart 线程写入受调试程序的 TXDATA 时使用,
        # 每个条目为 [hart_id, byte]; Rust termio 线程经 tx_drain 读出后写入
        # stdout, Python 经 _tx_log_rd 归档日志。
        self._tx_buf = (ctypes.c_uint8 * self.TX_CAP)()
        # 写索引, 由 CPU 引擎独占, 按 u32 单调递增
        self._tx_wr = ctypes.c_uint32(0)
        self._tx_drain = ctypes.c_uint32(0)  # 读出索引, 由 Rust termio 线程独占
        self._tx_log_rd: int = 0  # 日志消费者读索引, 由 Python 独占

        # 接收环形缓冲区 — Rust termio 线程读取 stdin 后写入,
        # Python drain_rx 读出。
        self._rx_buf = (ctypes.c_uint8 * self.RX_CAP)()
        self._rx_wr = ctypes.c_uint32(0)  # 写索引, 由 Rust termio 线程独占
        # 读索引, 由 Python 独占, Rust 读取该索引做容量控制
        self._rx_rd = ctypes.c_uint32(0)
        # drain_rx 由 RX daemon 线程与主线程 (_feed_uart_stdin) 并发调用,
        # 串行化读-改-写 _rx_rd 以免两个消费者读到同一 rd 值
        # 重复 preload 同批字节.
        self._rx_drain_lock = threading.Lock()

        # 共享停止标志 — Python 置 1 后 Rust 线程退出
        self._stop_flag = ctypes.c_uint8(0)
        self._pause_flag = ctypes.c_uint8(0)  # 调试器暂停/恢复
        # TermIO daemon 写 ring buffer 后置 1
        self._rx_notify = ctypes.c_uint8(0)

        # 运行状态
        self._native_active = False  # Rust 线程是否接管了终端
        self._atexit_registered = False

        # 缺乏libtermio.so时使用Python 轮询
        self._fallback_thread: threading.Thread | None = None
        self._fallback_running = False

        # 三对管道: tx_notify, rx_notify, rx_drain.
        self._create_pipes()
        self._tx_drain_lock = threading.Lock()
        self._tx_drain_running = False
        self._tx_drain_thread: threading.Thread | None = None

        # TX 归档 daemon — 异步将 ring buffer 写入 hart 日志,
        # 与单轮加速执行循环解耦
        self._tx_archive_running = False
        self._tx_archive_thread: threading.Thread | None = None

        # RX daemon — 独立线程持续把 ring buffer 的字节写入 UART FIFO,
        # 与指令执行完全解耦
        self._rx_daemon_running = False
        self._rx_daemon_thread: threading.Thread | None = None

    @property
    def tx_notify_w(self) -> int:
        """TX 通知管道写端 fd, 传给 Rust 的 UartInfo.tx_notify_fd.

        注意: Rust CPU 引擎实际从不写此 fd, 它在 state.rs 中恒为 -1, 通知仅保留
        接口形态; 后台线程在 poll 超时后无条件读出一次, 详见 _tx_archive_loop.
        """
        return self._tx_notify_w

    # ----------------------------------------------------------
    #  公开接口
    # ----------------------------------------------------------

    @property
    def tx_buf(self):
        """TX 环形缓冲区 ."""
        return self._tx_buf

    @property
    def tx_wr(self):
        """TX 写索引 ctypes 对象 ."""
        return self._tx_wr

    @property
    def rx_notify(self):
        """接收通知标志 ctypes 对象 ."""
        return self._rx_notify

    @property
    def tx_drain(self):
        """TX 读出索引 ctypes 对象, 由 Rust termio 线程独占写, Python 只读."""
        return self._tx_drain

    @property
    def tx_log_rd(self) -> int:
        """日志消费者的独立读索引."""
        return self._tx_log_rd

    @property
    def native_active(self) -> bool:
        """Rust termio 线程是否正在运行并接管终端."""
        return self._native_active

    def start(self) -> bool:
        """启动后台 I/O 线程.

        Returns:
            True — Rust native 线程接管终端;
            False — 回退到 Python 轮询线程。
        """
        if self._is_running():
            return self._native_active

        # 必须先重建管道, 否则 daemon 线程在 poll.register(-1) 抛未捕获异常.
        if self._tx_notify_r < 0:
            self._create_pipes()

        # 受调试程序从 RXDATA 读出字节后由 UART 回调 drain_rx, 就地写入接收环形
        # 缓冲区中剩余的字节, 不必等守护线程被唤醒或超时.
        if self._uart is not None:
            self._uart.set_rx_room_notifier(self.drain_rx)

        self._stop_flag.value = 0
        self._pause_flag.value = 0
        if termio_available() and termio_attach(self._build_handle()) == 0:
            self._native_active = True
            self._uart.set_console_echo(False)
            if not self._atexit_registered:
                # 进程异常退出时恢复终端
                atexit.register(self.stop)
                self._atexit_registered = True
            self.start_tx_archive_thread()
            self.start_rx_daemon()
            return True

        self._start_fallback()
        return False

    def stop(self) -> None:
        """停止后台 I/O 线程, 恢复终端属性, 读出残留数据.

        顺序敏感: Rust 线程退出前会最终把 TX 条目读出并写入 stdout,
        此时 tx_drain 追平 tx_wr, 故残留条目须先以"回显关闭"状态归档日志
        以免重复输出, 最后才把控制台回显交还给 Python 行缓冲。
        """
        # 先解除 UART 的槽位通知回调 — 停止受理新的 stdin 数据
        if self._uart is not None:
            self._uart.set_rx_room_notifier(None)
        # 再停 RX daemon
        self.stop_rx_daemon()
        # 再停归档 daemon — 线程退出后最后一次读出由 stop_tx_archive_thread 完成
        self.stop_tx_archive_thread()

        if termio_is_running():
            self._stop_flag.value = 1
            self._wake_event.set()
            # 唤醒阻塞在 poll(-1) 的 Rust 线程, 使其看到 stop_flag 退出 —
            # 修复 join 挂起 (线程仅在 drain 管道或 stdin 可读时从 poll 返回).
            self._notify_rx_drained()
            termio_stop()
        elif self._fallback_running:
            self._fallback_running = False
            if self._fallback_thread is not None:
                self._fallback_thread.join(timeout=1.0)
                self._fallback_thread = None

        # 读出 RX 与 TX 日志中尚未处理的数据
        self.drain_rx()
        if self._native_active:
            # native 模式: CPU 引擎内联 try_write_fd 已即时输出 stdout, ring
            # 仅作 hart 日志归档 — 这里只归档不回显, 否则 REPL 返回时会把这
            # 一段 ring 积压重放到控制台 (与键盘输入唤醒重放同一缺陷).
            self.drain_tx_logs_archive_only()
        else:
            self.drain_tx_logs()
        if self._native_active:
            self._native_active = False
            self._uart.set_console_echo(True)
        # 显式关闭全部管道 fd — 否则每实例泄漏 6 个 fd (3 pipe × 2 端),
        # 长进程/测试套件中积累到 3k+ fd, 触发 select() fd>=1024 上限.
        self._close_pipes()

    def _close_pipes(self) -> None:
        """关闭 __init__ 中创建的全部管道 fd.

        关闭后对应属性置 -1, 故 __del__ 再次调用时不再重复关闭.
        Rust 线程持有的 fd 副本在 termio_stop() 已先行终止,
        关闭 Python 侧 fd 不会影响已退出线程.
        """
        for name in (
            "_tx_notify_r",
            "_tx_notify_w",
            "_rx_notify_r",
            "_rx_notify_w",
            "_rx_drain_r",
            "_rx_drain_w",
        ):
            fd = getattr(self, name, -1)
            if fd < 0:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
            setattr(self, name, -1)

    def _create_pipes(self) -> None:
        """创建三对管道, 写端设为非阻塞.

        ``stop()`` 关闭管道时会把 fd 属性置为 -1。调试器在 REPL 与运行模式之间
        往返切换, 会反复调用 ``start()`` 和 ``stop()``; 第二次 ``start()``
        必须先重建管道, 否则 daemon 线程拿到 -1, 在 ``poll.register(-1)`` 处
        抛未捕获的 ValueError。
        """
        self._tx_notify_r, self._tx_notify_w = os.pipe()
        # 写端非阻塞: 管道满时 Rust 不卡死, 通知丢失可接受
        fl_w = fcntl.fcntl(self._tx_notify_w, fcntl.F_GETFL)
        fcntl.fcntl(self._tx_notify_w, fcntl.F_SETFL, fl_w | os.O_NONBLOCK)
        # 读端阻塞: daemon 线程 select/poll 等待

        self._rx_notify_r, self._rx_notify_w = os.pipe()
        fl_rx = fcntl.fcntl(self._rx_notify_w, fcntl.F_GETFL)
        fcntl.fcntl(self._rx_notify_w, fcntl.F_SETFL, fl_rx | os.O_NONBLOCK)

        self._rx_drain_r, self._rx_drain_w = os.pipe()
        fl_dr = fcntl.fcntl(self._rx_drain_w, fcntl.F_GETFL)
        fcntl.fcntl(self._rx_drain_w, fcntl.F_SETFL, fl_dr | os.O_NONBLOCK)

    def __del__(self) -> None:
        """对象回收时释放 fd: 未显式 stop() 的实例也在此关闭管道,
        避免测试或长进程泄漏 fd."""
        try:
            self._close_pipes()
        except Exception:
            pass

    def pause(self) -> None:
        """暂停 I/O 线程 (调试器断点)."""
        if self._native_active:
            self._pause_flag.value = 1

    def resume(self) -> None:
        """恢复 I/O 线程."""
        self._pause_flag.value = 0

    def _notify_rx_drained(self) -> None:
        """向管道写端写 1 字节, 唤醒 Rust termio 线程.

        用于两种场景: (1) drain_rx 消费了 ring buffer 后, 让 Rust
        投递 recv 中剩余字节; (2) stop 时唤醒阻塞在 poll(-1) 的线程使其看到
        stop_flag 退出, 修复 join 挂起。写端非阻塞, 满则通知丢失可接受。
        """
        try:
            os.write(self._rx_drain_w, b"\x01")
        except OSError:
            pass

    def drain_rx(self) -> bool:
        """将 Rust 线程写入的 RX 环形缓冲数据转移到 Python UART 模型.
        - 先查 ``uart.can_rx()``
        - 逐字节 preload, 每字节检查 can_rx; FIFO 满即停止
        - 未被消费的字节保留在 ring buffer 中,
          且因 rx_rd 未更新, Rust 端 ``free = cap - (wr - rd)`` 变小
          ->termio 线程自然容量控制停止读 stdin

        Returns:
            True 若有新数据被 preload.
        """
        with self._rx_drain_lock:
            return self._drain_rx_locked()

    def _drain_rx_locked(self) -> bool:
        """drain_rx 的锁内实现."""
        if self._uart is None:
            return False
        if not self._uart.can_rx():
            return False
        wr = self._rx_wr.value
        rd = self._rx_rd.value
        if wr == rd:
            return False
        pending = mask32(wr - rd)
        cap = self.RX_CAP
        had_input = False
        drained = 0
        # 只消费 UART FIFO 能接受的数量; 剩余留在环形缓冲区等下次读出
        for _ in range(pending):
            if not self._uart.can_rx():
                break
            b = self._rx_buf[rd % cap]
            rd = mask32(rd + 1)
            self._uart.preload(bytes([b]))
            drained += 1
            had_input = True
        self._rx_rd.value = rd  # 发布消费进度, Rust 据此做容量控制
        if drained > 0:
            self._notify_rx_drained()  # 唤醒 Rust 继续投递剩余字节, 解除反压
        if had_input:
            if self._on_irq is not None and self._uart._irq > 0:
                self._on_irq(self._uart._irq, self._uart.irq_asserted())
            elif self._ext_irq is not None:
                self._ext_irq.pending = 1  # 通知 CPU 引擎内联投递 SEIP/MEIP
            self._wake_event.set()
        return had_input

    def drain_rx_feed_uart(self) -> bool:
        """读出 RX ring buffer 并写入 UART FIFO, 同时安全清零 _rx_notify 通知位.

        在 ``drain_rx()`` 的基础上补充 ``_rx_notify`` 的清零: 该位由 Rust
        termio 线程在写入 ring buffer 后置 1, 需在确认 ring buffer 为空后
        才清零, 清零与判空之间 Rust 可能写入新数据, 必须二次校验
        恢复, 否则 CPU 引擎的快速退出信号丢失.

        供调试器空闲轮询路径调用. 普通 ``drain_rx()``
        不清零通知位 — RX daemon 抢先读出后 CPU 引擎仍需看到通知以触发
        快速单轮加速执行退出.

        Returns:
            True 若有新数据被 preload.
        """
        had_input = self.drain_rx()
        if self._rx_wr.value == self._rx_rd.value:
            self._rx_notify.value = 0
            if self._rx_wr.value != self._rx_rd.value:
                self._rx_notify.value = 1
        return had_input

    def drain_tx_logs(self) -> None:
        """把 CPU 引擎写入 TX 环形缓冲的 (hart, byte) 条目归入 UART 行缓冲.

        本消费者维护独立读索引 ``_tx_log_rd``; 控制台是否回显由
        ``UART._console_echo`` 决定。

        线程安全: 持有 ``_tx_drain_lock``, 允许 TX drain daemon 线程与
        主线程 (``_native_flush_uart``) 并发调用。
        """
        with self._tx_drain_lock:
            self._drain_tx_logs_locked()

    def drain_tx_logs_archive_only(self) -> None:
        """读出 TX ring buffer, 归档 hart 日志并写入 UART 行缓冲.

        用于 Rust libc::write 已即时输出到 stdout 的场景; 此处只保证
        ring buffer 不溢出 + hart 日志完整 + ``tx_data()`` 可读, 不重复
        输出到控制台 (``record_tx_byte`` 仅追加内存缓冲, 不触发回调).
        """
        if self._uart is None:
            return
        with self._tx_drain_lock:
            ecap = self.TX_CAP // 2
            wr = self._tx_wr.value
            pending = mask32(wr - self._tx_log_rd)
            if pending == 0:
                return
            if pending > ecap:
                self._tx_log_rd = mask32(wr - ecap)
                pending = ecap
            rd = self._tx_log_rd
            uart = self._uart
            for _ in range(pending):
                idx = rd % ecap
                hid = self._tx_buf[2 * idx]
                byte = self._tx_buf[2 * idx + 1]
                log_f = uart._hart_log_file(hid)
                if log_f is not None:
                    log_f.write(chr(byte))
                # 回填 UART 行缓冲 (tx_data 调试/测试用) — 不触发 stdout
                uart.record_tx_byte(byte)
                rd = mask32(rd + 1)
            self._tx_log_rd = rd

    def _drain_tx_logs_locked(self) -> None:
        """drain_tx_logs 的锁内实现."""
        if self._uart is None:
            return
        ecap = self.TX_CAP // 2
        wr = self._tx_wr.value
        pending = mask32(wr - self._tx_log_rd)
        if pending == 0:
            return
        if pending > ecap:
            self._tx_log_rd = mask32(wr - ecap)
            pending = ecap
        rd = self._tx_log_rd
        uart = self._uart
        for _ in range(pending):
            idx = rd % ecap
            hid = self._tx_buf[2 * idx]
            byte = self._tx_buf[2 * idx + 1]
            # Hart 日志文件: 直接从 ring buffer 写入, 不经 UART 行缓冲
            log_f = uart._hart_log_file(hid)
            if log_f is not None:
                log_f.write(chr(byte))
            # UART MMIO 写 — 触发 _tx_callback -> 控制台即时输出
            uart.write(0, bytes([byte]))
            rd = mask32(rd + 1)
        self._tx_log_rd = rd

    def start_tx_archive_thread(self) -> None:
        """启动 TX 归档 daemon: 事件驱动地将 ring buffer 写入 hart 日志."""
        if self._tx_archive_running:
            return
        if self._tx_notify_r < 0:
            # 管道已被 stop() 关闭且未重建，抛出 ValueError而不启动.
            return
        self._tx_archive_running = True
        self._tx_archive_thread = threading.Thread(
            target=self._tx_archive_loop,
            daemon=True,
        )
        self._tx_archive_thread.start()

    def stop_tx_archive_thread(self) -> None:
        """停止 TX 归档 daemon, 最终读出残留数据."""
        self._tx_archive_running = False
        if self._tx_archive_thread is not None:
            self._tx_archive_thread.join(timeout=1.0)
            self._tx_archive_thread = None
        self.drain_tx_logs_archive_only()

    def _drain_notify_pipe(self, notify_r: int) -> bool:
        """非阻塞读出通知管道中的积压字节.

        读端默认阻塞, 直接 ``os.read`` 会因管道为空挂起 daemon, 故先切非阻塞.
        返回 ``False`` 表示管道已失效, 调用方应停止
        poll 该 fd; 返回 ``True`` 表示本次排空正常完成, 后续可能还有通知.
        """
        try:
            os.set_blocking(notify_r, False)
            try:
                while True:
                    if os.read(notify_r, 256) == b"":
                        return False  # 写端已关闭 (EOF)
            except BlockingIOError:
                pass
            finally:
                os.set_blocking(notify_r, True)
        except OSError:
            return False
        return True

    def _tx_archive_loop(self) -> None:
        """TX 归档 daemon 入口: 轮询 + 事件驱动将 ring buffer 写入 hart 日志.

        与单轮加速执行循环完全异步。Rust 引擎实际从不写 ``tx_notify_fd``
        , 通知管道永远不会可读 —— 纯事件驱动会导致
        daemon 在 poll 超时后直接落入阻塞 ``os.read`` 而永久挂起, ring buffer
        永不归档。故每次 poll 超时后
        无条件 drain 一次, 通知仅作即时唤醒加速; drain 前先按非阻塞方式清空
        管道, 防止空管道阻塞 daemon 线程。

        等待通知用 ``select.poll`` 而非 ``select.select``: select() 只能 watch
        fd < FD_SETSIZE (1024), 对高位 fd 抛 ``ValueError: filedescriptor out of
        range``, 捕获即 break 会使 daemon 静默死亡。
        长进程/测试套件中 fd 会持续增长。
        """
        notify_r = self._tx_notify_r
        if notify_r < 0:
            return
        poll = select.poll()
        poll.register(notify_r, select.POLLIN)
        while self._tx_archive_running:
            try:
                ready = poll.poll(200)  # 0.2s 轮询周期 (毫秒)
            except ValueError, OSError:
                break
            if not self._tx_archive_running:
                break
            if ready:
                # 通知仅作即时唤醒; 归档不依赖它,
                # 管道失效的返回值得忽略.
                self._drain_notify_pipe(notify_r)
            # 无条件轮询归档 — Rust 不写通知管道, 必须靠 0.2s 周期追上.
            self.drain_tx_logs_archive_only()

    # ----------------------------------------------------------
    #  TX 即时读出 daemon 线程
    # ----------------------------------------------------------

    def start_tx_drain_thread(self) -> None:
        if self._tx_drain_running or self._tx_notify_r < 0:
            # 管道已被 stop() 关闭且未重建: 线程启动即抛 ValueError, 不启动.
            return
        self._tx_drain_running = True
        self._tx_drain_thread = threading.Thread(
            target=self._tx_drain_loop,
            daemon=True,
        )
        self._tx_drain_thread.start()

    def stop_tx_drain_thread(self) -> None:
        """停止 TX drain daemon 线程, 并最终读出残留数据."""
        self._tx_drain_running = False
        if self._tx_drain_thread is not None:
            self._tx_drain_thread.join(timeout=1.0)
            self._tx_drain_thread = None
        self.drain_tx_logs()

    def _tx_drain_loop(self) -> None:
        """TX drain daemon 线程入口: 阻塞等待 Rust 通知 -> 排空 ring buffer.

        Rust 每写一个 TX 字节后写 1 字节到 _tx_notify_w -> poll 唤醒 ->
        drain_tx_logs() 走完整 UART 回调链 -> TermProxy writer -> stdout.
        零轮询, 完全事件驱动. 等待通知用 poll.
        """
        notify_r = self._tx_notify_r
        if notify_r < 0:
            # 管道已被 stop() 关闭, 无法 poll
            return
        poll = select.poll()
        poll.register(notify_r, select.POLLIN)
        while self._tx_drain_running:
            try:
                # 阻塞等待通知, 无 fd 上限. 返回值不查: timeout=-1 时 poll
                # 只会因注册 fd 就绪/POLLHUP 返回, 不会返回空列表; 就绪后
                # 无论事件类型一律走下方排空.
                poll.poll(-1)
            except ValueError, OSError:
                break
            if not self._tx_drain_running or not self._drain_notify_pipe(
                notify_r
            ):
                # 写端已关闭, 退出线程, 避免无限忙转
                break
            # 排空 ring buffer -> UART 回调 -> TermProxy -> stdout
            self.drain_tx_logs()

    # ----------------------------------------------------------
    #  RX daemon — 独立线程, 与指令执行完全解耦
    # ----------------------------------------------------------

    def start_rx_daemon(self) -> None:
        """启动接收守护线程: 持续把接收环形缓冲区的字节写入 UART FIFO.

        Rust termio 线程写 stdin 到接收环形缓冲区后置 _rx_notify=1,
        守护线程检测到后调用 drain_rx() 把字节写入 UART FIFO 并置位中断.
        指令执行循环完全不需要参与数据搬运.
        """
        if (
            self._rx_daemon_running
            or self._stdin_fd < 0
            or self._rx_notify_r < 0
        ):
            # 测试环境下给出的是占位文件描述符, 或管道已被 stop() 关闭且未重建:
            # 无法 poll
            return
        self._rx_daemon_running = True
        self._rx_daemon_thread = threading.Thread(
            target=self._rx_daemon_loop,
            daemon=True,
        )
        self._rx_daemon_thread.start()

    def stop_rx_daemon(self) -> None:
        """停止接收守护线程, 最后排空一次剩余的字节."""
        self._rx_daemon_running = False
        if self._rx_daemon_thread:
            self._rx_daemon_thread.join(timeout=1.0)
            self._rx_daemon_thread = None
        self.drain_rx()

    def _rx_daemon_tick(
        self,
        notify_r: int,
        poll: select.poll,
        timeout_ms: int = 500,
    ) -> bool:
        """单次接收守护线程迭代: 等待通知 (最多 timeout_ms), 随后写入 UART FIFO.

        写入在每次迭代都执行, 通知只用来缩短等待:
        - 通知到达时 poll 立即返回, 随后写入, 并置位唤醒事件.
        - 通知字节可能丢失: Rust termio 线程的写端非阻塞, 突发输入时管道已满,
          该次写返回 EAGAIN, 通知未发出; 或守护线程恰好读完管道后新数据在轮询
          间隔内到达, 通知写在 poll 返回之前完成, 字节留在管道中而管道已不可读.
          仅靠通知唤醒会让输入留在接收环形缓冲区, 键入速度较快时回显停滞
          (用户报告). 输入由 poll 超时后的那一次写入 UART FIFO,
          最迟时刻为 timeout_ms.
        - 接收环形缓冲区为空时 drain_rx 不写入任何字节.
        - Rust termio 线程识别 Ctrl+Q 时同样向该管道写 1 字节,
          该路径不向接收环形缓冲区写入, 唤醒事件因此不依赖 drain_rx 的写入结果.

        Args:
            notify_r: 通知管道读端 fd.
            poll: 已注册 notify_r 的 select.poll 实例.
            timeout_ms: 轮询超时, 单位ms。

        Returns:
            False — 通知管道已失效, 调用方应停止 poll 该 fd.
        """
        try:
            ready = poll.poll(timeout_ms)
        except ValueError, OSError:
            return False
        if ready:
            if not self._drain_notify_pipe(notify_r):
                return False  # 管道已失效: 停止 poll 该 fd
            # 通知字节由 Rust termio 线程在写入接收环形缓冲区之后与识别到
            # Ctrl+Q 时写入. 后一种情形不写入环形缓冲区, drain_rx 因而不置位
            # 唤醒事件; 全部 hart 处于 WFI 时引擎不执行指令, 主线程正阻塞在
            # 该事件上, 故在此置位.
            self._wake_event.set()
        # 无论有无通知都写入一次 — 通知字节可能丢失, 写入不依赖它.
        self.drain_rx()
        return True

    def _rx_daemon_loop(self) -> None:
        """接收守护线程入口: 循环调用 _rx_daemon_tick, 直到通知管道失效.

        Rust termio 线程写接收环形缓冲区后向 _rx_notify_w 写 1 字节 -> poll
        立即返回 -> drain_rx() 把字节写入 UART FIFO。突发输入时通知字节可能丢失
        , 故每次 poll 超时后也写入一次, 保证输入
        最迟 0.5s 内写入.
        等待通知用 poll, 不用 select.
        """
        notify_r = self._rx_notify_r
        if notify_r < 0:
            # 管道已被 stop() 关闭, 无法 poll
            return
        poll = select.poll()
        poll.register(notify_r, select.POLLIN)
        while self._rx_daemon_running:
            if not self._rx_daemon_tick(notify_r, poll):
                break

    # ----------------------------------------------------------
    #  Rust native 路径
    # ----------------------------------------------------------

    def _build_handle(self) -> TermIoHandle:
        """构建传给 ``terminal_io_start`` 的 FFI 结构体.

        指针字段指向本实例的 ctypes 缓冲区;
        Rust 侧在调用返回前复制全部字段, 结构体本身无需长期存活。
        """
        h = TermIoHandle()
        h.stdin_fd = self._stdin_fd
        h.stdout_fd = self._stdout_fd
        h.rx_buf = ctypes.addressof(self._rx_buf) or 0
        h.rx_cap = self.RX_CAP  # Rust termio 线程读取 stdin -> ring buffer
        h.rx_wr = ctypes.addressof(self._rx_wr)
        h.rx_rd = ctypes.addressof(self._rx_rd)
        h.tx_buf = ctypes.addressof(self._tx_buf) or 0
        h.tx_cap = self.TX_CAP // 2  # 条目容量 (非字节容量)
        h.tx_wr = ctypes.addressof(self._tx_wr)
        h.tx_drain = ctypes.addressof(self._tx_drain)
        h.stop_flag = ctypes.addressof(self._stop_flag)
        h.pause_flag = ctypes.addressof(self._pause_flag)
        h.rx_notify = ctypes.addressof(self._rx_notify)
        h.rx_notify_fd = self._rx_notify_w
        h.rx_drain_fd = self._rx_drain_r
        return h

    # ----------------------------------------------------------
    #  libtermio.so 不可用时的处理函数
    # ----------------------------------------------------------

    def _preload_stdin_chunk(self) -> bool:
        """从 stdin 读取一块数据并 preload 到 UART RX.

        Returns:
            True 若成功 preload 了数据, False 表示无数据或出错 (需退出轮询).
        """
        try:
            data = os.read(self._stdin_fd, 4096)
        except OSError, ValueError:
            return False
        if not data:
            return False
        self._uart.preload(translate_host_keys(data))
        self._wake_event.set()
        return True

    def _fallback_poll_loop(self) -> None:
        """Python 轮询循环 — daemon thread 入口."""

        stdin_fd = self._stdin_fd
        if stdin_fd < 0:
            return  # stdin 已关闭, 无可轮询的 fd
        poll = select.poll()
        poll.register(stdin_fd, select.POLLIN)
        while self._fallback_running:
            try:
                # 20ms 超时轮询 stdin; poll 无 fd>=1024 上限.
                ready = poll.poll(20)
            except ValueError, OSError:
                break
            if not self._fallback_running:
                break
            if not ready or self._uart is None:
                continue
            self._preload_stdin_chunk()

    def _start_fallback(self) -> None:
        """启动 Python daemon thread 作为回退轮询.

        在 libtermio.so 不可用或 native 启动失败时使用。
        以 20ms 间隔轮询 stdin, 不设置 cbreak 模式
        """
        self._fallback_running = True
        self._fallback_thread = threading.Thread(
            target=self._fallback_poll_loop,
            daemon=True,
        )
        self._fallback_thread.start()

    def _is_running(self) -> bool:
        """检查后台线程是否已运行."""
        if termio_is_running():
            return True
        if self._fallback_running and self._fallback_thread is not None:
            return self._fallback_thread.is_alive()
        return False
