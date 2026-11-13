#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""RunOps — 执行循环、时钟推进与 WFI 休眠.

执行循环使用 Emulator 的装配结果, 并经 NativeOps 调用加速执行引擎.
"""

from enum import IntEnum
import random
import time

from pyremu.configs_aux import cfg_int
from pyremu.configs_gen import CPU_FREQ_HZ
from pyremu.core.mem_check_aux import (
    MemoryAccessError,
)
from pyremu.core.trap_def import TrapType
from pyremu.peripheral.power_ctrl import PowerRequest
from pyremu.utils.mask import mask64
from pyremu.utils.tick import yield_cpu

CYCLES_PER_INSTR = cfg_int("NS_PER_INSTR") * CPU_FREQ_HZ // 1_000_000_000


class RunStopReason(IntEnum):
    """run() 的停止原因, 由边界检查或引擎退出映射写入
    ``Emulator._run_stop_reason``.

    设备暂停事件由外部置位 stop_flag 表示, 不属于本枚举列出的停止: 该标志保留给
    调用方消费, 此时的停止原因为 NONE. 关机与复位请求同样置位该标志, 停止原因
    另行取 ``_power_stop_reason()``.
    """

    NONE = 0  # 设备暂停事件 / 全部 halted / WFI 空闲 / 正常结束
    TIMEOUT = 1  # 时钟源超时 (单轮加速执行边界复核)
    BREAKPOINT = 2  # 断点命中 (引擎 EXIT_BREAKPOINT)
    EBREAK = 3  # 固件执行停机序列 (semihosting SYS_EXIT, 引擎 EXIT_EBREAK)
    SHUTDOWN = 4  # 受调试程序请求关机
    REBOOT = 5  # 受调试程序请求复位


class TimeoutError(RuntimeError):
    """执行超时, 可能是死循环."""

    def __init__(
        self,
        timeout_sec: float,
        cycles: int,
        pc: int | None = None,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.cycles = cycles
        self.pc = pc
        msg = f"模拟器超时 ({timeout_sec:g}s), 已执行 {cycles} 周期"
        if pc is not None:
            msg += f", 最后 PC={pc:#018x}"
        super().__init__(msg)


class RunOps:
    """执行循环、时钟推进与 WFI 休眠."""

    def _advance_mcycle(self) -> None:
        """记录时钟源流逝对应的周期数到 ``_cycle``, 提供 ``run()`` 的返回值与
        ``Emulator.cycle`` 属性.

        该值不写入 mcycle: mcycle 由各 hart 的指令数折算, 见 ``sync_counters``.
        """
        now = time.monotonic()
        elapsed = now - self._last_clock_sync
        self._last_clock_sync = now
        self._cycle += int(elapsed * CPU_FREQ_HZ)

    def _advance_mtime_instr(self, instr_delta: int) -> None:
        """按指令条数推进 mtime, 每条指令计 NS_PER_INSTR=20ns.

        仅纯 Python 的 step 路径使用; 加速执行路径由 Rust 的
        `advance_clock_source` 按同一个 NS_PER_INSTR 换算推进. 换算与时钟源
        流逝的时间无关:

            tick 数 = 指令条数 * timebase_freq * NS_PER_INSTR / 1e9

        divmod 得到的余数留到下次累加, 使 step 路径每次只执行一条指令时,
        不会因整除截断而长期丢失 tick.
        """
        if self.clint is None or instr_delta <= 0:
            return
        total = instr_delta * self._cfg.timebase_freq * cfg_int("NS_PER_INSTR")
        total += self._mtime_instr_frac
        ticks, self._mtime_instr_frac = divmod(total, 1_000_000_000)
        if ticks:
            self.clint.tick(ticks)

    def _watchdog_timeout_ns(self) -> int:
        """剩余时钟源超时时间 (纳秒), 注入 FfiWatchdogCtx; 取 0 表示禁用."""
        if self._timeout_deadline <= 0.0:
            return 0
        remaining = self._timeout_deadline - time.monotonic()
        if remaining <= 0.0:
            return 0
        return int(remaining * 1_000_000_000)

    def _wfi_ticks_until_wake(self, active_harts: list) -> int | None:
        """返回最早到期的定时器中断剩余的 tick 数; 无活跃定时器时返回 None.

        检查 CLINT 的 mtimecmp 与 Sstc 的 stimecmp 两个定时器源, 取最早到期的
        一个. 两者的取值 0 都表示该 hart 未设置定时器.
        """
        if self.clint is None:
            return None
        now = self.clint.get_mtime()
        best = None
        for h in active_harts:
            cmp = self.clint.get_mtimecmp(h.id)
            if cmp > 0 and cmp >= now:
                rem = max(0, cmp - now)
                if best is None or rem < best:
                    best = rem
            sstc = h._csr_read_raw("stimecmp")
            if sstc > 0 and sstc >= now:
                rem = max(0, sstc - now)
                if best is None or rem < best:
                    best = rem
        return best

    def _wfi_wait_bound_sec(self, active: list) -> float | None:
        """返回全部 hart 等待时单次等待的上限 (秒); None 表示不设上限.

        上限取最早到期的定时器与本次连续执行的超时截止时刻中较早的一个. 运行
        超时只在轮次之间检查, 故等待不得超过该截止时刻; 两者都没有时不设上限,
        只由 ``_wake_event`` 唤醒.
        """
        tb = self._cfg.timebase_freq
        bounds: list[float] = []
        ticks = self._wfi_ticks_until_wake(active)
        if ticks is not None and tb:
            bounds.append(ticks / tb)
        if self._timeout_deadline > 0.0:
            bounds.append(max(0.0, self._timeout_deadline - time.monotonic()))
        return min(bounds) if bounds else None

    def _wfi_sleep_if_idle(self, active: list, waiting_count: int) -> None:
        """全部 hart 处于 WFI 等待时阻塞本线程, 避免处理器空转.

        等待对象为 ``_wake_event``. 键盘输入由守护线程经 select(stdin) 分发:
        Ctrl+Q 交调试器暂停, 其余字节写入 UART 接收路径并触发外部中断, legacy
        模式由 PLIC 投递, AIA 模式由 APLIC 转为 MSI 后交 IMSIC, 随后置位该事件;
        termio 的接收排空路径同样置位该事件. stdin 由守护线程独占, 本函数不读取.

        mtime 是自由运行的计数器, 与 hart 是否执行指令、是否设置定时器都无关.
        等待结束后按真实流逝时间推进 mtime, 等待上限见 ``_wfi_wait_bound_sec``.

        ``_wake_event`` 为电平信号: 任何外设活动都会置位它, 只有中断唤醒 hart 的
        路径会清除它. 等待前必须清除, 否则首次活动之后该事件一直处于置位状态,
        wait 每次立即返回, 空闲时处理器持续空转.
        """
        if waiting_count < len(active) or waiting_count == 0:
            return

        sleep_sec = self._wfi_wait_bound_sec(active)
        if sleep_sec is not None and abs(sleep_sec) <= 1e-9:
            # 截止时间已到或不足 1 纳秒时不进入等待,
            # 让定时器在下一轮加速执行中触发
            return

        tb = self._cfg.timebase_freq
        t_sleep = time.monotonic()
        self._wake_event.clear()
        self._wake_event.wait(timeout=sleep_sec)
        slept = time.monotonic() - t_sleep
        if slept > 0 and self.clint is not None and tb:
            self.clint.tick(int(slept * tb))

    def sync_counters(self, instr_delta: int = 0) -> None:
        """同步硬件计数器 CSR 镜像 (mcycle/cycle/minstret/instret/time).

        mcycle 与 cycle 按本 hart 已执行完成的指令数折算, 与 Rust 加速引擎的
        ``csr_read`` 给出同一取值; mtime 由 CLINT 当前值给出. 本函数仅把当前
        值写入各 hart 的 CSR 镜像, 不推进任何计数.

        Args:
            instr_delta: 自上次调用以来全部 hart 合计新增的指令数, 累加到
                全局 ``_total_instrs``; 各 hart 的 ``_total_instrs`` 由执行路径
                自行递增.
        """
        self._total_instrs += instr_delta
        time_val = mask64(self.clint.get_mtime())
        for h in self.harts:
            # 各 hart 的 mcycle 只由该 hart 的指令数给出, 不受其它 hart 与
            # 时钟源流逝影响. 处于 WFI 等待状态的 hart 不执行指令, 两个计数
            # 都不变.
            cycle_val = mask64(h._total_instrs * CYCLES_PER_INSTR)
            h._csr_write_raw("mcycle", cycle_val)
            h._csr_write_raw("cycle", cycle_val)
            h._csr_write_raw("minstret", mask64(h._total_instrs))
            h._csr_write_raw("instret", mask64(h._total_instrs))
            h._csr_write_raw("time", time_val)

    def step(self) -> int:
        """每个周期让所有未停机的 hart 各执行一条指令.

        每条指令执行后检查中断; CLINT 时钟按指令计数推进, 与时钟源流逝的时间
        无关. 本函数恒为单条指令的纯 Python 执行路径, 高速连续执行由 run() 经
        加速执行引擎承担.

        全部 hart 处于 WFI 等待时本函数不阻塞, 直接返回 0: 单步调用方 (调试器、
        逐周期驱动固件的用例) 需要立刻拿回控制权. 空闲等待由 ``run()`` 的轮次
        循环发出, 见 ``_run_one_round``.

        Returns:
            本轮执行的指令数.
        """
        # 关机或复位请求置位后不再执行指令, 直到该请求被撤销.
        if self.power_request is not None:
            return 0
        active = [h for h in self.harts if not h._halted]
        random.shuffle(active)
        all_exec_cnt = 0
        for hart in active:
            # 设置 L2 缓存的当前域标记, 分配/命中行时自动打上 hart 的 mdid
            if self.bus._l2 is not None:
                self.bus._l2.current_mdid = hart.mdid_val

            # WFI 等待状态: 不取指/执行, 但仍检查中断唤醒
            if hart._waiting:
                # WFI 唤醒只需 mip 与 mie 在同一个中断源上同时置位, 不要求
                # mstatus.MIE 置位; 全局使能决定中断是否投递.
                hart.sync_pending_interrupts()
                if hart.wake_hart_from_wfi():
                    # 唤醒后尝试投递中断, MIE 置位时立即投递.
                    hart.check_pending_interrupts()
                continue

            pc_before = hart.pc

            # 取指校验: 先经 itlb 把虚拟地址翻译为物理地址,
            # 再做 PMP 执行权限检查
            ok, fetch_pa = hart.check_instruction_fetch(hart.pc)
            if not ok:
                # trap 已在 check_instruction_fetch 内部投递
                continue

            # 跨页取指: PC 距所在虚拟页末尾不足 2 字节, 即页内偏移不小于 0xFFE
            # 时, 4 字节取指跨越到下一个虚拟页. 虚拟页之间的物理页不保证连续,
            # 需分别经 MMU 翻译后从各物理地址读取各自字节.
            page_off = hart.pc & 0xFFF
            if page_off >= 0xFFE:
                ok2, fetch_pa2 = hart.check_instruction_fetch(
                    mask64(hart.pc + 2)
                )
                if not ok2:
                    continue
                low_half = self.bus.read(fetch_pa, 2)
                instr_bytes = low_half + self.bus.read(fetch_pa2, 2)
            else:
                instr_bytes = self.bus.read(fetch_pa, 4)
            instr = int.from_bytes(instr_bytes, "little", signed=False)

            try:
                advance = hart.exec_instr(instr)
            except NotImplementedError, MemoryAccessError:
                hart.deliver_trap(
                    TrapType.IllInstr, tval=instr, is_interrupt=False
                )
                advance = 0

            # 顺序执行时由调用方推进 PC
            if advance != 0 and hart.pc == pc_before:
                hart.pc = mask64(hart.pc + advance)

            # 在指令边界检查中断
            hart.check_pending_interrupts()

            # WFI 唤醒后经中断处理程序 mret 回到的这条指令不计入指令数, 使
            # _total_instrs 反映固件在中断处理之外实际执行的指令.
            if not hart._wfi_woken:
                hart._total_instrs += 1
                all_exec_cnt += 1

        self._advance_mcycle()
        self._advance_mtime_instr(all_exec_cnt)
        self.sync_counters(all_exec_cnt)

        return all_exec_cnt

    def _check_bp_hit_py(self) -> bool:
        """纯 Python 连续执行下的地址断点判定; 加速执行引擎在 Rust 侧比对.

        ``_bp_addrs`` 由调试器在 ``run()`` 前注入, 含符号物理地址对应的虚拟地址
        副本. 任一活跃 hart 的 PC 命中即返回 True, 由 ``run()`` 置 BREAKPOINT
        停止, 与加速执行引擎在取指前比对断点的语义一致.
        """
        if not self._bp_addrs:
            return False
        for h in self.harts:
            if not h._halted and h.pc in self._bp_addrs:
                return True
        return False

    def _semihosting_exit_py(self) -> bool:
        """消费 semihosting SYS_EXIT 停机标记.

        ``trap_ebreak`` 检测到由 a0 为 0x18 后接 slli、ebreak、srai 三条指令
        构成的停机序列时, 置 ``hart._semihosting_sys_exit``; 此处消费该标记
        并返回 True, 由 ``run()`` 置 RunStopReason.EBREAK 停止, 与加速执行
        引擎的 EXIT_EBREAK 一致. 否则固件停机序列退化为 WFI 自旋,
        纯 Python 的 run() 永不返回.
        """
        hit = any(
            getattr(h, "_semihosting_sys_exit", False) for h in self.harts
        )
        if hit:
            for h in self.harts:
                h._semihosting_sys_exit = False
        return hit

    @property
    def power_request(self) -> PowerRequest | None:
        """受调试程序经关机与复位请求设备给出的请求; 没有请求时返回 None.

        请求一经置位即保持, 由 :meth:`PowerCtrl.clear_request` 撤销; 置位期间
        step() 与 run() 都不执行指令.
        """
        if self.power_ctrl is None:
            return None
        return self.power_ctrl.request

    def _power_stop_reason(self) -> RunStopReason | None:
        """关机与复位请求设备给出的停止原因; 没有请求时返回 None.

        请求一经置位即保持, 下一次连续执行在同一处停止.
        """
        request = self.power_request
        if request is PowerRequest.SHUTDOWN:
            return RunStopReason.SHUTDOWN
        if request is PowerRequest.REBOOT:
            return RunStopReason.REBOOT
        return None

    def run(
        self,
        *,
        timeout: float = 1800.0,
        yield_every: int = 10000,
        yield_interval: float = 0.001,
    ) -> int:
        """连续执行, 直至停止条件满足.

        引擎无指令配额, 持续执行. 停止条件:
        - 固件执行停机序列, 即 semihosting SYS_EXIT, 全部 hart 停止
        - 断点命中, 引擎以 EXIT_BREAKPOINT 退出
        - 全部 hart 停机
        - 受调试程序经关机与复位请求设备请求关机或复位
        - 超过 *timeout*

        全部 hart 处于 WFI 等待时 Python 侧阻塞等待唤醒. 执行中暂停由外部设备经
        :meth:`notify_processor` 置 stop_flag: 引擎逐指令检查并即时退出,
        状态保留在跨轮保留的数组中, 该标志留给调用方消费, 不属于上述停止条件.

        Args:
            timeout: 超时秒数, 默认 1800, 即 30 分钟; 取 0 表示禁用.
            yield_every: 每执行 *yield_every* 条指令后让出处理器, 默认 10000;
                取 0 表示不限速, 处理器由本循环占满.
            yield_interval: 每次让出时等待的秒数, 默认 0.001.

        Returns:
            实际流逝的时钟周期数, 即 self._cycle, 按真实流逝时间记录; 各 hart 的
            mcycle 另由该 hart 的指令数折算, 见 sync_counters.

        Raises:
            TimeoutError: 当 *timeout* 秒数被超过.
        """
        # 清除上次未处理的设备暂停标志; 执行期间新置位的标志留给调用方.
        self._native_stop_flag.value = 0
        self._run_stop_reason = RunStopReason.NONE

        # 超时直接依据时钟源 time.monotonic() 判定, 不依赖 mtime 的推进速率.
        if timeout > 0:
            self._timeout_deadline = time.monotonic() + timeout
        else:
            self._timeout_deadline = 0.0
        do_yield = yield_every > 0
        instr_start = self._total_instrs
        last_yield = instr_start

        while True:
            # 请求一经置位就不再执行指令, 再次调用时在此直接停止.
            if self._power_stop_reason() is not None:
                break
            active = [h for h in self.harts if not h._halted]
            if not active:
                break
            self._check_run_timeout(timeout, instr_start)
            if self._stdin_forward_callback is not None:
                self._stdin_forward_callback()
            if self._run_one_round(active, timeout, instr_start):
                break
            if do_yield and self._total_instrs - last_yield >= yield_every:
                yield_cpu(yield_interval)
                last_yield = self._total_instrs

        stop_reason = self._power_stop_reason()
        if stop_reason is not None:
            self._run_stop_reason = stop_reason
        self._native_flush_uart()
        return self._cycle

    def _check_run_timeout(self, timeout: float, instr_start: int) -> None:
        """达到时钟源超时则置停止原因并抛出 TimeoutError.

        截止时刻取 0 表示禁用超时, 此时不检查.
        """
        if (
            abs(self._timeout_deadline) <= 1e-9
            or time.monotonic() < self._timeout_deadline
        ):
            return
        self._run_stop_reason = RunStopReason.TIMEOUT
        raise TimeoutError(
            timeout,
            self._total_instrs - instr_start,
            self.harts[0].pc if self.harts else None,
        )

    def _run_one_round(self, active, timeout: float, instr_start: int) -> bool:
        """执行一轮; 返回 True 表示应结束连续执行."""
        if self._speedup_hart_states is not None:
            self._speedup_for_cmd_step(active)
            if self._run_stop_reason == RunStopReason.TIMEOUT:
                raise TimeoutError(
                    timeout,
                    self._total_instrs - instr_start,
                    self.harts[0].pc if self.harts else None,
                )
            # 设备暂停事件的标志保留给调用方消费; 断点命中与固件停机若不在
            # 此返回, 重入单轮加速执行会立即再次命中.
            has_stop_flag = self._native_stop_flag.value != 0
            return has_stop_flag or self._run_stop_reason in (
                RunStopReason.BREAKPOINT,
                RunStopReason.EBREAK,
            )
        if self._check_bp_hit_py():
            self._run_stop_reason = RunStopReason.BREAKPOINT
            return True
        self.step()
        if self._semihosting_exit_py():
            self._run_stop_reason = RunStopReason.EBREAK
            return True
        live = [h for h in active if not h._halted]
        if live and all(h._waiting for h in live):
            # 全部存活 hart 处于 WFI 等待时阻塞本线程, 不再轮询; 唤醒源为
            # 定时器截止时刻、运行超时与 _wake_event, 见 _wfi_wait_bound_sec.
            self._wfi_sleep_if_idle(live, len(live))
        return False
