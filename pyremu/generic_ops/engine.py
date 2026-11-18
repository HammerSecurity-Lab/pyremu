#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""加速执行引擎的一次连续执行 — 配置结构、上下文编组与调用.

本模块把 Python 侧的设备状态编组为 Rust 侧的 repr(C) 上下文, 调用
``run_parallel``, 并在返回后回读引擎改写过的状态. 结构体定义由
``pyremu/_native/defs_aux.py`` 从 Rust 侧 DI 元数据生成.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from pyremu._native import defs_gen, loaded_lib
from pyremu.utils.mask import mask64


@dataclass(slots=True)
class PmpInfo:
    """各 hart 共用的 PMP 条目缓冲区.

    cfg 每项 1 字节, addr 每项 1 个 u64, 两者按 hart 依次拼接;
    hart h 的切片自索引 h * num 起, num 为每个 hart 的条目数.
    """

    cfg: Any
    addr: Any
    num: int
    pmpsplit: int = 0

    @classmethod
    def from_buffers(
        cls,
        cfg: Any,
        addr: Any,
        hart_num: int,
        pmpsplit: int = 0,
    ) -> PmpInfo:
        """按共享缓冲区与 hart 数量给出每 hart 的条目数."""
        if len(cfg) != len(addr):
            raise ValueError(
                f"PMP 缓冲区长度不一致: cfg {len(cfg)}, addr {len(addr)}"
            )
        if hart_num <= 0 or len(cfg) % hart_num != 0:
            raise ValueError(
                f"PMP 缓冲区长度 {len(cfg)} 无法被 hart 的数量 {hart_num} 整除"
            )
        num = len(cfg) // hart_num
        if num > 0xFF:
            raise ValueError(
                f"per-hart PMP num={num} 超出 FfiPmpCtx.num (u8) 范围"
            )
        return cls(cfg=cfg, addr=addr, num=num, pmpsplit=pmpsplit)


@dataclass(slots=True)
class ClintInfo:
    """CLINT state"""

    mtime: int = 0
    mtimecmp: Any = None  # list or ctypes array
    msip: Any = None  # list or ctypes array (level + edge counter)
    base: int = 0
    timebase_hz: int = 10_000_000  # mtime 时钟源频率


@dataclass(slots=True)
class DevInfo:
    """Device MMIO ranges"""

    bases: Any = None  # ctypes array of uint64
    ends: Any = None  # ctypes array of uint64


@dataclass(slots=True)
class PlicInfo:
    """PLIC 内联上下文: 数组由 PLIC 对象持有, Rust 在加速执行内联读写.

    数组在该对象生命周期内保持同一份, 设备线程经 set_irq 写穿 pending 与 level,
    使批次内新到达的设备中断对 Rust 内联仲裁可见.
    """

    base: int = 0
    num_sources: int = 0
    num_contexts: int = 0
    priority: Any = None  # ctypes array of uint8 (num_sources+1)
    pending: Any = None  # ctypes array of uint8 (num_sources+1)
    level: Any = None  # ctypes array of uint8 (num_sources+1)
    enable: Any = None  # ctypes array of uint32 (num_contexts * num_words)
    threshold: Any = None  # ctypes array of uint8 (num_contexts)
    claimed: Any = None  # ctypes array of uint32 (num_contexts)


@dataclass(slots=True)
class UartInfo:
    """UART context — lets Rust buffer sbi_printf output inline
    and handle IE/IP/TXCTRL register reads without exiting from speedup lib"""

    base: int = 0
    tx_buf: Any = None
    tx_wr: Any = None
    ie: int = 0
    txctrl: int = 0
    rxctrl: int = 0
    rx_fifo_len: int = 0
    tx_notify_fd: int = -1
    no_stdout: int = 0
    rx_notify: Any = None
    # 持久 ctypes FfiUartCtx — 由 Emulator 持有并注入 UART 设备, 设备侧
    # 状态变化时直接改写其寄存器字段; 提供时不再每轮重建快照.
    ffi: Any = None


@dataclass(slots=True)
class VirtIOInfo:
    """virtio-blk inline context — Rust handles all MMIO register
    accesses inline; only QueueNotify exits to Python.

    Carries the full runtime state of the virtio-blk MMIO register file
    across speedup process.  Without this, dynamic state written by the guest
    (queue descriptors, feature negotiation, InterruptStatus, etc.) is
    silently reset to zero, and the guest sees a dead device.
    """

    base: int = 0
    capacity: int = 0
    queue_num_max: int = 256
    device_features_sel: int = 0
    driver_features_sel: int = 0
    driver_features: int = 0
    queue_sel: int = 0
    queue_num: int = 0
    queue_ready: bool = False
    queue_desc: int = 0
    queue_driver: int = 0
    queue_device: int = 0
    status: int = 0
    interrupt_status: int = 0


@dataclass(slots=True)
class RunConfig:
    """一次 run_parallel 调用的输入: 必给的执行上下文与可选的设备状态."""

    states: Any  # ctypes array of HartState
    num_harts: int
    ram_ptr: int
    ram_size: int
    ram_base: int
    shadow_base: int
    shadow_size: int
    result: Any
    pmp: PmpInfo | None = None
    clint: ClintInfo | None = None
    dev: DevInfo | None = None
    uart: UartInfo | None = None
    virtio: VirtIOInfo | None = None
    plic: PlicInfo | None = None
    watchdog_timeout_ns: int = 0  # 时钟源超时时间 (纳秒); 0 = 禁用
    bp_addrs: list[int] | None = None
    stop_flag: Any = None  # ctypes.c_uint8 — Ctrl+Q 与设备共用的停止标志
    ext_irq: Any = None  # FfiExtIrqCtx — 外部中断上下文
    flush_cnt: Any = None  # ctypes.c_uint64 — 已发生的 TLB 刷新次数
    flush_cnt_per_hart: Any = (
        None  # ctypes array of c_uint64 — 各 hart 上次见到的取值
    )


@dataclass(slots=True)
class FfiParts:
    """一个 FFI 结构与它指向的 ctypes 缓冲区.

    FFI 结构内只存裸地址, 缓冲区由本对象的 buffers 持有, 存活至 run_parallel
    返回; 缺少该引用时引擎会读到已释放的内存.
    """

    ctx: Any
    buffers: tuple[Any, ...] = ()
    is_present: bool = True


def _addr_or_zero(obj) -> int:
    """对象为 None 时返回 0, 否则返回其地址.

    按"是否提供"判定, 不能用真值判定: ctypes 标量的真值取自它的当前取值
    (c_uint8(0) 为假), 真值判定会把取值为 0 的停止标志与计数器当作未提供,
    从而向引擎传空指针.
    """
    return ctypes.addressof(obj) if obj is not None else 0


class ClintMarshal:
    """CLINT 状态在调用期间的 ctypes 副本: 调用前写入, 返回后回读."""

    def __init__(self, clint: ClintInfo | None, num_harts: int) -> None:
        nh = self.num_harts = max(int(num_harts), 1)
        self.mtime = ctypes.c_uint64(0)
        self.mtimecmp = (ctypes.c_uint64 * nh)()
        self.msip = (ctypes.c_uint8 * nh)()
        if clint is None:
            for i in range(nh):
                self.mtimecmp[i] = 0xFFFF_FFFF_FFFF_FFFF
        else:
            self.mtime.value = clint.mtime
            if clint.mtimecmp:
                for i in range(min(nh, len(clint.mtimecmp))):
                    self.mtimecmp[i] = int(clint.mtimecmp[i])
            else:
                for i in range(nh):
                    self.mtimecmp[i] = 0xFFFF_FFFF_FFFF_FFFF
            if clint.msip:
                for i in range(min(nh, len(clint.msip))):
                    self.msip[i] = int(clint.msip[i])

        self.ctx = defs_gen.FfiClintCtx()
        self.ctx.mtime = ctypes.addressof(self.mtime)
        self.ctx.mtimecmp = ctypes.addressof(self.mtimecmp)
        self.ctx.msip = ctypes.addressof(self.msip)
        self.ctx.base = clint.base if clint is not None else 0
        self.ctx.timebase_hz = clint.timebase_hz if clint is not None else 0

    def sync_back(self, clint: ClintInfo | None) -> None:
        """把引擎改写后的 mtime、mtimecmp 与 msip 复制回调用方的 ClintInfo.

        mtime 由引擎逐指令按原子操作推进; mtimecmp 与 msip 可能被引擎内的
        内联 CLINT 处理改写, 两者都要回读.
        """
        if clint is None:
            return
        clint.mtime = self.mtime.value
        if clint.msip:
            for i in range(min(self.num_harts, len(clint.msip))):
                clint.msip[i] = int(self.msip[i])
        if clint.mtimecmp:
            for i in range(min(self.num_harts, len(clint.mtimecmp))):
                clint.mtimecmp[i] = int(self.mtimecmp[i])


def _build_pmp_ffi(pmp: PmpInfo | None) -> FfiParts:
    ffi = defs_gen.FfiPmpCtx()
    if pmp is None:
        return FfiParts(ffi)
    ffi.num = pmp.num
    ffi.pmpsplit = pmp.pmpsplit
    if pmp.num <= 0:
        return FfiParts(ffi)
    ffi.cfg = ctypes.addressof(pmp.cfg)
    ffi.addr = ctypes.addressof(pmp.addr)
    return FfiParts(ffi, (pmp.cfg, pmp.addr))


def _build_dev_ffi(dev: DevInfo | None) -> defs_gen.DevMMIOAddrInfo:
    ffi = defs_gen.DevMMIOAddrInfo()
    if dev is not None and dev.bases and dev.ends:
        ffi.bases = ctypes.addressof(dev.bases)
        ffi.ends = ctypes.addressof(dev.ends)
        ffi.num = len(dev.bases)
    return ffi


def _build_uart_ffi(uart: UartInfo | None) -> FfiParts:
    # 调用方提供持久上下文时直接复用; 否则按参数值构建一次性快照.
    if uart is None:
        return FfiParts(defs_gen.FfiUartCtx())
    if uart.ffi is not None:
        return FfiParts(uart.ffi)

    ffi = defs_gen.FfiUartCtx()
    ffi.base = uart.base
    buffers: list[Any] = []
    if uart.tx_buf is not None:
        ffi.tx_buf = ctypes.addressof(uart.tx_buf)
        ffi.tx_cap = len(uart.tx_buf)
        buffers.append(uart.tx_buf)
    if uart.tx_wr is not None:
        ffi.tx_wr = ctypes.addressof(uart.tx_wr)
        buffers.append(uart.tx_wr)
    ffi.ie = uart.ie
    ffi.txctrl = uart.txctrl
    ffi.rxctrl = uart.rxctrl
    ffi.rx_fifo_len = uart.rx_fifo_len
    ffi.tx_notify_fd = uart.tx_notify_fd
    ffi.no_stdout = uart.no_stdout
    if uart.rx_notify is not None:
        ffi.rx_notify = ctypes.addressof(uart.rx_notify)
        buffers.append(uart.rx_notify)
    return FfiParts(ffi, tuple(buffers))


def _build_virtio_ffi(virtio: VirtIOInfo | None) -> FfiParts:
    ffi = defs_gen.FfiVirtIoCtx()
    if virtio is None or virtio.base == 0:
        return FfiParts(ffi, is_present=False)
    ffi.base = virtio.base
    ffi.capacity = virtio.capacity
    ffi.queue_num_max = virtio.queue_num_max
    ffi.device_features_sel = virtio.device_features_sel
    ffi.driver_features_sel = virtio.driver_features_sel
    ffi.driver_features = virtio.driver_features
    ffi.queue_sel = virtio.queue_sel
    ffi.queue_num = (
        virtio.queue_num if virtio.queue_num else virtio.queue_num_max
    )
    ffi.queue_ready = 1 if virtio.queue_ready else 0
    ffi.queue_desc = virtio.queue_desc
    ffi.queue_driver = virtio.queue_driver
    ffi.queue_device = virtio.queue_device
    ffi.status = virtio.status
    ffi.interrupt_status = virtio.interrupt_status
    return FfiParts(ffi)


def _build_plic_ffi(plic: PlicInfo | None) -> FfiParts:
    """持久数组指针直传, Rust 在连续执行内读写, 设备线程按同一数组写入."""
    ffi = defs_gen.FfiPlicCtx()
    if plic is None or plic.base == 0:
        return FfiParts(ffi, is_present=False)
    ffi.base = plic.base
    ffi.num_sources = plic.num_sources
    ffi.num_contexts = plic.num_contexts
    ffi.priority = ctypes.addressof(plic.priority)
    ffi.pending = ctypes.addressof(plic.pending)
    ffi.level = ctypes.addressof(plic.level)
    ffi.enable = ctypes.addressof(plic.enable)
    ffi.threshold = ctypes.addressof(plic.threshold)
    ffi.claimed = ctypes.addressof(plic.claimed)
    return FfiParts(ffi)


def _build_bp_ffi(bp_addrs: list[int] | None) -> FfiParts:
    ffi = defs_gen.FfiBpCtx()
    if not bp_addrs:
        return FfiParts(ffi)
    arr = (ctypes.c_uint64 * len(bp_addrs))()
    for i, addr in enumerate(bp_addrs):
        arr[i] = mask64(addr)
    ffi.addrs = ctypes.addressof(arr)
    ffi.count = len(bp_addrs)
    return FfiParts(ffi, (arr,))


def _build_watchdog_ffi(
    timeout_ns: int,
) -> tuple[defs_gen.FfiWatchdogCtx, bool]:
    """时钟源超时时间的 FFI 结构与"是否提供"标志; 0 表示禁用, 不传指针."""
    ffi = defs_gen.FfiWatchdogCtx()
    if not timeout_ns:
        return ffi, False
    ffi.timeout_ns = mask64(int(timeout_ns))
    return ffi, True


def run_parallel(cfg: RunConfig) -> defs_gen.FfiVirtIoCtx | None:
    lib = loaded_lib()
    if lib is None:
        return None

    mem = defs_gen.MemCtx()
    mem.ram = int(cfg.ram_ptr) if cfg.ram_ptr else 0
    mem.ram_size = cfg.ram_size
    mem.ram_base = cfg.ram_base
    mem.shadow_base = cfg.shadow_base
    mem.shadow_size = cfg.shadow_size

    clint_state = ClintMarshal(cfg.clint, cfg.num_harts)
    pmp_parts = _build_pmp_ffi(cfg.pmp)
    dev_ffi = _build_dev_ffi(cfg.dev)
    uart_parts = _build_uart_ffi(cfg.uart)
    virtio_parts = _build_virtio_ffi(cfg.virtio)
    plic_parts = _build_plic_ffi(cfg.plic)
    watchdog_ffi, has_watchdog = _build_watchdog_ffi(cfg.watchdog_timeout_ns)
    bp_parts = _build_bp_ffi(cfg.bp_addrs)

    hart_ctx = defs_gen.FfiHartCtx()
    hart_ctx.states = (
        ctypes.addressof(cfg.states) if cfg.states is not None else 0
    )
    hart_ctx.num_harts = cfg.num_harts
    hart_ctx.instr_group = ctypes.addressof(cfg.result)
    hart_ctx.stop_flag = _addr_or_zero(cfg.stop_flag)
    hart_ctx.ext_irq = _addr_or_zero(cfg.ext_irq)

    mem_ctx = defs_gen.FfiMemCtx()
    mem_ctx.mem = ctypes.addressof(mem)
    mem_ctx.pmp = ctypes.addressof(pmp_parts.ctx)

    intr_ctx = defs_gen.FfiInterruptCtx()
    intr_ctx.clint = ctypes.addressof(clint_state.ctx)
    intr_ctx.plic = (
        _addr_or_zero(plic_parts.ctx) if plic_parts.is_present else 0
    )

    dev_ctx = defs_gen.FfiDevicesCtx()
    dev_ctx.dev = ctypes.addressof(dev_ffi)
    dev_ctx.uart = ctypes.addressof(uart_parts.ctx)
    dev_ctx.virtio = (
        _addr_or_zero(virtio_parts.ctx) if virtio_parts.is_present else 0
    )
    dev_ctx.watchdog = _addr_or_zero(watchdog_ffi) if has_watchdog else 0

    tlb_ctx = defs_gen.FfiTlbCtx()
    tlb_ctx.flush_cnt = _addr_or_zero(cfg.flush_cnt)
    tlb_ctx.flush_cnt_per_hart = _addr_or_zero(cfg.flush_cnt_per_hart)

    lib.run_parallel(
        ctypes.byref(hart_ctx),
        ctypes.byref(mem_ctx),
        ctypes.byref(intr_ctx),
        ctypes.byref(dev_ctx),
        ctypes.byref(bp_parts.ctx),
        ctypes.byref(tlb_ctx),
    )

    clint_state.sync_back(cfg.clint)

    # Return the virtio FFI struct so the caller can read back changed fields.
    return virtio_parts.ctx if cfg.virtio else None
