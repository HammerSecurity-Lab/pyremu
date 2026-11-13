#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""
RISC-V Platform-Level Interrupt Controller (PLIC).

实现 PLIC 规范 v1.0.0 的核心功能:
- 中断源优先级 (可编程)
- 中断挂起 / 清除 (pending)
- 按上下文 (hart * privilege) 的使能位
- 优先级阈值 + Claim/Complete 机制

内存布局 (SiFive 兼容, context stride = 0x1000):

  0x000000 - 0x000FFC   Source priorities (4 bytes each, source 1..N)
  0x001000 - 0x00107C   Pending bits (32 words * 32 bits)
  0x002000 - 0x00207C   Enable bits context 0 (32 words)
  0x002080 - 0x0020FC   Enable bits context 1
  ...                   (每个 context 0x80 字节)
  0x200000              Context 0 threshold (u32)
  0x200004              Context 0 claim/complete (u32)
  0x201000              Context 1 threshold (u32)
  ...

与 CLINT 集成: PLIC 不直接实现 InterruptController;
而是通过 hart._plic 引用, 在 check_pending_interrupts 中
将 PLIC 返回的 MEIP/SEIP 位合并到 mip 寄存器.

用法:
    plic = PLIC(base_addr=0x0C00_0000, num_sources=128, num_contexts=4)
    plic.set_irq(source_id=10, pending=True)   # 硬件置起中断
    plic.get_pending_mip(hart_id=0)            # -> MEIP 或 SEIP bit
"""

from __future__ import annotations

import ctypes
import threading

from pyremu.memory.bus import Device

# PLIC 常量 — 地址空间分区
PLIC_PRIORITY_BASE = 0x000000
PLIC_PRIORITY_STRIDE = 4
PLIC_PENDING_BASE = 0x001000
PLIC_ENABLE_BASE = 0x002000
PLIC_ENABLE_STRIDE = 0x80  # 每 context 128 bytes = 32 u32 words
PLIC_CONTEXT_BASE = 0x200000
PLIC_CONTEXT_STRIDE = 0x1000  # 每 context 4 KiB
PLIC_CONTEXT_THRESHOLD_OFF = 0x000
PLIC_CONTEXT_CLAIM_OFF = 0x004

# 默认 PLIC 基址 (SiFive FU540: 0x0C00_0000)
PLIC_DEFAULT_BASE = 0x0C00_0000


class PLIC(Device):
    """RISC-V Platform-Level Interrupt Controller (PLIC).

    实现 MMIO 寄存器接口供 Guest 访问,
    同时提供 set_irq / get_pending_mip 供硬件模型集成.
    """

    def __init__(
        self,
        base_addr: int = PLIC_DEFAULT_BASE,
        num_sources: int = 128,
        num_contexts: int = 1,
    ) -> None:
        self.base_addr = base_addr
        self.num_sources = num_sources  # source 1..N (source 0 保留)
        self.num_contexts = num_contexts
        self.num_enable_words = (num_sources + 31) // 32

        # 下列四个 ctypes 数组由本对象持有, 加速执行引擎直接读写同一份存储.
        # priority[i] 为 source i 的优先级; enable[c * num_enable_words + w] 为
        # context c 第 w 个使能字; threshold[c] 为 context c 的优先级阈值;
        # claimed[c] 为 context c 当前正在服务的中断源, 0 表示无.
        enable_words = num_contexts * self.num_enable_words
        self.priority = (ctypes.c_uint8 * (num_sources + 1))()
        self.enable = (ctypes.c_uint32 * enable_words)()
        self.threshold = (ctypes.c_uint8 * num_contexts)()
        self.claimed = (ctypes.c_uint32 * num_contexts)()

        # pending 与 level 同样由本对象持有, 引擎在批次内直接改写这两份数组.
        # PLIC gateway 语义: claim 清除 pending, complete 时若电平仍为高则重新
        # 置位 pending, 否则电平中断在 claim 后无设备寄存器访问的窗口内丢失.
        self.pending = (ctypes.c_uint8 * (num_sources + 1))()
        self.level = (ctypes.c_uint8 * (num_sources + 1))()

        # 计算设备区域大小 — 到最后一个 context + 4 KiB
        last_context_end = (
            PLIC_CONTEXT_BASE
            + (num_contexts - 1) * PLIC_CONTEXT_STRIDE
            + 0x1000
        )
        self.size = last_context_end

        # 并发安全: RX daemon (设备线程) 经 set_irq 写 pending/level, 主线程经
        # get_pending_mip/read/write 读仲裁状态 — 共享状态访问需互斥.
        self._lock = threading.Lock()

    # ---- 硬件集成 API (供模拟器其他组件调用) ----

    def set_irq(self, source: int, pending: bool) -> None:
        """由设备模型调用: 设置中断源电平与挂起状态.

        level-triggered 语义: pending 镜像电平, 非
        边沿锁存 — deassert 时同时清除挂起, 由驱动保持数据源电平直到消费完成.
        两个数组与引擎共享, 批次内 Rust 内联仲裁实时看到电平变化.
        """
        with self._lock:
            if 0 < source <= self.num_sources:
                val = 1 if pending else 0
                self.level[source] = val
                self.pending[source] = val

    def get_pending_mip(self, hart_id: int) -> int:
        """返回该 hart 的待处理外部中断 mip 位.

        标准双 context 布局: 2*hart_id 为 M 模式, 2*hart_id+1 为 S 模式.
        分别检查两个 context 是否有优先级高于阈值、使能且挂起的中断源:
        - M context 命中时置 MEIP, 即 mip 的位 11
        - S context 命中时置 SEIP, 即 mip 的位 9
        两者可同时置位.
        """
        m_ctx = 2 * hart_id
        s_ctx = m_ctx + 1
        mip = 0
        with self._lock:
            if m_ctx < self.num_contexts and self._find_highest(m_ctx) > 0:
                mip |= 1 << 11  # MEIP (M-context)
            if s_ctx < self.num_contexts and self._find_highest(s_ctx) > 0:
                mip |= 1 << 9  # SEIP (S-context)
            return mip

    # ---- 中断仲裁 ----

    def _find_highest(self, context: int) -> int:
        """返回 context 中优先级最高且符合条件的中断源编号, 若无则返回 0.

        条件: pending[i] AND enable[context][i] AND
        priority[i] > threshold[context]
        有多个时取最高优先级; 同优先级取最小 source id (RISC-V spec §7.3).

        注意: 不检查 ``claimed`` 状态.  PLIC 规范中 pending 是 per-source
        (非 per-context), claim 操作原子清除 pending, 其他 context 自然看不到.
        complete 后若 level 仍高则重挂 pending, 所有 context (含原 claimer)
        均可再次 claim.  添加 claimed 检查会阻止同一 context 重入 claim
        (level 重挂场景) 或其他 context claim (多 hart 共享场景),
        导致 MEIP/SEIP 断言但 claim 返回 0 的死锁.
        """
        threshold = self.threshold[context]
        enable_base = context * self.num_enable_words
        best_source = 0
        best_prio = 0
        # 使能位只覆盖 enable 数组的字数, 字号超出数组的 source 不参与仲裁
        limit = min(self.num_sources, self.num_enable_words * 32 - 1)
        # 挂起的中断源通常只有少数几个: 先把 pending 整份读成字节串, 再按置起
        # 的字节升序遍历, 访问次数与挂起的中断源数成正比, 与中断源总数无关.
        # 升序保证同优先级取编号最小的中断源.
        pending_bytes = bytes(self.pending)
        i = pending_bytes.find(1, 1, limit + 1)
        while i != -1:
            if (self.enable[enable_base + (i >> 5)] >> (i & 31)) & 1:
                pri = self.priority[i]
                if pri > threshold and pri > best_prio:
                    best_prio = pri
                    best_source = i
            i = pending_bytes.find(1, i + 1, limit + 1)

        return best_source

    # ---- Device 接口 ----

    def read(self, offset: int, size: int) -> bytes:
        if size not in (2, 4):
            return b"\x00" * size
        with self._lock:
            val = self._mmio_read(offset)
            return val.to_bytes(size, "little")

    def write(self, offset: int, data: bytes) -> None:
        size = len(data)
        if size not in (2, 4):
            return
        val = int.from_bytes(data, "little")
        with self._lock:
            self._mmio_write(offset, val)

    def _mmio_read(self, offset: int) -> int:
        # Source priorities (0x000000 - 0x000FFC)
        if offset < PLIC_PENDING_BASE:
            src = offset // PLIC_PRIORITY_STRIDE
            if 1 <= src <= self.num_sources:
                return self.priority[src] & 0x7
            return 0

        # Pending bits (0x001000 - 0x00107C)
        if offset < PLIC_ENABLE_BASE:
            return self._read_pending_word((offset - PLIC_PENDING_BASE) // 4)

        # Enable bits (0x002000 - ...)
        if offset < PLIC_CONTEXT_BASE:
            rel = offset - PLIC_ENABLE_BASE
            return self._read_enable_word(
                rel // PLIC_ENABLE_STRIDE, (rel % PLIC_ENABLE_STRIDE) // 4
            )

        # Context registers (0x200000 - ...)
        return self._read_context(offset - PLIC_CONTEXT_BASE)

    def _read_context(self, rel: int) -> int:
        """读取 context 段: 阈值寄存器与 claim 寄存器, 其余偏移读零."""
        context = rel // PLIC_CONTEXT_STRIDE
        ctx_off = rel % PLIC_CONTEXT_STRIDE
        if context >= self.num_contexts:
            return 0
        if ctx_off == PLIC_CONTEXT_THRESHOLD_OFF:
            return self.threshold[context] & 0x7
        if ctx_off == PLIC_CONTEXT_CLAIM_OFF:
            return self._do_claim(context)
        return 0

    def _mmio_write(self, offset: int, val: int) -> None:
        # Source priorities
        if offset < PLIC_PENDING_BASE:
            src = offset // PLIC_PRIORITY_STRIDE
            if 1 <= src <= self.num_sources:
                self.priority[src] = val & 0x7
            return

        # Pending bits — read-only (pending 由硬件 set_irq 控制)
        if offset < PLIC_ENABLE_BASE:
            return

        # Enable bits
        if offset < PLIC_CONTEXT_BASE:
            rel = offset - PLIC_ENABLE_BASE
            context = rel // PLIC_ENABLE_STRIDE
            word_idx = (rel % PLIC_ENABLE_STRIDE) // 4
            self._write_enable_word(context, word_idx, val)
            return

        # Context registers
        rel = offset - PLIC_CONTEXT_BASE
        context = rel // PLIC_CONTEXT_STRIDE
        ctx_off = rel % PLIC_CONTEXT_STRIDE

        if context >= self.num_contexts:
            return

        if ctx_off == PLIC_CONTEXT_THRESHOLD_OFF:
            self.threshold[context] = val & 0x7
        elif ctx_off == PLIC_CONTEXT_CLAIM_OFF:
            self._do_complete(context, val)

    # ---- Claim / Complete ----

    def _do_claim(self, context: int) -> int:
        """Claim: 返回最高优先级待处理源, 清除 pending 位.

        RISC-V PLIC 规范: claim 仅清除 pending, 不修改 level.
        level 由设备侧 set_irq 独占控制 — 设备降电平后 complete
        不会重挂 pending, 设备保持高电平时 complete 立即重挂.
        """
        src = self._find_highest(context)
        if src > 0:
            self.pending[src] = 0
            self.claimed[context] = src
        return src

    def _do_complete(self, context: int, src: int) -> None:
        """Complete: 标记中断处理完成, 允许再次触发.

        若设备电平仍为高 (claim 后设备未拉低 set_irq),
        complete 时重新置位 pending, 使中断再次投递
        """
        if 0 < src <= self.num_sources and self.claimed[context] == src:
            self.claimed[context] = 0
            if self.level[src]:
                self.pending[src] = 1

    # ---- 位数组辅助 ----

    def _read_pending_word(self, word_idx: int) -> int:
        result = 0
        word_idx <<= 5
        for i in range(32):
            src = word_idx + i
            if src <= self.num_sources and self.pending[src]:
                result |= 1 << i
        return result

    def _read_enable_word(self, context: int, word_idx: int) -> int:
        if context >= self.num_contexts or word_idx >= self.num_enable_words:
            return 0
        return self.enable[context * self.num_enable_words + word_idx]

    def _write_enable_word(self, context: int, word_idx: int, val: int) -> None:
        if context >= self.num_contexts or word_idx >= self.num_enable_words:
            return
        src_base = word_idx << 5
        bits = val & 0xFFFF_FFFF
        # source 0 为保留项, 始终不使能
        if src_base == 0:
            bits &= ~1
        bit_count = self.num_sources + 1 - src_base
        if bit_count < 32:
            bits &= (1 << bit_count) - 1
        self.enable[context * self.num_enable_words + word_idx] = bits
