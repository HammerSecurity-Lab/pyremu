#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""加速执行每轮的记录: 批次数、退出原因、每批指令数与三段耗时.

三段耗时: ``sync_before`` 为本轮进入加速执行引擎之前的状态复制与 L2 缓存回写,
``engine`` 为 ``run_parallel`` 的执行时间, ``sync_after`` 为退出之后的状态回读与收尾.
"""

from __future__ import annotations

from collections import Counter
import time

from pyremu.core.hart_ffi import (
    EXIT_BREAKPOINT,
    EXIT_EBREAK,
    EXIT_ECALL,
    EXIT_MMIO,
    EXIT_NORMAL,
    EXIT_NOT_MAINRAM,
    EXIT_RX_WAIT,
    EXIT_TIMEOUT,
    EXIT_TRAP,
    EXIT_WFI_WAIT,
)

# 退出原因到可读名称的映射
EXIT_REASON_NAMES: dict[int, str] = {
    EXIT_NORMAL: "NORMAL",
    EXIT_TRAP: "TRAP",
    EXIT_MMIO: "MMIO",
    EXIT_ECALL: "ECALL",
    EXIT_EBREAK: "EBREAK",
    EXIT_WFI_WAIT: "WFI_WAIT",
    EXIT_NOT_MAINRAM: "NOT_MAINRAM",
    EXIT_BREAKPOINT: "BREAKPOINT",
    EXIT_TIMEOUT: "TIMEOUT",
    EXIT_RX_WAIT: "RX_WAIT",
}

# 每批指令数的分档上界; 超过最后一项的计入最后一段.
INSTR_BUCKETS: tuple[int, ...] = (16, 64, 256, 1024, 4096)

# 退出位置的记录上限: 只统计最先出现的这么多个地址, 避免长时间运行后
# 计数表随地址数无限增长.
EXIT_PC_TRACK_LIMIT = 64
EXIT_PC_REPORT_LIMIT = 5

# 特权指令的 funct12 到名称的映射; 其余 funct12 归入 system.
_SYSTEM_INSTR_NAMES: dict[int, str] = {
    0x000: "ecall",
    0x001: "ebreak",
    0x102: "sret",
    0x105: "wfi",
    0x302: "mret",
}

# 主操作码到归类名称的映射; 未列出的按操作码数值报告.
_OPCODE_NAMES: dict[int, str] = {
    0x03: "load",
    0x07: "load-fp",
    0x0F: "fence",
    0x13: "op-imm",
    0x17: "auipc",
    0x23: "store",
    0x27: "store-fp",
    0x2F: "amo",
    0x33: "op",
    0x37: "lui",
    0x53: "op-fp",
    0x57: "vector",
    0x63: "branch",
    0x67: "jalr",
    0x6F: "jal",
}

# 三段耗时的记录名称与报告中显示的名称, 顺序即报告中的顺序.
PHASE_KEYS: tuple[str, ...] = ("sync_before", "engine", "sync_after")
PHASE_LABELS: dict[str, str] = {
    "sync_before": "进入前同步",
    "engine": "引擎执行",
    "sync_after": "退出后同步",
}


def decode_exit_instr(instr: int) -> str:
    """按编码给出退出指令的归类名称.

    压缩指令按象限与 funct3 归类, 特权指令给出助记符, CSR 指令给出 CSR 编号,
    其余按主操作码归类. 归类名只用于统计报告, 不参与执行.
    """
    if instr == 0:
        return "无"
    if instr & 0x3 != 0x3:
        return f"c{instr & 0x3}.{(instr >> 13) & 0x7}"
    opcode = instr & 0x7F
    if opcode == 0x73:
        return _decode_system_instr(instr)
    return _OPCODE_NAMES.get(opcode, f"opcode 0x{opcode:02x}")


def _decode_system_instr(instr: int) -> str:
    """按 funct3 与 funct12 给出 SYSTEM 指令的归类名称."""
    if (instr >> 12) & 0x7:
        return f"csr 0x{(instr >> 20) & 0xFFF:03x}"
    funct12 = (instr >> 20) & 0xFFF
    name = _SYSTEM_INSTR_NAMES.get(funct12)
    if name is not None:
        return name
    # sfence.vma 的 funct12 为 0x120 与 rs2 的按位或
    if 0x120 <= funct12 <= 0x13F:
        return "sfence.vma"
    return f"system 0x{funct12:03x}"


class BatchStats:
    """进程内全部加速执行轮的汇总."""

    def __init__(self) -> None:
        self.batch_count = 0
        self.instr_total = 0
        self.exit_counts: Counter[int] = Counter()
        self.exit_instrs: Counter[int] = Counter()
        # 按退出指令的归类、退出 hart 与退出地址汇总; 同一轮分别计入一次.
        self.exit_kind_counts: Counter[str] = Counter()
        self.exit_kind_instrs: Counter[str] = Counter()
        self.exit_hart_counts: Counter[int] = Counter()
        self.exit_pc_counts: Counter[int] = Counter()
        self.phase_ns: Counter[str] = Counter()
        self.instr_bucket_counts: list[int] = [0] * (len(INSTR_BUCKETS) + 1)
        self._mark_ns = 0
        self.is_round_open = False

    def begin(self) -> None:
        """开始记录一轮, 计时起点取调用时刻."""
        self._mark_ns = time.perf_counter_ns()
        self.is_round_open = True

    def mark(self, phase: str) -> None:
        """结束当前阶段, 把自上一次记录以来的耗时累加到 ``phase``."""
        if not self.is_round_open:
            return
        now = time.perf_counter_ns()
        self.phase_ns[phase] += now - self._mark_ns
        self._mark_ns = now

    def end(
        self,
        exit_reason: int,
        instrs: int,
        exit_instr: int = 0,
        exit_pc: int = 0,
        exit_hart_id: int = 0,
    ) -> None:
        """登记本轮的退出原因、退出指令、退出地址与指令数."""
        if not self.is_round_open:
            return
        self.is_round_open = False
        self.batch_count += 1
        self.instr_total += instrs
        self.exit_counts[exit_reason] += 1
        self.exit_instrs[exit_reason] += instrs
        kind = decode_exit_instr(exit_instr)
        self.exit_kind_counts[kind] += 1
        self.exit_kind_instrs[kind] += instrs
        self.exit_hart_counts[exit_hart_id] += 1
        if exit_pc in self.exit_pc_counts or len(self.exit_pc_counts) < EXIT_PC_TRACK_LIMIT:
            self.exit_pc_counts[exit_pc] += 1
        for index, upper in enumerate(INSTR_BUCKETS):
            if instrs <= upper:
                self.instr_bucket_counts[index] += 1
                return
        self.instr_bucket_counts[-1] += 1

    def report(self) -> str:
        """给出多行汇总文本."""
        if self.batch_count == 0:
            return "未记录任何一轮"
        total_ns = sum(self.phase_ns.values())
        per_batch = total_ns / self.batch_count
        lines = [
            f"批次 {self.batch_count}, 指令 {self.instr_total}, "
            f"平均每批 {self.instr_total / self.batch_count:.1f} 条",
            f"\t累计耗时 {total_ns / 1e9:.3f} s, 每批 {per_batch / 1e3:.1f} us",
        ]
        for key in PHASE_KEYS:
            ns = self.phase_ns.get(key, 0)
            share = 100.0 * ns / total_ns if total_ns else 0.0
            lines.append(
                f"\t{PHASE_LABELS[key]}: 每批 {ns / self.batch_count / 1e3:.1f} us, "
                f"占 {share:.1f}%"
            )
        lines.append("  退出原因:")
        for reason, count in self.exit_counts.most_common():
            name = EXIT_REASON_NAMES.get(reason, str(reason))
            avg = self.exit_instrs[reason] / count
            share = 100.0 * count / self.batch_count
            lines.append(f"\t{name}: {count} 批次, 占 {share:.1f}%, 平均每批 {avg:.1f} 条")
        lines.append("\t每批指令数:")
        lower = 0
        for index, upper in enumerate(INSTR_BUCKETS):
            lines.append(f"\t{lower + 1}-{upper}: {self.instr_bucket_counts[index]}")
            lower = upper
        lines.append(f"\t大于 {INSTR_BUCKETS[-1]}: {self.instr_bucket_counts[-1]}")
        lines.append("  退出指令:")
        for kind, count in self.exit_kind_counts.most_common():
            avg = self.exit_kind_instrs[kind] / count
            share = 100.0 * count / self.batch_count
            lines.append(f"\t{kind}: {count} 批次, 占 {share:.1f}%, 平均每批 {avg:.1f} 条")
        lines.append("  退出 hart:")
        for hart_id, count in sorted(self.exit_hart_counts.items()):
            lines.append(f"\t{hart_id}: {count} 批次")
        lines.append("  退出位置:")
        for pc, count in self.exit_pc_counts.most_common(EXIT_PC_REPORT_LIMIT):
            lines.append(f"\t0x{pc:x}: {count} 批次")
        return "\n".join(lines)
