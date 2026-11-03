#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""加速执行统计的记录与汇总.

覆盖 ``BatchStats`` 的聚合规则与 ``pyremu.stat.recording`` 的开关判定. 统计打开时
``end_round`` 会在进程退出时输出汇总, 故打开开关的用例只记录轮次而不结束轮次,
使退出时的输出为空.
"""

from __future__ import annotations

import importlib

from pyremu.core.hart_ffi import EXIT_ECALL, EXIT_MMIO, EXIT_WFI_WAIT
from pyremu.stat import recording
from pyremu.stat.batch import (
    BatchStats,
    decode_exit_instr,
    EXIT_PC_TRACK_LIMIT,
    INSTR_BUCKETS,
)


def test_stats_disabled_by_default():
    # 测试进程未设置 PYREMU_BATCH_STATS, 记录入口应给出空对象.
    assert recording.get_batch_stats() is None


def test_recording_facade_noop_when_disabled():
    # 统计关闭时三个入口均为空操作, 不抛异常也不改变任何状态.
    recording.begin_round()
    recording.mark_phase("sync_before")
    recording.end_round(EXIT_ECALL, 1000)
    assert recording.get_batch_stats() is None


def test_recording_enabled_by_env(monkeypatch):
    monkeypatch.setenv("PYREMU_BATCH_STATS", "1")
    module = importlib.reload(recording)
    try:
        stats = module.get_batch_stats()
        assert stats is not None
        module.begin_round()
        module.mark_phase("sync_before")
        module.mark_phase("engine")
        # 同一轮内多次记录同一阶段时累加到该阶段.
        module.mark_phase("engine")
        assert stats.is_round_open
        assert stats.phase_ns["sync_before"] >= 0
        assert stats.phase_ns["engine"] >= 0
        # 同一进程内重复取用得到同一对象.
        assert module.get_batch_stats() is stats
        # 不结束轮次, 使退出时的汇总为空.
    finally:
        monkeypatch.delenv("PYREMU_BATCH_STATS")
        importlib.reload(recording)


def test_end_round_accumulates_exit_reasons():
    stats = BatchStats()
    stats.begin()
    stats.end(EXIT_ECALL, 100)
    stats.begin()
    stats.end(EXIT_ECALL, 300)
    stats.begin()
    stats.end(EXIT_MMIO, 50)
    assert stats.batch_count == 3
    assert stats.instr_total == 450
    assert stats.exit_counts[EXIT_ECALL] == 2
    assert stats.exit_instrs[EXIT_ECALL] == 400
    assert stats.exit_counts[EXIT_MMIO] == 1


def test_end_round_without_begin_ignored():
    # 未调用 begin 时 end 不生效, 避免把不成对的记录计入汇总.
    stats = BatchStats()
    stats.end(EXIT_ECALL, 100)
    assert stats.batch_count == 0
    assert stats.instr_total == 0


def test_instr_buckets_by_batch_length():
    stats = BatchStats()
    lengths = [1, 16, 17, 64, 65, 1024, 1025, INSTR_BUCKETS[-1] + 1]
    for length in lengths:
        stats.begin()
        stats.end(EXIT_WFI_WAIT, length)
    # 1 与 16 落在 1-16, 17 与 64 落在 17-64, 65 落在 65-256,
    # 1024 落在 257-1024, 1025 与超过最后一项的值各落在最后一段.
    assert stats.instr_bucket_counts[0] == 2
    assert stats.instr_bucket_counts[1] == 2
    assert stats.instr_bucket_counts[2] == 1
    assert stats.instr_bucket_counts[3] == 1
    assert stats.instr_bucket_counts[-2] == 1
    assert stats.instr_bucket_counts[-1] == 1


def test_report_contains_totals_and_exit_names():
    stats = BatchStats()
    for _ in range(3):
        stats.begin()
        stats.mark("sync_before")
        stats.mark("engine")
        stats.mark("sync_after")
        stats.end(EXIT_ECALL, 200)
    text = stats.report()
    assert "批次 3" in text
    assert "指令 600" in text
    assert "平均每批 200.0 条" in text
    assert "ECALL: 3 批次" in text
    assert "进入前同步" in text
    assert "引擎执行" in text
    assert "退出后同步" in text


def test_report_empty_when_no_round():
    assert "未记录" in BatchStats().report()


def test_decode_exit_instr_unrecorded():
    """未记录退出指令时给出占位名称."""
    assert decode_exit_instr(0) == "无"


def test_decode_exit_instr_system():
    """特权指令按 funct12 给出助记符, sfence.vma 的取值含 rs2 的低位."""
    assert decode_exit_instr(0x0000_0073) == "ecall"
    assert decode_exit_instr(0x0010_0073) == "ebreak"
    assert decode_exit_instr(0x1020_0073) == "sret"
    assert decode_exit_instr(0x1050_0073) == "wfi"
    assert decode_exit_instr(0x3020_0073) == "mret"
    assert decode_exit_instr(0x1200_0073) == "sfence.vma"
    # rs2 = 31 时 funct12 为 0x13F, 仍属 sfence.vma
    assert decode_exit_instr(0x13F0_0073) == "sfence.vma"
    # 未登记的 funct12 按数值报告
    assert decode_exit_instr(0x7FF0_0073) == "system 0x7ff"


def test_decode_exit_instr_csr_gives_number():
    """CSR 指令给出 CSR 编号, 与 op-imm 等普通指令区分."""
    # csrr a0, 0x7c2: funct3 = 2, csr = 0x7c2
    assert decode_exit_instr(0x7C20_2573) == "csr 0x7c2"


def test_decode_exit_instr_32bit_opcodes():
    """按主操作码归类, 未登记的按操作码数值报告."""
    assert decode_exit_instr(0x0001_2083) == "load"
    assert decode_exit_instr(0x00A1_2023) == "store"
    assert decode_exit_instr(0x0000_00B3) == "op"
    assert decode_exit_instr(0x0000_0013) == "op-imm"
    assert decode_exit_instr(0x0000_0063) == "branch"
    assert decode_exit_instr(0x0000_006F) == "jal"
    assert decode_exit_instr(0x0000_0057) == "vector"
    assert decode_exit_instr(0x0000_000B) == "opcode 0x0b"


def test_decode_exit_instr_compressed():
    """压缩指令按象限与 funct3 归类, 不按 32 位主操作码解释."""
    # c.li a0, 0: 象限 1, funct3 = 2
    assert decode_exit_instr(0x4501) == "c1.2"


def test_end_round_records_kind_hart_and_pc():
    """每轮分别登记退出指令的归类、退出 hart 与退出地址."""
    stats = BatchStats()
    stats.begin()
    stats.end(EXIT_ECALL, 100, 0x0000_0073, 0x8000_1000, 1)
    stats.begin()
    stats.end(EXIT_MMIO, 50, 0x0001_2083, 0x8000_1000, 0)
    assert stats.exit_kind_counts["ecall"] == 1
    assert stats.exit_kind_counts["load"] == 1
    assert stats.exit_kind_instrs["ecall"] == 100
    assert stats.exit_kind_instrs["load"] == 50
    assert stats.exit_hart_counts[1] == 1
    assert stats.exit_hart_counts[0] == 1
    assert stats.exit_pc_counts[0x8000_1000] == 2


def test_exit_pc_tracking_limit():
    """退出地址只登记最先出现的数量上限, 已登记地址的再次出现仍累加."""
    stats = BatchStats()
    for pc in range(EXIT_PC_TRACK_LIMIT + 8):
        stats.begin()
        stats.end(EXIT_MMIO, 1, 0, pc << 2, 0)
    assert len(stats.exit_pc_counts) == EXIT_PC_TRACK_LIMIT
    assert stats.exit_pc_counts[0] == 1
    stats.begin()
    stats.end(EXIT_MMIO, 1, 0, 0, 0)
    assert stats.exit_pc_counts[0] == 2
    # 超出上限的地址不再登记
    assert (EXIT_PC_TRACK_LIMIT + 8) << 2 not in stats.exit_pc_counts


def test_report_contains_exit_details():
    """汇总文本包含退出指令、退出 hart 与退出位置三节."""
    stats = BatchStats()
    stats.begin()
    stats.end(EXIT_ECALL, 100, 0x0000_0073, 0x8000_1000, 1)
    text = stats.report()
    assert "退出指令:" in text
    assert "ecall: 1 批次" in text
    assert "退出 hart:" in text
    assert "\t1: 1 批次" in text
    assert "退出位置:" in text
    assert "0x80001000: 1 批次" in text
