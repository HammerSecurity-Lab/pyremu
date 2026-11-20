#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""FFI 结构布局、状态编组与设备状态的跨轮同步."""

from __future__ import annotations

import ctypes
import json
from pathlib import Path
import re
import struct
import time

import pytest

from pyremu._native import (
    defs_gen,
    HartState,
    InstrToBeExec,
    IsaExts,
    TlbEntry,
)
from pyremu.configs_gen import CPU_FREQ_HZ
from pyremu.core.hart import RatifiedHartAttrs, RiscvMode
from pyremu.emu.hart import Hart
from pyremu.emulator import Emulator, RunStopReason
from pyremu.interrupt.imsic import IMSIC
from pyremu.utils.mask import mask64


class TestNativeBatchLayout:
    """Python ctypes ↔ Rust repr(C) 结构体布局一致性验证.

    Rust 侧将 TLB 存储为 ``[TlbEntry; 32]`` (array-of-structs).
    若 Python 侧错误地使用分离数组 (如 itlb_vpn, itlb_ppn, ...)
    会造成内存布局不匹配 -> SIGBUS (Bus error).
    这些用例在每次构建后锁死布局合约.
    """

    def test_tlb_entry_size_40(self) -> None:
        """TlbEntry 必须恰好 40 字节.

        mdid 从 u8 加宽为 u64 后 TlbEntry 由 32B 涨到 40B (mdid 对齐到偏移 24).
        与 Rust ``state::TlbEntry`` 逐字节一致, 否则 Rust 在错误偏移读字段,
        引发 SIGBUS.
        """
        assert ctypes.sizeof(TlbEntry) == 40, (
            f"TlbEntry 应为 40 字节, 实际 {ctypes.sizeof(TlbEntry)}B"
        )

    def test_hart_state_8byte_aligned(self) -> None:
        """HartState 必须 8 字节对齐."""
        assert ctypes.sizeof(HartState) % 8 == 0

    def test_hart_state_reasonable_size(self) -> None:
        """HartState 不应异常膨胀,
        与 Rust 侧 ``hart_state_size_reasonable`` 对齐.

        256 TLB 条目 × 40B × 2 (itlb+dtlb) ≈ 20 KB, 实际 ~22 KB < 64 KB.
        若某次 FFI 改动让布局爆炸 (如把整块 RAM 塞进 HartState), 此测试会拦住.
        """
        assert ctypes.sizeof(HartState) < 65536

    def test_batch_result_8byte_aligned(self) -> None:
        """InstrToBeExec (原 BatchResult) 必须 8 字节对齐."""
        assert ctypes.sizeof(InstrToBeExec) % 8 == 0

    def test_itlb_is_array_of_structs(self) -> None:
        """itlb 确保 array-of-structs 而非 struct-of-arrays.

        struct-of-arrays 会导致 Rust 在 offsetof(itlb[i].ppn) 读到错误数据,
        引发 SIGBUS.
        """
        hs = HartState()
        assert len(hs.itlb) % 32 == 0
        assert hasattr(hs.itlb[0], "vpn")
        assert hasattr(hs.itlb[0], "ppn")
        assert hasattr(hs.itlb[0], "valid")

    def test_dtlb_is_array_of_structs(self) -> None:
        """dtlb 确保 array-of-structs."""
        hs = HartState()
        assert len(hs.dtlb) % 32 == 0
        assert hasattr(hs.dtlb[0], "vpn")
        assert hasattr(hs.dtlb[0], "ppn")
        assert hasattr(hs.dtlb[0], "valid")

    def test_isa_exts_layout(self) -> None:
        """IsaExts 每项占 1 字节, 字段偏移与 Rust ``state::IsaExts`` 相同.

        两侧的字段总数、每项宽度与字段顺序任一不符, 引擎读到的开关就会落到
        其他扩展上. 此处锁死的偏移与 Rust 侧 ``isa_exts_offsets`` 用例相同.
        """
        assert ctypes.sizeof(IsaExts) == 21
        assert IsaExts.is_i.offset == 0
        assert IsaExts.is_zicsr.offset == 9
        assert IsaExts.is_sstc.offset == 17
        assert IsaExts.is_smepmp.offset == 20
        for name, val in IsaExts._fields_:
            assert val is ctypes.c_bool, f"{name} 应为布尔字段"
        # 追加在 HartState 末尾: 其后只有对齐填充, 不挤占已有字段
        extent = HartState.isa_exts.offset + ctypes.sizeof(IsaExts)
        assert extent <= ctypes.sizeof(HartState) < extent + 8

    def test_marshal_isa_exts_writes_switches(self) -> None:
        """平台声明决定各开关, 未声明的扩展保持关闭."""
        h = Hart(
            id=0,
            ratified_hart_attrs=RatifiedHartAttrs.from_platform(
                16, "rv64imac_zicsr_zifencei"
            ),
        )
        state = HartState()
        h.marshal_isa_exts(state)
        assert (
            state.isa_exts.is_i and state.isa_exts.is_m and state.isa_exts.is_c
        )
        assert state.isa_exts.is_zicsr and state.isa_exts.is_zifencei
        assert not state.isa_exts.is_sstc
        assert not state.isa_exts.is_f and not state.isa_exts.is_d
        assert not state.isa_exts.is_b and not state.isa_exts.is_smaia

    def test_marshal_to_leaves_isa_exts_untouched(self) -> None:
        """逐轮编组与解组都不写扩展开关.

        扩展开关是平台的静态属性, 只在状态数组分配时写入一次. 若 marshal_to
        恢复为逐轮写入, 该用例中预先置位的开关会被平台的取值覆盖.
        """
        h = Hart(
            id=0,
            ratified_hart_attrs=RatifiedHartAttrs.from_platform(16, "rv64i"),
        )
        state = HartState()
        state.isa_exts.is_sstc = True
        h.marshal_to(state)
        h.unmarshal_from(state)
        assert state.isa_exts.is_sstc is True


class TestNativePmpSlice:
    """每个 hart 的 PMP 切片步长取该 hart 的实际条目数.

    旧实现按固定 64 项划分切片, 并把每 hart 的条目数报为 64. 配置 16 项时,
    加速执行引擎因此把 pmpaddr16..63 视为已实现, 与 Python 侧实际实现的条目数
    不符; 芯片设备树声明其余条目数时同样错位.
    """

    @pytest.mark.parametrize("entries", [16, 32, 57, 64])
    def test_slice_stride_equals_entry_count(self, entries: int) -> None:
        """切片总长与每 hart 条目数均为配置值; 57 等非 2 的幂同样适用."""
        emu = Emulator(num_harts=2, pmp_entries=entries)
        info = emu._native_marshal_pmp([])
        assert info.num == entries
        assert len(info.cfg) == entries * 2
        assert len(info.addr) == entries * 2

    def test_configured_16_entries_report_16(self) -> None:
        """配置 16 项时引擎看到的条目数为 16, 不再是修复前的 64."""
        emu = Emulator(num_harts=1, pmp_entries=16)
        info = emu._native_marshal_pmp([])
        assert info.num == 16
        assert info.num != 64

    def test_each_hart_slice_is_independent(self) -> None:
        """写入一个 hart 的切片不改变另一个 hart 的切片."""
        emu = Emulator(num_harts=2, pmp_entries=16)
        emu.harts[0].csrs["pmpcfg0"].val = 0x1F
        emu.harts[0]._pmp.invalidate_cache()
        info = emu._native_marshal_pmp([])
        assert info.cfg[0] == 0x1F
        assert info.cfg[16] == 0


@pytest.mark.usefixtures("legacy_plic")
class TestPlicNativeInline:
    """Rust 内联处理 PLIC MMIO 时的数组共享约定.

    claim、complete、enable、threshold 与 priority 的访问由 Rust 在加速
    执行期间内联处理, 不退回 Python 的 MMIO 路径. PLIC 对象持有全部 ctypes
    数组, 引擎与 Python 侧读写同一份存储, marshal 只传递地址; 设备线程经
    ``irq_sink`` 写入 pending 与 level, 保证加速执行期间新设备中断对 Rust
    内联仲裁可见.
    """

    def test_marshal_plic_shares_plic_arrays(self):
        """marshal 返回的数组就是 PLIC 持有的数组, 不做复制."""
        emu = Emulator(num_harts=2)
        plic = emu.plic
        assert plic is not None
        plic.priority[10] = 5
        plic.enable[0 * plic.num_enable_words + 0] = 1 << 10
        plic.enable[0 * plic.num_enable_words + 1] = 1 << 1
        plic.enable[1 * plic.num_enable_words + 0] = 1 << 7
        info = emu._native_marshal_plic()
        assert info is not None
        assert info.base == plic.base_addr
        assert info.num_sources == plic.num_sources
        assert info.num_contexts == plic.num_contexts
        assert info.priority is plic.priority
        assert info.pending is plic.pending
        assert info.level is plic.level
        assert info.enable is plic.enable
        assert info.threshold is plic.threshold
        assert info.claimed is plic.claimed
        assert info.priority[10] == 5
        nw = plic.num_enable_words
        assert info.enable[0 * nw + 0] & (1 << 10) != 0, (
            "source 10 应落 word 0 bit 10"
        )
        assert info.enable[0 * nw + 1] & (1 << 1) != 0, (
            "source 33 应落 word 1 bit 1"
        )
        assert info.enable[1 * nw + 0] & (1 << 7) != 0, "context 1 source 7"

    def test_claim_and_complete_use_shared_arrays(self):
        """引擎内联 claim/complete 改写的数组就是 PLIC 仲裁读取的数组."""
        emu = Emulator(num_harts=2)
        plic = emu.plic
        assert plic is not None
        plic.priority[10] = 5
        plic.enable[0] = 1 << 10
        plic.set_irq(10, True)
        info = emu._native_marshal_plic()
        assert info is not None and info.pending is plic.pending
        # claim: 清 pending 并记录 claimed, 仲裁随即看不到该源
        claimed = int.from_bytes(plic.read(0x200004, 4), "little")
        assert claimed == 10
        assert plic.pending[10] == 0
        assert plic.claimed[0] == 10
        assert plic.level[10] == 1
        assert plic.get_pending_mip(0) & (1 << 11) == 0
        # complete 时电平仍高, 重新置位 pending
        plic.write(0x200004, (10).to_bytes(4, "little"))
        assert plic.claimed[0] == 0
        assert plic.pending[10] == 1
        assert plic.get_pending_mip(0) & (1 << 11) != 0

    def test_irq_sink_write_through(self):
        """设备线程经 irq_sink 写入 PLIC 持有的数组,
        使加速执行期间对 Rust 可见."""
        emu = Emulator(num_harts=2)
        emu.irq_sink(25, True)
        assert emu.plic.pending[25] == 1
        assert emu.plic.level[25] == 1
        emu.irq_sink(25, False)
        assert emu.plic.pending[25] == 0
        assert emu.plic.level[25] == 0

    def test_marshal_plic_none_when_no_plic(self):
        """无 PLIC 时 marshal 返回 None (native 侧回落 MMIO)."""
        emu = Emulator(num_harts=1)
        emu.plic = None
        assert emu._native_marshal_plic() is None


class TestClockDecoupling:
    """指令计数时钟模型: mtime 按已执行指令数推进, mcycle 按时钟源推进.

    回归: 旧实现按时钟源 (time.monotonic()) 推进 mtime, 使 mtime 速率与执行
    速度无关 — 固件忙等 (rdtime 自旋) 期间 mtime 仍推进, SMP bringup 超时.
    改为 mtime 按指令计数推进 (100 指令 = 1 tick), mcycle 仍按时钟源推进.
    """

    @pytest.fixture
    def nop_emu(self) -> Emulator:
        """单 hart 模拟器, 加载 4096 条 NOP — 无 WFI/ECALL/trap.

        时钟源频率固定为 10 MHz, 使换算结果不随 TIMER_FREQ 变化.
        """
        emu = Emulator(num_harts=1, timebase_freq=10_000_000)
        nops = b"\x13\x00\x00\x00" * 4096  # addi x0, x0, 0
        emu.load_code(0x8000_0000, nops)
        return emu

    def test_mtime_advances_per_100_instructions(self, nop_emu):
        """mtime 按指令计数推进: 100 条指令 = 20 tick
        (10 MHz × NS_PER_INSTR=20ns)."""
        emu = nop_emu
        mtime_before = emu.clint.get_mtime()
        for _ in range(100):
            emu.step()
        assert emu.clint.get_mtime() - mtime_before == 20, (
            "100 条指令应推进 mtime 恰好 20 tick (5 指令/tick)"
        )

    def test_advance_mtime_instr_conversion(self, nop_emu):
        """_advance_mtime_instr 按 timebase_freq*NS_PER_INSTR 换算,
        余数跨调用累积."""
        emu = nop_emu
        mtime_before = emu.clint.get_mtime()

        # 5 指令 -> 恰好 1 tick (10 MHz × 20ns/instr)
        emu._advance_mtime_instr(5)
        assert emu.clint.get_mtime() - mtime_before == 1

        # 4 指令 -> 0 tick (余数累积 0.8); 再 1 指令 -> 满 1 tick
        emu._advance_mtime_instr(4)
        assert emu.clint.get_mtime() - mtime_before == 1
        emu._advance_mtime_instr(1)
        assert emu.clint.get_mtime() - mtime_before == 2

    def test_advance_mcycle_clock_source(self, nop_emu, monkeypatch):
        """_advance_mcycle 按时钟源推进 mcycle, 不动 mtime."""
        now_holder = {"t": 100.0}
        monkeypatch.setattr(time, "monotonic", lambda: now_holder["t"])
        emu = nop_emu
        emu._last_clock_sync = 100.0
        cyc_before = emu._cycle
        mtime_before = emu.clint.get_mtime()

        now_holder["t"] = 101.0
        emu._advance_mcycle()
        assert emu._cycle - cyc_before == CPU_FREQ_HZ
        assert emu.clint.get_mtime() == mtime_before

    def test_marshal_clint_no_mtime_advance(self, nop_emu, monkeypatch):
        """_native_marshal_clint 不再按时钟源推进 mtime (mtime 与时钟源解耦)."""
        now_holder = {"t": 300.0}
        monkeypatch.setattr(time, "monotonic", lambda: now_holder["t"])
        emu = nop_emu
        emu._last_clock_sync = 300.0
        mtime_before = emu.clint.get_mtime()

        now_holder["t"] = 300.5
        info = emu._native_marshal_clint()
        assert emu.clint.get_mtime() == mtime_before, (
            "marshal_clint 不得再按时钟源推进 mtime"
        )
        assert info.mtime == mtime_before

    def test_native_batch_mtime_pure_instruction_count(self, nop_emu):
        """加速执行引擎下 mtime 纯按指令计数推进, 与流逝时间解耦.

        回归: 工作树曾把 Rust ``advance_clock_source`` 改为实时/混合模型,
        legacy 模式 PLIC 相位后 HZ=250 的 4ms tick 指令预算不足 (~8-12K 条),
        低于 kernel post-PLIC timer handler 路径 -> mret 后立即再 trap 的活锁,
        kernel_init 被饿死, 串口停在 plic 设备树节点输出. 修复为纯指令源
        (20ns/instr) 后, native 路径 mtime 推进率必须与 Python 路径一致:
        5 条指令 = 1 tick, 流逝时间完全不参与.
        """
        emu = nop_emu
        assert emu._speedup_hart_states is not None, (
            "回归测试必须走 native batch"
        )
        # 断点设在第 2000 条 NOP 之后, run() 经 native batch 返回
        emu._bp_addrs = [0x8000_0000 + 2000 * 4]
        emu.run(timeout=15)
        assert emu._run_stop_reason == RunStopReason.BREAKPOINT, (
            f"应命中断点, 实际 reason={emu._run_stop_reason}"
        )
        assert emu._total_instrs == 2000, (
            f"应恰好执行 2000 条 NOP, 实际 {emu._total_instrs}"
        )
        mtime = emu.clint.get_mtime()
        # 5 条指令 = 1 tick (10 MHz × 20ns/instr / 1e9). 边界滞后 <=1 条
        # (advance_clock_source 在每条指令执行前的循环顶推进), 故期望落在
        # elapsed*timebase ≈ 10^3~10^4+ tick, 远越上界 -> 复现修复前行为.
        lo = emu._total_instrs // 5 - 1
        hi = emu._total_instrs // 5
        assert lo <= mtime <= hi, (
            f"native batch 2000 条指令 mtime 应为 [{lo}, {hi}] tick, "
            f"实际 {mtime}"
        )
        emu.close()

    def test_native_mtime_no_wallclock_leak_on_idle(self, nop_emu):
        """无指令执行时, mtime 不随流逝时间推进 (无实时泄漏).

        回归: 实时/混合模型在空闲批次 instr_delta=0 时仍按真实流逝推进 mtime,
        与 Python 侧 ``_wfi_sleep_if_idle`` 的 clint.tick 实时补偿叠加成
        ~2× real 双倍计数, 重新制造 tick 风暴压力. 修复后空闲期 mtime 静止,
        由 WFI 补偿独占实时源.
        """
        emu = nop_emu
        emu._bp_addrs = [0x8000_0000 + 2000 * 4]
        emu.run(timeout=15)
        assert emu._run_stop_reason == RunStopReason.BREAKPOINT
        mtime_before = emu.clint.get_mtime()
        time.sleep(0.3)  # 无指令执行, 流逝 300ms
        assert emu.clint.get_mtime() == mtime_before, (
            "空闲期 mtime 不得随流逝时间推进 (实时泄漏)"
        )
        emu.close()


class TestMarshalUnmarshalRoundtrip:
    """marshal_to 与 unmarshal_from 的双向数据完整性验证.

    batch 边界 marshal/unmarshal 是 Python HartWithRegs ↔ Rust HartState
    的唯一数据通道.  若任一字段在往返过程中丢失或损坏, batch 内部的 Rust
    执行会基于错误状态继续运行 — 产生静默错误 (如 ld-linux s4=-1 消失).

    本测试覆盖 HartState 中所有非 pad 字段的往返保真度.
    """

    # ---------- helpers ----------
    @staticmethod
    def _fresh_hart(hart_id: int = 0) -> Hart:
        """创建一个处于 M 模式的 Hart (__init__ 默认)."""
        return Hart(id=hart_id)

    @staticmethod
    def _roundtrip(hart: Hart) -> Hart:
        """把状态编组后解组到新 hart, 返回新 hart."""
        state = HartState()
        hart.marshal_to(state)
        out = Hart(id=hart.id + 1)
        out.unmarshal_from(state)
        return out

    # ---------- GPR 往返 ----------
    def test_gpr_all_zero_init(self) -> None:
        """所有 GPR 初始为 0 时往返不变."""
        hart = self._fresh_hart()
        out = self._roundtrip(hart)
        for i in range(32):
            assert out.gprs[i] == 0, f"gprs[{i}] = {out.gprs[i]}, expected 0"

    def test_gpr_fills_pattern_roundtrip(self) -> None:
        """每寄存器写入唯一值后往返不变."""
        hart = self._fresh_hart()
        for i in range(32):
            hart.gprs[i] = mask64(
                i * 0x1111_1111_1111_1111 + 0xDEAD_BEEF_CAFE_BABE
            )
        # x0 写保护 — GprFile 应忽略写入
        hart.gprs[0] = 0  # explicitly ensure
        out = self._roundtrip(hart)
        assert out.gprs[0] == 0, "x0 must always be 0"
        for i in range(1, 32):
            expected = mask64(i * 0x1111_1111_1111_1111 + 0xDEAD_BEEF_CAFE_BABE)
            assert out.gprs[i] == expected, (
                f"gprs[{i}] = {out.gprs[i]:#018x}, expected {expected:#018x}"
            )

    def test_s4_negative_one_preserved(self) -> None:
        """s4 (x20) = -1 (0xFFFF_FFFF_FFFF_FFFF) 在往返后必须保持.

        ld-linux 用 s4=-1 作为循环退出哨兵.  若 unmarshal 在某处将其清零
        或截断, BNE s2,s4 将永不退出 — 继续迭代到 DT_RELA=7 -> LoadPageFault.
        """
        hart = self._fresh_hart()
        hart.gprs[20] = 0xFFFF_FFFF_FFFF_FFFF  # s4 = -1
        out = self._roundtrip(hart)
        assert out.gprs[20] == 0xFFFF_FFFF_FFFF_FFFF, (
            f"s4 = {out.gprs[20]:#018x}, expected -1"
        )

    def test_gpr_edge_values_roundtrip(self) -> None:
        """GPR 极端值 (0, -1, MAX, 符号位, 交替 bits) 往返不变."""
        hart = self._fresh_hart()
        test_values = {
            1: 0,  # zero
            2: 0xFFFF_FFFF_FFFF_FFFF,  # -1 (ld-linux s4 sentinel)
            3: 0x7FFF_FFFF_FFFF_FFFF,  # max positive signed
            4: 0x8000_0000_0000_0000,  # min negative signed
            5: 0xAAAA_AAAA_AAAA_AAAA,  # alternating bits
            6: 0x5555_5555_5555_5555,  # alternating bits (inverted)
            7: 0x0000_0000_0000_0001,  # 1 (smallest non-zero)
            8: 0x8000_0000_0000_0001,  # sign bit + 1
        }
        for idx, val in test_values.items():
            hart.gprs[idx] = val
        out = self._roundtrip(hart)
        for idx, val in test_values.items():
            assert out.gprs[idx] == val, (
                f"gprs[{idx}] = {out.gprs[idx]:#018x}, expected {val:#018x}"
            )

    # ---------- 关键 CSR 往返 ----------
    @pytest.mark.parametrize(
        "csr_name,val",
        [
            ("mstatus", 0x0000000A00001800),  # MPP=M, SPP=S, FS=1, XS=1
            ("mtvec", 0x80001000),  # vectored M-mode
            ("stvec", 0x80200000),  # direct S-mode
            ("mepc", 0x80001234),
            ("sepc", 0x3FFF_FFFF_F000),
            ("mcause", 0x8000_0000_0000_000D),  # LoadPageFault interrupt
            ("scause", 0x0000_0000_0000_0008),  # EcallFromUmode
            ("mtval", 0x0000_0033D),
            ("stval", 0x3FFF_FFFF_F000),
            ("satp", 0x8000_0000_0001_2345),  # Sv39, PPN=0x12345
            ("mie", 0x888),  # MEIE | SEIE | MTIE
            ("mip", 0x080),  # STIP
            ("medeleg", 0xBEEF),
            ("mideleg", 0xDEAD),
        ],
    )
    def test_csr_roundtrip(self, csr_name: str, val: int) -> None:
        """关键 CSR 往返不变."""
        hart = self._fresh_hart()
        hart.csrs[csr_name].val = val
        out = self._roundtrip(hart)
        actual = out.csrs[csr_name].val
        assert actual == val, (
            f"{csr_name}: {actual:#018x} ≠ expected {val:#018x}"
        )

    # ---------- TLB 刷新 ----------
    def test_unmarshal_keeps_tlb_when_satp_unchanged(self) -> None:
        """satp 往返取值相同时保持既有 TLB 条目."""
        hart = self._fresh_hart()
        hart.satp_val = (8 << 60) | 0x12345
        hart.itlb.insert(0xABC, 0xDEF, 5)
        hart.dtlb.insert(0xABC, 0xDEF, 3)
        state = HartState()
        hart.marshal_to(state)
        hart.unmarshal_from(state)
        assert hart.itlb.lookup(0xABC)[0] is True
        assert hart.dtlb.lookup(0xABC)[0] is True

    def test_unmarshal_flushes_tlb_when_satp_changed(self) -> None:
        """satp 往返取值不同时刷新 TLB."""
        hart = self._fresh_hart()
        hart.satp_val = (8 << 60) | 0x12345
        hart.dtlb.insert(0xABC, 0xDEF, 3)
        state = HartState()
        hart.marshal_to(state)
        state.satp = (8 << 60) | 0x54321
        hart.unmarshal_from(state)
        assert hart.dtlb.lookup(0xABC)[0] is False

    # ---------- 状态字段 ----------
    def test_pc_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart.pc = 0x3FFF_FFFF_3ABA
        out = self._roundtrip(hart)
        assert out.pc == 0x3FFF_FFFF_3ABA

    @pytest.mark.parametrize("mode", [RiscvMode.U, RiscvMode.S, RiscvMode.M])
    def test_mode_roundtrip(self, mode: RiscvMode) -> None:
        hart = Hart(id=0)
        hart.mode = mode
        out = self._roundtrip(hart)
        assert out.mode == mode

    def test_mmu_mode_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._mmu_mode = 8  # Sv39
        out = self._roundtrip(hart)
        assert out.mmu_mode == 8

    # ---------- LR/SC reservation ----------
    def test_reservation_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._reservation_valid = True
        hart._reservation_addr = 0x8000_1234
        out = self._roundtrip(hart)
        assert out._reservation_valid is True
        assert out._reservation_addr == 0x8000_1234

    def test_reservation_invalid_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._reservation_valid = False
        out = self._roundtrip(hart)
        assert out._reservation_valid is False

    # ---------- WFI / halted ----------
    def test_waiting_wfi_woken_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._waiting = True
        hart._wfi_woken = True
        out = self._roundtrip(hart)
        assert out._waiting is True
        assert out._wfi_woken is True

    def test_halted_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._halted = True
        out = self._roundtrip(hart)
        assert out._halted is True

    # ---------- TEE CSRs ----------
    def test_mdid_pmpsplit_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._mdid_val = 5
        hart._pmpsplit_val = 2
        out = self._roundtrip(hart)
        assert out.mdid_val == 5
        assert out.pmpsplit_val == 2

    def test_mdid_above_255_roundtrip(self) -> None:
        """
        mdid 超过 255 时 marshal 往返必须保持完整 64-bit 值.

        回归: HartState.mdid / TlbEntry.mdid 曾声明为 c_uint8 (Rust 侧 u8),
        与 csr.rs ``val as u8`` 截断共同构成 batch-4 (2000 并发, id >= 256)
        挂死根因 — 300->44, 256->0 (别名回 host, SUSPEND handler 误判而挂死).
        c_uint8 字段赋值 300 会直接抛 ValueError, 本用例在旧布局下无法通过.
        """
        hart = self._fresh_hart()
        hart._mdid_val = 300
        out = self._roundtrip(hart)
        assert out.mdid_val == 300

        # 256 ≡ 0 (mod 256) 是最危险别名 (-> host), 必须保留原值
        hart2 = self._fresh_hart()
        hart2._mdid_val = 256
        out2 = self._roundtrip(hart2)
        assert out2.mdid_val == 256

    # ---------- Extra CSRs ----------
    def test_extra_csrs_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart.csrs["mscratch"].val = 0xDEAD_BEEF_0000_1111
        hart.csrs["sscratch"].val = 0xCAFE_BABE_2222_3333

        # mhartid is read-only (set in __init__ to hart.id)
        # Write mcounteren directly
        hart.csrs["mcounteren"].val = 0x0000_0000_0000_0007  # CY|TM|IR

        out = self._roundtrip(hart)
        assert out.csrs["mscratch"].val == 0xDEAD_BEEF_0000_1111
        assert out.csrs["sscratch"].val == 0xCAFE_BABE_2222_3333
        assert out.csrs["mhartid"].val == 0  # original hart had id=0
        assert out.csrs["mcounteren"].val == 0x0000_0000_0000_0007

    # ---------- instruction counter ----------
    def test_total_instrs_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart._total_instrs = 123456789
        out = self._roundtrip(hart)
        assert out._total_instrs == 123456789

    # ---------- float ----------
    def test_fpr_roundtrip(self) -> None:
        hart = self._fresh_hart()
        for i in range(32):
            hart.fpr_bits[i] = mask64(
                0x3FF0_0000_0000_0000 + i * 0x1000_0000_0000
            )
        out = self._roundtrip(hart)
        for i in range(32):
            expected = mask64(0x3FF0_0000_0000_0000 + i * 0x1000_0000_0000)
            assert out.fpr_bits[i] == expected, f"fpr[{i}] mismatch"

    def test_fcsr_roundtrip(self) -> None:
        hart = self._fresh_hart()
        hart.csrs["fcsr"].val = 0x0000_0000_0000_00A0  # FRM=2, NV|DZ flags
        out = self._roundtrip(hart)
        assert out.csrs["fcsr"].val == 0x0000_0000_0000_00A0


class TestImsicMarshalRoundtrip:
    """IMISC 的 eip 与 eie 在编组与解组之间的取值.

    eip 与 eie 各为 64 个 32 位字, 编组按字整体拷贝. 解组时引擎写回的 eip 需
    与编组之后由接收线程置位的位合并; eie 由引擎写回, 不参与合并.
    """

    _EIP_WORDS = 64
    _LAST_WORD = 63

    @staticmethod
    def _make_hart() -> tuple[Hart, IMSIC]:
        """创建一个接 IMSIC 的 hart, 编号为 0."""
        hart = Hart(id=0)
        hart.imsic = IMSIC(
            num_harts=1,
            m_base_addr=0x2400_0000,
            s_base_addr=0x2800_0000,
        )
        return hart, hart.imsic

    @staticmethod
    def _eip_of(state: HartState, priv: str) -> tuple[int, ...]:
        mirror = state.imsic_m if priv == "M" else state.imsic_s
        return struct.unpack_from("<64I", bytes(mirror.eip))

    @staticmethod
    def _eie_of(state: HartState, priv: str) -> tuple[int, ...]:
        mirror = state.imsic_m if priv == "M" else state.imsic_s
        return struct.unpack_from("<64I", bytes(mirror.eie))

    def test_eip_last_word_copied(self) -> None:
        """中断号 2047 落在第 63 个字, 编组之后该字必须带位.

        只拷贝前 63 个字时该中断号丢失.
        """
        hart, imsic = self._make_hart()
        imsic.set_ip_number(0, "M", 2047)
        state = HartState()
        hart.marshal_to(state)
        words = self._eip_of(state, "M")
        assert words[self._LAST_WORD] == 1 << 31
        assert all(w == 0 for w in words[: self._LAST_WORD])

    def test_s_file_eip_copied(self) -> None:
        """S 模式的 eip 单独编组到 imsic_s, 不混入 M 模式."""
        hart, imsic = self._make_hart()
        imsic.set_ip_number(0, "S", 40 * 32 + 5)
        state = HartState()
        hart.marshal_to(state)
        assert self._eip_of(state, "S")[40] == 1 << 5
        assert all(w == 0 for w in self._eip_of(state, "M"))

    def test_ipi_only_is_not_external(self) -> None:
        """只有软件中断 (中断号 1 与 3) 挂起时 eip_ext_any 为 0."""
        hart, imsic = self._make_hart()
        imsic.set_ip_number(0, "M", 1)
        imsic.set_ip_number(0, "M", 3)
        state = HartState()
        hart.marshal_to(state)
        assert state.imsic_m.eip_ext_any == 0

    def test_external_bit_sets_ext_any(self) -> None:
        """中断号不小于 6 的位挂起时 eip_ext_any 为 1."""
        hart, imsic = self._make_hart()
        imsic.set_ip_number(0, "M", 10)
        state = HartState()
        hart.marshal_to(state)
        assert state.imsic_m.eip_ext_any == 1

    def test_bit_set_after_marshal_survives_unmarshal(self) -> None:
        """编组之后由接收线程置位的 eip 位在解组之后仍然存在.

        引擎写回的 eip 是编组时刻的旧值, 直接覆盖会丢掉这一位.
        """
        hart, imsic = self._make_hart()
        state = HartState()
        hart.marshal_to(state)
        imsic.set_ip_number(0, "M", 10)
        hart.unmarshal_from(state)
        state2 = HartState()
        hart.marshal_to(state2)
        assert self._eip_of(state2, "M")[0] == 1 << 10

    def test_engine_set_bit_applied(self) -> None:
        """引擎写回的 eip 位在解组之后进入中断文件."""
        hart, imsic = self._make_hart()
        state = HartState()
        hart.marshal_to(state)
        state.imsic_m.eip[0] = 1 << 12
        hart.unmarshal_from(state)
        state2 = HartState()
        hart.marshal_to(state2)
        assert self._eip_of(state2, "M")[0] == 1 << 12

    def test_engine_eie_overwrites_file(self) -> None:
        """引擎写回的 eie 覆盖中断文件的 eie."""
        hart, imsic = self._make_hart()
        imsic.csr_write(0, "M", 0xC0, 1 << 10)
        state = HartState()
        hart.marshal_to(state)
        assert self._eie_of(state, "M")[0] == 1 << 10
        state.imsic_m.eie[0] = 0
        hart.unmarshal_from(state)
        assert imsic.csr_read(0, "M", 0xC0) == 0

    def test_eie_last_word_roundtrip(self) -> None:
        """eie 的第 63 个字双向可传, 且不影响相邻的字."""
        hart, imsic = self._make_hart()
        imsic.csr_write(0, "M", 0xFF, 0x8000_0001)
        state = HartState()
        hart.marshal_to(state)
        assert self._eie_of(state, "M")[self._LAST_WORD] == 0x8000_0001
        state.imsic_m.eie[self._LAST_WORD] = 0x1
        hart.unmarshal_from(state)
        assert imsic.csr_read(0, "M", 0xFF) == 0x1

    def test_no_imsic_clears_present(self) -> None:
        """未接 IMSIC 的 hart 编组之后 present 为 0."""
        hart = Hart(id=0)
        state = HartState()
        state.imsic_m.present = 1
        state.imsic_s.present = 1
        hart.marshal_to(state)
        assert state.imsic_m.present == 0
        assert state.imsic_s.present == 0


class TestFfiSpecDrift:
    """生成物与 Rust 导出函数集合互为镜像.

    ``pyremu/_native/ffi_spec.json`` 与 ``defs_gen.py`` 均由 defs_aux.py
    从 Rust 侧 LLVM IR 生成; Rust 侧新增或删除 ``#[no_mangle]``
    ``pub extern "C" fn`` 后未重新生成时, 本类用例失败.
    """

    REPO_ROOT = Path(__file__).resolve().parents[2]
    NATIVE_DIR = REPO_ROOT / "pyremu" / "_native"
    EXPORT_PATTERN = re.compile(
        r"#\[no_mangle\]\s*(?:#[^\n]*\n\s*)*"
        r'pub (?:unsafe )?extern "C" fn (\w+)'
    )

    @classmethod
    def _declared(
        cls,
        lib_name: str,
    ) -> set[str]:
        spec = json.loads((cls.NATIVE_DIR / "ffi_spec.json").read_text("utf-8"))
        return {entry["name"] for entry in spec["functions"][lib_name]}

    @classmethod
    def _exported(
        cls,
        source_dir: Path,
    ) -> set[str]:
        names: set[str] = set()
        for path in source_dir.rglob("*.rs"):
            names.update(cls.EXPORT_PATTERN.findall(path.read_text("utf-8")))
        return names

    @classmethod
    def _assert_mirrored(
        cls,
        lib_name: str,
        source_dir: Path,
    ) -> None:
        exported = cls._exported(source_dir)
        declared = cls._declared(lib_name)
        assert exported == declared, (
            f"{lib_name} 库导出与声明不一致: 多出 {exported - declared}, "
            f"缺少 {declared - exported}"
        )

    def test_cpu_exports_match_spec(self) -> None:
        self._assert_mirrored("cpu", self.NATIVE_DIR / "cpu" / "src")

    def test_termio_exports_match_spec(self) -> None:
        self._assert_mirrored("termio", self.NATIVE_DIR / "termio" / "src")

    def test_struct_sizes_match_rust_layout(self) -> None:
        """每个生成的结构体, ctypes 字节数等于 Rust 侧 DI 元数据给出的字节数."""
        for name, cls in defs_gen.STRUCTS.items():
            assert ctypes.sizeof(cls) == defs_gen.STRUCT_SIZES[name], name
