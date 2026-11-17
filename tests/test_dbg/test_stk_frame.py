#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.stk_frame — 栈回溯与跨特权级边界帧."""

from pyremu.core.hart import RiscvMode
from tests.conftest import (
    make_test_dbg,
)


class TestStackWalk:
    """栈帧回溯."""

    def test_single_frame_when_fp_zero(self):
        dbg = make_test_dbg()
        h = dbg.hart
        h.gprs[8] = 0  # fp = 0
        frames = dbg._walk_frame_chain()
        assert len(frames) == 1
        assert frames[0].idx == 0
        assert frames[0].pc == h.pc

    def test_frame_chain_with_valid_fp(self):
        """构造 3 层栈帧链: fp-8=ra, fp-16=saved_fp.

        _walk_frame_chain 在 saved_ra==0 时提前 break (不追加空帧),
        因此要得到 N 帧需要 N-1 层非零 RA 链接.

        链末帧的 RA 已用于算出该帧自身的 pc, 不再追加 pc 相同的帧.
        """
        dbg = make_test_dbg()
        h = dbg.hart

        # 帧 #0 (当前): sp=0x80001000, fp=0x80001080
        h.gprs[2] = 0x80001000  # sp
        h.gprs[8] = 0x80001080  # fp

        bus = dbg._emu.bus
        # 帧 #1 链接 (fp=0x80001080): RA->call_site_A, saved_fp->F1
        bus.write(0x80001080 - 16, (0x80001100).to_bytes(8, "little"))
        bus.write(0x80001080 - 8, (0x80000200).to_bytes(8, "little"))

        # 帧 #2 链接 (fp=0x80001100): RA->call_site_B, saved_fp->F2
        bus.write(0x80001100 - 16, (0x80001180).to_bytes(8, "little"))
        bus.write(0x80001100 - 8, (0x80000300).to_bytes(8, "little"))

        # 帧 #3 链接 (fp=0x80001180): terminal — RA=0 导致 walk 截断
        bus.write(0x80001180 - 16, (0).to_bytes(8, "little"))
        bus.write(0x80001180 - 8, (0).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()
        assert len(frames) == 3
        assert frames[0].idx == 0
        assert frames[0].fp == 0x80001080
        assert frames[1].idx == 1
        assert frames[1].fp == 0x80001100
        # frames[1].pc = ra - 4 = 0x80000200 - 4
        assert frames[1].pc == 0x800001FC
        assert frames[1].ra == 0x80000200
        assert frames[2].idx == 2
        assert frames[2].fp == 0x80001180
        assert frames[2].ra == 0x80000300
        # 帧 #2 的 RA 已用于算出 frames[2].pc, 不再追加重复帧
        assert frames[2].pc == 0x800002FC

    def test_stack_walk_detects_cycle(self):
        """FP 链成环 -> 截断回溯."""
        dbg = make_test_dbg()
        h = dbg.hart
        h.gprs[8] = 0x80001000  # fp
        bus = dbg._emu.bus
        bus.write(0x80001000 - 16, (0x80001000).to_bytes(8, "little"))
        bus.write(0x80001000 - 8, (0x80000400).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()
        assert len(frames) <= 2, f"{len(frames)}!"

    def test_cmd_frame_shows_backtrace(self):
        dbg = make_test_dbg()
        dbg.hart.gprs[8] = 0
        dbg.cmd_frame()  # 单帧

    def test_cmd_frame_with_valid_fp(self):
        dbg = make_test_dbg()
        h = dbg.hart
        h.gprs[2] = 0x80001000
        h.gprs[8] = 0x80001080
        bus = dbg._emu.bus
        bus.write(0x80001080 - 16, (0x80001100).to_bytes(8, "little"))
        bus.write(0x80001080 - 8, (0x80000400).to_bytes(8, "little"))
        bus.write(0x80001100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x80001100 - 8, (0).to_bytes(8, "little"))
        dbg.cmd_frame()

    def test_cmd_frame_switch(self):
        dbg = make_test_dbg()
        h = dbg.hart
        h.gprs[8] = 0x80001080
        bus = dbg._emu.bus
        bus.write(0x80001080 - 16, (0x80001100).to_bytes(8, "little"))
        bus.write(0x80001080 - 8, (0x80000400).to_bytes(8, "little"))
        bus.write(0x80001100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x80001100 - 8, (0).to_bytes(8, "little"))
        dbg.cmd_frame("1")  # 切换到帧 1
        assert dbg._current_frame_idx == 1

    def test_cmd_frame_out_of_range(self):
        dbg = make_test_dbg()
        dbg.hart.gprs[8] = 0
        dbg.cmd_frame("99")  # 超出范围

    def test_stale_sepc_sv39_ram_addr_skipped(self):
        """Sv39 启用后 SPP=S 时 sepc 为裸 RAM 地址 -> 残留 sepc, 不生成边界帧.

        Kernel 在 S 模式运行 (SPP=S), Sv39 启用, 但 sepc 指向 0x80201048
        (物理 RAM 地址).  这不是真实的 S->S trap 现场 — 内核代码运行在高
        VA (0xffffffc6XXXXXXXX), sepc 中的低地址是 M->S 过渡后的残留值.
        即使 SPP=S 也应跳过.
        """
        dbg = make_test_dbg(ram_size=0x800000)
        h = dbg.hart
        # S 模式, Sv39 启用, 无有效 FP 链
        h.mode = RiscvMode.S
        h.gprs[8] = 0  # fp = 0
        h.gprs[2] = 0x80001000  # sp
        # 设置 mstatus: SPP=S (bit 8), MPP=S
        h.csrs["mstatus"].val = h.csrs["mstatus"].val | (1 << 8)  # SPP=1
        # 启用 Sv39 (satp MODE=8) — 必须经 satp_val setter 更新 _mmu_mode
        root_ppn = 0x80000
        h.satp_val = (8 << 60) | root_ppn
        # 模拟残留 sepc: 内核入口 PA (非 Sv39 规范高 VA)
        h.csrs["sepc"].val = 0x80201048
        # stvec 指向合法代码
        stvec_addr = 0x80008000
        h.csrs["stvec"].val = stvec_addr
        dbg._emu.bus.write(stvec_addr, (0x00008067).to_bytes(4, "little"))

        frames = dbg._walk_frame_chain()
        # Sv39 启用时 sepc 为裸 RAM 地址 -> 残留, 不生成边界帧
        assert len(frames) == 1, (
            f"Sv39 + RAM sepc 不应生成边界帧 (即使是 SPP=S), "
            f"但得到 {len(frames)} 帧"
        )
        assert frames[0].idx == 0

    def test_ra_corruption_live_x1_falls_back_to_saved_ra(self):
        """live x1 被函数覆盖 (如 blake2s) 时降级使用栈上保存的 RA.

        blake2s_compress_generic 的 G 宏将 x1 用作临时寄存器,
        导致 live x1 变为非合法代码地址 (0xed462571a7333171).
        但栈上 fp-8 的 saved_ra 仍然有效, 回溯应降级使用.
        """
        dbg = make_test_dbg()
        h = dbg.hart
        bus = dbg._emu.bus

        # 帧 #0 (当前): 模拟 blake2s_compress_generic
        h.pc = 0x80001000
        h.gprs[1] = 0xDEADBEEF  # live x1 — 被哈希函数覆盖
        h.gprs[2] = 0x8000F000  # sp
        h.gprs[8] = 0x8000F080  # fp

        # 帧 #1 链接 (fp=0x8000F080):
        #   fp-16: saved_fp -> 0x8000F100 (caller's fp)
        #   fp-8:  saved_ra -> 0x80002000 (valid return address)
        bus.write(0x8000F080 - 16, (0x8000F100).to_bytes(8, "little"))
        bus.write(0x8000F080 - 8, (0x80002000).to_bytes(8, "little"))

        # 帧 #2 链接 (fp=0x8000F100): terminal
        bus.write(0x8000F100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x8000F100 - 8, (0).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()

        assert len(frames) >= 2, (
            f"应至少有帧 #0 和帧 #1, 但只有 {len(frames)} 帧"
        )
        # 帧 #1 为调用者: pc 应取 saved_ra 0x80002000, 不取 live x1 0xDEADBEEF
        frame1 = frames[1]
        assert frame1.pc == 0x80001FFC, (
            f"帧 #1 pc 应 = saved_ra - 4 = 0x80001FFC, 但得到 0x{frame1.pc:x}"
        )
        # 帧 #1 ra 应为栈上保存的 0x80002000
        assert frame1.ra == 0x80002000, (
            f"帧 #1 ra 应为 saved_ra = 0x80002000, 但得到 0x{frame1.ra:x}"
        )
        # 帧 #0 应无 note (当前帧不检查 RA 合法性)
        assert not frames[0].note

    def test_ra_corruption_both_live_and_saved_invalid(self):
        """live x1 和 saved_ra 均为非法地址时, 帧带损坏标记.

        极端情况: 函数不仅覆盖了 x1, 栈帧 fp-8 也被覆写.
        """
        dbg = make_test_dbg()
        h = dbg.hart
        bus = dbg._emu.bus

        h.pc = 0x80001000
        h.gprs[1] = 0xDEADBEEF  # live x1 — 非法
        h.gprs[2] = 0x8000F000
        h.gprs[8] = 0x8000F080

        # saved_ra 也是非法地址 (栈被哈希中间数据覆写)
        bus.write(0x8000F080 - 16, (0x8000F100).to_bytes(8, "little"))
        bus.write(0x8000F080 - 8, (0xCAFEBABE).to_bytes(8, "little"))  # 非法

        # 终端帧
        bus.write(0x8000F100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x8000F100 - 8, (0).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()
        assert len(frames) >= 2
        # 帧 #1 应带有损坏标记
        frame1 = frames[1]
        assert frame1.note, "帧 #1 在 RA 完全不可恢复时应带有损坏标记"

    def test_frameless_function_keeps_caller_frame(self):
        """当前函数没有自己的帧时, x1 的当前值给出其调用者帧.

        sp == fp 时 fp 指向调用者的帧, [fp-8] 是调用者的返回地址. 若以它取代
        x1, 当前函数所在的那一级被并入更上一层, 回溯少一帧.
        """
        dbg = make_test_dbg()
        h = dbg.hart
        bus = dbg._emu.bus
        h.pc = 0x80003000
        h.gprs[1] = 0x80002000  # x1: 当前函数返回调用者
        h.gprs[2] = 0x8000F080  # sp == fp
        h.gprs[8] = 0x8000F080  # fp: 调用者的帧
        bus.write(0x8000F080 - 16, (0x8000F100).to_bytes(8, "little"))
        bus.write(0x8000F080 - 8, (0x80004000).to_bytes(8, "little"))
        bus.write(0x8000F100 - 16, (0x8000F180).to_bytes(8, "little"))
        bus.write(0x8000F100 - 8, (0x80006000).to_bytes(8, "little"))
        bus.write(0x8000F180 - 16, (0).to_bytes(8, "little"))
        bus.write(0x8000F180 - 8, (0).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()
        assert [f.pc for f in frames] == [
            0x80003000,
            0x80001FFC,
            0x80003FFC,
            0x80005FFC,
        ], f"{[hex(f.pc) for f in frames]}"
        assert frames[1].ra == 0x80002000
        assert frames[2].ra == 0x80004000


class TestUmodeBacktrace:
    """U-mode 直接回溯与 S->U 边界帧恢复."""

    # ---------- 直接 U-mode FP 链 ----------

    def test_umode_fp_chain_walk(self):
        """hart 处于 U-mode 时, FP 链帧全部标记为 U.

        使用 Bare 翻译 (mmu_mode=0), VA=PA.
        """
        dbg = make_test_dbg(ram_size=0x20000)
        h = dbg.hart
        bus = dbg._emu.bus

        h.mode = RiscvMode.U
        h._mmu_mode = 0  # Bare 翻译
        h.pc = 0x80001000
        h.gprs[1] = 0x80002000  # ra (frame #1 uses live x1)
        h.gprs[2] = 0x8000F000  # sp
        h.gprs[8] = 0x8000F080  # fp

        # 帧 #1 链接: saved_ra=0x80004000, saved_fp=0x8000F100
        bus.write(0x8000F080 - 16, (0x8000F100).to_bytes(8, "little"))
        bus.write(0x8000F080 - 8, (0x80004000).to_bytes(8, "little"))
        # 帧 #2 链接: terminal
        bus.write(0x8000F100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x8000F100 - 8, (0).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()
        assert len(frames) >= 3, f"应有 >=3 帧, 但只有 {len(frames)}"
        for i, f in enumerate(frames):
            assert f.mode == "U", f"帧 #{i} mode={f.mode!r}, 预期 U"
        assert frames[0].pc == 0x80001000
        # 帧 #1 由 x1 的当前值给出, 帧 #2 由 [fp-8] 给出
        assert frames[1].pc == 0x80001FFC
        assert frames[1].ra == 0x80002000
        assert frames[2].pc == 0x80003FFC
        assert frames[2].ra == 0x80004000

    def test_umode_single_frame_when_fp_zero(self):
        """U-mode 且 fp=0 时仅有当前帧."""
        dbg = make_test_dbg()
        h = dbg.hart
        h.mode = RiscvMode.U
        h._mmu_mode = 0
        h.pc = 0x80001000
        h.gprs[8] = 0  # fp = 0

        frames = dbg._walk_frame_chain()
        assert len(frames) == 1
        assert frames[0].mode == "U"

    def test_umode_ra_inference_when_fp_chain_broken(self):
        """FP 链不可达时 (fp=0), 由 live RA 推断一个调用者帧."""
        dbg = make_test_dbg()
        h = dbg.hart
        h.mode = RiscvMode.U
        h._mmu_mode = 0
        h.pc = 0x80001000
        h.gprs[1] = 0x80002000  # ra — 有效返回地址
        h.gprs[8] = 0  # fp = 0 ->FP 链不可达

        frames = dbg._walk_frame_chain()
        assert len(frames) == 2, (
            f"RA 推断应产生 1 个调用者帧 (共 2 帧), 但只有 {len(frames)}"
        )
        assert frames[0].mode == "U"
        assert frames[1].mode == "U"
        assert frames[1].pc == 0x80001FFC  # ra - 4
        assert frames[1].fp == 0

    # ---------- S->U 边界帧恢复 ----------

    def test_smode_to_umode_boundary(self):
        """S-mode 下 SPP=U: 从 sepc 恢复 U-mode FP 链."""
        dbg = make_test_dbg(ram_size=0x20000)
        h = dbg.hart
        bus = dbg._emu.bus

        # S-mode 当前状态
        h.mode = RiscvMode.S
        h._mmu_mode = 0
        h.pc = 0x80010000  # S-mode kernel code
        h.gprs[2] = 0x8001F000  # S-mode sp
        h.gprs[8] = 0x8001F080  # S-mode fp

        bus.write(0x8001F080 - 16, (0x8001F100).to_bytes(8, "little"))
        bus.write(0x8001F080 - 8, (0x80010200).to_bytes(8, "little"))
        bus.write(0x8001F100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x8001F100 - 8, (0).to_bytes(8, "little"))

        # Trap CSRs: S-mode 捕获 U-mode 异常
        h.csrs["sepc"].val = 0x80003AE8  # U-mode PC (fault site, valid PA)
        h.csrs["scause"].val = 0xD  # LoadPageFault
        h.csrs["mstatus"].val = h.csrs["mstatus"].val & ~(1 << 8)

        # stvec 指向含 RA/FP 保存的 trap 入口
        # addi sp,sp,-240; sd x1,0(sp); sd x8,8(sp)
        tvec_addr = 0x80018000
        h.csrs["stvec"].val = tvec_addr
        trap_entry = bytes(
            [
                0x13,
                0x01,
                0x01,
                0xF1,  # addi sp, sp, -240
                0x23,
                0x30,
                0x11,
                0x00,  # sd   x1, 0(sp)
                0x23,
                0x34,
                0x81,
                0x00,  # sd   x8, 8(sp)
            ]
        )
        bus.write(tvec_addr, trap_entry)

        # S-mode 内核栈上的 trap 帧 — 由栈扫描找到
        trap_sp = 0x8001E000
        bus.write(trap_sp, (0x80003AE8).to_bytes(8, "little"))  # trapped PC
        bus.write(trap_sp + 0, (0).to_bytes(8, "little"))  # zero verify (sp+0)
        # saved_ra @ ra_off=8
        bus.write(trap_sp + 8, (0x80002000).to_bytes(8, "little"))
        # saved_fp @ fp_off=16
        bus.write(trap_sp + 16, (0x8000F080).to_bytes(8, "little"))

        # U-mode FP 链 (位于 saved_fp=0x8000F080)
        bus.write(0x8000F080 - 16, (0x8000F100).to_bytes(8, "little"))
        bus.write(0x8000F080 - 8, (0x80003000).to_bytes(8, "little"))
        bus.write(0x8000F100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x8000F100 - 8, (0).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()

        umode_frames = [f for f in frames if f.mode == "U"]
        assert len(umode_frames) >= 1, (
            f"{[(f.idx, f.mode, hex(f.pc)) for f in frames]}"
        )

    # ---------- Fallback trap offsets ----------

    def test_fallback_trap_offsets_for_s_to_u(self):
        """S->U 边界且 stvec 无 sd x1/sd x8 时, 回退到常见布局扫描."""
        dbg = make_test_dbg(ram_size=0x30000)
        h = dbg.hart
        bus = dbg._emu.bus

        # S-mode 当前状态 (fp=0 ->FP 链立即终止)
        h.mode = RiscvMode.S
        h._mmu_mode = 0
        h.pc = 0x80010000
        h.gprs[8] = 0  # fp=0
        h.gprs[2] = 0x8001F000

        # Trap CSRs: SPP=U
        h.csrs["sepc"].val = 0x80001000  # U-mode PC
        h.csrs["mstatus"].val = h.csrs["mstatus"].val & ~(1 << 8)

        # stvec: ret 指令 — _parse_trap_save_offsets 返回 None
        tvec_addr = 0x80018000
        h.csrs["stvec"].val = tvec_addr
        bus.write(tvec_addr, (0x00008067).to_bytes(4, "little"))  # ret

        trap_sp = 0x8001E000
        bus.write(trap_sp, (0x80001000).to_bytes(8, "little"))  # trapped PC
        bus.write(trap_sp + 0, (0).to_bytes(8, "little"))  # zero verify
        # saved_ra @ ra_off=0, 但 zero verify 在同一个位置,
        # 所以 ra_off=0 布局无法通过
        # 用 ra_off=8, fp_off=64 (Linux pt_regs) 布局
        # 在 trap_sp 上方找位置放 saved_ra
        # saved_ra @ ra_off=8
        bus.write(trap_sp + 8, (0x80002000).to_bytes(8, "little"))
        # saved_fp @ fp_off=64
        bus.write(trap_sp + 64, (0x8000F080).to_bytes(8, "little"))

        # U-mode FP 链
        bus.write(0x8000F080 - 16, (0x8000F100).to_bytes(8, "little"))
        bus.write(0x8000F080 - 8, (0x80003000).to_bytes(8, "little"))
        bus.write(0x8000F100 - 16, (0).to_bytes(8, "little"))
        bus.write(0x8000F100 - 8, (0).to_bytes(8, "little"))

        frames = dbg._walk_frame_chain()
        assert len(frames) >= 2, (
            f"fallback 应至少生成 1 个 U-mode 边界帧, 但只有 {len(frames)} 帧"
        )
        modes = [f.mode for f in frames]
        assert "U" in modes, f"fallback 后应有 U-mode 帧, 模式列表: {modes}"

    def test_fallback_all_fail_gives_pc_only_frame(self):
        dbg = make_test_dbg(ram_size=0x20000)
        h = dbg.hart
        bus = dbg._emu.bus

        h.mode = RiscvMode.S
        h._mmu_mode = 0
        h.pc = 0x80010000
        h.gprs[8] = 0  # fp=0

        h.csrs["sepc"].val = 0x80001000  # U-mode PC
        h.csrs["mstatus"].val = h.csrs["mstatus"].val & ~(1 << 8)  # SPP=U

        # stvec: ret — _parse_trap_save_offsets 返回 None
        tvec_addr = 0x80018000
        h.csrs["stvec"].val = tvec_addr
        bus.write(tvec_addr, (0x00008067).to_bytes(4, "little"))

        # 不写任何 trap 帧数据 ->所有 fallback 布局在栈扫描中找不到 trapped PC
        # _add_prev_mode_frame_fallback 捕获此情况并回退到仅 PC 帧

        frames = dbg._walk_frame_chain()
        assert len(frames) >= 2, (
            f"fallback 应回退到仅 PC 帧 (>=2 帧), 但只有 {len(frames)}: "
            f"{[(f.idx, f.mode, f.note) for f in frames]}"
        )
        last = frames[-1]
        assert "无法解析" in last.note, (
            f"fallback 失败时应带 '无法解析' 备注, 实际: {last.note!r}"
        )
