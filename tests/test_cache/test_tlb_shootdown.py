"""验证跨核 TLB shootdown 同步 — tlb_sync 递增/递减原子模式.

模拟 OpenSBI tlb_update、tlb_sync、tlb_entry_process 的调用链:
  - Hart 1 (发起者): amoadd 递增共享计数器, 随后写 MSIP, 随后自旋直到计数器归零
  - Hart 0 (接收者): 被 WFI 唤醒, 随后 amoadd 递减同一计数器, 随后重新进入 WFI
  - 验证 Hart 1 最终看到计数器=0 且不会死锁

这是 SMP boot 死锁 (ticket spinlock in sbi_fifo.qlock) 的简化版复现.
"""

import struct

from pyremu.core.hart import RiscvMode
from pyremu.emulator import Emulator
from pyremu.platform import PlatformConfig

CLINT_BASE = 0x02000000


def _encode_amoadd_w(rd=5, rs1=10, rs2=11, aq=1, rl=1):
    """amoadd.w rd, rs2, (rs1) — funct5=AMOADD=00000."""
    return (
        (0b00000 << 27)
        | (aq << 26)
        | (rl << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (0b010 << 12)  # .W
        | (rd << 7)
        | 0b0101111
    )


def _encode_lw(rd=6, rs1=10):
    """lw rd, 0(rs1)."""
    return (0b010 << 12) | (rs1 << 15) | (rd << 7) | 0b0000011


def _encode_wfi():
    return 0x10500073


def _encode_nop():
    return 0x00000013


def _encode_j_self():
    """j . — 跳转到自身."""
    return 0x0000006F


class TestTlbSyncCounter:
    """验证 tlb_sync 计数器在跨核 MSIP + AMO 下的正确性."""

    SHARED_ADDR = 0x80001000  # 模拟 tlb_sync[H1] 的内存位置
    H0_BASE = 0x80000000
    H1_BASE = 0x80000100
    MTVEC0 = 0x80003000  # H0 的陷态处理程序入口, 内容为 mret

    @staticmethod
    def _setup_two_mmode_harts(emu):
        # Fill code region with WFI so that harts stop cleanly after
        # executing their test instructions instead of running into
        # zero-filled memory (which decodes as valid loads and loops
        # forever without a max_instrs cap).
        wfi_raw = struct.pack("<I", _encode_wfi())
        for h in emu.harts:
            h.mode = RiscvMode.M
            h.satp_val = 0
            h.csrs["mie"].val = 1 << 3  # MSIE
            h.csrs["mstatus"].val = 1 << 3  # MIE=1
            mtvec = 0x80003000 + h.id * 0x1000
            h.csrs["mtvec"].val = mtvec
            # Trap handler: mret
            emu.bus.write(mtvec, struct.pack("<I", 0x30200073))
            # Fill per-hart code area with WFI (don't touch mtvec)
            code_base = 0x80000000 + h.id * 0x100
            for offset in range(0, 256, 4):
                addr = code_base + offset
                if addr != mtvec:
                    emu.bus.write(addr, wfi_raw)

    @classmethod
    def _setup_pair(cls):
        """构造两个 M 模式 hart: H0 待测, H1 在原地跳转保持活跃.

        H1 必须保持活跃: 构造时两个 hart 的代码区都填充了 WFI, 若 H1 也进入
        等待, ``Emulator.step()`` 在全部未停机 hart 都等待时阻塞本线程, 直到
        有中断或外部事件唤醒, 用例将无法推进.
        """
        cfg = PlatformConfig(
            num_harts=2, ram_base=0x80000000, ram_size=64 * 1024 * 1024
        )
        emu = Emulator(cfg, bootargs="")
        h0, h1 = emu.harts
        cls._setup_two_mmode_harts(emu)
        emu.bus.write(cls.H1_BASE, struct.pack("<I", _encode_j_self()))
        h1.pc = cls.H1_BASE
        return emu, h0, h1

    @staticmethod
    def _run_until(emu, cond, limit: int = 8) -> bool:
        """逐条执行指令直到 cond 成立或达到步数上限, 返回 cond 的最终取值."""
        for _ in range(limit):
            if cond():
                return True
            emu.step()
        return cond()

    # ================================================================
    #  Test 1: 基本场景 — H1 amoadd +1 ->H0 amoadd -1
    # ================================================================

    def test_basic_amo_cross_hart_visibility(self):
        """H0 的 amoadd 写入应对 H1 的 lw 立即可见."""
        cfg = PlatformConfig(
            num_harts=2, ram_base=0x80000000, ram_size=64 * 1024 * 1024
        )
        emu = Emulator(cfg, bootargs="")
        h0, h1 = emu.harts
        self._setup_two_mmode_harts(emu)

        # 将共享计数器初始化为 1
        emu.bus.write(self.SHARED_ADDR, struct.pack("<I", 1))

        # H0: amoadd.w t0, a1, (a0) — 递减 1
        instr = _encode_amoadd_w(rd=5, rs1=10, rs2=11)
        emu.bus.write(self.H0_BASE, struct.pack("<I", instr))
        h0.pc = self.H0_BASE
        h0.gprs[10] = self.SHARED_ADDR  # rs1 = addr
        h0.gprs[11] = 0xFFFF_FFFF  # rs2 = -1
        h0.exec_instr(instr)

        after = struct.unpack("<I", emu.bus.read(self.SHARED_ADDR, 4))[0]
        h0_rd = h0.gprs[5] & 0xFFFF_FFFF

        assert after == 0, f"递减后应为 0, 实际 {after}"
        assert h0_rd == 1, f"amoadd 应返回旧值 1, 实际 {h0_rd}"

        # H1 读取应看到 0
        instr_lw = _encode_lw(rd=6, rs1=10)
        emu.bus.write(self.H1_BASE, struct.pack("<I", instr_lw))
        h1.pc = self.H1_BASE
        h1.gprs[10] = self.SHARED_ADDR
        h1.exec_instr(instr_lw)
        assert (h1.gprs[6] & 0xFFFF_FFFF) == 0, (
            f"H1 应读到 H0 的写入结果 0, 实际 {h1.gprs[6] & 0xFFFF_FFFF}"
        )

    # ================================================================
    #  Test 2: WFI 唤醒后执行 AMO — 完整的 MSIP 唤醒与 AMO 执行流程
    # ================================================================

    def test_wfi_wake_then_amo(self):
        """H0 在 WFI 等待时被 H1 写 MSIP 唤醒, 中断返回后执行 AMOADD 递减
        共享计数器."""
        emu, h0, _h1 = self._setup_pair()
        emu.bus.write(self.SHARED_ADDR, struct.pack("<I", 1))

        # H0 代码: WFI (+0) -> AMOADD -1 (+4)
        emu.bus.write(self.H0_BASE, struct.pack("<I", _encode_wfi()))
        emu.bus.write(
            self.H0_BASE + 4,
            struct.pack("<I", _encode_amoadd_w(rd=5, rs1=10, rs2=11)),
        )
        h0.pc = self.H0_BASE
        h0.gprs[10] = self.SHARED_ADDR
        h0.gprs[11] = 0xFFFF_FFFF  # -1

        assert self._run_until(emu, lambda: h0._waiting), "H0 应进入 WFI 等待"
        assert h0.pc == self.H0_BASE + 4, f"WFI 之后 PC 应推进, 实际 {h0.pc:#x}"

        # H1 写 CLINT MSIP[0] = 1, H0 在下一轮被唤醒并立即投递 M 模式中断
        emu.bus.write(CLINT_BASE, struct.pack("<I", 1))
        emu.step()
        assert not h0._waiting, "H0 应被 MSIP 唤醒"
        assert h0.pc == self.MTVEC0, f"唤醒后应进入 mtvec, 实际 {h0.pc:#x}"

        # 中断处理程序写 0 撤销 MSIP; mret 返回被中断处
        emu.bus.write(CLINT_BASE, struct.pack("<I", 0))
        emu.step()
        assert h0.pc == self.H0_BASE + 4, (
            f"mret 应回到 WFI 的下一条指令, 实际 {h0.pc:#x}"
        )

        emu.step()
        after = struct.unpack("<I", emu.bus.read(self.SHARED_ADDR, 4))[0]
        h0_rd = h0.gprs[5] & 0xFFFF_FFFF

        assert after == 0, f"MSIP 唤醒后 H0 amoadd: 1->0 期望, 实际 {after}"
        assert h0_rd == 1, f"amoadd 应返回旧值 1, 实际 {h0_rd}"

    # ================================================================
    #  Test 3: 完整 tlb_sync 模拟
    # ================================================================

    def test_tlb_sync_simulation(self):
        """完整模拟 tlb_sync 协议: 唤醒、中断返回、递减、重新进入 WFI.

        H0 的代码布局: WFI (+0) -> AMOADD -1 (+4) -> WFI (+8), 陷态处理程序
        在 mtvec 处为 mret, 中断返回后 PC 回到 WFI 的下一条指令.

        流程:
          1. H0 执行 WFI 进入等待
          2. H1 通过 Bus.write 设置 MSIP[0] (模拟 sbi_ipi_send_many)
          3. H0 在下一轮被唤醒并陷入 mtvec; 处理程序写 0 撤销 MSIP 后 mret
          4. H0 执行 AMOADD 递减共享变量, 随后回到 +8 的 WFI 重新等待
          5. H1 读共享变量, 应为 0
        """
        emu, h0, h1 = self._setup_pair()

        # tlb_sync 原始值 = 1 (模拟 H1 的 tlb_update 递增后)
        emu.bus.write(self.SHARED_ADDR, struct.pack("<I", 1))

        # H0 代码: wfi ->amoadd -1 ->wfi
        instr_dec = _encode_amoadd_w(rd=5, rs1=10, rs2=11)
        emu.bus.write(self.H0_BASE, struct.pack("<I", _encode_wfi()))  # +0
        emu.bus.write(self.H0_BASE + 4, struct.pack("<I", instr_dec))  # +4
        emu.bus.write(self.H0_BASE + 8, struct.pack("<I", _encode_wfi()))  # +8

        # 预设 H0 寄存器
        h0.gprs[10] = self.SHARED_ADDR  # rs1 = addr
        h0.gprs[11] = 0xFFFF_FFFF  # rs2 = -1
        h0.pc = self.H0_BASE

        # --- 阶段 1: 让 H0 进入 WFI ---
        assert self._run_until(emu, lambda: h0._waiting), "H0 应在 WFI (阶段 1)"

        # --- 阶段 2: H1 发送 MSIP[0] (模拟 sbi_ipi_send_many) ---
        emu.bus.write(CLINT_BASE, struct.pack("<I", 1))
        emu.step()
        assert not h0._waiting, "H0 应被 MSIP 唤醒 (阶段 2)"
        assert h0.pc == self.MTVEC0, f"唤醒后应进入 mtvec, 实际 {h0.pc:#x}"

        # MSIP 必须撤销, 否则 mret 之后中断立即再次投递, AMOADD 不会执行
        emu.bus.write(CLINT_BASE, struct.pack("<I", 0))
        emu.step()
        assert h0.pc == self.H0_BASE + 4, f"mret 应回到 AMOADD, 实际 {h0.pc:#x}"

        # --- 阶段 3: 验证 H0 执行了 amoadd -1 ---
        emu.step()
        after = struct.unpack("<I", emu.bus.read(self.SHARED_ADDR, 4))[0]
        h0_rd = h0.gprs[5] & 0xFFFF_FFFF

        assert after == 0, f"递减后应为 0, 实际 {after}"
        assert h0_rd == 1, f"amoadd 应返回旧值 1, 实际 {h0_rd}"

        # 唤醒后 _wfi_woken 仍为真: 紧随其后的第一条 WFI (+8) 按 NOP 处理,
        # 使 while (cond) wfi(); 形式的循环得以重新检查条件; 第二条 WFI (+0xC)
        # 才真正进入等待
        assert self._run_until(emu, lambda: h0._waiting), "H0 应重新进入 WFI"
        assert h0.pc == self.H0_BASE + 0x10, (
            f"WFI 之后 PC 应推进, 实际 {h0.pc:#x}"
        )

        # --- 阶段 4: H1 读取应看到 0 (模拟 tlb_sync 自旋退出) ---
        lw_instr = _encode_lw(rd=6, rs1=10)
        emu.bus.write(self.H1_BASE + 4, struct.pack("<I", lw_instr))
        h1.pc = self.H1_BASE + 4
        h1.gprs[10] = self.SHARED_ADDR
        h1.exec_instr(lw_instr)
        h1_sees = h1.gprs[6] & 0xFFFF_FFFF

        assert h1_sees == 0, f"H1 应看到 tlb_sync=0, 实际 {h1_sees}"

    # ================================================================
    #  Test 4: 多次 MSIP 唤醒 + AMO 的序列正确性
    # ================================================================

    def test_multiple_wake_amo_sequence(self):
        """连续两次 MSIP 唤醒, 每次中断返回后执行一条 AMOADD, 计数器由 2
        递减到 0."""
        emu, h0, _h1 = self._setup_pair()
        emu.bus.write(self.SHARED_ADDR, struct.pack("<I", 2))  # 起始=2

        # H0 代码: WFI (+0) -> AMOADD -1 (+4) -> WFI (+8, 唤醒后的第一条 WFI,
        # 按 NOP 处理) -> WFI (+0xC) -> AMOADD -1 (+0x10)
        emu.bus.write(self.H0_BASE, struct.pack("<I", _encode_wfi()))
        emu.bus.write(
            self.H0_BASE + 4,
            struct.pack("<I", _encode_amoadd_w(rd=5, rs1=10, rs2=11)),
        )
        emu.bus.write(self.H0_BASE + 8, struct.pack("<I", _encode_wfi()))
        emu.bus.write(self.H0_BASE + 0xC, struct.pack("<I", _encode_wfi()))
        emu.bus.write(
            self.H0_BASE + 0x10,
            struct.pack("<I", _encode_amoadd_w(rd=5, rs1=10, rs2=11)),
        )
        h0.pc = self.H0_BASE
        h0.gprs[10] = self.SHARED_ADDR
        h0.gprs[11] = 0xFFFF_FFFF

        for round_index, (expected_after, expected_rd, resume_pc) in enumerate(
            [(1, 2, self.H0_BASE + 4), (0, 1, self.H0_BASE + 0x10)]
        ):
            assert self._run_until(emu, lambda: h0._waiting), (
                f"第 {round_index + 1} 次唤醒前 H0 应处于 WFI"
            )
            emu.bus.write(CLINT_BASE, struct.pack("<I", 1))
            emu.step()
            assert not h0._waiting, (
                f"第 {round_index + 1} 次唤醒后 H0 不应处于 WFI"
            )
            assert h0.pc == self.MTVEC0, f"唤醒后应进入 mtvec, 实际 {h0.pc:#x}"

            emu.bus.write(CLINT_BASE, struct.pack("<I", 0))
            emu.step()
            assert h0.pc == resume_pc, (
                f"mret 应回到 {resume_pc:#x}, 实际 {h0.pc:#x}"
            )

            emu.step()
            counter = struct.unpack("<I", emu.bus.read(self.SHARED_ADDR, 4))[0]
            assert counter == expected_after, (
                f"第 {round_index + 1} 次递减后应为 {expected_after}, "
                f"实际 {counter}"
            )
            assert (h0.gprs[5] & 0xFFFF_FFFF) == expected_rd, (
                f"第 {round_index + 1} 次 amoadd 应返回旧值 {expected_rd}, "
                f"实际 {h0.gprs[5] & 0xFFFF_FFFF}"
            )
