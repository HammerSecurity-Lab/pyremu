#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""与加速执行引擎的随机差分, 以及引擎在中断与原子操作上的行为."""

from __future__ import annotations

import random
from unittest import mock

import pytest

from pyremu.core.hart import RiscvMode
from pyremu.emulator import Emulator, RunStopReason
from pyremu.generic_ops import run_parallel
from tests.conftest import make_test_config, make_test_emu
from tests.instr_encode import (
    b_type,
    i_type,
    pack_funct,
    pack_src_regs,
    r_type,
    s_type,
)


class TestNativeBatchBitmanip:
    """加速执行引擎执行 Zba / Zbb / Zbs 指令.

    回归: 加速执行引擎曾对 orc.b 返回非法指令陷态, Linux 的 strlen_zbb 首次执行
    时投递 IllInstr, 内核停在 sepc 指向 orc.b 的位置 (mtval=0x28735313).
    """

    TEXT_PA = 0x1000
    # orc.b x6,x6 / rev8 x7,x7 / sh1add x9,x8,x9
    PROG = bytes.fromhex("1353732893d3836bb3249420")

    def test_bitmanip_executes_in_batch(self):
        emu = Emulator(
            num_harts=1,
            prog_cnt=0x1000,
            ram_base=0,
            ram_size=64 * 1024,
        )
        h = emu.harts[0]
        h.gprs[6] = 0x0100
        h.gprs[7] = 0x0123_4567_89AB_CDEF
        h.gprs[8] = 1
        h.gprs[9] = 0
        emu.load_code(self.TEXT_PA, self.PROG)
        h.pc = self.TEXT_PA
        emu._bp_addrs = [self.TEXT_PA + len(self.PROG)]

        emu.run(timeout=15)

        assert emu._run_stop_reason == RunStopReason.BREAKPOINT, (
            f"应在程序末尾命中断点, 实际 reason={emu._run_stop_reason} "
            f"pc=0x{h.pc:x} mcause=0x{h.csrs['mcause'].val:x}"
        )
        assert h.csrs["mcause"].val == 0, "不应投递任何异常"
        assert h.gprs[6] == 0xFF00, f"orc.b 结果错误: {h.gprs[6]:#x}"
        assert h.gprs[7] == 0xEFCD_AB89_6745_2301, (
            f"rev8 结果错误: {h.gprs[7]:#x}"
        )
        assert h.gprs[9] == 2, f"sh1add 结果错误: {h.gprs[9]:#x}"


class TestNativeBatchAmoWSignExtension:
    """加速执行引擎执行 AMO.W 时把写入前读出的 32 位值符号扩展到 64 位.

    引擎的原子读改写路径把该值按无符号 32 位零扩展写回 rd, 使 rd 得到
    0x0000_0000_8000_0000 而非 0xFFFF_FFFF_8000_0000. 取 bit31 为 1 的取值,
    使零扩展与符号扩展的结果不同.
    """

    TEXT_PA = 0x1000
    DATA_PA = 0x4000
    # amoadd.w x14, x7, (x6) / addi x0, x0, 0
    PROG = bytes.fromhex("2f277300" + "13000000")

    def test_amoadd_w_sign_extends_old_value(self):
        emu = Emulator(
            num_harts=1, prog_cnt=self.TEXT_PA, ram_base=0, ram_size=64 * 1024
        )
        assert emu._speedup_hart_states is not None, (
            "回归测试必须走加速执行引擎"
        )
        h = emu.harts[0]
        h.gprs[6] = self.DATA_PA
        h.gprs[7] = 0x8000_0000
        h.gprs[14] = 0x1111
        emu.load_code(self.TEXT_PA, self.PROG)
        emu.load_code(self.DATA_PA, (0x8000_0000).to_bytes(4, "little"))
        h.pc = self.TEXT_PA
        emu._bp_addrs = [self.TEXT_PA + len(self.PROG)]

        emu.run(timeout=15)
        emu.close()

        assert emu._run_stop_reason == RunStopReason.BREAKPOINT, (
            f"应在程序末尾命中断点, 实际 reason={emu._run_stop_reason} "
            f"pc=0x{h.pc:x} mcause=0x{h.csrs['mcause'].val:x}"
        )
        assert h.gprs[14] == 0xFFFF_FFFF_8000_0000, (
            f"AMO.W 写回 rd 的值应为符号扩展结果, 实际 {h.gprs[14]:#x}"
        )
        assert emu.bus.read(self.DATA_PA, 4) == bytes(4), "内存应写入 32 位和 0"


class TestNativeScReservation:
    """加速执行引擎的 SC 仅按地址判定预留是否有效.

    引擎的并发原子路径曾以 LR 读出的值作 compare_exchange 的比较基准. LR.W 与
    SC.D 成对出现时两者的宽度不同, 该比较必然失败: SC 写回 1 且不写内存, 与
    解释器写回 0 并写内存的结果相反. 初值取 bit31 置位的值, 使符号扩展后的
    32 位读出值与 64 位内存内容不同.
    """

    TEXT_PA = 0x1000
    DATA_PA = 0x4000
    DATA_INIT = 0x8000_0000
    STORE_VAL = 0xDEAD_BEEF_0000_0001
    LR_W_LR_READ_EXT = 0xFFFF_FFFF_8000_0000

    def _prepare(self):
        # lr.w x24, (x5) / sc.d x3, x7, (x5) / addi x0, x0, 0
        lr_w = (0x02 << 27) | (5 << 15) | (2 << 12) | (24 << 7) | 0x2F
        sc_d = (
            (0x03 << 27) | (7 << 20) | (5 << 15) | (3 << 12) | (3 << 7) | 0x2F
        )
        prog = b"".join(w.to_bytes(4, "little") for w in (lr_w, sc_d, 0x13))
        emu = Emulator(
            num_harts=1,
            prog_cnt=self.TEXT_PA,
            ram_base=0,
            ram_size=64 * 1024,
        )
        h = emu.harts[0]
        h.gprs[3] = 0x1111
        h.gprs[5] = self.DATA_PA
        h.gprs[7] = self.STORE_VAL
        h.gprs[24] = 0
        emu.load_code(self.TEXT_PA, prog)
        emu.load_code(self.DATA_PA, self.DATA_INIT.to_bytes(4, "little"))
        h.pc = self.TEXT_PA
        return emu, h, prog

    def _readbacks(self, emu, h):
        return (
            h.gprs[3],
            h.gprs[24],
            int.from_bytes(emu.bus.read(self.DATA_PA, 8), "little"),
            h.reservation_valid,
        )

    def _run_engine(self):
        emu, h, prog = self._prepare()
        assert emu._speedup_hart_states is not None, (
            "回归测试必须走加速执行引擎"
        )
        emu._bp_addrs = [self.TEXT_PA + len(prog)]
        emu.run(timeout=15)
        out = self._readbacks(emu, h)
        reason = emu._run_stop_reason
        emu.close()
        assert reason == RunStopReason.BREAKPOINT, (
            f"应在程序末尾命中断点, 实际 reason={reason} "
            f"pc=0x{h.pc:x} mcause=0x{h.csrs['mcause'].val:x}"
        )
        return out

    def _run_interp(self):
        emu, h, prog = self._prepare()
        end_pc = self.TEXT_PA + len(prog)
        steps = 0
        while h.pc != end_pc and steps < 16:
            emu.step()
            steps += 1
        out = self._readbacks(emu, h)
        emu.close()
        return out

    def test_mixed_width_sc_succeeds(self):
        eng = self._run_engine()
        py = self._run_interp()
        assert eng == py, f"引擎 {eng} 与解释器 {py} 的结果不一致"
        rd_sc, rd_lr, mem, is_reserved = eng
        assert rd_sc == 0, (
            f"LR.W 之后对同一地址的 SC.D 应成功, rd 实际 {rd_sc:#x}"
        )
        assert rd_lr == self.LR_W_LR_READ_EXT, (
            f"LR.W 写回 rd 的值应为符号扩展结果, 实际 {rd_lr:#x}"
        )
        assert mem == self.STORE_VAL, (
            f"SC.D 应写入 {self.STORE_VAL:#x}, 实际内存 {mem:#x}"
        )
        assert is_reserved is False, "SC 之后预留应无效"


class TestNativeXonlyFetch:
    """native 引擎对 X-only 页 (R=0, W=0, X=1) 的取指回归.

    回归 (Batch-20 trap loop 根因): Rust ``walk_l0`` / ``walk_l1_leaf`` 对
    取指也强制 PTE_R, 使 runtime 映射在 0xffffffe000001000 的 X-only text
    (trap_vector) 取指被误判 InstrPageFault. 修复后取指仅要求 PTE_X.

    本测试通过 emulator 的 native run_parallel 引擎端到端复现: STIP 投递到
    stvec=trap_vector (X-only 高 VA 页), 若取指失败则陷入 M 模式 trap loop,
    永远命不中断点; 修复后 trap_vector 首条指令被取指+执行, 断点命中.
    """

    # 与 runtime identity_map_trampoline / map_sections 生成值逐位一致:
    #   L1[0x57] = 0x22b800cf  R|W|X 2 MiB superleaf  -> PA 0x8ae00000
    #   L0[1]    = 0x22b804c9  X-only 4 KiB leaf       -> PA 0x8ae01000
    MAN_PA = 0x8AE0_0000
    TRAP_VEC_VA = 0xFFFF_FFE0_0000_1000
    ROOT_PA = 0x8AE0_A000
    L1_LOW_PA = 0x8AE0_B000
    L1_HIGH_PA = 0x8AE0_C000
    L0_HIGH_PA = 0x8AE0_D000
    TEXT_PA = 0x8AE0_1000

    @staticmethod
    def _pte_ptr(target_pa: int) -> int:
        """指针 PTE (V=1, R=W=X=0), 指向 *target_pa*."""
        return 1 | ((target_pa >> 12) << 10)

    def _build_page_tables(
        self,
        emu: Emulator,
    ) -> None:
        """写入 Sv39 页表:
        低 VA identity 超页 + 高 VA X-only trap_vector 映射."""
        ram = emu.bus

        def wr64(pa: int, val: int) -> None:
            ram.write_ram_direct(pa, val.to_bytes(8, "little"))

        # root[vpn2=2] -> L1_LOW (低 VA identity 区域)
        wr64(self.ROOT_PA + 2 * 8, self._pte_ptr(self.L1_LOW_PA))
        # root[vpn2=0x180] -> L1_HIGH (高 VA trap_vector 区域)
        wr64(self.ROOT_PA + 0x180 * 8, self._pte_ptr(self.L1_HIGH_PA))
        # L1_LOW[vpn1=0x57] = R|W|X 2 MiB superleaf -> PA 0x8ae00000
        wr64(self.L1_LOW_PA + 0x57 * 8, 0x22B8_00CF)
        # L1_HIGH[vpn1=0] -> L0_HIGH
        wr64(self.L1_HIGH_PA + 0 * 8, self._pte_ptr(self.L0_HIGH_PA))
        # L0_HIGH[vpn0=1] = X-only leaf (R=0 W=0 X=1, A|D 预置) -> PA 0x8ae01000
        wr64(self.L0_HIGH_PA + 1 * 8, 0x22B8_04C9)

    def _make_enclave_emu(
        self,
    ) -> tuple[Emulator, object]:
        """构建单 hart 模拟器:
        页表 + 代码 + S 模式飞地入口态 (STIP 立即 pending)."""
        # MAN_PA=0x8ae00000 偏移 0xae00000 (182 MiB) > 默认 128 MiB RAM —
        # 必须扩 RAM 才能覆盖 enclave 池与页表 (对齐 make stress 场景).
        emu = make_test_emu(ram_size=0x1000_0000)
        h = emu.harts[0]
        self._build_page_tables(emu)
        # trap_vector: lui x1, 0x5AA (5AA005B7) 然后 NOP 填充
        trap_code = (0x5AA0_05B7).to_bytes(4, "little") + (
            b"\x13\x00\x00\x00" * 255
        )
        emu.load_code(self.TEXT_PA, trap_code)
        # 低 VA 预中断点 NOP 填充
        emu.load_code(self.MAN_PA, b"\x13\x00\x00\x00" * 64)

        # ---- hart 状态 (镜像 OpenSBI 飞地入口 + 全权限 PMP) ----
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["stvec"].val = self.TRAP_VEC_VA
        h.csrs["mideleg"].val = 0x222  # SSI|STI|SEI 委派 S
        h.csrs["mie"].val |= 1 << 5  # STIE
        h.mstatus_val |= 1 << 1  # SIE
        h.csrs["pmpaddr0"].val = (1 << 64) - 1
        h.csrs["pmpcfg0"].val = 0xF
        h._pmp.invalidate_cache()
        # SSTC: stimecmp=1, mtime 置为 1 -> STIP 立即 pending (native 引擎用
        # stimecmp/mtime 重新评估 STIP, 手工 mip 位会被 sync 覆盖)
        h.csrs["stimecmp"].val = 1
        emu.clint._mtime = 1
        # M-mode trap handler 指向低 VA (identity 映射),
        # 便于失败时观察 trap loop
        h.csrs["mtvec"].val = self.MAN_PA
        h.pc = self.MAN_PA
        return emu, h

    def test_xonly_fetch_via_stip_trap_vector(
        self,
    ) -> None:
        """X-only 高 VA trap_vector 在 native 引擎下取指成功并执行.

        修复前 walk_l0 对取指强制 PTE_R -> InstrPageFault -> M 模式 trap loop,
        永不抵达断点; 修复后 trap_vector 首条指令执行, pc 推进到 +4 命中断点.
        """
        emu, h = self._make_enclave_emu()
        emu._bp_addrs = [self.TRAP_VEC_VA + 4]

        emu.run(timeout=15)

        assert emu._run_stop_reason == RunStopReason.BREAKPOINT, (
            f"应在 trap_vector+4 命中断点, 实际 reason={emu._run_stop_reason} "
            f"pc=0x{h.pc:x} mode={h.mode} mcause=0x{h.csrs['mcause'].val:x}"
        )
        assert h.pc == self.TRAP_VEC_VA + 4, (
            "trap_vector 首条指令应被取指+执行 (X-only 页取指成功)"
        )
        assert h.mode == RiscvMode.S, (
            f"不应陷入 M 模式 trap loop, 实际 mode={h.mode}"
        )
        assert h.csrs["mcause"].val == 0, (
            f"不应投递任何异常, 实际 mcause=0x{h.csrs['mcause'].val:x}"
        )

    def test_xonly_page_data_read_still_faults(
        self,
    ) -> None:
        """X-only 页数据读仍被拒绝 (取指放宽不影响 R 位要求)."""
        emu, h = self._make_enclave_emu()
        # 让 S 模式从 X-only 页读取: 若实现错误地把取指放宽波及数据读,
        # 这里将不再触发 LoadPageFault.
        h.pc = self.TRAP_VEC_VA
        h.gprs[4] = self.TRAP_VEC_VA  # ld x1, 0(x4) 的源地址指向 X-only 页
        # 在 trap_vector 放一条加载指令: ld x1, 0(x4) = 0x00023083
        emu.load_code(
            self.TEXT_PA,
            (0x0002_3083).to_bytes(4, "little") + b"\x13\x00\x00\x00" * 255,
        )
        # 关闭 STIP 干扰 (stimecmp 设远未来), 专注数据访问
        h.csrs["stimecmp"].val = 1 << 40
        emu.clint._mtime = 0
        # LoadPageFault (bit 13) 委派 S — 否则同步异常投递到 M 模式写
        # mcause/mtval, scause 不更新 (与 runtime 显式委派页错误的配置一致)
        h.csrs["medeleg"].val |= 1 << 13

        emu.step()

        # S 模式同步异常投递到 stvec, cause 存于 scause (非 mcause)
        assert h.csrs["scause"].val == 13, (  # LoadPageFault
            f"X-only 页数据读应触发 LoadPageFault, "
            f"实际 scause=0x{h.csrs['scause'].val:x}"
        )
        assert h.csrs["stval"].val == self.TRAP_VEC_VA


class TestRandomizedBitAndAtomDiff:
    """随机与边界取值下, 位操作指令与原子指令在两条执行路径上的结果一致.

    这类指令一旦在特定取值上出错, 污染的是寄存器值与内存字, 进而可能
    被用作地址; 逐条编码的定点用例覆盖不到这种组合, 故用固定种子的随机
    取值与边界值各跑一遍, 同时校验目的寄存器与目标内存.
    """

    PC = 0x8000_0000
    DATA = 0x8000_4000
    ZERO_TAIL = b"\x13\x00\x00\x00"  # addi x0, x0, 0

    # 边界值与随机值混合; 随机部分用固定种子保证可复现
    @staticmethod
    def _operands() -> list[int]:
        edges = [
            0,
            1,
            2,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            0x7FFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0xFFFF_FFFF_FFFF_FFFF,
            0x0123_4567_89AB_CDEF,
            0x3F,
            0x40,
        ]
        rng = random.Random(0x5EED)
        rand = [rng.getrandbits(64) for _ in range(6)]
        return edges + rand

    @classmethod
    def _run(cls, code: bytes, regs: dict[int, int], is_engine: bool):
        emu = Emulator(make_test_config())
        emu.load_code(cls.PC, code + cls.ZERO_TAIL)
        emu.load_code(cls.DATA, (0x5A5A_5A5A_5A5A_5A5A).to_bytes(8, "little"))
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        h.pc = cls.PC
        if is_engine:
            emu.add_breakpoint(cls.PC + len(code))
            # 编码不被支持时投递陷态并跳到 mtvec, 同样需要在那里停下.
            emu.add_breakpoint(h.csrs["mtvec"].val)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        mem = int.from_bytes(emu.bus.read(cls.DATA, 8), "little")
        # pc 一并参与比较: 编码不被支持时两条路径应投递相同的陷态,
        # 任何一侧单独陷入都会体现为 pc 不同.
        return h.pc, int(h.gprs[5]), int(h.gprs[6]), mem

    @pytest.mark.timeout(120)
    def test_random_bitops(self) -> None:
        """Zbb/Zbs 位操作: 引擎与纯 Python 的 (rd, 内存) 一致."""
        ops = [
            (
                "andn",
                r_type(0x33, 5, pack_funct(0x20, 0b111), pack_src_regs(6, 7)),
            ),
            (
                "orn",
                r_type(0x33, 5, pack_funct(0x20, 0b110), pack_src_regs(6, 7)),
            ),
            (
                "xnor",
                r_type(0x33, 5, pack_funct(0x20, 0b100), pack_src_regs(6, 7)),
            ),
            (
                "max",
                r_type(0x33, 5, pack_funct(0x05, 0b110), pack_src_regs(6, 7)),
            ),
            (
                "maxu",
                r_type(0x33, 5, pack_funct(0x05, 0b111), pack_src_regs(6, 7)),
            ),
            (
                "min",
                r_type(0x33, 5, pack_funct(0x05, 0b100), pack_src_regs(6, 7)),
            ),
            (
                "minu",
                r_type(0x33, 5, pack_funct(0x05, 0b101), pack_src_regs(6, 7)),
            ),
            (
                "rol",
                r_type(0x33, 5, pack_funct(0x30, 0b001), pack_src_regs(6, 7)),
            ),
            (
                "ror",
                r_type(0x33, 5, pack_funct(0x30, 0b101), pack_src_regs(6, 7)),
            ),
            (
                "bset",
                r_type(0x33, 5, pack_funct(0x14, 0b001), pack_src_regs(6, 7)),
            ),
            (
                "bclr",
                r_type(0x33, 5, pack_funct(0x24, 0b001), pack_src_regs(6, 7)),
            ),
            (
                "binv",
                r_type(0x33, 5, pack_funct(0x34, 0b001), pack_src_regs(6, 7)),
            ),
            (
                "bext",
                r_type(0x33, 5, pack_funct(0x24, 0b101), pack_src_regs(6, 7)),
            ),
            (
                "zext.h",
                r_type(0x33, 5, pack_funct(0x04, 0b100), pack_src_regs(6, 0)),
            ),
        ]
        imm_ops = [
            ("clz", i_type(0x13, 5, 0b001, 6, 0x600)),
            ("ctz", i_type(0x13, 5, 0b001, 6, 0x601)),
            ("cpop", i_type(0x13, 5, 0b001, 6, 0x602)),
            ("sext.b", i_type(0x13, 5, 0b001, 6, 0x604)),
            ("sext.h", i_type(0x13, 5, 0b001, 6, 0x605)),
            ("rev8", i_type(0x13, 5, 0b101, 6, 0x6B8)),
            ("orc.b", i_type(0x13, 5, 0b101, 6, 0x287)),
            ("rori 7", i_type(0x13, 5, 0b101, 6, 0x607)),
            ("rori 63", i_type(0x13, 5, 0b101, 6, 0x63F)),
        ]
        vals = self._operands()
        for name, word in ops:
            code = word.to_bytes(4, "little")
            for a in vals:
                b = vals[a % len(vals)]
                py = self._run(code, {6: a, 7: b}, is_engine=False)
                eng = self._run(code, {6: a, 7: b}, is_engine=True)
                assert py == eng, f"{name} a={a:#x} b={b:#x}: {py} != {eng}"
        for name, word in imm_ops:
            code = word.to_bytes(4, "little")
            for a in vals:
                py = self._run(code, {6: a}, is_engine=False)
                eng = self._run(code, {6: a}, is_engine=True)
                assert py == eng, f"{name} a={a:#x}: {py} != {eng}"

    @pytest.mark.timeout(120)
    def test_random_atomics(self) -> None:
        """AMO 指令: 引擎与纯 Python 的 (rd, 内存) 一致."""
        ops = [
            (name, funct5, funct3)
            for name, funct5 in [
                ("amoswap", 0b00001),
                ("amoadd", 0b00000),
                ("amoxor", 0b00100),
                ("amoand", 0b01100),
                ("amoor", 0b01000),
                ("amomin", 0b10000),
                ("amomax", 0b10100),
                ("amominu", 0b11000),
                ("amomaxu", 0b11100),
            ]
            for funct3 in (0b010, 0b011)
        ]
        vals = self._operands()
        for name, funct5, funct3 in ops:
            word = r_type(
                0x2F, 5, pack_funct(funct5 << 2, funct3), pack_src_regs(18, 7)
            )
            code = word.to_bytes(4, "little")
            for a in vals:
                b = vals[a % len(vals)]
                regs = {18: self.DATA, 7: b}
                py = self._run(code, regs, is_engine=False)
                eng = self._run(code, regs, is_engine=True)
                assert py == eng, (
                    f"{name} f3={funct3:#b} a={a:#x} b={b:#x}: {py} != {eng}"
                )


class TestRandomizedStoreDiff:
    """随机地址与取值下, 存储指令只改动目标字节, 且两条路径结果一致.

    跨度取三页, 覆盖页内未对齐、跨页与靠近页边界的地址; 校验整段字节,
    任何落到目标之外的写入都会被发现.
    """

    PC = 0x8000_0000
    BASE = 0x8000_4000
    SPAN = 3 * 4096
    PATTERN = bytes((i * 11 + 3) & 0xFF for i in range(SPAN))

    @classmethod
    def _run(cls, code: bytes, regs: dict[int, int], is_engine: bool):
        emu = Emulator(make_test_config())
        emu.load_code(cls.PC, code + b"\x13\x00\x00\x00")
        emu.load_code(cls.BASE, cls.PATTERN)
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        h.pc = cls.PC
        if is_engine:
            emu.add_breakpoint(cls.PC + len(code))
            emu.add_breakpoint(h.csrs["mtvec"].val)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        return bytes(emu.bus.read(cls.BASE, cls.SPAN)), h.pc

    @pytest.mark.timeout(120)
    def test_random_stores(self) -> None:
        rng = random.Random(0xBEEF)
        cases = [
            ("sb", 0x23, 0, 1),
            ("sh", 0x23, 1, 2),
            ("sw", 0x23, 2, 4),
            ("sd", 0x23, 3, 8),
        ]
        for it in range(160):
            name, opc, func3, width = cases[it % len(cases)]
            # 宽度对齐: 未对齐访存在规范外, 模拟器按缺页/访问故障处理.
            off = rng.randrange(0, self.SPAN - 8)
            off -= off % width
            value = rng.getrandbits(64)
            # S 型立即数只有 12 位有符号, 超出部分由基址寄存器承担.
            imm = off % 0x800
            imm -= imm % width
            word = s_type(opc, func3, 6, 7, imm)
            code = word.to_bytes(4, "little")
            regs = {6: self.BASE + off - imm, 7: value}
            want, py_pc = self._run(code, regs, is_engine=False)
            got, eng_pc = self._run(code, regs, is_engine=True)
            expect = bytearray(self.PATTERN)
            expect[off : off + width] = (
                value & ((1 << (8 * width)) - 1)
            ).to_bytes(width, "little")
            assert want == bytes(expect), (
                f"{name} off={off:#x}: 纯 Python 写错位置"
            )
            assert got == bytes(expect), f"{name} off={off:#x}: 引擎写错位置"
            assert py_pc == eng_pc == self.PC + 4, (
                f"{name} off={off:#x}: pc 异常"
            )


class TestInterruptAtCompressedBoundary:
    """定时中断在压缩指令边界投递后, 返回处与寄存器状态必须精确.

    ``sv_gets`` 的扫描循环由大量压缩指令构成且运行时间很长, 定时中断会频繁
    落在循环中间的指令边界上; ``sepc`` 若偏移或返回时寄存器被改动, 循环就会
    少走或多走一次, 表现为缓冲区数据被少量字节替换.
    """

    PC = 0x8000_0000
    HANDLER = 0x8000_1000
    END = 0x8000_0000 + 6  # 三条压缩指令之后
    ISA = "rv64imac_zicsr_zifencei_sstc"

    # c.addi x5, 1
    CADDI_X5_1 = 0x0285
    # csrr t0, time ; addi t0, t0, 2000 ; csrw stimecmp, t0 ; sret
    HANDLER_CODE = (
        b"".join(
            w.to_bytes(4, "little")
            for w in (
                # 处理函数用 t3 (x28), 不碰被测的 x5
                (0xC01 << 20) | (2 << 12) | (28 << 7) | 0x73,
                (2000 << 20) | (28 << 15) | (28 << 7) | 0x13,
                (0x14D << 20) | (28 << 15) | (1 << 12) | 0x73,
                0x10200073,
            )
        )
        + b"\x13\x00\x00\x00" * 4
    )

    def _assemble(self) -> Emulator:
        cfg = make_test_config()
        cfg.isa = self.ISA
        emu = Emulator(cfg)
        code = self.CADDI_X5_1.to_bytes(2, "little") * 3
        emu.load_code(self.PC, code + b"\x13\x00\x00\x00")
        emu.load_code(self.HANDLER, self.HANDLER_CODE)
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.csrs["stvec"].val = self.HANDLER
        h.csrs["mie"].val = 1 << 5  # STIE
        h.csrs["mideleg"].val |= 1 << 5  # 定时器中断委派到 S 模式
        h.csrs["mcounteren"].val = 0b111  # 允许 S 模式读取 time
        h.mstatus_val |= 1 << 1  # SIE
        # 让定时器在进入本轮之前就已到期: STIP 在第一条指令前投递.
        # stimecmp 取 0 表示未使用 sstc 定时器, 故先推进 mtime 再设非零比较值.
        emu.clint.tick(100)
        h.csrs["stimecmp"].val = 100
        h.pc = self.PC
        return emu

    def _run(self, is_engine: bool):
        emu = self._assemble()
        h = emu.harts[0]
        if is_engine:
            emu.add_breakpoint(self.END)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            for _ in range(64):
                if emu.harts[0].pc == self.END:
                    break
                emu.step()
        return h.pc, int(h.gprs[5]), int(h.csrs["stimecmp"].val), emu

    def test_interrupt_before_first_compressed_instruction(self) -> None:
        for is_engine in (False, True):
            path = "引擎" if is_engine else "纯 Python"
            pc, x5, stimecmp, emu = self._run(is_engine)
            assert x5 == 3, f"{path}: 三条 c.addi 应各执行一次, x5={x5}"
            assert pc == self.END, f"{path}: pc={pc:#x}"
            assert stimecmp > emu.clint.get_mtime(), (
                f"{path}: 处理函数应把 stimecmp 推到未来, {stimecmp:#x}"
            )


class TestLongScanLoopWithInterrupts:
    """长时间扫描循环叠加频繁定时中断时, 累加结果与迭代次数必须精确.

    对应 ``sv_gets`` 快速路径的扫描循环: 大量 ``lbu`` 与压缩 ``c.addi`` 混排,
    运行时间长到定时中断反复落在循环中间. 单条指令与单次陷态都已分别验证,
    本类把两者叠加成与真实负载同构的时序, 用"结果必须逐位精确"判定.
    """

    PC = 0x8000_0000
    HANDLER = 0x8000_2000
    DATA = 0x8000_7000
    BUF = 0x8000_8000
    ITERS = 20000
    TICK_GAP = 40  # 每约 200 条指令一次定时中断

    def _program(self) -> bytes:
        loop = self.PC
        body = [
            # lbu x7, 0(x8)
            i_type(0x03, 7, 0b100, 8, 0).to_bytes(4, "little"),
            # add x9, x9, x7
            r_type(
                0x33, 9, pack_funct(0x00, 0b000), pack_src_regs(9, 7)
            ).to_bytes(4, "little"),
            # c.addi x8, 1
            (0x0405).to_bytes(2, "little"),
            # c.addi x5, 1
            (0x0285).to_bytes(2, "little"),
            # bne x5, x6, loop
            b_type(0x63, 0b001, 5, 6, loop - (self.PC + 12)).to_bytes(
                4, "little"
            ),
        ]
        tail = [
            s_type(0x23, 0b011, 3, 9, 0).to_bytes(4, "little"),  # sd x9, 0(x3)
            s_type(0x23, 0b011, 3, 5, 8).to_bytes(4, "little"),  # sd x5, 8(x3)
            b"\x13\x00\x00\x00",  # 停在这里
        ]
        return b"".join(body) + b"".join(tail)

    def _handler(self) -> bytes:
        words = [
            i_type(0x73, 28, 0b010, 0, 0xC01),  # csrr t3, time
            i_type(0x13, 28, 0b000, 28, self.TICK_GAP),
            i_type(0x73, 0, 0b001, 28, 0x14D),  # csrw stimecmp, t3
            i_type(0x03, 29, 0b011, 3, 16),  # ld t4, 16(x3)
            i_type(0x13, 29, 0b000, 29, 1),
            s_type(0x23, 0b011, 3, 29, 16),  # sd t4, 16(x3)
            0x10200073,  # sret
        ]
        return b"".join(w.to_bytes(4, "little") for w in words) + (
            b"\x13\x00\x00\x00" * 4
        )

    def _assemble(self) -> Emulator:
        cfg = make_test_config()
        cfg.isa = "rv64imac_zicsr_zifencei_sstc"
        emu = Emulator(cfg)
        emu.load_code(self.PC, self._program())
        emu.load_code(self.HANDLER, self._handler())
        buf = bytes((i * 7 + 3) & 0xFF for i in range(self.ITERS))
        emu.load_code(self.BUF, buf)
        emu.load_code(self.DATA, bytes(32))
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.csrs["stvec"].val = self.HANDLER
        h.csrs["mie"].val = 1 << 5
        h.csrs["mideleg"].val |= 1 << 5
        h.csrs["mcounteren"].val = 0b111
        h.mstatus_val |= 1 << 1
        h.gprs[3] = self.DATA
        h.gprs[5] = 0
        h.gprs[6] = self.ITERS
        h.gprs[8] = self.BUF
        h.gprs[9] = 0
        h.pc = self.PC
        emu.clint.tick(1000)
        h.csrs["stimecmp"].val = 1000 + self.TICK_GAP
        return emu, sum(buf) & ((1 << 64) - 1)

    @pytest.mark.timeout(120)
    def test_engine(self) -> None:
        emu, want = self._assemble()
        h = emu.harts[0]
        end = self.PC + len(self._program()) - 4
        emu.add_breakpoint(end)
        with mock.patch(
            "pyremu.emu.native.run_parallel", wraps=run_parallel
        ) as engine:
            emu.run(timeout=60)
        assert engine.called, "本用例应经加速执行引擎运行"
        mem = emu.bus.read(self.DATA, 32)
        got_sum = int.from_bytes(mem[0:8], "little")
        got_cnt = int.from_bytes(mem[8:16], "little")
        got_irq = int.from_bytes(mem[16:24], "little")
        assert h.pc == end, f"pc={h.pc:#x}"
        assert got_cnt == self.ITERS, f"迭代次数 {got_cnt} != {self.ITERS}"
        assert got_sum == want, f"累加值 {got_sum:#x} != {want:#x}"
        assert got_irq > 0, "定时中断必须真的发生过"

    @pytest.mark.timeout(120)
    def test_engine_long_run(self) -> None:
        """把扫描迭代数提高到二十万次, 覆盖更长的时序与更多次中断."""
        old = type(self).ITERS
        type(self).ITERS = 200000
        try:
            emu, want = self._assemble()
            end = self.PC + len(self._program()) - 4
            emu.add_breakpoint(end)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=60)
            assert engine.called, "本用例应经加速执行引擎运行"
            mem = emu.bus.read(self.DATA, 32)
            assert int.from_bytes(mem[8:16], "little") == 200000
            assert int.from_bytes(mem[0:8], "little") == want
            assert int.from_bytes(mem[16:24], "little") > 0
        finally:
            type(self).ITERS = old

    @pytest.mark.timeout(120)
    def test_python_path(self) -> None:
        emu, want = self._assemble()
        h = emu.harts[0]
        end = self.PC + len(self._program()) - 4
        for _ in range(20 * self.ITERS + 4000):
            if h.pc == end:
                break
            emu.step()
        mem = emu.bus.read(self.DATA, 32)
        assert int.from_bytes(mem[8:16], "little") == self.ITERS
        assert int.from_bytes(mem[0:8], "little") == want
