#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""基础整数指令: 字段解码与执行边界."""

import pytest

from pyremu.core.decoder import Hart
from pyremu.core.hart import RiscvMode
from pyremu.emulator import Emulator
from pyremu.memory.bus import Bus


class TestStoreImmediateOffset:
    """回归: parse_imm_s 的 imm[11:5] 缺少 <<5 位移导致 offset>=32 时错误."""

    @pytest.fixture
    def emu(self):
        emu = Emulator(num_harts=1)
        emu.harts[0].gprs[2] = 0x80001000  # sp
        emu.harts[0].gprs[10] = 0xCAFEBABEDEADBEEF  # a0 = test value
        return emu

    def _exec_sd(self, emu, offset: int):
        """执行 sd a0, offset(sp)."""
        h = emu.harts[0]
        h.pc = 0x80000000
        # imm[11:5] = offset >> 5, imm[4:0] = offset & 0x1F
        imm_11_5 = (offset >> 5) & 0x7F
        imm_4_0 = offset & 0x1F
        instr = (
            (imm_11_5 << 25)
            | (10 << 20)  # rs2 = a0 = x10
            | (2 << 15)  # rs1 = sp = x2
            | (3 << 12)  # funct3 = sd
            | (imm_4_0 << 7)  # rd field = imm[4:0]
            | 0b0100011  # opcode = STORE
        )
        h.exec_instr(instr)
        if h.pc != 0x80000000:  # trap occurred
            return None, h.mcause_val
        # Read back from the written address
        addr = (emu.harts[0].gprs[2] + offset) & 0xFFFF_FFFF_FFFF_FFFF
        data = emu.dump_memory(addr, 8)
        return int.from_bytes(data, "little"), 0

    def test_sd_offset_0(self, emu):
        """sd offset=0: 边界值, imm[11:5]=0 (原 bug 不触发)."""
        val, mcause = self._exec_sd(emu, 0)
        assert mcause == 0
        assert val == 0xCAFEBABEDEADBEEF

    def test_sd_offset_32(self, emu):
        """sd offset=32: imm[11:5]=1, 原 bug 会算出 offset=1 导致未对齐故障."""
        val, mcause = self._exec_sd(emu, 32)
        assert mcause == 0, f"unexpected trap mcause=0x{mcause:x}"
        assert val == 0xCAFEBABEDEADBEEF

    def test_sd_offset_64(self, emu):
        """sd offset=64: imm[11:5]=2."""
        val, mcause = self._exec_sd(emu, 64)
        assert mcause == 0
        assert val == 0xCAFEBABEDEADBEEF

    def test_sd_offset_96(self, emu):
        """sd offset=96: imm[11:5]=3."""
        val, mcause = self._exec_sd(emu, 96)
        assert mcause == 0
        assert val == 0xCAFEBABEDEADBEEF

    def test_sd_offset_2047(self, emu):
        """sd offset=2047: 12-bit S-type 最大正偏移."""
        val, mcause = self._exec_sd(emu, 2047)
        # 2047 未对齐 -> 预期 StAddrMisaligned
        assert mcause == 0x6


class TestAuipcSignExtension:
    """回归: AUIPC/LUI 的 U-immediate 缺少 32-bit 符号扩展."""

    @pytest.fixture
    def emu(self):
        return Emulator(num_harts=1)

    def _exec_auipc(self, emu, imm20_raw: int):
        """执行 auipc rd, imm20_raw."""
        h = emu.harts[0]
        h.pc = 0x80000000
        instr = ((imm20_raw & 0xFFFFF) << 12) | (5 << 7) | 0b0010111
        h.exec_instr(instr)
        return h.gprs[5]

    def test_auipc_positive(self, emu):
        """AUIPC with positive offset (bit 19=0) — 原代码也可正确处理."""
        result = self._exec_auipc(emu, 1)
        assert result == 0x80001000  # 0x80000000 + 0x1000

    def test_auipc_negative(self, emu):
        """AUIPC with negative offset (bit 19=1) — 原 bug 导致高位错误."""
        result = self._exec_auipc(emu, 0xFFFFF)  # -1 in 20-bit signed
        # PC + (-1 << 12) = 0x80000000 - 0x1000 = 0x7FFFF000
        assert result == 0x7FFFF000

    def test_auipc_max_negative(self, emu):
        """AUIPC most-negative offset (0x80000 = -2^19)."""
        result = self._exec_auipc(emu, 0x80000)  # most negative 20-bit value
        # PC + (0x80000 << 12) signed = PC - 0x80000000
        # 0x80000000 - 0x80000000 = 0
        assert result == 0

    def test_lui_negative(self, emu):
        """LUI with bit 31 set -> sign-extended to 64-bit negative."""
        h = emu.harts[0]
        h.pc = 0x80000000
        instr = (0xFFFFF << 12) | (5 << 7) | 0b0110111  # LUI x5, 0xFFFFF
        h.exec_instr(instr)
        # imm20_raw << 12 = 0xFFFFF000, sign-extended from 32-bit -> -0x1000
        assert h.gprs[5] == 0xFFFFFFFFFFFFF000


class TestLoadAlignmentSizes:
    """回归: handle_ld 对所有 load 类型统一读 8 字节导致虚假对齐故障."""

    @pytest.fixture
    def emu(self):
        emu = Emulator(num_harts=1)
        # 在 0x80000048-0x8000004F 区域写入已知数据
        test_data = bytes(range(0x48, 0x50))  # 0x48, 0x49, ..., 0x4F
        emu.load_code(0x80000048, test_data)
        return emu

    def _exec_load(self, emu, addr: int, funct3: int):
        """执行 ld-type 指令: rd=x5, rs1=x10, offset=0."""
        h = emu.harts[0]
        h.gprs[10] = addr  # rs1
        h.pc = 0x80000000
        instr = (5 << 7) | (funct3 << 12) | (10 << 15) | 0b0000011
        h.exec_instr(instr)
        return h.gprs[5], h.mcause_val

    def test_lbu_at_0x49(self, emu):
        """lbu 从奇地址读取 1 字节, 不应触发对齐故障."""
        val, mcause = self._exec_load(emu, 0x80000049, 0b100)  # funct3=lbu
        assert mcause == 0, f"unexpected trap mcause=0x{mcause:x}"
        assert val == 0x49

    def test_lbu_at_0x48(self, emu):
        """lbu 从 8 字节对齐地址读取."""
        val, mcause = self._exec_load(emu, 0x80000048, 0b100)  # funct3=lbu
        assert mcause == 0
        assert val == 0x48

    def test_lhu_at_0x4a(self, emu):
        """lhu 从 2 字节对齐地址读取."""
        val, mcause = self._exec_load(emu, 0x8000004A, 0b101)  # funct3=lhu
        assert mcause == 0
        assert val == 0x4B4A  # little-endian

    def test_lwu_at_0x4c(self, emu):
        """lwu 从 4 字节对齐地址读取."""
        val, mcause = self._exec_load(emu, 0x8000004C, 0b110)  # funct3=lwu
        assert mcause == 0
        assert val == 0x4F4E4D4C

    def test_lh_misaligned(self, emu):
        """lh 从奇数地址 -> 应对齐故障."""
        val, mcause = self._exec_load(emu, 0x80000049, 0b001)  # funct3=lh
        assert mcause == 0x4  # LdAddrMisaligned


class TestITypeShifts:
    """回归: I-type 移位使用 funct6 (bits 31:26) 而非 funct7 — bit 25 属于 shamt."""

    @pytest.fixture
    def h(self):
        bus = Bus(ram_size=0x10000, ram_base=0x80000000)
        hart = Hart(id=0)
        hart.mem_read_phy = bus.read
        hart.mem_write_phy = bus.write
        hart.bus = bus
        hart.pc = 0x80000000
        return hart

    # -- helpers: 构造指令编码并执行 --

    @staticmethod
    def _slli(rd, rs1, shamt):
        """slli rd, rs1, shamt — RV64."""
        return (
            (0b000000 << 26)  # funct6
            | (shamt << 20)  # 6-bit shamt
            | (rs1 << 15)
            | (0b001 << 12)  # funct3
            | (rd << 7)
            | 0b0010011  # opcode OP-IMM
        )

    @staticmethod
    def _srli(rd, rs1, shamt):
        return (
            (0b000000 << 26)
            | (shamt << 20)
            | (rs1 << 15)
            | (0b101 << 12)
            | (rd << 7)
            | 0b0010011
        )

    @staticmethod
    def _srai(rd, rs1, shamt):
        return (
            (0b010000 << 26)
            | (shamt << 20)
            | (rs1 << 15)
            | (0b101 << 12)
            | (rd << 7)
            | 0b0010011
        )

    def _exec(self, hart, instr):
        advance = hart.exec_instr(instr)
        if advance != 0 and hart.pc == 0x80000000:
            hart.pc = (hart.pc + advance) & 0xFFFF_FFFF_FFFF_FFFF

    # -- SLLI --

    def test_slli_shamt_0(self, h):
        """SLLI shamt=0 应该是 NOP (恒等)."""
        h.gprs[10] = 0x123456789ABCDEF0
        self._exec(h, self._slli(10, 10, 0))
        assert h.gprs[10] == 0x123456789ABCDEF0

    def test_slli_shamt_1(self, h):
        h.gprs[11] = 0x1
        self._exec(h, self._slli(11, 11, 1))
        assert h.gprs[11] == 0x2

    def test_slli_shamt_32(self, h):
        """SLLI shamt=32 — bit 25 置位, 曾触发 funct7≠0 的误判."""
        h.gprs[12] = 0xFFFFFFFFDEADBEEF
        self._exec(h, self._slli(12, 12, 32))
        assert h.gprs[12] == 0xDEADBEEF00000000

    def test_slli_shamt_63(self, h):
        """SLLI 最大移位量 63."""
        h.gprs[13] = 0x3
        self._exec(h, self._slli(13, 13, 63))
        assert h.gprs[13] == (0x3 << 63) & 0xFFFF_FFFF_FFFF_FFFF

    def test_slli_wraps_64(self, h):
        """移位后 & mask 保证 64 位截断."""
        h.gprs[14] = 0xABCD
        self._exec(h, self._slli(14, 14, 60))
        assert h.gprs[14] == 0xD000000000000000

    # -- SRLI --

    def test_srli_shamt_32(self, h):
        """SRLI shamt=32 — bit 25 置位."""
        h.gprs[15] = 0xDEADBEEF00000000
        self._exec(h, self._srli(15, 15, 32))
        assert h.gprs[15] == 0xDEADBEEF

    def test_srli_shamt_0(self, h):
        h.gprs[16] = 0x8000000000000000
        self._exec(h, self._srli(16, 16, 0))
        assert h.gprs[16] == 0x8000000000000000

    # -- SRAI --

    def test_srai_shamt_32_positive(self, h):
        """SRAI 正数算术右移 — 高位补 0."""
        h.gprs[17] = 0x7ABCDEF000000000
        self._exec(h, self._srai(17, 17, 32))
        assert h.gprs[17] == 0x7ABCDEF0

    def test_srai_shamt_32_negative(self, h):
        """SRAI 负数算术右移 — 高位补 1 (符号扩展)."""
        h.gprs[18] = 0x8000000000000000  # 最小负值
        self._exec(h, self._srai(18, 18, 32))
        assert h.gprs[18] == 0xFFFFFFFF80000000

    def test_srai_shamt_63(self, h):
        """SRAI 最大移位量 — 符号位填满全部位."""
        h.gprs[19] = 0x8000000000000000
        self._exec(h, self._srai(19, 19, 63))
        assert h.gprs[19] == 0xFFFFFFFFFFFFFFFF

    # -- 非法 funct6 被拒绝 --

    def test_slli_bad_funct6_traps(self, h):
        """非法 funct6 应触发 IllInstr."""
        bad = (0b111111 << 26) | (0 << 20) | (10 << 15) | (0b001 << 12) | (10 << 7) | 0b0010011
        advance = h.exec_instr(bad)
        assert advance == 0
        assert h.mcause_val != 0


class TestLdLinuxAddrChain:
    """AUIPC + slli/add: ld-linux 数组索引地址计算链.

    ld-linux 偏移 0x3aba-0x3ace:
      slli s1,a5,2; add s1,s1,a5; slli s1,s1,5
      addi s1,s1,-0xa0; auipc a5,0x1e; addi a5,a5,0x542; add s1,s1,a5
    若任一指令结果错误则 s1 指向错误元素 -> ld a5,0(s1) 读到 DT_RELA=7.
    """

    SLLI_S1_A5_2 = 0x00279493  # 4B: slli s1, a5, 2
    C_ADD_S1_A5 = 0x94BE  # 2B: c.add s1, a5
    C_SLLI_S1_5 = 0x0496  # 2B: c.slli s1, 5
    ADDI_S1_NEG_A0 = 0xF6048493  # 4B: addi s1, s1, -0xa0
    AUIPC_A5_1E = 0x0001E797  # 4B: auipc a5, 0x1e
    ADDI_A5_A5_542 = 0x54278793  # 4B: addi a5, a5, 0x542
    C_ADD_S1_A5_FINAL = 0x94BE  # 2B: c.add s1, a5
    PC_START = 0x3ABA
    PC_AT_AUIPC = 0x3AC6  # 0x3aba + 4 + 2 + 2 + 4

    @staticmethod
    def _make_hart() -> Hart:
        hart = Hart(id=0)
        hart.mode = RiscvMode.M  # M-mode, bare translation
        return hart

    @pytest.mark.parametrize("counter", [0, 1, 2, 3, 5, 10, 256])
    def test_s1_address(self, counter: int) -> None:
        """s1 == (counter-1)*0xa0 + pc_auipc + 0x1e542."""
        hart = self._make_hart()
        hart.pc = self.PC_START
        hart.gprs[15] = counter  # a5

        for instr in (
            self.SLLI_S1_A5_2,
            self.C_ADD_S1_A5,
            self.C_SLLI_S1_5,
            self.ADDI_S1_NEG_A0,
            self.AUIPC_A5_1E,
            self.ADDI_A5_A5_542,
            self.C_ADD_S1_A5_FINAL,
        ):
            hart.pc += hart.exec_instr(instr)

        expected = (counter - 1) * 0xA0 + self.PC_AT_AUIPC + 0x1E000 + 0x542
        assert hart.gprs[9] == expected, (
            f"counter={counter}: s1={hart.gprs[9]:#018x}, expected {expected:#018x}"
        )

    @pytest.mark.parametrize(
        "pc_base",
        [
            0x3ABA,
            0x3F_F7FD_CABA,  # ld-linux 运行时 VA
        ],
    )
    @pytest.mark.parametrize("counter", [1, 2, 5])
    def test_auipc_pc_relative(self, counter: int, pc_base: int) -> None:
        """AUIPC 使用自身 PC 而非其他值."""
        hart = self._make_hart()
        hart.pc = pc_base
        hart.gprs[15] = counter

        for instr in (
            self.SLLI_S1_A5_2,
            self.C_ADD_S1_A5,
            self.C_SLLI_S1_5,
            self.ADDI_S1_NEG_A0,
            self.AUIPC_A5_1E,
            self.ADDI_A5_A5_542,
            self.C_ADD_S1_A5_FINAL,
        ):
            hart.pc += hart.exec_instr(instr)

        pc_auipc = pc_base + (self.PC_AT_AUIPC - self.PC_START)
        expected = (counter - 1) * 0xA0 + pc_auipc + 0x1E000 + 0x542
        assert hart.gprs[9] == expected
        assert hart.gprs[15] == pc_auipc + 0x1E000 + 0x542


class TestBranchEdgeCases:
    """分支边界值测试 — ld-linux 循环退出条件.

    ld-linux 偏移 0x3ab6:  bltz s2, 0x3b0a  (s2<0 时跳过循环)
    ld-linux 偏移 0x3b06:  bne  s2, s4, 0x3ad0  (s2!=-1 时继续循环)
    """

    def _make_hart(self) -> Hart:
        hart = Hart(id=0)
        hart.mode = RiscvMode.M
        return hart

    # ---- BLTZ (s2 < 0 -> branch) ----
    @pytest.mark.parametrize(
        "s2_val,taken",
        [
            (-1, True),  # s2=-1 < 0 -> branch to skip loop
            (0, False),  # s2=0 >= 0 -> fall through (enter loop)
            (1, False),  # s2=1 >= 0 -> fall through
            (-2, True),  # s2=-2 < 0 -> branch
        ],
    )
    def test_bltz_edge(self, s2_val: int, taken: bool) -> None:
        """BLTZ at 0x3ab6: branch taken iff s2 < 0."""
        hart = self._make_hart()
        hart.pc = 0x3AB6
        hart.gprs[18] = s2_val & 0xFFFF_FFFF_FFFF_FFFF  # s2

        # bltz s2, 0x3b0a = 0x04094a63
        advance = hart.exec_instr(0x04094A63)
        hart.pc += advance

        if taken:
            assert hart.pc == 0x3B0A, f"s2={s2_val}: should branch to 0x3b0a"
        else:
            # Fall-through: pc += advance (4 for non-taken 32-bit branch)
            assert hart.pc == 0x3ABA, f"s2={s2_val}: should fall through to 0x3aba"

    # ---- BNE (s2 != s4 -> branch back) ----
    @pytest.mark.parametrize(
        "s2_val,s4_val,taken",
        [
            (-1, -1, False),  # s2 == s4 -> exit loop
            (0, -1, True),  # s2 != s4 -> continue loop
            (1, -1, True),  # continue
            (-2, -1, True),  # s2=-2 != -1 -> continue
        ],
    )
    def test_bne_exit_edge(self, s2_val: int, s4_val: int, taken: bool) -> None:
        """BNE at 0x3b06: branch NOT taken when s2 == s4."""
        hart = self._make_hart()
        hart.pc = 0x3B06
        hart.gprs[18] = s2_val & 0xFFFF_FFFF_FFFF_FFFF  # s2
        hart.gprs[20] = s4_val & 0xFFFF_FFFF_FFFF_FFFF  # s4

        # bne s2, s4, 0x3ad0 = 0xFD4915E3
        advance = hart.exec_instr(0xFD4915E3)
        hart.pc += advance

        if taken:
            assert hart.pc == 0x3AD0, f"s2={s2_val} s4={s4_val}: should loop to 0x3ad0"
        else:
            assert hart.pc == 0x3B0A, f"s2={s2_val} s4={s4_val}: should exit to 0x3b0a"
