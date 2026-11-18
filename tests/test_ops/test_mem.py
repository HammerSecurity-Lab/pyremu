#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""访存编码、跨页访问、缺页重放、权限检查与返回地址对齐."""

from __future__ import annotations

from unittest import mock

import pytest

from pyremu.core.hart import RiscvMode
from pyremu.emulator import Emulator
from pyremu.generic_ops import pte_parse, run_parallel
from tests.conftest import make_test_config
from tests.instr_encode import (
    b_type,
    i_type,
    pack_funct,
    pack_src_regs,
    r_type,
    s_type,
)
from tests.test_ops.common import (
    assert_ill_instr,
    MASK64,
    OP_AMO,
    OP_BRANCH,
    OP_LOAD,
    OP_STORE,
    OP_SYS,
    PTE_U,
)


class TestBranchAndMemoryEncodings:
    """分支与访存的边界编码."""

    @pytest.mark.parametrize(
        "funct3, v1, v2, taken",
        [
            (0b110, 1, 2, True),  # BLTU
            (0b110, 2, 1, False),
            (0b111, 2, 1, True),  # BGEU
            (0b111, 1, 2, False),
        ],
    )
    def test_unsigned_branches(self, hart, funct3, v1, v2, taken):
        hart.gprs[1] = v1
        hart.gprs[2] = v2
        hart.pc = 0x2000
        hart.exec_instr(b_type(OP_BRANCH, funct3, 1, 2, 8))
        assert hart.pc == (0x2008 if taken else 0x2000)

    def test_branch_invalid_funct3_advances(self, hart):
        hart.pc = 0x2000
        assert hart.exec_instr(b_type(OP_BRANCH, 0b010, 1, 2, 8)) == 4
        assert hart.pc == 0x2000

    @pytest.mark.parametrize(
        "funct3, raw, expect",
        [
            (0b000, bytes([0x80, 0, 0, 0, 0, 0, 0, 0]), MASK64 - 0x7F),  # LB
            (0b100, bytes([0x80, 0, 0, 0, 0, 0, 0, 0]), 0x80),  # LBU
            # LH
            (0b001, bytes([0x00, 0x80, 0, 0, 0, 0, 0, 0]), MASK64 - 0x7FFF),
            (0b101, bytes([0x00, 0x80, 0, 0, 0, 0, 0, 0]), 0x8000),  # LHU
        ],
    )
    def test_load_sign_extension(self, hart, funct3, raw, expect):
        hart.mem_write_phy(0x100, raw)
        hart.gprs[1] = 0x100
        hart.exec_instr(i_type(OP_LOAD, 3, funct3, 1, 0))
        assert hart.gprs[3] == expect

    def test_load_invalid_funct3_traps(self, hart):
        assert_ill_instr(hart, i_type(OP_LOAD, 3, 0b111, 1, 0))

    @pytest.mark.parametrize(
        "funct3, val, expect",
        [
            (0b001, 0x1234, bytes([0x34, 0x12])),
            (0b010, 0x1234_5678, bytes([0x78, 0x56, 0x34, 0x12])),
            (
                0b011,
                0x0123_4567_89AB_CDEF,
                bytes([0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]),
            ),
        ],
    )
    def test_store_widths(self, hart, funct3, val, expect):
        hart.gprs[1] = 0x100
        hart.gprs[2] = val
        hart.exec_instr(s_type(OP_STORE, funct3, 1, 2, 0))
        assert hart.mem_read_phy(0x100, len(expect)) == expect

    def test_store_invalid_funct3_traps(self, hart):
        assert_ill_instr(hart, s_type(OP_STORE, 0b100, 1, 2, 0))

    def test_fence_and_fence_i(self, hart):
        hart.pc = 0x2000
        assert hart.exec_instr(0b0001111) == 4  # FENCE
        assert hart.exec_instr(0b0001111 | (1 << 12)) == 4  # FENCE.I

    def test_fence_invalid_funct3_traps(self, hart):
        assert_ill_instr(hart, 0b0001111 | (0b010 << 12))

    def test_amo_invalid_encoding_traps(self, hart):
        assert_ill_instr(
            hart, r_type(OP_AMO, 3, pack_funct(0, 0b100), pack_src_regs(1, 2))
        )

    def test_sys_invalid_funct3_traps(self, hart):
        assert_ill_instr(
            hart, r_type(OP_SYS, 3, pack_funct(0, 0b100), pack_src_regs(1, 2))
        )


class TestPtePermBits:
    """PTE 权限字段取 bits[4:1], 即 R|W|X|U。"""

    def test_u_bit_is_reported(self, pure_python):
        """raw 置 U 位时 perm 必须含 U 位 (改前掩码为 0xF, U 位恒缺)。"""
        perm = pte_parse(0x1F).perm
        assert perm == 0x1E
        assert perm & PTE_U

    def test_perm_excludes_valid_bit(self, pure_python):
        """raw=0xCF 的 perm 为 0x0E: V 位不进 perm (改前为 0x0F)。"""
        assert pte_parse(0xCF).perm == 0x0E

    def test_rwx_bits_are_preserved(self, pure_python):
        """R/W/X 三位逐位保留, 与 raw 的 bits[3:1] 相同。"""
        for raw in (0x0F, 0x1B, 0x1E, 0xCF, 0xDF, 0xEF):
            assert pte_parse(raw).perm & 0b1110 == raw & 0b1110


class TestCrossPageFetch:
    """跨页取指: 4 字节指令的两半落在互不相邻的物理页上.

    PC 位于页尾 ``0xFFE`` 时, 指令的后两字节来自下一个虚拟页; 两个虚拟页指向
    不相邻的物理页时, 引擎必须先翻译第二页再把两半拼成一个指令字.
    """

    VA = 0x4000_0000
    ROOT_PA = 0x8000_8000
    L2_PA = 0x8000_9000
    L3_PA = 0x8000_A000
    CODE_LO_PA = 0x8000_4000
    CODE_HI_PA = 0x8000_6000
    ADDI_X5_42 = 0x02A00293  # addi x5, x0, 42

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    def _assemble(self) -> Emulator:
        """装配页表与跨页指令, 返回 S 模式、已启用 Sv39 的模拟器."""
        cfg = make_test_config()
        emu = Emulator(cfg)
        bus = emu.bus
        leaf = 0xCF  # V|R|W|X|A|D

        def write_pte(addr: int, pte: int) -> None:
            bus.write(addr, pte.to_bytes(8, "little"))

        # 根页表 [VPN2=1] -> L2, L2 [VPN1=0] -> L3
        write_pte(self.ROOT_PA + 8, self._pte(self.L2_PA, 0x01))
        write_pte(self.L2_PA, self._pte(self.L3_PA, 0x01))
        # L3 [VPN0=0] -> CODE_LO_PA, [VPN0=1] -> CODE_HI_PA (不相邻)
        write_pte(self.L3_PA, self._pte(self.CODE_LO_PA, leaf))
        write_pte(self.L3_PA + 8, self._pte(self.CODE_HI_PA, leaf))
        lo = (self.ADDI_X5_42 & 0xFFFF).to_bytes(2, "little")
        hi = (self.ADDI_X5_42 >> 16).to_bytes(2, "little")
        bus.write(self.CODE_LO_PA + 0xFFE, lo)
        bus.write(self.CODE_HI_PA, hi)
        # 下一条指令的地址为 0x4000_0FFE + 4 = 0x4000_1002, 仍落在第二页内
        bus.write(self.CODE_HI_PA + 2, b"\x13\x00\x00\x00")
        h = emu.harts[0]
        # S 模式取指要经 PMP 判定; 未配置条目时按规范拒绝, 故装一条覆盖全空间
        # 的 TOR 条目 (R|W|X).
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.pc = self.VA + 0xFFE
        return emu

    def _run_engine(self) -> tuple[mock.Mock, Emulator]:
        emu = self._assemble()
        emu.add_breakpoint(self.VA + 0x1002)
        with mock.patch(
            "pyremu.emu.native.run_parallel", wraps=run_parallel
        ) as engine:
            emu.run(timeout=10)
        return engine, emu

    def test_engine_fetches_across_discontiguous_pages(self) -> None:
        engine, emu = self._run_engine()
        assert engine.called, "本用例应经加速执行引擎运行"
        h = emu.harts[0]
        assert h.gprs[5] == 42, (
            f"应执行 addi x5, x0, 42, 实际 x5={h.gprs[5]:#x}"
        )
        assert h.pc == self.VA + 0x1002, f"PC 应推进到下一页, 实际 {h.pc:#x}"

    def test_python_path_matches_engine(self) -> None:
        """纯 Python 路径对同一布局得到相同结果."""
        emu = self._assemble()
        h = emu.harts[0]
        emu.step()
        assert h.gprs[5] == 42
        assert h.pc == self.VA + 0x1002


class TestStoreTargetDifferential:
    """存储指令的目标地址与写入宽度: 引擎与纯 Python 逐字节一致.

    目标区间预先填成 0xAA 哨兵, 执行后比较整段字节: 同时验证写入的值、宽度
    与偏移, 以及没有写到相邻地址.
    """

    PC = 0x8000_0000
    DATA = 0x8000_4000
    SPAN = 96
    BASE_OFF = 32
    SENTINEL = 0xAA

    @classmethod
    def _run(
        cls,
        code: bytes,
        regs: dict[int, int],
        is_engine: bool,
    ) -> bytes:
        emu = Emulator(make_test_config())
        emu.load_code(cls.PC, code)
        span_pa = cls.DATA - cls.BASE_OFF
        emu.load_code(span_pa, bytes([cls.SENTINEL]) * cls.SPAN)
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        h.pc = cls.PC
        if is_engine:
            emu.add_breakpoint(cls.PC + len(code))
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        assert h.pc == cls.PC + len(code), f"PC 未推进, 实际 {h.pc:#x}"
        return bytes(emu.bus.read(span_pa, cls.SPAN))

    @classmethod
    def _expected(cls, offset: int, width: int, value: int) -> bytes:
        span = bytearray([cls.SENTINEL]) * cls.SPAN
        start = cls.BASE_OFF + offset
        span[start : start + width] = value.to_bytes(width, "little")
        return bytes(span)

    # CASES 的每一项依次为名称、编码、寄存器初值、目标偏移、写入宽度与写入值.
    _BASE = 0x8000_4000
    _W32 = 0x1122_3344
    _W64 = 0x1122_3344_5566_7788
    CASES = [
        (
            "sb",
            s_type(0x23, 0, 5, 6, 8).to_bytes(4, "little"),
            {5: _BASE, 6: _W32},
            8,
            1,
            0x44,
        ),
        (
            "sh",
            s_type(0x23, 1, 5, 6, 10).to_bytes(4, "little"),
            {5: _BASE, 6: _W32},
            10,
            2,
            0x3344,
        ),
        (
            "sw",
            s_type(0x23, 2, 5, 6, 12).to_bytes(4, "little"),
            {5: _BASE, 6: _W64},
            12,
            4,
            0x5566_7788,
        ),
        (
            "sd",
            s_type(0x23, 3, 5, 6, 16).to_bytes(4, "little"),
            {5: _BASE, 6: _W64},
            16,
            8,
            _W64,
        ),
        (
            "c.sw",
            (0xC29C).to_bytes(2, "little"),
            {13: _BASE, 15: _W32},
            0,
            4,
            _W32,
        ),
        (
            "c.sd",
            (0xE29C).to_bytes(2, "little"),
            {13: _BASE, 15: _W64},
            0,
            8,
            _W64,
        ),
        (
            "c.swsp",
            (0xC23E).to_bytes(2, "little"),
            {2: _BASE, 15: _W32},
            4,
            4,
            _W32,
        ),
        (
            "c.sdsp",
            (0xE43E).to_bytes(2, "little"),
            {2: _BASE, 15: _W64},
            8,
            8,
            _W64,
        ),
    ]

    def test_engine_matches_python_and_expected(self) -> None:
        for name, code, regs, offset, width, value in self.CASES:
            py = self._run(code, regs, is_engine=False)
            eng = self._run(code, regs, is_engine=True)
            assert py == eng, f"{name}: 引擎与纯 Python 写入结果不同"
            assert eng == self._expected(offset, width, value), (
                f"{name}: 写入的位置或宽度与预期不符"
            )


class TestCrossPageLoadDiff:
    """跨页加载: 两个虚拟页指向不相邻的物理页, 拼接结果与独立期望一致.

    按规范, 自然对齐的访问不会跨 4 KiB 页边界; 跨页只可能出现在未对齐访问
    上. 引擎对这种访问做静默的逐字节模拟, 结果是本类单独实现出来的, 没有
    第二条实现可以互相印证, 故期望值在此独立计算.
    """

    VA = 0x4000_0000
    ROOT_PA = 0x8000_8000
    L2_PA = 0x8000_9000
    L3_PA = 0x8000_A000
    LO_PA = 0x8000_4000
    HI_PA = 0x8000_6000  # 与 LO_PA 相隔两页, 物理上不相邻
    PC = 0x8000_0000

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    @classmethod
    def _assemble(cls, code: bytes) -> Emulator:
        emu = Emulator(make_test_config())
        emu.load_code(cls.PC, code + b"\x13\x00\x00\x00")
        # 两个虚拟页分别映射到不相邻的物理页
        leaf = 0xCF  # V|R|W|X|U|A|D
        bus = emu.bus
        bus.write(
            cls.ROOT_PA + 8, cls._pte(cls.L2_PA, 0x01).to_bytes(8, "little")
        )
        bus.write(
            cls.L2_PA + 0, cls._pte(cls.L3_PA, 0x01).to_bytes(8, "little")
        )
        vpn0_lo = (cls.VA >> 12) & 0x1FF
        vpn0_hi = ((cls.VA + 0x1000) >> 12) & 0x1FF
        bus.write(
            cls.L3_PA + vpn0_lo * 8,
            cls._pte(cls.LO_PA, leaf).to_bytes(8, "little"),
        )
        bus.write(
            cls.L3_PA + vpn0_hi * 8,
            cls._pte(cls.HI_PA, leaf).to_bytes(8, "little"),
        )
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (cls.ROOT_PA >> 12)
        h.pc = cls.PC
        return emu

    @classmethod
    def _expected(cls, off_in_page: int, size: int) -> int:
        """按两个物理页各自的字节拼出期望值."""
        lo = bytearray(cls._page_bytes(cls.LO_PA))
        hi = bytearray(cls._page_bytes(cls.HI_PA))
        out = bytearray()
        for i in range(size):
            pos = off_in_page + i
            out.append(lo if pos < 0x1000 else hi[pos - 0x1000])
        return int.from_bytes(out, "little")

    @staticmethod
    def _page_bytes(pa: int) -> bytes:
        return bytes(((pa >> 12) + i * 13 + 7) & 0xFF for i in range(0x1000))

    def _run(self, code: bytes, regs: dict[int, int], is_engine: bool):
        emu = self._assemble(code)
        # 两页按各自的物理页号填不同图案
        for pa in (self.LO_PA, self.HI_PA):
            emu.bus.write(pa, self._page_bytes(pa))
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        h.pc = self.PC
        if is_engine:
            emu.add_breakpoint(self.PC + len(code))
            emu.add_breakpoint(h.csrs["mtvec"].val)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        return h.pc, int(h.gprs[5])

    @pytest.mark.timeout(120)
    def test_cross_page_loads(self) -> None:
        base = self.VA
        for size, opc, func3 in (
            (2, 0x03, 0b101),
            (4, 0x03, 0b110),
            (8, 0x03, 0b011),
        ):
            for off in range(0x1000 - size + 1, 0x1000):
                imm = 0x200  # 基址指向 0x4000_0200, 偏移接近页尾
                va_off = (imm + off) & 0xFFF
                if va_off != off:
                    continue
                # 直接把基址放在页内偏移处, 立即数为 0
                word = i_type(opc, 5, func3, 6, 0)
                code = word.to_bytes(4, "little")
                regs = {6: base + off}
                # 该地址是未对齐的, 期望值由两页字节拼接
                expect = self._expected(off, size)
                for is_engine in (False, True):
                    pc, val = self._run(code, regs, is_engine)
                    path = "引擎" if is_engine else "纯 Python"
                    assert pc == self.PC + 4, (
                        f"{path} size={size} off={off:#x}: pc"
                    )
                    assert val == expect, (
                        f"{path} size={size} off={off:#x}: "
                        f"{val:#x} != {expect:#x}"
                    )


class TestStoreReplayAfterPageFault:
    """存储触发缺页, 处理函数补好页表项后返回到同一条存储并重放.

    ``sv_gets`` 的单帧约 8 KiB: ``c.addi16sp -0x120`` 加 ``lui 0xffffe``
    与 ``add sp, sp, t0``,
    序言里的 ``sd``/``sw`` 会越过已映射的栈页触发栈增长缺页; 内核补页后回到同
    一条存储重放它. 若重放时地址或取值有偏差, 写进帧内的就是别的数据.
    """

    PC = 0x8000_0000
    HANDLER = 0x8000_2000
    ROOT_PA = 0x8000_8000
    L2_PA = 0x8000_9000
    L3_PA = 0x8000_A000
    DATA_PA = 0x8000_5000
    VA = 0x4000_0000
    PTE_ADDR = L3_PA  # 0x4000_0000 的末级页表项

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    def _assemble(self, code: bytes) -> Emulator:
        emu = Emulator(make_test_config())
        emu.load_code(self.PC, code + b"\x13\x00\x00\x00")
        # 处理函数: sd a1, 0(a0); sfence.vma x0, x0; sret
        handler = b"".join(
            w.to_bytes(4, "little")
            for w in (
                s_type(0x23, 0b011, 10, 11, 0),
                0x12000073,
                0x10200073,
            )
        )
        emu.load_code(self.HANDLER, handler + b"\x13\x00\x00\x00" * 4)
        bus = emu.bus
        # VA 0x4000_0000 的 vpn2 为 1: 根页表项 1 指向二级页表
        bus.write(
            self.ROOT_PA + 8, self._pte(self.L2_PA, 0x01).to_bytes(8, "little")
        )
        bus.write(self.L2_PA, self._pte(self.L3_PA, 0x01).to_bytes(8, "little"))
        # 根页表项 2 做一个 1 GiB 恒等映射, 使处理函数能按物理地址访问页表页
        bus.write(
            self.ROOT_PA + 2 * 8,
            self._pte(0x8000_0000, 0xCF).to_bytes(8, "little"),
        )
        # 叶子项初始不带 W: 存储触发 StPageFault
        bus.write(
            self.L3_PA,
            self._pte(self.DATA_PA, 0x47).to_bytes(8, "little"),
        )
        bus.write(self.DATA_PA, bytes(64))
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["stvec"].val = self.HANDLER
        h.csrs["medeleg"].val |= (1 << 15) | (1 << 13)
        h.pc = self.PC
        return emu

    def _run(self, code: bytes, regs: dict[int, int], is_engine: bool):
        emu = self._assemble(code)
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        end = self.PC + len(code)
        if is_engine:
            emu.add_breakpoint(end)
            emu.add_breakpoint(self.HANDLER)
            emu.add_breakpoint(end + 4)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            for _ in range(16):
                emu.step()
                if h.pc in (end, end + 4):
                    break
        return (
            h.pc,
            int(h.gprs[14]),
            bytes(emu.bus.read(self.DATA_PA, 8)),
            int(h.csrs["stvec"].val),
        )

    @pytest.mark.timeout(120)
    def test_store_replayed_after_fault(self) -> None:
        # sd a3, 0(a2) ; ld a4, 0(a2)
        code = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little") + i_type(
            0x03, 14, 0b011, 12, 0
        ).to_bytes(4, "little")
        for width, func3 in ((8, 0b011), (4, 0b010), (2, 0b001), (1, 0b000)):
            value = 0x1122_3344_5566_7788
            store = s_type(0x23, func3, 12, 13, 0).to_bytes(4, "little")
            load = {
                8: i_type(0x03, 14, 0b011, 12, 0),
                4: i_type(0x03, 14, 0b110, 12, 0),
                2: i_type(0x03, 14, 0b101, 12, 0),
                1: i_type(0x03, 14, 0b100, 12, 0),
            }[width]
            code = store + load.to_bytes(4, "little")
            regs = {
                10: self.PTE_ADDR,  # a0: 页表项地址
                11: self._pte(self.DATA_PA, 0xCF),  # a1: 补上 W 的页表项
                12: self.VA,  # a2: 存储目标
                13: value,  # a3: 写入值
            }
            want = value & ((1 << (8 * width)) - 1)
            for is_engine in (False, True):
                path = "引擎" if is_engine else "纯 Python"
                pc, a4, mem, _ = self._run(code, regs, is_engine)
                assert pc == self.PC + 8, f"{path} w={width}: pc={pc:#x}"
                assert a4 == want, (
                    f"{path} w={width}: 重放后读回 {a4:#x} != {want:#x}"
                )
                assert int.from_bytes(mem[:width], "little") == want, (
                    f"{path} w={width}: 内存 {mem.hex()}"
                )


class TestCopyToUserFaultCycle:
    """按内核把文件内容拷入用户页的过程, 逐条核对存储与缺页重试.

    ``copy_to_user`` 由若干条存储组成, 目标页首次触摸时逐条投递 StPageFault,
    内核补好页表项后返回到同一条存储重放. 本类覆盖: 跨页存储的第二页缺页时
    前半部分不得提前写入; 逐页首次触摸的整段拷贝结果必须与源数据一致;
    ``sfence.vma`` 之后重映射必须按新页表项写入.
    """

    PC = 0x8000_0000
    MTVEC = 0x8000_2000
    SFENCE_PC = 0x8000_0040
    ROOT_PA = 0x8000_9000
    L2_PA = 0x8000_A000
    L3_PA = 0x8000_B000
    VA = 0x4000_0000
    FRAMES = (0x8000_5000, 0x8000_6000, 0x8000_7000, 0x8000_8000)

    ST_PAGE_FAULT = 15
    ST_ACCESS_FAULT = 7

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    def _build(self, code: bytes) -> Emulator:
        emu = Emulator(make_test_config())
        emu.load_code(self.PC, code + b"\x13\x00\x00\x00" * 8)
        emu.load_code(self.MTVEC, b"\x13\x00\x00\x00" * 4)
        bus = emu.bus
        # 根页表项 1 指向二级页表, 覆盖 VA 0x4000_0000 起的 1 GiB
        bus.write(
            self.ROOT_PA + 8, self._pte(self.L2_PA, 0x01).to_bytes(8, "little")
        )
        bus.write(self.L2_PA, self._pte(self.L3_PA, 0x01).to_bytes(8, "little"))
        # 根页表项 2 做 1 GiB 恒等映射, 供 S 模式访问页表页与取指
        bus.write(
            self.ROOT_PA + 16,
            self._pte(0x8000_0000, 0xCF).to_bytes(8, "little"),
        )
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["mtvec"].val = self.MTVEC
        # SUM: 允许 S 模式访问 U 页, 与内核拷贝用户页的情形一致
        h.csrs["mstatus"].val |= 1 << 18
        h.pc = self.PC
        return emu

    def _map(self, emu: Emulator, idx: int, pa: int, flags: int) -> None:
        emu.bus.write(
            self.L3_PA + idx * 8, self._pte(pa, flags).to_bytes(8, "little")
        )

    @staticmethod
    def _flags(*, is_writable: bool = True, is_present: bool = True) -> int:
        flags = 0x10  # U
        if is_present:
            flags |= 0x01 | 0x02  # V | R
        if is_writable:
            flags |= 0x04
        return flags

    def _step(self, emu: Emulator, is_engine: bool, next_pc: int | None = None):
        if is_engine:
            emu.add_breakpoint(self.PC + 4 if next_pc is None else next_pc)
            emu.add_breakpoint(self.MTVEC)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        return emu.harts[0].pc

    def _store(
        self,
        emu: Emulator,
        is_engine: bool,
        regs: dict[int, int],
        mapper=None,
        next_pc: int | None = None,
    ):
        """执行位于 PC 的存储, 缺页时按需要补页表项并返回到同一条存储重放."""
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        h.pc = self.PC
        h.mode = RiscvMode.S
        faults = []
        while True:
            self._step(emu, is_engine, next_pc)
            if h.pc != self.MTVEC:
                return faults
            cause = int(h.csrs["mcause"].val)
            tval = int(h.csrs["mtval"].val)
            faults.append((cause, tval))
            assert len(faults) <= 4, f"陷态次数过多: {faults}"
            if mapper is not None:
                mapper(cause, tval)
            h.pc = self.PC
            h.mode = RiscvMode.S

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_cross_page_store_second_page_faults(self, is_engine: bool) -> None:
        """跨页存储的第二页缺页时, 前半部分不得先写入内存."""
        code = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        value = 0x1122_3344_5566_7788
        va = self.VA + 0xFFC
        emu = self._build(code)
        self._map(emu, 0, self.FRAMES[0], self._flags())
        h = emu.harts[0]
        for reg, val in {12: va, 13: value}.items():
            h.gprs[reg] = val
        # 第一次执行: 第二页没有页表项, 必须投递 StPageFault 且不写入首半部分
        self._step(emu, is_engine)
        assert h.pc == self.MTVEC, f"应陷入 mtvec, 实际 pc={h.pc:#x}"
        assert int(h.csrs["mcause"].val) == self.ST_PAGE_FAULT
        assert int(h.csrs["mtval"].val) == va + 4, (
            f"mtval={int(h.csrs['mtval'].val):#x}"
        )
        assert bytes(emu.bus.read(self.FRAMES[0], 8)) == bytes(8), (
            "第二页缺页时首半部分不得写入"
        )
        # 内核补上第二页的页表项, 返回到同一条存储重放
        self._map(emu, 1, self.FRAMES[1], self._flags())
        h.pc = self.PC
        h.mode = RiscvMode.S
        self._step(emu, is_engine)
        assert h.pc == self.PC + 4, f"重放后 pc={h.pc:#x}"
        assert (
            bytes(emu.bus.read(self.FRAMES[0] + 0xFFC, 4))
            == value.to_bytes(8, "little")[:4]
        )
        assert (
            bytes(emu.bus.read(self.FRAMES[1], 4))
            == value.to_bytes(8, "little")[4:]
        )

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_copy_over_fresh_pages_matches_source(
        self,
        is_engine: bool,
    ) -> None:
        """逐页首次触摸的整段拷贝, 每页内容必须与源数据一致."""
        code = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        emu = self._build(code)
        values = [
            0x0102_0304_0506_0708 + i * 0x1111_1111_1111_1111 for i in range(8)
        ]
        strides = [0, 8, 0x1000, 0x1008, 0x2000, 0x2008, 0x3000, 0x3008]
        for idx, frame in enumerate(self.FRAMES):
            self._map(emu, idx, frame, self._flags(is_present=False))

        def mapper(cause: int, tval: int) -> None:
            assert cause == self.ST_PAGE_FAULT, f"mcause={cause}"
            idx = (tval - self.VA) // 0x1000
            self._map(emu, idx, self.FRAMES[idx], self._flags())

        for stride, value in zip(strides, values):
            faults = self._store(
                emu, is_engine, {12: self.VA + stride, 13: value}, mapper
            )
            assert len(faults) <= 1, f"同一页再次缺页: {faults}"
        for stride, value in zip(strides, values):
            page = stride // 0x1000
            off = stride % 0x1000
            got = bytes(emu.bus.read(self.FRAMES[page] + off, 8))
            assert int.from_bytes(got, "little") == value, (
                f"落在 {self.FRAMES[page] + off:#x} 的 {got.hex()} 与源数据不符"
            )

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_remap_after_sfence_uses_new_frame(self, is_engine: bool) -> None:
        """sfence.vma 之后改写页表项, 后续存储必须写入新的物理页."""
        code = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        first, second = 0xAA55_AA55_AA55_AA55, 0x5A5A_5A5A_5A5A_5A5A
        emu = self._build(code)
        emu.load_code(self.SFENCE_PC, (0x12000073).to_bytes(4, "little"))
        self._map(emu, 0, self.FRAMES[0], self._flags())
        self._store(emu, is_engine, {12: self.VA, 13: first})
        assert bytes(emu.bus.read(self.FRAMES[0], 8)) == first.to_bytes(
            8, "little"
        )
        # 改写页表项指向另一物理页, 再执行 sfence.vma
        self._map(emu, 0, self.FRAMES[1], self._flags())
        h = emu.harts[0]
        h.pc = self.SFENCE_PC
        if is_engine:
            emu.add_breakpoint(self.SFENCE_PC + 4)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called
        else:
            emu.step()
        assert h.pc == self.SFENCE_PC + 4, f"sfence.vma 后 pc={h.pc:#x}"
        self._store(emu, is_engine, {12: self.VA, 13: second})
        assert bytes(emu.bus.read(self.FRAMES[1], 8)) == second.to_bytes(
            8, "little"
        ), "重映射后的存储应写入新物理页"
        assert bytes(emu.bus.read(self.FRAMES[0], 8)) == first.to_bytes(
            8, "little"
        ), "旧物理页不得被再次写入"

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_compressed_store_replayed_after_fault(
        self,
        is_engine: bool,
    ) -> None:
        """c.sd 触发缺页后重放, 写入的值与宽度必须与指令编码一致.

        llvm-mc: c.sd a3, 0(a2) -> 0xe214.
        """
        code = (0xE214).to_bytes(2, "little")
        emu = self._build(code)
        self._map(emu, 0, self.FRAMES[0], self._flags(is_present=False))
        value = 0x0F0E_0D0C_0B0A_0908

        def mapper(cause: int, tval: int) -> None:
            assert cause == self.ST_PAGE_FAULT, f"mcause={cause}"
            assert tval == self.VA, f"mtval={tval:#x}"
            self._map(emu, 0, self.FRAMES[0], self._flags())

        faults = self._store(
            emu,
            is_engine,
            {12: self.VA, 13: value},
            mapper,
            next_pc=self.PC + 2,
        )
        assert [cause for cause, _ in faults] == [self.ST_PAGE_FAULT], faults
        got = int.from_bytes(bytes(emu.bus.read(self.FRAMES[0], 8)), "little")
        assert got == value, f"重放后内存 {got:#x}"

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_store_to_non_ram_page_faults(self, is_engine: bool) -> None:
        """页表项指向主存之外的物理地址时投递访问故障, 不得静默丢弃."""
        code = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        emu = self._build(code)
        self._map(emu, 0, 0x4000_0000_0000, self._flags())
        h = emu.harts[0]
        for reg, val in {12: self.VA, 13: 0x1234}.items():
            h.gprs[reg] = val
        self._step(emu, is_engine)
        assert h.pc == self.MTVEC, f"应陷入 mtvec, 实际 pc={h.pc:#x}"
        assert int(h.csrs["mcause"].val) == self.ST_ACCESS_FAULT, (
            f"mcause={int(h.csrs['mcause'].val)}"
        )


class TestUserStoreFaultDelegation:
    """U 模式的存储缺页委派给 S 模式后, 补好页表项返回时必须重放该存储.

    与内核把页缓存内容拷入用户页的情形一致: 目标页首次触摸时由 U 模式访存触发
    StPageFault, medeleg 把它交给 S 模式; 处理函数写入页表项并执行 sfence.vma,
    随后 sret 返回到同一条存储. 缺失重放时该页会保留内核清零后的内容.
    """

    U_PC = 0x4000_0000
    U_DATA = 0x4000_1000
    HANDLER = 0x8000_2000
    ROOT_PA = 0x8000_9000
    L2_PA = 0x8000_A000
    L3_PA = 0x8000_B000
    CODE_PA = 0x8000_C000
    DATA_PA = 0x8000_D000

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    def _build(self, code: bytes) -> Emulator:
        emu = Emulator(make_test_config())
        emu.load_code(self.CODE_PA, code + b"\x13\x00\x00\x00" * 4)
        # 处理函数: sd a1, 0(a0); sfence.vma x0, x0; sret
        handler = b"".join(
            w.to_bytes(4, "little")
            for w in (
                s_type(0x23, 0b011, 10, 11, 0),
                0x12000073,
                0x10200073,
            )
        )
        emu.load_code(self.HANDLER, handler + b"\x13\x00\x00\x00" * 4)
        bus = emu.bus
        bus.write(
            self.ROOT_PA + 8, self._pte(self.L2_PA, 0x01).to_bytes(8, "little")
        )
        bus.write(self.L2_PA, self._pte(self.L3_PA, 0x01).to_bytes(8, "little"))
        # 根页表项 2: 1 GiB 恒等映射, 供 S 模式访问页表页并取指
        bus.write(
            self.ROOT_PA + 16,
            self._pte(0x8000_0000, 0xCF).to_bytes(8, "little"),
        )
        # 用户代码页, 权限为可读、可写、可执行并属于用户
        bus.write(
            self.L3_PA,
            self._pte(self.CODE_PA, 0x1F).to_bytes(8, "little"),
        )
        # 用户数据页初始没有页表项
        bus.write(self.L3_PA + 8, bytes(8))
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.U
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["stvec"].val = self.HANDLER
        h.csrs["medeleg"].val |= 1 << 15
        h.pc = self.U_PC
        return emu

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_user_store_replayed_after_delegated_fault(
        self,
        is_engine: bool,
    ) -> None:
        """llvm 无关: sd a3, 0(a2) 在 U 模式向未建立的用户页写入."""
        code = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        value = 0x1122_3344_5566_7788
        emu = self._build(code)
        h = emu.harts[0]
        for reg, val in {
            10: self.L3_PA + 8,  # a0: 页表项地址
            11: self._pte(self.DATA_PA, 0x17),  # a1: V|R|W|U
            12: self.U_DATA,  # a2: 存储目标
            13: value,  # a3: 写入值
        }.items():
            h.gprs[reg] = val
        if is_engine:
            emu.add_breakpoint(self.U_PC + 4)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                for _ in range(4):
                    if h.pc == self.U_PC + 4:
                        break
                    emu.run(timeout=10)
                assert engine.called, "本用例应经加速执行引擎运行"
        else:
            for _ in range(12):
                emu.step()
                if h.pc in (self.U_PC + 4, self.HANDLER):
                    break
            if h.pc == self.HANDLER:
                for _ in range(12):
                    emu.step()
                    if h.pc == self.U_PC + 4:
                        break
        assert h.pc == self.U_PC + 4, f"重放后 pc={h.pc:#x}"
        got = int.from_bytes(bytes(emu.bus.read(self.DATA_PA, 8)), "little")
        assert got == value, f"重放后内存 {got:#x}"


class TestSumPermission:
    """S 模式访问 U 级页的 SUM 判定.

    内核在 ``copy_to_user`` 前后用 ``sstatus.SUM`` 打开与关闭 S 模式对 U 级页的
    数据访问. 该位判定错误会整段改变拷贝是否发生, 直接决定系统调用返回给受调
    试程序的数据.
    """

    PC = 0x8000_0000
    HANDLER = 0x8000_1000
    ROOT_PA = 0x8000_8000
    L2_PA = 0x8000_9000
    L3_PA = 0x8000_A000
    USER_PA = 0x8000_5000
    VA = 0x4000_0000
    SUM = 1 << 18

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    def _assemble(self, code: bytes, is_sum: bool) -> Emulator:
        emu = Emulator(make_test_config())
        emu.load_code(self.PC, code + b"\x13\x00\x00\x00")
        emu.load_code(self.HANDLER, b"\x13\x00\x00\x00" * 4)
        bus = emu.bus
        # 1 GiB 恒等映射, 使 S 模式能取指并运行在 0x8000_0000 附近
        bus.write(
            self.ROOT_PA + 2 * 8,
            self._pte(0x8000_0000, 0xCF).to_bytes(8, "little"),
        )
        # VA 0x4000_0000 -> USER_PA, 叶子项带 U 位
        bus.write(
            self.ROOT_PA + 8, self._pte(self.L2_PA, 0x01).to_bytes(8, "little")
        )
        bus.write(self.L2_PA, self._pte(self.L3_PA, 0x01).to_bytes(8, "little"))
        bus.write(
            self.L3_PA, self._pte(self.USER_PA, 0xD7).to_bytes(8, "little")
        )
        bus.write(self.USER_PA, b"\x11\x22\x33\x44\x55\x66\x77\x88")
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["stvec"].val = self.HANDLER
        h.csrs["medeleg"].val |= (1 << 12) | (1 << 13) | (1 << 15)
        if is_sum:
            h.mstatus_val |= self.SUM
        h.gprs[12] = self.VA
        h.gprs[13] = 0xDEAD_BEEF_CAFE_1234
        h.pc = self.PC
        return emu

    def _run(self, code: bytes, is_sum: bool, is_engine: bool):
        emu = self._assemble(code, is_sum)
        h = emu.harts[0]
        end = self.PC + len(code)
        if is_engine:
            emu.add_breakpoint(end)
            emu.add_breakpoint(self.HANDLER)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        return (
            h.pc,
            int(h.gprs[14]),
            int(h.csrs["scause"].val),
            int(h.csrs["stval"].val),
            bytes(emu.bus.read(self.USER_PA, 8)),
        )

    @pytest.mark.timeout(120)
    def test_sum_gates_user_page_access(self) -> None:
        load = i_type(0x03, 14, 0b011, 12, 0).to_bytes(4, "little")
        store = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        for is_engine in (False, True):
            path = "引擎" if is_engine else "纯 Python"
            # SUM=0: 读与写都必须按缺页处理, tval 为访问的虚拟地址
            pc, _a4, cause, tval, _mem = self._run(load, False, is_engine)
            assert (pc, cause, tval) == (self.HANDLER, 13, self.VA), (
                f"{path}: SUM=0 的读应投递 LdPageFault, 实际 "
                f"cause={cause} tval={tval:#x} pc={pc:#x}"
            )
            pc, _a4, cause, tval, _mem = self._run(store, False, is_engine)
            assert (pc, cause, tval) == (self.HANDLER, 15, self.VA), (
                f"{path}: SUM=0 的写应投递 StPageFault, 实际 "
                f"cause={cause} tval={tval:#x}"
            )
            # SUM=1: 读写都必须成功
            pc, a4, _cause, _tval, _mem = self._run(load, True, is_engine)
            assert pc == self.PC + 4, f"{path}: SUM=1 的读应完成, pc={pc:#x}"
            assert a4 == 0x8877_6655_4433_2211, f"{path}: 读回 {a4:#x}"
            pc, _a4, _cause, _tval, mem = self._run(store, True, is_engine)
            assert pc == self.PC + 4, f"{path}: SUM=1 的写应完成, pc={pc:#x}"
            assert mem == (0xDEAD_BEEF_CAFE_1234).to_bytes(8, "little"), (
                f"{path}: 写入后内存为 {mem.hex()}"
            )

    @pytest.mark.timeout(120)
    def test_fetch_from_user_page_always_denied(self) -> None:
        """S 模式从 U 级页取指必须失败, 与 SUM 无关."""
        for is_sum in (False, True):
            for is_engine in (False, True):
                emu = self._assemble(b"\x13\x00\x00\x00", is_sum)
                h = emu.harts[0]
                h.pc = self.VA  # 直接取自 U 级页
                emu.add_breakpoint(self.HANDLER)
                if is_engine:
                    with mock.patch(
                        "pyremu.emu.native.run_parallel", wraps=run_parallel
                    ) as engine:
                        emu.run(timeout=10)
                    assert engine.called
                else:
                    emu.step()
                assert h.csrs["scause"].val == 12, (
                    f"SUM={is_sum}: 取指应投递 InstrPageFault, "
                    f"实际 {h.csrs['scause'].val}"
                )
                assert h.csrs["stval"].val == self.VA


class TestUserPageFaultFixup:
    """S 模式访问未映射的 U 级页: 陷态不得改动任何通用寄存器.

    ``copy_to_user`` 中途缺页时, 内核的异常表修复代码依赖寄存器计算剩余长度;
    陷态若改写了目的寄存器或其余寄存器, 修复后拷贝的源/目的指针就会错位.
    """

    PC = 0x8000_0000
    HANDLER = 0x8000_1000
    ROOT_PA = 0x8000_8000
    L2_PA = 0x8000_9000
    L3_PA = 0x8000_A000
    USER_PA = 0x8000_5000
    VA = 0x4000_0000
    SUM = 1 << 18

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    def _assemble(self, code: bytes, is_valid: bool) -> Emulator:
        emu = Emulator(make_test_config())
        emu.load_code(self.PC, code + b"\x13\x00\x00\x00")
        handler = s_type(0x23, 0b011, 10, 11, 0).to_bytes(4, "little")
        emu.load_code(
            self.HANDLER, handler + b"\x73\x00\x20\x10" + b"\x13\x00\x00\x00"
        )
        bus = emu.bus
        bus.write(
            self.ROOT_PA + 2 * 8,
            self._pte(0x8000_0000, 0xCF).to_bytes(8, "little"),
        )
        bus.write(
            self.ROOT_PA + 8, self._pte(self.L2_PA, 0x01).to_bytes(8, "little")
        )
        bus.write(self.L2_PA, self._pte(self.L3_PA, 0x01).to_bytes(8, "little"))
        # 叶子项: 有效时带 U|R|W|A|D, 无效时清零 V 位
        leaf = 0xD7 if is_valid else 0x00
        bus.write(
            self.L3_PA, self._pte(self.USER_PA, leaf).to_bytes(8, "little")
        )
        bus.write(self.USER_PA, b"\x11\x22\x33\x44\x55\x66\x77\x88")
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["stvec"].val = self.HANDLER
        h.csrs["medeleg"].val |= (1 << 13) | (1 << 15)
        h.mstatus_val |= self.SUM
        h.gprs[10] = self.L3_PA  # a0: 处理函数写回页表项的地址
        h.gprs[11] = self._pte(self.USER_PA, 0xD7)  # a1: 修好后的页表项
        h.gprs[12] = self.VA
        h.gprs[13] = 0xDEAD_BEEF_CAFE_1234
        h.pc = self.PC
        return emu

    def _run(self, code: bytes, is_valid: bool, is_engine: bool):
        emu = self._assemble(code, is_valid)
        h = emu.harts[0]
        before = tuple(int(g) for g in h.gprs)
        end = self.PC + len(code)
        if is_engine:
            emu.add_breakpoint(end)
            emu.add_breakpoint(self.HANDLER)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        return (
            h.pc,
            tuple(int(g) for g in h.gprs),
            before,
            int(h.csrs["scause"].val),
            int(h.csrs["stval"].val),
            bytes(emu.bus.read(self.USER_PA, 8)),
        )

    @pytest.mark.timeout(120)
    def test_fault_preserves_all_registers(self) -> None:
        load = i_type(0x03, 14, 0b011, 12, 0).to_bytes(4, "little")
        store = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        for is_engine in (False, True):
            path = "引擎" if is_engine else "纯 Python"
            for code, cause in ((load, 13), (store, 15)):
                pc, after, before, got_cause, tval, _mem = self._run(
                    code, False, is_engine
                )
                assert pc == self.HANDLER, f"{path}: pc={pc:#x}"
                assert got_cause == cause, f"{path}: scause={got_cause}"
                assert tval == self.VA, f"{path}: stval={tval:#x}"
                assert after == before, (
                    f"{path}: 陷态改动了通用寄存器, cause={cause}"
                )

    @pytest.mark.timeout(120)
    def test_replay_after_fixup(self) -> None:
        """处理函数补好页表项后, 返回到同一条存储重放并写入准确的值."""
        store = s_type(0x23, 0b011, 12, 13, 0).to_bytes(4, "little")
        want = (0xDEAD_BEEF_CAFE_1234).to_bytes(8, "little")
        for is_engine in (False, True):
            path = "引擎" if is_engine else "纯 Python"
            emu = self._assemble(store, is_valid=False)
            h = emu.harts[0]
            end = self.PC + len(store)
            if is_engine:
                emu.add_breakpoint(end)
                with mock.patch(
                    "pyremu.emu.native.run_parallel", wraps=run_parallel
                ) as engine:
                    emu.run(timeout=10)
                assert engine.called, "本用例应经加速执行引擎运行"
            else:
                for _ in range(16):
                    emu.step()
                    if h.pc == end:
                        break
            assert h.pc == end, f"{path}: pc={h.pc:#x}"
            mem = bytes(emu.bus.read(self.USER_PA, 8))
            assert mem == want, f"{path}: 重放后内存 {mem.hex()}"


class TestSepcAlign:
    """sepc 的低位按 IALIGN 取零, sret 可返回到 2 字节对齐的压缩指令.

    行读取的拷贝循环由压缩指令构成, 异常表修复与信号返回都可能把 sepc 指向
    2 字节对齐的地址; 低位规则错会使返回落点偏移一条指令.
    """

    PC = 0x8000_0000
    TARGET = 0x8000_0040
    ISA_WITH_C = "rv64imac_zicsr_zifencei"
    ISA_NO_C = "rv64ima_zicsr_zifencei"

    def _assemble(self, isa: str, code: bytes) -> Emulator:
        cfg = make_test_config()
        cfg.isa = isa
        emu = Emulator(cfg)
        emu.load_code(self.PC, code + b"\x13\x00\x00\x00" * 4)
        # 目标处放一条压缩指令 c.addi x5, 1 与若干填充
        emu.load_code(self.TARGET, (0x0285).to_bytes(2, "little"))
        emu.load_code(self.TARGET + 2, b"\x13\x00\x00\x00" * 4)
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.csrs["stvec"].val = self.PC + 0x100
        h.pc = self.PC
        return emu

    @pytest.mark.timeout(120)
    def test_sepc_low_bits_follow_ialign(self) -> None:
        # csrw sepc, a0 ; csrr a1, sepc
        code = i_type(0x73, 0, 0b001, 10, 0x141).to_bytes(4, "little") + i_type(
            0x73, 11, 0b010, 0, 0x141
        ).to_bytes(4, "little")
        for isa, is_c in ((self.ISA_WITH_C, True), (self.ISA_NO_C, False)):
            emu = self._assemble(isa, code)
            h = emu.harts[0]
            h.gprs[10] = self.TARGET | 0b11
            emu.step()
            emu.step()
            # 写回 0x…43: 有 C 时只清 bit0, 无 C 时清 bits[1:0]
            want = (self.TARGET | 0b10) if is_c else self.TARGET
            assert h.gprs[11] == want, (
                f"{isa}: sepc 读回 {h.gprs[11]:#x}, 期望 {want:#x}"
            )

    @pytest.mark.timeout(120)
    def test_sret_returns_to_compressed_instruction(self) -> None:
        code = (0x10200073).to_bytes(4, "little")  # sret
        emu = self._assemble(self.ISA_WITH_C, code)
        h = emu.harts[0]
        h.csrs["sepc"].val = self.TARGET
        emu.step()  # sret 本身
        assert h.pc == self.TARGET, f"sret 返回落点 {h.pc:#x}"
        emu.step()  # 目标处的 c.addi x5, 1
        assert h.gprs[5] == 1, f"压缩指令未执行, x5={h.gprs[5]}"
        assert h.pc == self.TARGET + 2, f"pc={h.pc:#x}"
