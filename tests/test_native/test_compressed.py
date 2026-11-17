#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""压缩指令的解码、与非压缩等效指令的差分及跨页访存."""

from __future__ import annotations

import random
from unittest import mock

import pytest

from pyremu import _native
from pyremu._native import (
    native_available,
    run_parallel,
)
from pyremu.core.hart import RiscvMode
from pyremu.emulator import Emulator
from tests.conftest import make_test_config


class TestCompressedDecode:
    """压缩指令的立即数位段与 RISC-V 编码一致。"""

    def test_lwsp_offset_bits(self, pure_python):
        """C.LWSP 的 uimm[7:6] 取 bits[3:2]、uimm[4:2] 取 bits[6:4]。

        0x4522 的偏移为 8 (改前取 bits[5:4] 与 bits[4:2], 得 64)。
        """
        assert _native.decode_compressed(0x4522).imm == 8
        assert _native.decode_compressed(0x5522).imm == 40

    def test_ldsp_and_fldsp_share_uimm(self, pure_python):
        """C.FLDSP 与 C.LDSP 共用 uimm[5|4:3|8:6]: 0x2006 与 0x6006 均为 64。"""
        assert _native.decode_compressed(0x2006).imm == 64
        assert _native.decode_compressed(0x6006).imm == 64

    def test_c0_floating_load_store_uimm(self, pure_python):
        """C.FLD 与 C.FSD 与 C.LD / C.SD 共用 uimm[5:3|6|7]。

        0x2020 (funct3=1) 与 0xA020 (funct3=5) 均为 64 (改前返回 0)。
        """
        assert _native.decode_compressed(0x2020).imm == 64
        assert _native.decode_compressed(0xA020).imm == 64

    def test_fsdsp_uimm2(self, pure_python):
        """C.FSDSP 与 C.SDSP 共用 uimm[5:3|8:6]: 0xA082 为 64 (改前返回 0)。"""
        assert _native.decode_compressed(0xA082).imm2 == 64
        assert _native.decode_compressed(0xE082).imm2 == 64


@pytest.mark.skipif(not native_available(), reason="需要加速执行库作为对照")
class TestCompressedMemDiff:
    """压缩访存指令在全部立即数与寄存器组合下与纯 Python 路径一致.

    ``sv_gets`` 快速路径大量使用 C.LD/C.SD/C.LW/C.SW 与其栈指针形式, 且
    偏移覆盖整个立即数范围; 逐个编码的定点用例覆盖不到这种组合, 故对
    立即数取全量、寄存器组合取随机样本, 校验寄存器、内存与 PC.
    """

    PC = 0x8000_0000
    BASE = 0x8000_4000
    SPAN = 2 * 4096

    @classmethod
    def _run(cls, code: bytes, regs: dict[int, int], is_engine: bool):
        emu = Emulator(make_test_config())
        emu.load_code(cls.PC, code + b"\x13\x00\x00\x00")
        pattern = bytes((i * 7 + 5) & 0xFF for i in range(cls.SPAN))
        emu.load_code(cls.BASE, pattern)
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
        return (
            h.pc,
            tuple(int(g) for g in h.gprs),
            bytes(emu.bus.read(cls.BASE, cls.SPAN)),
        )

    @staticmethod
    def _c0_mem(funct3: int, rs1p: int, rd: int, uimm: int) -> int:
        """C0 象限访存编码: C.LW/C.SW 用 uimm[5:3|2|6], 其余用 uimm[5:3|7:6]."""
        if funct3 in (2, 6):
            hi = ((uimm >> 3) & 0x7) << 10
            lo = (((uimm >> 2) & 1) << 6) | (((uimm >> 6) & 1) << 5)
        else:
            hi = ((uimm >> 3) & 0x7) << 10
            lo = ((uimm >> 6) & 0x3) << 5
        return (
            (funct3 << 13) | hi | ((rs1p & 0x7) << 7) | lo | ((rd & 0x7) << 2)
        )

    @staticmethod
    def _c2_ldsp(rd: int, uimm: int) -> int:
        return (
            (0b011 << 13)
            | (((uimm >> 5) & 1) << 12)
            | ((rd & 0x1F) << 7)
            | (((uimm >> 3) & 0x3) << 5)
            | (((uimm >> 6) & 0x7) << 2)
            | 0b10
        )

    @staticmethod
    def _c2_sdsp(rs2: int, uimm: int) -> int:
        return (
            (0b111 << 13)
            | (((uimm >> 3) & 0x7) << 10)
            | (((uimm >> 6) & 0x7) << 7)
            | ((rs2 & 0x1F) << 2)
            | 0b10
        )

    @staticmethod
    def _c2_lwsp(rd: int, uimm: int) -> int:
        return (
            (0b010 << 13)
            | (((uimm >> 5) & 1) << 12)
            | ((rd & 0x1F) << 7)
            | (((uimm >> 2) & 0x7) << 4)
            | (((uimm >> 6) & 0x3) << 2)
            | 0b10
        )

    @staticmethod
    def _c2_swsp(rs2: int, uimm: int) -> int:
        return (
            (0b110 << 13)
            | (((uimm >> 2) & 0xF) << 9)
            | (((uimm >> 6) & 0x3) << 7)
            | ((rs2 & 0x1F) << 2)
            | 0b10
        )

    def _diff(self, code: bytes, regs: dict[int, int], what: str) -> None:
        py = self._run(code, regs, is_engine=False)
        eng = self._run(code, regs, is_engine=True)
        assert py == eng, f"{what} 引擎与纯 Python 不一致: {py} != {eng}"

    @pytest.mark.timeout(120)
    def test_c0_load_store_all_immediates(self) -> None:
        rng = random.Random(0x1DEA)
        # funct3: 2 = C.LW, 3 = C.LD, 6 = C.SW, 7 = C.SD
        for funct3, width in ((2, 4), (3, 8), (6, 4), (7, 8)):
            uimms = list(range(0, 512, 8 if width == 8 else 4))
            for uimm in uimms:
                rs1p = rng.randrange(8)
                rd = rng.randrange(8)
                base = self.BASE + 64
                value = rng.getrandbits(64)
                regs = {
                    8 + rs1p: base,
                    8 + rd: value,
                }
                code = self._c0_mem(funct3, rs1p, rd, uimm).to_bytes(
                    2, "little"
                )
                self._diff(code, regs, f"C.f3={funct3} uimm={uimm}")

    @pytest.mark.timeout(120)
    def test_c2_sp_load_store_all_immediates(self) -> None:
        rng = random.Random(0x2DEA)
        base = self.BASE + 64
        for uimm in range(0, 512, 8):
            rd = rng.randrange(1, 32)
            regs = {2: base, rd: rng.getrandbits(64)}
            self._diff(
                self._c2_ldsp(rd, uimm).to_bytes(2, "little"),
                regs,
                f"C.LDSP uimm={uimm} rd={rd}",
            )
            rs2 = rng.randrange(32)
            regs = {2: base, rs2: rng.getrandbits(64)}
            self._diff(
                self._c2_sdsp(rs2, uimm).to_bytes(2, "little"),
                regs,
                f"C.SDSP uimm={uimm} rs2={rs2}",
            )
        for uimm in range(0, 256, 4):
            rd = rng.randrange(1, 32)
            regs = {2: base, rd: rng.getrandbits(64)}
            self._diff(
                self._c2_lwsp(rd, uimm).to_bytes(2, "little"),
                regs,
                f"C.LWSP uimm={uimm} rd={rd}",
            )
            rs2 = rng.randrange(32)
            regs = {2: base, rs2: rng.getrandbits(64)}
            self._diff(
                self._c2_swsp(rs2, uimm).to_bytes(2, "little"),
                regs,
                f"C.SWSP uimm={uimm} rs2={rs2}",
            )


class TestCompressedBranchImmDiff:
    """压缩跳转、分支与栈指针立即数在全部取值上与纯 Python 路径一致.

    行读取的拷贝循环由 ``c.beqz``/``c.bnez``/``c.addi16sp`` 与移位指令构成,
    偏移或立即数算错会让循环少走或多走一次, 表现为数据被少量字节替换.
    """

    PC = 0x8000_0000

    @classmethod
    def _run(
        cls,
        code: bytes,
        regs: dict[int, int],
        is_engine: bool,
        stops: tuple[int, ...] = (),
    ):
        emu = Emulator(make_test_config())
        emu.load_code(cls.PC, code + b"\x13\x00\x00\x00" * 8)
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        h.pc = cls.PC
        if is_engine:
            # 分支与跳转的落点由纯 Python 路径给出, 在此处与顺序执行处一并设点,
            # 使引擎停在同一条指令之前, 便于比较 pc.
            for addr in stops:
                emu.add_breakpoint(addr)
            emu.add_breakpoint(cls.PC + len(code))
            emu.add_breakpoint(h.csrs["mtvec"].val)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        return h.pc, tuple(int(g) for g in h.gprs)

    def _diff(self, code: bytes, regs: dict[int, int], what: str) -> None:
        py_pc, py_gprs = self._run(code, regs, is_engine=False)
        eng_pc, eng_gprs = self._run(code, regs, is_engine=True, stops=(py_pc,))
        assert (py_pc, py_gprs) == (eng_pc, eng_gprs), (
            f"{what}: {(py_pc, py_gprs)} != {(eng_pc, eng_gprs)}"
        )

    @staticmethod
    def _c_j(off: int) -> int:
        u = off & 0xFFF
        return (
            (0b101 << 13)
            | (((u >> 11) & 1) << 12)
            | (((u >> 4) & 1) << 11)
            | (((u >> 8) & 0x3) << 9)
            | (((u >> 10) & 1) << 8)
            | (((u >> 6) & 1) << 7)
            | (((u >> 7) & 1) << 6)
            | (((u >> 1) & 0x7) << 3)
            | (((u >> 5) & 1) << 2)
            | 0b01
        )

    @staticmethod
    def _c_branch(funct3: int, rs1p: int, off: int) -> int:
        u = off & 0x1FF
        return (
            (funct3 << 13)
            | (((u >> 8) & 1) << 12)
            | (((u >> 3) & 0x3) << 10)
            | ((rs1p & 0x7) << 7)
            | (((u >> 6) & 0x3) << 5)
            | (((u >> 1) & 0x3) << 3)
            | (((u >> 5) & 1) << 2)
            | 0b01
        )

    @staticmethod
    def _c_addi16sp(imm: int) -> int:
        n = imm & 0x3FF
        return (
            (0b011 << 13)
            | (((n >> 9) & 1) << 12)
            | (2 << 7)
            | (((n >> 4) & 1) << 6)
            | (((n >> 6) & 1) << 5)
            | (((n >> 7) & 0x3) << 3)
            | (((n >> 5) & 1) << 2)
            | 0b01
        )

    @staticmethod
    def _c_addi4spn(rd: int, uimm: int) -> int:
        return (
            (((uimm >> 4) & 0x3) << 11)
            | (((uimm >> 6) & 0xF) << 7)
            | (((uimm >> 2) & 1) << 6)
            | (((uimm >> 3) & 1) << 5)
            | ((rd & 0x7) << 2)
        )

    @pytest.mark.timeout(120)
    def test_c_j_all_offsets(self) -> None:
        for off in range(-2048, 2048, 16):
            code = self._c_j(off).to_bytes(2, "little")
            self._diff(code, {}, f"C.J off={off}")

    @pytest.mark.timeout(120)
    def test_c_branch_all_offsets(self) -> None:
        for funct3 in (0b110, 0b111):  # C.BEQZ / C.BNEZ
            for taken in (0, 1):
                for off in range(-256, 256, 8):
                    code = self._c_branch(funct3, 5, off).to_bytes(2, "little")
                    regs = {13: taken}  # x13 = a3, 对应 rs1'=5
                    self._diff(
                        code, regs, f"C.br f3={funct3} off={off} t={taken}"
                    )

    @pytest.mark.timeout(120)
    def test_c_addi16sp_all_immediates(self) -> None:
        for imm in range(-512, 512, 16):
            code = self._c_addi16sp(imm).to_bytes(2, "little")
            self._diff(code, {2: 0x8000_8000}, f"C.ADDI16SP imm={imm}")

    @pytest.mark.timeout(120)
    def test_c_addi4spn_all_immediates(self) -> None:
        for uimm in range(4, 1024, 4):
            code = self._c_addi4spn(1, uimm).to_bytes(2, "little")
            self._diff(code, {2: 0x8000_8000}, f"C.ADDI4SPN uimm={uimm}")

    @pytest.mark.timeout(120)
    def test_c_shift_all_amounts(self) -> None:
        rng = random.Random(0x3DEA)
        for shamt in range(64):
            val = rng.getrandbits(64)
            # C.SRLI/C.SRAI: 100 shamt[5] 00 rs1' shamt[4:0] 01
            for bit12 in (0, 1):
                word = (
                    (0b100 << 13)
                    | (bit12 << 12)
                    | ((shamt & 0x1F) << 2)
                    | (1 << 7)
                    | 0b01
                )
                self._diff(
                    word.to_bytes(2, "little"),
                    {9: val},
                    f"C.SR{'A' if bit12 else 'L'}I shamt={shamt}",
                )
            # C.SLLI: 000 shamt[5] rd shamt[4:0] 10
            word = (
                ((shamt >> 5) << 12) | (10 << 7) | ((shamt & 0x1F) << 2) | 0b10
            )
            self._diff(
                word.to_bytes(2, "little"), {10: val}, f"C.SLLI shamt={shamt}"
            )


class TestCompressedAluExpectation:
    """压缩 ALU 指令的结果与独立计算的期望值一致, 两条路径同时校验.

    只比较"引擎与 Python 一致"不足以排除两侧共有的误读, 故期望值在此
    独立计算, 不经过任何一侧的译码实现.
    """

    PC = 0x8000_0000
    MASK = (1 << 64) - 1

    @classmethod
    def _run(cls, code: bytes, regs: dict[int, int], is_engine: bool):
        emu = Emulator(make_test_config())
        emu.load_code(cls.PC, code + b"\x13\x00\x00\x00")
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
        return h.pc, tuple(int(g) for g in h.gprs)

    @staticmethod
    def _sext(val: int, bits: int) -> int:
        sign = 1 << (bits - 1)
        val &= (1 << bits) - 1
        return (val - (1 << bits)) if val & sign else val

    @classmethod
    def _sext32(cls, val: int) -> int:
        return cls._sext(val, 32) & cls.MASK

    def _check(
        self,
        code: bytes,
        regs: dict[int, int],
        reg: int,
        expect: int,
        what: str,
    ) -> None:
        for is_engine in (False, True):
            pc, gprs = self._run(code, regs, is_engine)
            path = "引擎" if is_engine else "纯 Python"
            assert pc == self.PC + len(code), f"{what} ({path}): pc={pc:#x}"
            want = expect & self.MASK
            assert gprs[reg] == want, (
                f"{what} ({path}): x{reg}={gprs[reg]:#x} != {want:#x}"
            )

    @pytest.mark.timeout(120)
    def test_c_alu_expectations(self) -> None:
        vals = [
            0,
            1,
            2,
            0x7F,
            0x80,
            0xFFFF_FFFF,
            0x8000_0000,
            0x7FFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0xFFFF_FFFF_FFFF_FFFF,
            0x0123_4567_89AB_CDEF,
            0xDEAD_BEEF_DEAD_BEEF,
        ]
        rng = random.Random(0x4DEA)
        vals.extend(rng.getrandbits(64) for _ in range(6))

        for a in vals:
            for imm6 in range(-32, 32, 7):
                u = imm6 & 0x3F
                # C.ADDI x10, imm
                w = ((u >> 5) << 12) | (10 << 7) | ((u & 0x1F) << 2) | 0b01
                self._check(
                    w.to_bytes(2, "little"),
                    {10: a},
                    10,
                    a + self._sext(u, 6),
                    f"C.ADDI imm={imm6}",
                )
                # C.LI x10, imm
                w = (
                    ((u >> 5) << 12)
                    | (0b010 << 13)
                    | (10 << 7)
                    | ((u & 0x1F) << 2)
                    | 0b01
                )
                self._check(
                    w.to_bytes(2, "little"),
                    {},
                    10,
                    self._sext(u, 6),
                    f"C.LI imm={imm6}",
                )
                # C.ADDIW x10, imm
                w = (
                    ((u >> 5) << 12)
                    | (0b001 << 13)
                    | (10 << 7)
                    | ((u & 0x1F) << 2)
                    | 0b01
                )
                self._check(
                    w.to_bytes(2, "little"),
                    {10: a},
                    10,
                    self._sext32(a + self._sext(u, 6)),
                    f"C.ADDIW imm={imm6}",
                )
                # C.LUI x10, imm (imm != 0)
                if imm6 != 0:
                    w = (
                        ((u >> 5) << 12)
                        | (0b011 << 13)
                        | (10 << 7)
                        | ((u & 0x1F) << 2)
                        | 0b01
                    )
                    self._check(
                        w.to_bytes(2, "little"),
                        {},
                        10,
                        self._sext(u, 6) << 12,
                        f"C.LUI imm={imm6}",
                    )
                # C.ANDI x10, imm (rd' = x10 -> rdp = 2)
                w = (
                    (0b100 << 13)
                    | ((u >> 5) << 12)
                    | (0b10 << 10)
                    | (2 << 7)
                    | ((u & 0x1F) << 2)
                    | 0b01
                )
                self._check(
                    w.to_bytes(2, "little"),
                    {10: a},
                    10,
                    a & self._sext(u, 6),
                    f"C.ANDI imm={imm6}",
                )

            # C.SUB/C.XOR/C.OR/C.AND: rd'=x10(2), rs1'=x11(3)
            for op, f2 in enumerate((0b00, 0b01, 0b10, 0b11)):
                b = vals[(op * 3 + 1) % len(vals)]
                # 压缩 ALU 形式: rd' 在 [9:7], rs2' 在 [4:2].
                w = (
                    (0b100 << 13)
                    | (0b11 << 10)
                    | (2 << 7)
                    | (f2 << 5)
                    | (3 << 2)
                    | 0b01
                )
                expect = [a - b, a ^ b, a | b, a & b][op]
                self._check(
                    w.to_bytes(2, "little"),
                    {10: a, 11: b},
                    10,
                    expect,
                    f"C.ALU f2={f2:#b}",
                )
            # C.SUBW / C.ADDW: bit12=1
            for f2, sign in ((0b00, -1), (0b01, 1)):
                b = vals[3]
                w = (
                    (0b100 << 13)
                    | (1 << 12)
                    | (0b11 << 10)
                    | (2 << 7)
                    | (f2 << 5)
                    | (3 << 2)
                    | 0b01
                )
                self._check(
                    w.to_bytes(2, "little"),
                    {10: a, 11: b},
                    10,
                    self._sext32(a + sign * b),
                    f"C.SUBW/ADDW f2={f2:#b}",
                )
            # C.MV / C.ADD: rd = x10, rs2 = x11
            b = vals[5]
            w = (0b100 << 13) | (10 << 7) | (11 << 2) | 0b10
            self._check(w.to_bytes(2, "little"), {11: b}, 10, b, "C.MV")
            w = (0b100 << 13) | (1 << 12) | (10 << 7) | (11 << 2) | 0b10
            self._check(
                w.to_bytes(2, "little"),
                {10: a, 11: b},
                10,
                a + b,
                "C.ADD",
            )


class TestCompressedCrossPage:
    """压缩访存跨页时必须按两页分别翻译.

    ``c.ld`` / ``c.sd`` 的偏移按 4 或 8 字节对齐, 但基址寄存器可以取任意值,
    有效地址因此可以跨过页边界. 两个虚拟页可能映射到不相邻的物理页, 按第一页
    的物理地址连续读写会把数据放到错误的物理页上.
    """

    PC = 0x8000_0000
    MTVEC = 0x8000_2000
    ROOT_PA = 0x8000_9000
    L2_PA = 0x8000_A000
    L3_PA = 0x8000_B000
    VA = 0x4000_0000
    FRAME_A = 0x8000_5000  # VA 0x4000_0000
    FRAME_X = 0x8000_6000  # 紧跟 FRAME_A 的物理页, 不得被跨页访问触碰
    FRAME_B = 0x8000_7000  # VA 0x4000_1000

    @staticmethod
    def _pte(pa: int, flags: int) -> int:
        return ((pa >> 12) << 10) | flags

    def _build(self, code: bytes) -> Emulator:
        emu = Emulator(make_test_config())
        emu.load_code(self.PC, code + b"\x13\x00\x00\x00" * 4)
        emu.load_code(self.MTVEC, b"\x13\x00\x00\x00" * 4)
        bus = emu.bus
        flags = 0x01 | 0x02 | 0x04 | 0x40 | 0x80  # V|R|W|A|D
        bus.write(
            self.ROOT_PA + 8, self._pte(self.L2_PA, 0x01).to_bytes(8, "little")
        )
        bus.write(self.L2_PA, self._pte(self.L3_PA, 0x01).to_bytes(8, "little"))
        bus.write(
            self.ROOT_PA + 16,
            self._pte(0x8000_0000, 0xCF).to_bytes(8, "little"),
        )
        bus.write(
            self.L3_PA, self._pte(self.FRAME_A, flags).to_bytes(8, "little")
        )
        bus.write(
            self.L3_PA + 8, self._pte(self.FRAME_B, flags).to_bytes(8, "little")
        )
        bus.write(self.FRAME_X, b"\xee" * 64)
        h = emu.harts[0]
        h.csrs["pmpcfg0"].val = 0x0F
        h.csrs["pmpaddr0"].val = (1 << 54) - 1
        h.mode = RiscvMode.S
        h.satp_val = (8 << 60) | (self.ROOT_PA >> 12)
        h.csrs["mtvec"].val = self.MTVEC
        h.pc = self.PC
        return emu

    def _run(self, emu: Emulator, is_engine: bool, regs: dict[int, int]):
        h = emu.harts[0]
        for reg, val in regs.items():
            h.gprs[reg] = val
        if is_engine:
            emu.add_breakpoint(self.PC + 2)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        assert h.pc == self.PC + 2, f"pc={h.pc:#x}"
        return h

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_c_sd_cross_page(self, is_engine: bool) -> None:
        """llvm-mc: c.sd a3, 0(a2) -> 0xe214, 有效地址取页末 4 字节."""
        code = (0xE214).to_bytes(2, "little")
        value = 0x1122_3344_5566_7788
        emu = self._build(code)
        self._run(emu, is_engine, {12: self.VA + 0xFFC, 13: value})
        raw = value.to_bytes(8, "little")
        assert bytes(emu.bus.read(self.FRAME_A + 0xFFC, 4)) == raw[:4], (
            "第一页的 4 个字节未写入"
        )
        assert bytes(emu.bus.read(self.FRAME_B, 4)) == raw[4:], (
            "第二页的 4 个字节未按第二页的翻译写入"
        )
        assert bytes(emu.bus.read(self.FRAME_X, 8)) == b"\xee" * 8, (
            "紧跟第一页的物理页不得被跨页存储触碰"
        )

    @pytest.mark.parametrize("is_engine", [False, True])
    @pytest.mark.timeout(120)
    def test_c_ld_cross_page(self, is_engine: bool) -> None:
        """llvm-mc: c.ld a3, 0(a2) -> 0x6214, 读出值必须来自两个被映射的页."""
        code = (0x6214).to_bytes(2, "little")
        emu = self._build(code)
        emu.bus.write(self.FRAME_A + 0xFFC, b"\xaa\xbb\xcc\xdd")
        emu.bus.write(self.FRAME_B, b"\x11\x22\x33\x44")
        h = self._run(emu, is_engine, {12: self.VA + 0xFFC})
        assert int(h.gprs[13]) == 0x4433_2211_DDCC_BBAA, (
            f"a3={int(h.gprs[13]):#x}, 读到了错误的物理页"
        )


class TestCompressedJumpRegDiff:
    """C.JR / C.JALR / C.EBREAK 与退化编码在两条路径上行为一致.

    间接跳转的落点由寄存器给出, 需按规范清除最低位; ``ra`` 的写入时机与
    目标计算不能互相影响. ``c.jr x0`` 与``c.jalr x0`` 属保留编码, 必须投递
    IllInstr; ``c.ebreak`` 投递断点陷态.
    """

    PC = 0x8000_0000
    TARGET = 0x8000_0040
    HANDLER = 0x8000_1000

    @classmethod
    def _run(cls, half: int, regs: dict[int, int], is_engine: bool, stop: int):
        emu = Emulator(make_test_config())
        code = half.to_bytes(2, "little") + b"\x13\x00\x00\x00" * 8
        emu.load_code(cls.PC, code)
        emu.load_code(cls.TARGET, b"\x13\x00\x00\x00" * 8)
        emu.load_code(cls.HANDLER, b"\x13\x00\x00\x00" * 4)
        h = emu.harts[0]
        h.csrs["mtvec"].val = cls.HANDLER
        for reg, val in regs.items():
            h.gprs[reg] = val
        h.pc = cls.PC
        if is_engine:
            emu.add_breakpoint(stop)
            emu.add_breakpoint(cls.HANDLER)
            with mock.patch(
                "pyremu.emu.native.run_parallel", wraps=run_parallel
            ) as engine:
                emu.run(timeout=10)
            assert engine.called, "本用例应经加速执行引擎运行"
        else:
            emu.step()
        return h.pc, tuple(int(g) for g in h.gprs), int(h.csrs["mcause"].val)

    def _diff(self, half: int, regs: dict[int, int], what: str) -> None:
        py = self._run(half, regs, is_engine=False, stop=self.PC)
        eng = self._run(half, regs, is_engine=True, stop=py[0])
        assert py == eng, f"{what}: {py} != {eng}"

    @pytest.mark.timeout(120)
    def test_c_jr_and_jalr(self) -> None:
        for rs1 in (1, 5, 10, 15, 28):
            for low in (0, 1):
                target = self.TARGET | low
                regs = {rs1: target}
                # C.JR rs1: 落点清最低位, 不写 ra
                half = (0b100 << 13) | (rs1 << 7) | 0b10
                pc, gprs, _ = self._run(
                    half, regs, is_engine=False, stop=self.PC
                )
                assert pc == self.TARGET, f"C.JR x{rs1}: pc={pc:#x}"
                if rs1 != 1:
                    assert gprs[1] == 0, f"C.JR x{rs1}: 不得写 ra"
                self._diff(half, regs, f"C.JR x{rs1} -> {target:#x}")
                # C.JALR rs1: ra 取下一条指令地址, 落点清
                # 最低位
                half = (0b100 << 13) | (1 << 12) | (rs1 << 7) | 0b10
                pc, gprs, _ = self._run(
                    half, regs, is_engine=False, stop=self.PC
                )
                assert pc == self.TARGET, f"C.JALR x{rs1}: pc={pc:#x}"
                if rs1 != 1:
                    assert gprs[1] == self.PC + 2, (
                        f"C.JALR x{rs1}: ra={gprs[1]:#x}"
                    )
                self._diff(half, regs, f"C.JALR x{rs1} -> {target:#x}")

    @pytest.mark.timeout(120)
    def test_c_jr_zero_is_illegal(self) -> None:
        """bit12 清零且 rd 与 rs2 均为 0 是保留的 C.JR x0, 必须投递非法指令.

        bit12 置位的同一编码是 C.EBREAK, 由 test_c_ebreak 覆盖.
        """
        half = (0b100 << 13) | 0b10
        pc, _gprs, cause = self._run(half, {}, is_engine=False, stop=self.PC)
        assert cause == 2 and pc == self.HANDLER, f"C.JR x0: mcause={cause}"
        self._diff(half, {}, "C.JR x0")

    @pytest.mark.timeout(120)
    def test_c_ebreak(self) -> None:
        pc, _gprs, cause = self._run(0x9002, {}, is_engine=False, stop=self.PC)
        assert cause == 3 and pc == self.HANDLER, f"C.EBREAK: mcause={cause}"
        self._diff(0x9002, {}, "C.EBREAK")

    @pytest.mark.timeout(120)
    def test_c_mv_add_degenerate(self) -> None:
        # c.mv x0, x5 与 c.add x0, x5 属提示编码, 不改变任何寄存器
        rng = random.Random(0x6DEA)
        val = rng.getrandbits(64)
        self._diff((0b100 << 13) | (5 << 2) | 0b10, {5: val}, "C.MV x0, x5")
        self._diff(
            (0b100 << 13) | (1 << 12) | (5 << 2) | 0b10,
            {5: val},
            "C.ADD x0, x5",
        )
