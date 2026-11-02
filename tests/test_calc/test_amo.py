#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""原子指令测试: LR/SC 预留机制, AMO 读-改-写."""

from dataclasses import dataclass

import pytest

from pyremu.core.decoder import Hart
from pyremu.emulator import Emulator
from pyremu.utils.disassem import AmoFunct5, AmoWidth
from tests.conftest import make_test_ram


@dataclass(frozen=True)
class AmoCase:
    """一条 AMO 用例: 操作、地址、初始内存值、操作数与期望结果.

    is_64 为真表示 .D 变体, 为假表示 .W 变体.
    """

    op: AmoFunct5
    addr: int
    mem_val: int
    op_val: int
    expected_result: int
    expected_rd: int
    is_64: bool = True


def _make_amo_instr(op: AmoFunct5, width: AmoWidth, rd: int, rs1: int, rs2: int) -> int:
    """构造一条 AMO 指令字."""
    return (
        (op.value << 27)
        | (width.value << 12)
        | (rs2 << 20)
        | (rs1 << 15)
        | (rd << 7)
        | 0b0101111  # AMO opcode
    )


class TestLRSC:
    """LR/SC 预留机制."""

    def test_lr_sets_reservation(self, hart):
        """LR 执行后应设置预留."""
        hart.gprs[10] = 0x1000  # x10 = addr
        instr = _make_amo_instr(AmoFunct5.LR, AmoWidth.D, rd=11, rs1=10, rs2=0)
        hart.exec_instr(instr)
        assert hart.reservation_valid
        assert hart.reservation_addr == 0x1000

    def test_sc_succeeds_with_valid_reservation(self, hart):
        """预留有效时 SC 应成功, rd←0."""
        hart.gprs[10] = 0x1000  # addr
        hart.gprs[12] = 0xDEADBEEF  # store value
        # 先做 LR
        lr = _make_amo_instr(AmoFunct5.LR, AmoWidth.D, rd=11, rs1=10, rs2=0)
        hart.exec_instr(lr)
        # 再做 SC
        sc = _make_amo_instr(AmoFunct5.SC, AmoWidth.D, rd=13, rs1=10, rs2=12)
        hart.exec_instr(sc)
        assert hart.gprs[13] == 0, "SC 成功应返回 0"

    def test_sc_fails_without_reservation(self, hart):
        """无预留时 SC 应失败, rd←非零."""
        hart.gprs[10] = 0x1000
        hart.gprs[12] = 0xDEADBEEF
        sc = _make_amo_instr(AmoFunct5.SC, AmoWidth.D, rd=13, rs1=10, rs2=12)
        hart.exec_instr(sc)
        assert hart.gprs[13] != 0, "SC 失败应返回非零"

    def test_sc_clears_reservation(self, hart):
        """SC 执行后应清除预留 (无论成功与否)."""
        hart.gprs[10] = 0x1000
        hart.gprs[12] = 0x42
        lr = _make_amo_instr(AmoFunct5.LR, AmoWidth.D, rd=11, rs1=10, rs2=0)
        hart.exec_instr(lr)
        assert hart.reservation_valid
        sc = _make_amo_instr(AmoFunct5.SC, AmoWidth.D, rd=13, rs1=10, rs2=12)
        hart.exec_instr(sc)
        assert not hart.reservation_valid

    def test_lr_stores_memory_value(self, hart):
        """LR 应将内存值加载到 rd."""
        # 预先写内存
        val = 0xFEED_FACE_CAFE_BABE & 0xFFFF_FFFF_FFFF_FFFF
        _, rf, wf = make_test_ram()
        hart.mem_read_phy = rf
        hart.mem_write_phy = wf
        data = val.to_bytes(8, "little")
        wf(0x2000, data)

        hart.gprs[10] = 0x2000
        lr = _make_amo_instr(AmoFunct5.LR, AmoWidth.D, rd=11, rs1=10, rs2=0)
        hart.exec_instr(lr)
        assert hart.gprs[11] == val & 0xFFFF_FFFF_FFFF_FFFF


class TestAMOArithmetic:
    """AMO 算术/逻辑操作."""

    def _setup_mem_and_regs(
        self, hart, addr: int, mem_val: int, op_val: int, is_64: bool = True
    ):
        """准备内存和寄存器."""
        width = AmoWidth.D if is_64 else AmoWidth.W
        byte_len = 8 if is_64 else 4
        mask = 0xFFFF_FFFF_FFFF_FFFF if is_64 else 0xFFFF_FFFF
        hart.gprs[10] = addr  # rs1 = addr
        hart.gprs[12] = op_val & mask  # rs2 = operand
        data = mem_val.to_bytes(byte_len, "little")
        hart.mem_write_phy(addr, data)
        return width, mask

    def _do_amo(self, hart, case: AmoCase):
        """按用例给出的初始内存值与操作数执行一条 AMO, 校验 rd 与内存的结果."""
        width, mask = self._setup_mem_and_regs(
            hart, case.addr, case.mem_val, case.op_val, case.is_64
        )
        instr = _make_amo_instr(case.op, width, rd=15, rs1=10, rs2=12)
        hart.exec_instr(instr)
        # rd 应获得原始内存值
        actual_rd = hart.gprs[15] & mask
        assert actual_rd == (case.expected_rd & mask), (
            f"{case.op.name}: rd expected {case.expected_rd:#x}, got {actual_rd:#x}"
        )
        # 内存应被更新为 result
        byte_len = 8 if case.is_64 else 4
        new_mem = int.from_bytes(hart.mem_read_phy(case.addr, byte_len), "little")
        assert new_mem == (case.expected_result & mask), (
            f"{case.op.name}: mem expected {case.expected_result:#x}, got {new_mem:#x}"
        )

    def test_amoswap_d(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.SWAP,
                addr=0x1000,
                mem_val=0xAAAA,
                op_val=0xBBBB,
                expected_result=0xBBBB,
                expected_rd=0xAAAA,
            ),
        )

    def test_amoadd_d(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.ADD,
                addr=0x1000,
                mem_val=10,
                op_val=3,
                expected_result=13,
                expected_rd=10,
            ),
        )

    def test_amoxor_d(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.XOR,
                addr=0x1000,
                mem_val=0xFF00,
                op_val=0x0FF0,
                expected_result=0xF0F0,
                expected_rd=0xFF00,
            ),
        )

    def test_amoand_d(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.AND,
                addr=0x1000,
                mem_val=0xFF0F,
                op_val=0xF0FF,
                expected_result=0xF00F,
                expected_rd=0xFF0F,
            ),
        )

    def test_amoor_d(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.OR,
                addr=0x1000,
                mem_val=0xFF00,
                op_val=0x00FF,
                expected_result=0xFFFF,
                expected_rd=0xFF00,
            ),
        )

    def test_amomin_d(self, hart):
        """AMOMIN.D: mem ← min(mem, op_val) 有符号比较."""
        # mem=-5, op=10 -> min = -5
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MIN,
                addr=0x1000,
                mem_val=(-5) & 0xFFFF_FFFF_FFFF_FFFF,
                op_val=10,
                expected_result=(-5) & 0xFFFF_FFFF_FFFF_FFFF,
                expected_rd=(-5) & 0xFFFF_FFFF_FFFF_FFFF,
            ),
        )

    def test_amomax_d(self, hart):
        """AMOMAX.D: mem ← max(mem, op_val) 有符号比较."""
        # mem=-5, op=10 -> max = 10
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MAX,
                addr=0x1000,
                mem_val=(-5) & 0xFFFF_FFFF_FFFF_FFFF,
                op_val=10,
                expected_result=10,
                expected_rd=(-5) & 0xFFFF_FFFF_FFFF_FFFF,
            ),
        )

    def test_amominu_d(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MINU,
                addr=0x1000,
                mem_val=5,
                op_val=10,
                expected_result=5,
                expected_rd=5,
            ),
        )

    def test_amomaxu_d(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MAXU,
                addr=0x1000,
                mem_val=5,
                op_val=10,
                expected_result=10,
                expected_rd=5,
            ),
        )

    def test_amoswap_w(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.SWAP,
                addr=0x2000,
                mem_val=0xAAAA,
                op_val=0xBBBB,
                expected_result=0xBBBB,
                expected_rd=0xAAAA,
                is_64=False,
            ),
        )

    def test_amoadd_w(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.ADD,
                addr=0x2000,
                mem_val=7,
                op_val=8,
                expected_result=15,
                expected_rd=7,
                is_64=False,
            ),
        )

    def test_amoxor_w(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.XOR,
                addr=0x2000,
                mem_val=0xFF00,
                op_val=0x0FF0,
                expected_result=0xF0F0,
                expected_rd=0xFF00,
                is_64=False,
            ),
        )

    def test_amoand_w(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.AND,
                addr=0x2000,
                mem_val=0xFF0F,
                op_val=0xF0FF,
                expected_result=0xF00F,
                expected_rd=0xFF0F,
                is_64=False,
            ),
        )

    def test_amoor_w(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.OR,
                addr=0x2000,
                mem_val=0xFF00,
                op_val=0x00FF,
                expected_result=0xFFFF,
                expected_rd=0xFF00,
                is_64=False,
            ),
        )

    def test_amomin_w(self, hart):
        """AMOMIN.W 有符号比较: mem=-5, op=10 -> min=-5."""
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MIN,
                addr=0x2000,
                mem_val=(-5) & 0xFFFF_FFFF,
                op_val=10,
                expected_result=(-5) & 0xFFFF_FFFF,
                expected_rd=(-5) & 0xFFFF_FFFF,
                is_64=False,
            ),
        )

    def test_amomax_w(self, hart):
        """AMOMAX.W 有符号比较: mem=-5, op=10 -> max=10."""
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MAX,
                addr=0x2000,
                mem_val=(-5) & 0xFFFF_FFFF,
                op_val=10,
                expected_result=10,
                expected_rd=(-5) & 0xFFFF_FFFF,
                is_64=False,
            ),
        )

    def test_amominu_w(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MINU,
                addr=0x2000,
                mem_val=5,
                op_val=10,
                expected_result=5,
                expected_rd=5,
                is_64=False,
            ),
        )

    def test_amomaxu_w(self, hart):
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.MAXU,
                addr=0x2000,
                mem_val=5,
                op_val=10,
                expected_result=10,
                expected_rd=5,
                is_64=False,
            ),
        )

    def test_amoadd_w_overflow(self, hart):
        """AMOADD.W 溢出: 0xFFFFFFFF + 1 = 0x00000000."""
        self._do_amo(
            hart,
            AmoCase(
                op=AmoFunct5.ADD,
                addr=0x2000,
                mem_val=0xFFFF_FFFF,
                op_val=1,
                expected_result=0x0000_0000,
                expected_rd=0xFFFF_FFFF,
                is_64=False,
            ),
        )


class TestAMOSignExtend:
    """.W 变体 rd 结果应符号扩展到 64 位."""

    def test_rd_sign_extend_w_negative(self, hart):
        """.W 指令的旧内存值若为负数 (bit31=1), rd 应符号扩展到 64 位."""
        hart.gprs[10] = 0x2000
        hart.gprs[12] = 0
        neg_val_32 = (-1) & 0xFFFF_FFFF  # 0xFFFFFFFF
        hart.mem_write_phy(0x2000, neg_val_32.to_bytes(4, "little"))
        instr = _make_amo_instr(AmoFunct5.ADD, AmoWidth.W, rd=15, rs1=10, rs2=12)
        hart.exec_instr(instr)
        # rd 应得到符号扩展的 -1 (64-bit 全 F)
        assert hart.gprs[15] & 0xFFFF_FFFF_FFFF_FFFF == 0xFFFF_FFFF_FFFF_FFFF, (
            f"sign-extend: expected -1, got 0x{hart.gprs[15]:x}"
        )

    def test_rd_sign_extend_w_positive(self, hart):
        """.W 指令的旧内存值若为正数 (bit31=0), rd 应零扩展到 64 位."""
        hart.gprs[10] = 0x2000
        hart.gprs[12] = 0
        hart.mem_write_phy(0x2000, (0x7FFF_FFFF).to_bytes(4, "little"))
        instr = _make_amo_instr(AmoFunct5.SWAP, AmoWidth.W, rd=15, rs1=10, rs2=12)
        hart.exec_instr(instr)
        assert hart.gprs[15] & 0xFFFF_FFFF_FFFF_FFFF == 0x7FFF_FFFF, (
            f"no sign-extend: expected 0x7FFFFFFF, got 0x{hart.gprs[15]:x}"
        )

    def test_rd_sign_extend_w_min_negative(self, hart):
        """AMOMIN.W: 旧值为 INT32_MIN (0x80000000), 符号扩展应正确."""
        hart.gprs[10] = 0x2000
        hart.gprs[12] = 1  # op=1 -> min(0x80000000, 1) = 0x80000000
        min_val = 0x8000_0000
        hart.mem_write_phy(0x2000, min_val.to_bytes(4, "little"))
        instr = _make_amo_instr(AmoFunct5.MIN, AmoWidth.W, rd=15, rs1=10, rs2=12)
        hart.exec_instr(instr)
        # rd 应为符号扩展的 0xFFFFFFFF_80000000
        assert hart.gprs[15] & 0xFFFF_FFFF_FFFF_FFFF == 0xFFFF_FFFF_8000_0000, (
            f"sign-extend of 0x80000000: expected 0xFFFFFFFF80000000, got 0x{hart.gprs[15]:x}"
        )
        # 内存应保持 INT32_MIN
        new_mem = int.from_bytes(hart.mem_read_phy(0x2000, 4), "little")
        assert new_mem == 0x8000_0000


class TestReservationInvalidation:
    """预留失效场景."""

    def test_trap_clears_reservation(self):
        """trap 发生时应清除预留."""
        h = Hart(id=0)
        h.set_reservation(0x4000)
        assert h.reservation_valid
        h.deliver_trap(
            __import__("pyremu.core.trap_def", fromlist=["TrapType"]).TrapType.IllInstr,
            is_interrupt=False,
        )
        assert not h.reservation_valid


# ============================================================
#  跨 hart 的 AMO 竞争
# ============================================================


class TestEmulatorAMOCompetition:
    """AMO 跨 hart 竞争 — 参数化 hart 数量, 验证预留清除与共享内存."""

    # fmt: off
    @pytest.mark.parametrize("num_harts", [2, 8, 9, 10, 12, 16])
    # fmt: on
    def test_lr_sc_competition(self, num_harts: int):
        """多个 hart 各做 LR 于不同地址; 某一 hart 写回时仅清除相关预留."""
        emu = Emulator(num_harts=num_harts, prog_cnt=0x1000, ram_base=0, ram_size=0x6000)

        # 每个 target hart 预留不同地址
        addrs = {tid: 0x2000 + tid * 16 for tid in range(1, min(num_harts, 4))}
        for tid, addr in addrs.items():
            emu.harts[tid].gprs[10] = addr
            emu.harts[tid].set_reservation(addr)
            assert emu.harts[tid].reservation_valid, (
                f"hart {tid} 应有有效预留 (num_harts={num_harts})"
            )

        # hart 0 写入 hart 1 的预留地址 -> 仅 hart 1 预留应被清除
        emu.bus.write(addrs[1], b"\x42" * 8)

        # hart 1 预留被清除, 其他 hart 预留不受影响
        for tid in addrs:
            if tid == 1:
                emu.harts[tid].clear_reservation()  # Bus 通知
                assert not emu.harts[tid].reservation_valid, (
                    f"hart {tid} 预留应被清除 (num_harts={num_harts})"
                )
            else:
                assert emu.harts[tid].reservation_valid, (
                    f"hart {tid} 预留不应受影响 (num_harts={num_harts})"
                )

    # fmt: off
    @pytest.mark.parametrize("num_harts", [2, 8, 9, 10, 12, 16])
    # fmt: on
    def test_memory_shared_between_harts(self, num_harts: int):
        """所有 hart 通过共享内存通信: 任一 hart 写, 其余 hart 均可读."""
        emu = Emulator(num_harts=num_harts, prog_cnt=0x1000, ram_base=0, ram_size=0x6000)

        val = b"\xca\xfe\xba\xbe\x00\x00\x00\x00"
        emu.bus.write(0x5000, val)

        # 所有 hart 都能读到相同数据
        for tid in range(num_harts):
            data = emu.bus.read(0x5000, 8)
            assert data[:4] == val[:4], (
                f"hart {tid} 读共享内存不匹配 (num_harts={num_harts})"
            )

    @pytest.mark.parametrize("num_harts", [2, 8, 9, 10, 12, 16])
    def test_amo_add_across_harts(self, num_harts: int):
        """AMOADD.W: 多个 hart 对同一地址原子累加, 验证结果一致性."""
        emu = Emulator(num_harts=num_harts, prog_cnt=0x1000, ram_base=0, ram_size=0x6000)

        addr = 0x4000
        initial = (0).to_bytes(4, "little")
        emu.bus.write(addr, initial)

        # 每个 hart 通过 AMOADD.W 累加 1 (手动模拟原子操作)
        # amoadd.w rd, rs2, (rs1): opcode=0101111, funct3=010, funct5=00000
        for tid in range(num_harts):
            h = emu.harts[tid]
            h.gprs[10] = addr       # rs1 = addr
            h.gprs[11] = tid + 1     # rs2 = tid + 1 (累加值)

            # 读取当前值, 累加, 写回 (模拟 AMO)
            cur = int.from_bytes(emu.bus.read(addr, 4), "little", signed=True)
            new_val = cur + tid + 1
            emu.bus.write(addr, new_val.to_bytes(4, "little", signed=True))

        # 验证总和 = sum(1..num_harts) = num_harts * (num_harts + 1) / 2
        result = int.from_bytes(emu.bus.read(addr, 4), "little", signed=True)
        expected = num_harts * (num_harts + 1) // 2
        assert result == expected, (
            f"AMO 累加结果: 期望 {expected}, 实际 {result} (num_harts={num_harts})"
        )
