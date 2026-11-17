#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""非法编码、扩展开关、CSR 立即数形式与浮点关闭时的陷态."""

from __future__ import annotations

from unittest import mock

import pytest

from pyremu._native import (
    run_parallel,
)
from pyremu.core.decoder import Hart
from pyremu.core.hart import RatifiedHartAttrs
from pyremu.disasm import Opc
from pyremu.emulator import Emulator
from pyremu.utils.isa import encode_misa, isa_ext_list
from tests.conftest import make_test_config
from tests.instr_encode import (
    i_type,
    pack_funct,
    pack_src_regs,
    r_type,
    s_type,
)
from tests.test_native.common import (
    assert_ill_instr,
    FS_ON,
    OP32,
    OP_ALU,
    OP_FMADD,
    OP_FMSUB,
    OP_FP_LOAD,
    OP_FP_OP,
    OP_FP_STORE,
    OP_IMM32,
    OP_SYS,
)


class TestNativePathEncodingTraps:
    """加速执行库返回无效编码后, 算术处理函数自身抛出的非法指令."""

    def test_alu_invalid_funct7_traps(self, hart):
        """funct7=0x10 且 funct3=000 不对应任何指令, 抛出 ValueError."""
        assert_ill_instr(
            hart,
            r_type(OP_ALU, 3, pack_funct(0x10, 0b000), pack_src_regs(1, 2)),
        )

    def test_alu_invalid_zbb_funct3_traps(self, hart):
        """funct7 属于 Zbb 但 funct3 不对应任何子指令."""
        assert_ill_instr(
            hart,
            r_type(OP_ALU, 3, pack_funct(0x05, 0b010), pack_src_regs(1, 2)),
        )

    @pytest.mark.parametrize(
        "funct3, funct7",
        [
            (0b000, 0x10),  # funct7 不属于任何 32 位字运算
            (0b010, 0x30),  # funct7=0x30 只适用于 001 / 101
        ],
    )
    def test_op32_invalid_encoding_traps(self, hart, funct3, funct7):
        assert_ill_instr(
            hart,
            r_type(OP32, 3, pack_funct(funct7, funct3), pack_src_regs(1, 2)),
        )

    def test_op_imm32_invalid_funct7_traps(self, hart):
        assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b001, 1, 0x200))

    def test_op_imm32_invalid_zbb_funct3_traps(self, hart):
        """funct7=0x30 且 funct3=010 不对应任何子指令, 抛出非法指令."""
        assert_ill_instr(hart, i_type(OP_IMM32, 3, 0b010, 1, 0x600))


class TestCsrImmediateForms:
    """CSRRWI / CSRRSI / CSRRCI."""

    MSCRATCH = 0x340

    def _csr_instr(self, funct3: int, rd: int, csr: int, uimm: int) -> int:
        return r_type(
            OP_SYS, rd, pack_funct(csr >> 5, funct3), pack_src_regs(uimm, 0)
        ) | ((csr & 0x1F) << 20)

    def test_csrrwi(self, hart):
        hart.csrs["mscratch"].val = 7
        hart.exec_instr(self._csr_instr(0b101, 3, self.MSCRATCH, 5))
        assert hart.gprs[3] == 7
        assert hart.csrs["mscratch"].val == 5

    def test_csrrsi_with_zero_uimm_reads_only(self, hart):
        hart.csrs["mscratch"].val = 7
        hart.exec_instr(self._csr_instr(0b110, 3, self.MSCRATCH, 0))
        assert hart.gprs[3] == 7
        assert hart.csrs["mscratch"].val == 7

    def test_csrrsi_or_immediate(self, hart):
        hart.csrs["mscratch"].val = 0b100
        hart.exec_instr(self._csr_instr(0b110, 3, self.MSCRATCH, 0b011))
        assert hart.csrs["mscratch"].val == 0b111

    def test_csrrci_clear_immediate(self, hart):
        hart.csrs["mscratch"].val = 0b111
        hart.exec_instr(self._csr_instr(0b111, 3, self.MSCRATCH, 0b011))
        assert hart.csrs["mscratch"].val == 0b100


class TestFpDisabled:
    """mstatus.FS=Off 时全部浮点指令触发非法指令陷态."""

    def test_fp_load_disabled(self, hart):
        assert_ill_instr(hart, i_type(OP_FP_LOAD, 3, 0b010, 1, 0))

    def test_fp_load_invalid_funct3(self, hart):
        hart.mstatus_val |= FS_ON
        assert_ill_instr(hart, i_type(OP_FP_LOAD, 3, 0b100, 1, 0))

    def test_fp_store_disabled(self, hart):
        assert_ill_instr(hart, s_type(OP_FP_STORE, 0b010, 1, 2, 0))

    def test_fp_store_invalid_funct3(self, hart):
        hart.mstatus_val |= FS_ON
        assert_ill_instr(hart, s_type(OP_FP_STORE, 0b100, 1, 2, 0))

    def test_fp_op_disabled(self, hart):
        assert_ill_instr(
            hart, r_type(OP_FP_OP, 3, pack_funct(0, 0b000), pack_src_regs(1, 2))
        )

    def test_fp_op_invalid_encoding(self, hart):
        hart.mstatus_val |= FS_ON
        assert_ill_instr(
            hart,
            r_type(OP_FP_OP, 3, pack_funct(0x7C, 0b000), pack_src_regs(1, 2)),
        )

    def test_fp_fma_disabled(self, hart):
        assert_ill_instr(
            hart, r_type(OP_FMADD, 3, pack_funct(0, 0b000), pack_src_regs(1, 2))
        )

    def test_fp_fma_invalid_fmt(self, hart):
        hart.mstatus_val |= FS_ON
        assert_ill_instr(
            hart,
            r_type(OP_FMSUB, 3, pack_funct(0b10, 0b000), pack_src_regs(1, 2)),
        )


# =====================================================================
#  pyremu._native 回退分支
# =====================================================================


class TestSstcSwitch:
    """平台未声明 sstc 时 stimecmp 不存在, 两条执行路径均投递 IllInstr.

    回归: 引擎原先无条件接受 ``csr 0x14D``. OpenSBI 以 ``csr_read_allowed`` 探测
    该 CSR 判断硬件是否支持 sstc, 引擎在未声明的平台上返回合法值会使固件误判,
    与 Python 侧 ``validate_csr`` 的判定不一致.
    """

    ISA_WITHOUT_SSTC = "rv64imac_zicsr_zifencei"
    ISA_WITH_SSTC = "rv64imac_zicsr_zifencei_sstc"
    # csrr x5, 0x14d 与 csrw 0x14d, x5
    CSRR = i_type(Opc.sys.value, 5, 2, 0, 0x14D)
    CSRW = i_type(Opc.sys.value, 0, 1, 5, 0x14D)

    def test_python_path_rejects_stimecmp(self, hart) -> None:
        """Python 路径: 未声明 sstc 时读取该 CSR 产生 IllInstr."""
        h = hart
        h.ratified_hart_attrs = RatifiedHartAttrs.from_platform(
            16, self.ISA_WITHOUT_SSTC
        )
        h.pc = 0x8000_0000
        h.exec_instr(self.CSRR)
        assert h.csrs["mcause"].val == 2, "应为 IllInstr"
        assert h.csrs["mepc"].val == 0x8000_0000

    PC, MTVEC = 0x8000_0000, 0x8000_1000

    def _run_engine(
        self,
        isa: str,
        instr: int,
        stimecmp: int = 0,
    ) -> tuple[mock.Mock, Emulator, Hart]:
        """以给定的 ISA 字符串装配模拟器, 经加速执行引擎执行一条指令.

        mtvec 与 pc+4 各设一个断点: 投递陷态时停在 mtvec, 指令正常完成时停在
        pc+4. 引擎调用被记录, 用于确认本用例确实经过 Rust 侧而非纯 Python 路径.
        """
        cfg = make_test_config()
        cfg.isa = isa
        emu = Emulator(cfg)
        emu.load_code(self.PC, instr.to_bytes(4, "little"))
        emu.load_code(self.MTVEC, b"\x13\x00\x00\x00" * 4)
        h = emu.harts[0]
        h.csrs["mtvec"].val = self.MTVEC
        h.csrs["stimecmp"].val = stimecmp
        emu.add_breakpoint(self.PC + 4)
        emu.add_breakpoint(self.MTVEC)
        with mock.patch(
            "pyremu.emu.native.run_parallel", wraps=run_parallel
        ) as engine:
            emu.run(timeout=10)
        return engine, emu, h

    @pytest.mark.parametrize("instr", [CSRR, CSRW])
    def test_engine_rejects_stimecmp(self, instr: int) -> None:
        """加速执行引擎: 未声明 sstc 时读写该 CSR 均产生 IllInstr."""
        engine, _emu, h = self._run_engine(self.ISA_WITHOUT_SSTC, instr)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.MTVEC, f"应陷入 mtvec, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 2, (
            f"应为 IllInstr, 实际 {h.csrs['mcause'].val:#x}"
        )

    def test_engine_accepts_stimecmp_when_declared(self) -> None:
        """声明 sstc 时引擎读取该 CSR 不投递任何异常."""
        engine, _emu, h = self._run_engine(
            self.ISA_WITH_SSTC, self.CSRR, stimecmp=0x1234
        )
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.PC + 4, f"不应陷入, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 0
        assert h.gprs[5] == 0x1234, f"应读回 stimecmp, 实际 {h.gprs[5]:#x}"


# 各可选扩展与一条属于该扩展的指令. 每项为 (含该扩展的 ISA 字符串, 指令字,
# 指令字节数); 判定拒绝时统一以 "rv64i" 作为未声明该扩展的平台.


_EXT_INSTR_CASES = [
    pytest.param(
        "rv64im",
        r_type(Opc.op.value, 5, pack_funct(0x01, 0b000), pack_src_regs(6, 7)),
        4,
        id="m-mul",
    ),
    pytest.param(
        "rv64ia",
        r_type(Opc.amo.value, 5, pack_funct(0, 0b010), pack_src_regs(7, 6)),
        4,
        id="a-amoadd",
    ),
    pytest.param(
        "rv64if", i_type(Opc.ld_fp.value, 1, 0b010, 2, 0), 4, id="f-flw"
    ),
    pytest.param(
        "rv64id", i_type(Opc.ld_fp.value, 1, 0b011, 2, 0), 4, id="d-fld"
    ),
    pytest.param(
        "rv64i_zba",
        r_type(Opc.op.value, 5, pack_funct(0x10, 0b010), pack_src_regs(6, 7)),
        4,
        id="zba-sh1add",
    ),
    pytest.param(
        "rv64i_zbb",
        r_type(Opc.op.value, 5, pack_funct(0x30, 0b001), pack_src_regs(6, 7)),
        4,
        id="zbb-rol",
    ),
    pytest.param(
        "rv64i_zbs",
        r_type(Opc.op.value, 5, pack_funct(0x14, 0b001), pack_src_regs(6, 7)),
        4,
        id="zbs-bset",
    ),
    pytest.param(
        "rv64i_zicsr",
        i_type(Opc.sys.value, 5, 2, 0, 0x301),
        4,
        id="zicsr-csrr-misa",
    ),
    pytest.param("rv64i_zifencei", 0x0000_100F, 4, id="zifencei-fence-i"),
    pytest.param("rv64ic", 0x0085, 2, id="c-c-addi"),
]


class TestExtSwitch:
    """平台未声明的扩展所对应的指令不存在, 两条执行路径均投递 IllInstr.

    解码按平台声明的扩展集合判定: 关闭 M/A/F/D/C/Zba/Zbb/Zbs/Zicsr/Zifencei
    之后这些指令均被拒绝, 使固件经 ``csr_read_allowed`` 与试探性执行探测
    扩展支持时得到与平台声明一致的结果.
    """

    PC, MTVEC = 0x8000_0000, 0x8000_1000
    # csrr x5, misa
    CSRR_MISA = i_type(Opc.sys.value, 5, 2, 0, 0x301)

    @staticmethod
    def _prepare(h: Hart, isa: str, mem_base: int) -> None:
        """按给定 ISA 字符串装配 hart: 设定 pc、mtvec、浮点状态与访存基址."""
        h.ratified_hart_attrs = RatifiedHartAttrs.from_platform(16, isa)
        h.pc = TestExtSwitch.PC
        h.csrs["mtvec"].val = TestExtSwitch.MTVEC
        # 浮点指令要求 mstatus.FS 非零, 否则会因浮点状态关闭而产生同样的异常
        h.csrs["mstatus"].val |= 3 << 13
        h.gprs[2] = mem_base
        h.gprs[7] = mem_base

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_python_path_rejects_undeclared_ext(
        self,
        hart,
        isa_with,
        instr,
        length,
    ) -> None:
        """Python 路径: 所属扩展未声明时投递 IllInstr, 不执行该指令."""
        h = hart
        self._prepare(h, "rv64i", 0x1000)
        assert h.exec_instr(instr) == 0
        assert h.csrs["mcause"].val == 2, "应为 IllInstr"
        assert h.csrs["mepc"].val == self.PC
        assert h.pc == self.MTVEC

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_python_path_accepts_declared_ext(
        self,
        hart,
        isa_with,
        instr,
        length,
    ) -> None:
        """Python 路径: 声明所属扩展时不产生异常, 按指令长度推进 pc."""
        h = hart
        self._prepare(h, isa_with, 0x1000)
        assert h.exec_instr(instr) == length
        assert h.csrs["mcause"].val == 0

    def _run_engine(
        self,
        isa: str,
        instr: int,
        length: int,
    ) -> tuple[mock.Mock, Emulator, Hart]:
        """以给定 ISA 字符串装配模拟器, 经加速执行引擎执行一条指令.

        指令正常完成时停在 pc 加指令长度处, 投递陷态时停在 mtvec.
        引擎调用被记录, 用于确认本用例确实经过 Rust 侧.
        """
        cfg = make_test_config()
        cfg.isa = isa
        emu = Emulator(cfg)
        emu.load_code(self.PC, instr.to_bytes(length, "little"))
        emu.load_code(self.MTVEC, b"\x13\x00\x00\x00" * 4)
        h = emu.harts[0]
        self._prepare(h, isa, 0x8000_2000)
        emu.add_breakpoint(self.PC + length)
        emu.add_breakpoint(self.MTVEC)
        with mock.patch(
            "pyremu.emu.native.run_parallel", wraps=run_parallel
        ) as engine:
            emu.run(timeout=10)
        return engine, emu, h

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_engine_rejects_undeclared_ext(
        self,
        isa_with,
        instr,
        length,
    ) -> None:
        """加速执行引擎: 所属扩展未声明时同样投递 IllInstr."""
        engine, _emu, h = self._run_engine("rv64i", instr, length)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.MTVEC, f"应陷入 mtvec, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 2, (
            f"应为 IllInstr, 实际 {h.csrs['mcause'].val:#x}"
        )

    @pytest.mark.parametrize(("isa_with", "instr", "length"), _EXT_INSTR_CASES)
    def test_engine_accepts_declared_ext(self, isa_with, instr, length) -> None:
        """加速执行引擎: 声明所属扩展时不产生异常, 执行到下一条指令."""
        engine, _emu, h = self._run_engine(isa_with, instr, length)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.pc == self.PC + length, f"不应陷入, 实际 pc=0x{h.pc:x}"
        assert h.csrs["mcause"].val == 0

    @pytest.mark.parametrize(
        "isa",
        ["rv64i_zicsr", "rv64imac_zicsr", "rv64imafdc_zicsr_zbb"],
    )
    def test_engine_misa_matches_isa_string(self, isa: str) -> None:
        """引擎读到的 misa 与 Python 侧由同一 ISA 字符串算出的取值相同."""
        engine, _emu, h = self._run_engine(isa, self.CSRR_MISA, 4)
        assert engine.called, "本用例应经加速执行引擎运行"
        assert h.gprs[5] == encode_misa(isa_ext_list(isa))
        assert h.csrs["mcause"].val == 0
