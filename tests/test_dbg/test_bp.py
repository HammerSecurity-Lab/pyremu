#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.breakpoint — 断点设置/命中检查."""

import sys

import pytest

from pyremu.core.hart import RiscvMode
from pyremu.core.mem_check_aux import MemoryAccessOps
from pyremu.core.registers import (
    csr_addr_from_name,
    gpr_idx_from_name,
)
from pyremu.debug.breakpoint import BreakpointOps
from pyremu.debug.types import Breakpoint
from pyremu.emulator import Emulator
from tests.conftest import (
    DbgTestBase,
    make_test_dbg,
    make_test_image,
    TEST_PROG_PA,
)

# 只带执行权限的代码页: 管理器把自身 .text 映射到的虚拟地址与部署的物理地址
CODE_VA = 0xFFFF_FFE0_0000_0000
CODE_PA = 0x8300_0000
SATP_SV39 = 8 << 60

# ============================================================
#  Mini 测试类
# ============================================================


class _TestBpDbg(DbgTestBase, BreakpointOps):
    """最小聚合类供 BreakpointOps 测试."""

    def __init__(self, emu, hart_id=0):
        super().__init__(emu, hart_id)
        self._breakpoints: list[Breakpoint] = []
        self._bp_mode = "sync"
        self._hart_paused: set[int] = set()
        self._bp_hit_this_run: set[tuple] = set()
        self._prev_instr_csr_addr = -1
        self._image = None
        self._load_offset = 0
        self._sym_symbols = None
        self._paused = False
        self._sym_ranges = []

    # 其余操作类提供的dummy方法
    def _fetch_and_disasm(self, pc):
        return ("00000013", "nop")

    def _resolve_addr(self, arg):
        try:
            return int(arg, 0)
        except ValueError, TypeError:
            return None

    def _read_gpr_by_name(self, name):
        idx = gpr_idx_from_name(name)
        return 0 if idx is None else self.hart.read_gpr(idx)

    def _read_csr_by_name(self, name):
        addr = csr_addr_from_name(name)
        return 0 if addr is None else self.hart.read_csr(addr)

    def _resolve_sym_addr(self, va):
        return None

    def _module_runtime_addr_of_name(self, name):
        """本测试类不登记符号模块, 按名称查找恒无结果."""
        return None

    def _check_rv64_addr(self, v):
        return 0 <= v < (1 << 64)


def _make_bpdbg():
    emu = Emulator(prog_cnt=0x1000)
    emu.load_code(0x1000, b"\x13\x00\x00\x00")  # NOP
    return _TestBpDbg(emu)


# ============================================================
#  _bp_match_pc
# ============================================================


class TestBpMatchPc:
    """静态地址匹配方法."""

    def test_direct_match(self):
        dbg = _make_bpdbg()
        assert dbg._bp_match_pc(dbg.hart, 0x80000000, 0x80000000)

    def test_no_match(self):
        dbg = _make_bpdbg()
        assert not dbg._bp_match_pc(dbg.hart, 0x1000, 0x2000)

    def test_bare_mode_pc_is_pa(self):
        dbg = _make_bpdbg()
        dbg.hart.pc = 0x80001000
        assert dbg._bp_match_pc(dbg.hart, dbg.hart.pc, 0x80001000)

    def test_translated_pc_matches_physical_breakpoint(self, monkeypatch):
        """代码页上按调试翻译得到的物理地址比对断点地址."""
        dbg = _make_bpdbg()
        hart = dbg.hart
        hart.mode = RiscvMode.S
        hart.satp_val = SATP_SV39
        seen: dict = {}

        def translate(h, va, **kwargs):
            seen.update(kwargs)
            return True, CODE_PA

        monkeypatch.setattr(MemoryAccessOps, "translate_addr", translate)
        assert dbg._bp_match_pc(hart, CODE_VA, CODE_PA)
        assert seen.get("is_hart_access") is False

    def test_untranslatable_pc_does_not_match(self, monkeypatch):
        dbg = _make_bpdbg()
        hart = dbg.hart
        hart.mode = RiscvMode.S
        hart.satp_val = SATP_SV39
        monkeypatch.setattr(
            MemoryAccessOps, "translate_addr", lambda *a, **k: (False, 0)
        )
        assert not dbg._bp_match_pc(hart, CODE_VA, CODE_PA)


# ============================================================
#  _eval_bp_condition
# ============================================================


class TestEvalBpCondition:
    """条件评估."""

    def test_no_condition_always_true(self):
        dbg = _make_bpdbg()
        bp = Breakpoint(kind="addr", value=0x1000, desc="test")
        assert dbg._eval_bp_condition(dbg.hart, bp)

    def test_reg_eq_true(self):
        dbg = _make_bpdbg()
        dbg.hart.gprs[10] = 42  # a0
        bp = Breakpoint(
            kind="cond",
            value=0,
            desc="test",
            cond_type="reg",
            cond_reg="a0",
            cond_op="==",
            cond_val=42,
        )
        assert dbg._eval_bp_condition(dbg.hart, bp)

    def test_reg_eq_false(self):
        dbg = _make_bpdbg()
        dbg.hart.gprs[10] = 42
        bp = Breakpoint(
            kind="cond",
            value=0,
            desc="test",
            cond_type="reg",
            cond_reg="a0",
            cond_op="==",
            cond_val=99,
        )
        assert not dbg._eval_bp_condition(dbg.hart, bp)

    def test_reg_ne(self):
        dbg = _make_bpdbg()
        dbg.hart.gprs[10] = 42
        bp = Breakpoint(
            kind="cond",
            value=0,
            desc="test",
            cond_type="reg",
            cond_reg="a0",
            cond_op="!=",
            cond_val=99,
        )
        assert dbg._eval_bp_condition(dbg.hart, bp)

    def test_reg_lt(self):
        dbg = _make_bpdbg()
        dbg.hart.gprs[10] = 5
        bp = Breakpoint(
            kind="cond",
            value=0,
            desc="test",
            cond_type="reg",
            cond_reg="a0",
            cond_op="<",
            cond_val=10,
        )
        assert dbg._eval_bp_condition(dbg.hart, bp)

    def test_reg_gt(self):
        dbg = _make_bpdbg()
        dbg.hart.gprs[10] = 100
        bp = Breakpoint(
            kind="cond",
            value=0,
            desc="test",
            cond_type="reg",
            cond_reg="a0",
            cond_op=">",
            cond_val=10,
        )
        assert dbg._eval_bp_condition(dbg.hart, bp)

    def test_csr_eq(self):
        dbg = _make_bpdbg()
        dbg.hart.csrs["mstatus"].val = 0x1800
        bp = Breakpoint(
            kind="cond",
            value=0,
            desc="test",
            cond_type="csr",
            cond_reg="mstatus",
            cond_op="==",
            # mstatus 的读出值含只读派生位 UXL=2
            cond_val=0x1800 | (2 << 32),
        )
        assert dbg._eval_bp_condition(dbg.hart, bp)


# ============================================================
#  断点命中检查
# ============================================================


class TestCheckBreakpoints:
    """_check_breakpoints 核心逻辑."""

    def test_no_breakpoints_returns_false(self):
        dbg = _make_bpdbg()
        assert not dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)

    def test_addr_bp_hit(self):
        dbg = _make_bpdbg()
        dbg._breakpoints = [Breakpoint(kind="addr", value=0x1000, desc="test")]
        assert dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)

    def test_addr_bp_no_hit(self):
        dbg = _make_bpdbg()
        dbg._breakpoints = [Breakpoint(kind="addr", value=0x2000, desc="test")]
        assert not dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)

    def test_opcode_bp_hit(self):
        dbg = _make_bpdbg()
        # 0x13 = OP-IMM (ADDI)
        dbg._breakpoints = [Breakpoint(kind="opcode", value=0x13, desc="op")]
        assert dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)

    def test_opcode_bp_skips_compressed(self):
        """压缩指令应跳过 opcode 断点检查."""
        dbg = _make_bpdbg()
        dbg._breakpoints = [Breakpoint(kind="opcode", value=0x13, desc="op")]
        # 0x4501 = c.li a0, 0 (压缩指令, 低 2 位 = 01 ≠ 11)
        assert not dbg._check_breakpoints(dbg.hart, 0x1000, 0x4501)


# ============================================================
#  断点管理命令
# ============================================================


class TestBpCommands:
    """断点列表/删除/清除/模式."""

    def test_list_empty(self):
        dbg = _make_bpdbg()
        dbg.cmd_bp_list()  # 应不抛异常

    def test_list_with_items(self):
        dbg = _make_bpdbg()
        dbg._breakpoints = [
            Breakpoint(kind="addr", value=0x1000, desc="test"),
            Breakpoint(kind="instr", value=0, desc="ecall"),
        ]
        dbg.cmd_bp_list()

    def test_delete_valid(self):
        dbg = _make_bpdbg()
        dbg._breakpoints = [Breakpoint(kind="addr", value=0x1000, desc="test")]
        dbg.cmd_bp_delete("1")
        assert len(dbg._breakpoints) == 0

    def test_delete_out_of_range(self):
        dbg = _make_bpdbg()
        dbg.cmd_bp_delete("99")

    def test_clear(self):
        dbg = _make_bpdbg()
        dbg._breakpoints = [
            Breakpoint(kind="addr", value=0x1000, desc="a"),
            Breakpoint(kind="addr", value=0x2000, desc="b"),
        ]
        dbg.cmd_bp_clear()
        assert len(dbg._breakpoints) == 0

    def test_mode_get(self):
        dbg = _make_bpdbg()
        dbg.cmd_bp_mode()  # 显示当前模式

    def test_mode_set_sync(self):
        dbg = _make_bpdbg()
        dbg._bp_mode = "async"
        dbg.cmd_bp_mode("sync")
        assert dbg._bp_mode == "sync"

    def test_mode_set_async(self):
        dbg = _make_bpdbg()
        dbg.cmd_bp_mode("async")
        assert dbg._bp_mode == "async"

    def test_mode_invalid(self):
        dbg = _make_bpdbg()
        dbg.cmd_bp_mode("invalid")


class TestBpOpcode:
    """opcode 断点设置."""

    def test_valid_opcode(self):
        dbg = _make_bpdbg()
        dbg.cmd_bp_opcode("0x13")
        assert len(dbg._breakpoints) == 1
        assert dbg._breakpoints[0].kind == "opcode"
        assert dbg._breakpoints[0].value == 0x13

    def test_invalid_opcode_beyond_7bit(self):
        dbg = _make_bpdbg()
        dbg.cmd_bp_opcode("0xFF")

    def test_unknown_opcode(self):
        """未知 opcode 应报错."""
        dbg = _make_bpdbg()
        dbg.cmd_bp_opcode("0x7E")  # 不是已知 RV64 opcode


class TestDispatchBp:
    """_dispatch_bp 子命令路由."""

    def test_empty_shows_list(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp([])  # 等价于 bp list

    def test_mode_subcommand(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["mode"])

    def test_clear_subcommand(self):
        dbg = _make_bpdbg()
        dbg._breakpoints = [Breakpoint(kind="addr", value=0x1000, desc="test")]
        dbg._dispatch_bp(["clear"])
        assert len(dbg._breakpoints) == 0

    def test_delete_subcommand(self):
        dbg = _make_bpdbg()
        dbg._breakpoints = [Breakpoint(kind="addr", value=0x1000, desc="test")]
        dbg._dispatch_bp(["delete", "1"])
        assert len(dbg._breakpoints) == 0

    def test_if_cond_bp(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["if", "reg", "a0", "==", "42"])
        assert len(dbg._breakpoints) == 1
        assert dbg._breakpoints[0].kind == "cond"
        assert dbg._breakpoints[0].cond_type == "reg"
        assert dbg._breakpoints[0].cond_reg == "a0"

    def test_named_instr_bp(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["ecall"])
        assert len(dbg._breakpoints) == 1
        assert dbg._breakpoints[0].kind == "instr"

    def test_set_addr_bp(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["0x80000000"])
        assert len(dbg._breakpoints) == 1
        assert dbg._breakpoints[0].kind == "addr"
        assert dbg._breakpoints[0].value == 0x80000000

    def test_opcode_subcommand(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["opcode", "0x13"])
        assert len(dbg._breakpoints) == 1
        assert dbg._breakpoints[0].kind == "opcode"


class TestBpConditionParse:
    """条件断点解析回归 — 数值曾误入比较符槽位或粘连在寄存器名上."""

    @staticmethod
    def _conds(dbg) -> tuple:
        bp = dbg._breakpoints[-1]
        return (bp.cond_type, bp.cond_reg, bp.cond_op, bp.cond_val)

    def test_op_omitted_defaults_to_eq(self):
        """缺省比较符 ('csr mepc 0x...') 应解析为相等比较."""
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["if", "csr", "mepc", "0xffffffe000001000"])
        assert len(dbg._breakpoints) == 1
        assert self._conds(dbg) == ("csr", "mepc", "==", 0xFFFF_FFE0_0000_1000)

    def test_single_eq_normalized(self):
        """单等号 ('mepc = 0x...') 应归一化为相等比较."""
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["if", "csr", "mepc", "=", "0xffffffe000001000"])
        assert self._conds(dbg) == ("csr", "mepc", "==", 0xFFFF_FFE0_0000_1000)

    def test_op_glued_to_reg(self):
        """比较符粘连在寄存器名上 ('mepc==0x...') 也须正确拆分."""
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["if", "csr", "mepc==0xffffffe000001000"])
        assert self._conds(dbg) == ("csr", "mepc", "==", 0xFFFF_FFE0_0000_1000)

    def test_less_than(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["if", "csr", "sepc", "<", "0x1000"])
        assert self._conds(dbg) == ("csr", "sepc", "<", 0x1000)

    def test_addr_bp_with_condition(self):
        """地址断点附带条件 — 用于钉住 M 模式 trap 入口的特定 mepc."""
        dbg = _make_bpdbg()
        dbg.cmd_bp_set("0x80000428 if csr mepc == 0xffffffe000001000")
        assert len(dbg._breakpoints) == 1
        bp = dbg._breakpoints[0]
        assert bp.kind == "addr"
        assert bp.value == 0x80000428
        assert self._conds(dbg) == ("csr", "mepc", "==", 0xFFFF_FFE0_0000_1000)

    def test_missing_value_rejected(self):
        """缺省比较符但无数值时应拒绝, 不创建残缺断点."""
        dbg = _make_bpdbg()
        dbg.cmd_bp_set("0x80000428 if csr mepc")
        assert len(dbg._breakpoints) == 0

    def test_garbage_value_rejected(self):
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["if", "csr", "mepc", "==", "bogus"])
        assert len(dbg._breakpoints) == 0

    def test_parsed_cond_matches_mepc(self):
        """解析后的条件能命中目标 mepc (修复前 cond_val 恒为 0 永不命中)."""
        dbg = _make_bpdbg()
        dbg._dispatch_bp(["if", "csr", "mepc", "0xffffffe000001000"])
        bp = dbg._breakpoints[0]
        dbg.hart.csrs["mepc"].val = 0xFFFF_FFE0_0000_1000
        assert dbg._eval_bp_condition(dbg.hart, bp)
        dbg.hart.csrs["mepc"].val = 0x80000428
        assert not dbg._eval_bp_condition(dbg.hart, bp)


class _BpOutputCapture:
    """捕获断点相关 Rich 输出."""

    def __init__(self, dbg) -> None:
        self._dbg = dbg
        self.lines: list[str] = []

    def __enter__(self):
        self._dbg._console.file = self
        return self

    def write(self, s: str, **_) -> None:
        self.lines.append(s)

    def __exit__(self, *_) -> None:
        self._dbg._console.file = sys.stderr

    def text(self) -> str:
        return "".join(self.lines)


class TestCmdBreakpoint:
    """断点设置、查询、命中."""

    # -- 地址断点 --

    def test_set_addr_bp(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x80000000")
        assert len(dbg._breakpoints) == 1
        bp = dbg._breakpoints[0]
        assert bp.kind == "addr"
        assert bp.value == 0x80000000

    def test_addr_bp_hit_in_step_one(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        dbg.hart.pc = TEST_PROG_PA  # 此处有 NOP (来自 make_test_dbg)
        dbg.cmd_bp_set(hex(TEST_PROG_PA))
        # 断点命中应阻止执行 (PC 不推进)
        dbg.step_one()
        # PC 不应推进 (断点在指令执行前命中)
        assert dbg.hart.pc == TEST_PROG_PA

    def test_addr_bp_miss_in_step_one(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        dbg.hart.pc = TEST_PROG_PA
        dbg.cmd_bp_set("0x80000000")  # 不匹配
        dbg.step_one()
        # PC 应已推进
        assert dbg.hart.pc != TEST_PROG_PA

    # -- 指令断点 --

    @pytest.mark.parametrize(
        "name, funct12",
        [
            ("ecall", 0x000),
            ("ebreak", 0x001),
            ("mret", 0x302),
            ("sret", 0x102),
            ("wfi", 0x105),
        ],
    )
    def test_set_instr_bp_named(self, name, funct12):
        dbg = make_test_dbg()
        dbg.cmd_bp_set(name)
        bp = dbg._breakpoints[0]
        assert bp.kind == "instr"
        assert bp.value == funct12

    def test_instr_bp_hit_on_ecall(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        dbg.cmd_bp_set("ecall")
        # 在 PC 处写一条 ECALL (0x00000073)
        dbg._emu.bus.write(TEST_PROG_PA, b"\x73\x00\x00\x00")
        dbg.hart.pc = TEST_PROG_PA
        dbg.step_one()
        assert dbg.hart.pc == TEST_PROG_PA, "ECALL 断点应命中 (PC 不推进)"

    def test_instr_bp_miss_on_addi(self):
        """非 ECALL 指令不应命中 instr 断点."""
        dbg = make_test_dbg()
        dbg.cmd_bp_set("ecall")
        # 0x1000 已有 NOP (addi x0, x0, 0 = 0x00000013)
        dbg.hart.pc = 0x1000
        dbg.step_one()
        assert dbg.hart.pc != 0x1000, "NOP 不应命中 ECALL 断点 (PC 推进)"

    # -- opcode 断点 --

    def test_set_opcode_bp(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_opcode("0x73")
        bp = dbg._breakpoints[0]
        assert bp.kind == "opcode"
        assert bp.value == 0x73

    def test_opcode_bp_hit(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        dbg.cmd_bp_opcode("0x73")
        # 写一条 CSRRS (opcode=0x73, funct3=0b010)
        # csrrw x0, cycle, x0 = (0xC00 << 20) | (0b001 << 12) | 0x73
        instr = (0xC00 << 20) | (0b001 << 12) | 0x73
        dbg._emu.bus.write(TEST_PROG_PA, instr.to_bytes(4, "little"))
        dbg.hart.pc = TEST_PROG_PA
        dbg.step_one()
        assert dbg.hart.pc == TEST_PROG_PA, "opcode 0x73 断点应命中 (PC 不推进)"

    # -- 列表 / 删除 / 清除 --

    def test_bp_list_empty(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_list()
        # 不抛异常即通过

    def test_bp_list(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x80000000")
        dbg.cmd_bp_set("ecall")
        # 验证列表有内容
        assert len(dbg._breakpoints) == 2
        dbg.cmd_bp_list()  # 不抛异常

    def test_bp_delete(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x1000")
        dbg.cmd_bp_set("0x2000")
        assert len(dbg._breakpoints) == 2
        dbg.cmd_bp_delete("1")
        assert len(dbg._breakpoints) == 1
        assert dbg._breakpoints[0].value == 0x2000

    def test_bp_delete_out_of_range(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x1000")
        dbg.cmd_bp_delete("99")  # 不抛异常, 静默警告

    def test_bp_clear(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x1000")
        dbg.cmd_bp_set("0x2000")
        dbg.cmd_bp_clear()
        assert len(dbg._breakpoints) == 0

    # -- 无效参数 --

    @pytest.mark.parametrize(
        "arg",
        [
            "not_a_thing",  # 非数字非指令名
            "-1",  # 负地址
        ],
    )
    def test_bp_set_invalid(self, arg):
        dbg = make_test_dbg()
        dbg.cmd_bp_set(arg)
        assert len(dbg._breakpoints) == 0

    @pytest.mark.parametrize(
        "arg",
        [
            "not_hex",  # @seize_val_err 捕获
            "-1",  # 负值超出 7-bit
            "0x80",  # 超出 7-bit 范围
            "0x55",  # 不是已知 RV64 opcode
        ],
    )
    def test_bp_opcode_invalid(self, arg):
        dbg = make_test_dbg()
        dbg.cmd_bp_opcode(arg)
        assert len(dbg._breakpoints) == 0

    def test_bp_opcode_compressed_quadrant(self):
        """压缩象限 opcode (0x00/0x01/0x02) 无对应标准指令, 应被拒绝."""
        dbg = make_test_dbg()
        dbg.cmd_bp_opcode("0x00")
        assert len(dbg._breakpoints) == 0  # 拒绝: 不在 Opc 中

    # -- restart 后断点持久化 --

    def test_bp_survives_restart(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x1000")
        assert len(dbg._breakpoints) == 1
        dbg.cmd_restart()
        assert len(dbg._breakpoints) == 1, "restart 后断点应保留"
        assert dbg._breakpoints[0].value == 0x1000

    def test_bp_runtime_state_cleared_on_restart(self):
        dbg = make_test_dbg()
        dbg._hart_paused.add(0)
        dbg._bp_hit_this_run.add(("addr", 0x1000))
        dbg.cmd_restart()
        assert len(dbg._hart_paused) == 0
        assert len(dbg._bp_hit_this_run) == 0

    def test_bp_c_skips_already_hit_addr(self):
        """同一 continue 内, 已命中过的地址断点不应重复停."""
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x1000")
        dbg.hart.pc = 0x1000
        # 第一次命中
        assert dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)
        assert ("addr", 0x1000) in dbg._bp_hit_this_run
        # 同一 continue 内再次检查 -> 应跳过
        hit_again = dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)
        assert not hit_again, "同一 continue 内不应重复命中"

    def test_bp_c_second_call_skips_same_addr(self):
        """第二遍 c 应跳过已命中地址, 执行指令推进 PC."""
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x1000")
        dbg.hart.pc = 0x1000
        assert dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)
        assert ("addr", 0x1000) in dbg._bp_hit_this_run
        # 模拟 c 后回到 REPL, 再 c 一次: 同一地址应被跳过
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)
        assert not hit, "第二次 c 应跳过同一地址的断点"
        # 推进 PC 后命中记录应失效 (不同地址不受影响)
        dbg.hart.pc = 0x1004
        assert ("addr", 0x1004) not in dbg._bp_hit_this_run

    # -- 条件断点 --

    def test_cond_bp_if_csr_dispatch(self):
        """bp if csr mtvec == 0x4a8 应创建 kind=cond 断点."""
        dbg = make_test_dbg()
        dbg._dispatch(["bp", "if", "csr", "mtvec", "==", "0x4a8"])
        assert len(dbg._breakpoints) == 1
        bp = dbg._breakpoints[0]
        assert bp.kind == "cond"
        assert bp.cond_type == "csr"
        assert bp.cond_reg == "mtvec"
        assert bp.cond_op == "=="
        assert bp.cond_val == 0x4A8

    def test_cond_bp_if_reg_dispatch(self):
        """bp if reg x0 == 0 应创建 kind=cond 断点."""
        dbg = make_test_dbg()
        dbg._dispatch(["bp", "if", "reg", "x0", "==", "0"])
        assert len(dbg._breakpoints) == 1
        bp = dbg._breakpoints[0]
        assert bp.kind == "cond"
        assert bp.cond_type == "reg"
        assert bp.cond_reg == "x0"

    def test_cond_bp_hit_on_match(self):
        """条件匹配时 cond 断点应命中 (指令写入目标 CSR)."""
        dbg = make_test_dbg()
        # mtvec 初始值为 0, 条件 mtvec==0 -> CSR 写指令触发检查
        dbg._dispatch(["bp", "if", "csr", "mtvec", "==", "0"])
        dbg.hart.pc = 0x1000
        # csrrw x0, mtvec, x1 — 写 x1=0 到 mtvec (保持 0)
        csr_instr = (0x305 << 20) | (1 << 15) | (1 << 12) | (0 << 7) | 0x73
        dbg._emu.bus.write(0x1000, csr_instr.to_bytes(4, "little"))
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, csr_instr)
        assert hit

    def test_cond_bp_miss_on_mismatch(self):
        """条件不匹配时 cond 断点不应命中."""
        dbg = make_test_dbg()
        dbg._dispatch(["bp", "if", "csr", "mtvec", "==", "0x4a8"])
        dbg.hart.pc = 0x1000
        # csrrw x0, mtvec, x1 — 写 x1=0 到 mtvec, 但 0 != 0x4a8
        csr_instr = (0x305 << 20) | (1 << 15) | (1 << 12) | (0 << 7) | 0x73
        dbg._emu.bus.write(0x1000, csr_instr.to_bytes(4, "little"))
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, csr_instr)
        assert not hit

    def test_addr_bp_with_cond_match(self):
        """地址断点+条件: 地址和条件都匹配才命中."""
        dbg = make_test_dbg()
        # bp 0x1000 if reg x0 == 0
        dbg._dispatch(["bp", "0x1000", "if", "reg", "x0", "==", "0"])
        dbg.hart.pc = 0x1000
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)
        assert hit

    def test_addr_bp_with_cond_mismatch(self):
        """地址匹配但条件不匹配 -> 不命中."""
        dbg = make_test_dbg()
        dbg._dispatch(["bp", "0x1000", "if", "reg", "x0", "==", "1"])
        dbg.hart.pc = 0x1000
        # x0 永远是 0, 不等于 1 -> 不命中
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, 0x00000013)
        assert not hit

    @pytest.mark.parametrize(
        "op,val,expect_hit",
        [
            ("==", 0, True),
            ("!=", 1, True),
            ("!=", 0, False),
            (">", -1, True),  # 0 > -1 (signed)
            ("<", 1, True),  # 0 < 1
        ],
    )
    def test_cond_bp_operators(self, op, val, expect_hit):
        """条件断点运算符: == != < > — 用 a0 (x10) 验证."""
        dbg = make_test_dbg()
        # a0 初始值为 0
        dbg._dispatch(["bp", "if", "reg", "a0", op, str(val)])
        dbg.hart.pc = 0x1000
        # ADDI a0, x0, 0 — 写 a0=0, rd=a0 (x10), 预过滤器放行
        addi_instr = (0 << 20) | (0 << 15) | (0 << 12) | (10 << 7) | 0x13
        dbg._emu.bus.write(0x1000, addi_instr.to_bytes(4, "little"))
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, addi_instr)
        assert hit == expect_hit

    def test_cond_bp_gpr_by_alias(self):
        """条件断点应按 GPR 别名查找 (例: t0 -> x5)."""
        dbg = make_test_dbg()
        # 写 t0 (x5) = 0x42
        dbg.hart.write_gpr(5, 0x42)
        dbg._dispatch(["bp", "if", "reg", "t0", "==", "0x42"])
        dbg.hart.pc = 0x1000
        # ADDI t0, x0, 0 — 写 t0=0 (与 0x42 不匹配, 但指令 rd=t0 会触发检查)
        addi_instr = (0 << 20) | (0 << 15) | (0 << 12) | (5 << 7) | 0x13
        dbg._emu.bus.write(0x1000, addi_instr.to_bytes(4, "little"))
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, addi_instr)
        assert hit

    def test_cond_bp_respects_bp_mode_async(self):
        """async 模式: 条件断点命中时设置 _hart_paused."""
        dbg = make_test_dbg(num_harts=2)
        dbg._bp_mode = "async"
        dbg._dispatch(["bp", "if", "csr", "mtvec", "==", "0"])
        dbg.hart.pc = 0x1000
        # csrrw x0, mtvec, x1 — 写 mtvec, CSR 指令触发条件检查
        csr_instr = (0x305 << 20) | (1 << 15) | (1 << 12) | (0 << 7) | 0x73
        dbg._emu.bus.write(0x1000, csr_instr.to_bytes(4, "little"))
        hit = dbg._check_breakpoints(dbg.hart, 0x1000, csr_instr)
        assert hit
        assert dbg.hart.id in dbg._hart_paused

    def test_cond_bp_invalid_syntax(self):
        """bp if 缺参数时警告, 不崩溃."""
        dbg = make_test_dbg()
        assert dbg._dispatch(["bp", "if"]) is True
        assert dbg._dispatch(["bp", "if", "csr"]) is True
        assert len(dbg._breakpoints) == 0

    # -- 分发 --

    def test_dispatch_bp_addr(self):
        dbg = make_test_dbg()
        assert dbg._dispatch(["bp", "0x80000000"]) is True
        assert len(dbg._breakpoints) == 1

    def test_dispatch_bp_list(self):
        dbg = make_test_dbg()
        dbg._dispatch(["bp", "0x1000"])
        assert dbg._dispatch(["bp", "list"]) is True

    def test_dispatch_bp_clear(self):
        dbg = make_test_dbg()
        dbg.cmd_bp_set("0x1000")
        assert dbg._dispatch(["bp", "clear"]) is True
        assert len(dbg._breakpoints) == 0

    # -- 内核符号断点 (vmlinux) --

    def test_kernel_sym_bp_lookup(self):
        """_try_set_symbol_bp 在固件符号中未命中时应查 vmlinux 符号."""
        dbg = make_test_dbg()
        dbg._image = make_test_image()
        dbg._load_offset = 0x80000000
        # 模拟加载了 Linux vmlinux 外部符号
        dbg._sym_symbols = {"handle_page_fault": 0xFFFFFFFF8001393C}
        dbg._sym_load_offset = 0x200000 - 0xFFFFFFFF80000000

        result = dbg._try_set_symbol_bp("handle_page_fault")
        assert result is True
        assert len(dbg._breakpoints) == 1
        bp = dbg._breakpoints[0]
        assert bp.kind == "addr"
        # 运行时地址应为 Bare 模式下的 PA (经 load_offset 映射)
        assert bp.value != 0, "断点地址不应为 0"
        assert "handle_page_fault" in bp.desc

    def test_kernel_sym_bp_not_found(self):
        """内核符号表中无匹配符号时返回 False,
        供 cmd_bp_set 继续尝试地址解析."""
        dbg = make_test_dbg()
        dbg._image = make_test_image()
        dbg._sym_symbols = {"some_func": 0xFFFFFFFF80001000}
        dbg._sym_load_offset = 0

        result = dbg._try_set_symbol_bp("nonexistent")
        assert result is False
        assert len(dbg._breakpoints) == 0

    def test_firmware_sym_bp_takes_priority(self):
        """固件符号与内核符号同名时, 固件符号优先 (先查 _image.symbols)."""
        dbg = make_test_dbg()
        dbg._image = make_test_image()  # 含 _start @ 0x1000
        dbg._load_offset = 0
        dbg._sym_symbols = {"_start": 0xFFFFFFFF80001000}  # 同名内核符号
        dbg._sym_load_offset = 0x200000

        result = dbg._try_set_symbol_bp("_start")
        assert result is True
        assert len(dbg._breakpoints) == 1
        bp = dbg._breakpoints[0]
        assert bp.value == 0x1000, (
            f"应使用固件符号地址 0x1000, 实际 {bp.value:#x}"
        )
