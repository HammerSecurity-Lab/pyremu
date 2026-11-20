#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.mem — 读写语义、地址解析、反汇编与内存显示."""

import pytest

from pyremu.core.hart import RiscvMode
from pyremu.debug.disasm_view import (
    colorize_asm,
    ctrl_flow_kind,
    ctrl_flow_kind_compressed,
)
from pyremu.debugger import (
    Debugger,
    HartSnapshot,
)
from pyremu.memory.mmu import PTE, satp_root_ppn, sv39_walk
from pyremu.utils.parse_bin import FirmwareImage, FirmwareSegment
from tests.conftest import (
    make_test_dbg,
    make_test_dbg_buffered,
    TEST_PROG_PA,
    TEST_PT_L1_BASE,
    TEST_PT_L2_BASE,
    TEST_PT_L3_BASE,
)

RAM_BASE = 0x8000_0000
RAM_SIZE = 0x0040_0000
CODE_PA = RAM_BASE + 0x1000  # 反汇编测试的代码区
DATA_PA = RAM_BASE + 0x8000  # 页映射的目标物理页
L1_BASE = RAM_BASE + 0x0002_0000  # 根页表
L2_BASE = RAM_BASE + 0x0002_1000
L3_BASE = RAM_BASE + 0x0002_2000
SATP_SV39 = 8 << 60
VA_TEXT = 0x1000  # 映射到 CODE_PA 的虚地址
VA_DATA = 0x2000  # 映射到 DATA_PA 的虚地址
HOLE_PA = 0x9000_0000  # 不落入任何 RAM 与设备窗口
NOP = b"\x13\x00\x00\x00"
JAL_ZERO = bytes.fromhex("6f000000")


def _fw_image(
    symbols: dict | None = None, segments: list | None = None
) -> FirmwareImage:
    return FirmwareImage(
        entry_point=CODE_PA,
        segments=list(segments or []),
        format="elf",
        symbols=dict(symbols or {}),
        symbol_ranges=[],
    )


def _write_pte(bus, pa: int, ppn: int, **flags) -> None:
    pte = PTE()
    pte.ppn = ppn & 0xF_FFFF_FFFF
    for name, value in flags.items():
        setattr(pte, name, value)
    bus.write(pa, pte.to_int().to_bytes(8, "little"))


def _map_page(bus, va: int, pa: int, **flags) -> None:
    """建立 4 KiB 页映射 VA 到 PA, 页表结构为 L1 指向 L2, L2 指向 L3."""
    _write_pte(bus, L1_BASE + ((va >> 30) & 0x1FF) * 8, L2_BASE >> 12, v=True)
    _write_pte(bus, L2_BASE + ((va >> 21) & 0x1FF) * 8, L3_BASE >> 12, v=True)
    _write_pte(
        bus, L3_BASE + ((va >> 12) & 0x1FF) * 8, pa >> 12, v=True, **flags
    )


def _enable_sv39(hart) -> None:
    """使 hart 以 S 模式在 Sv39 下运行, 根页表指向 L1_BASE."""
    hart.mode = RiscvMode.S
    hart.satp_val = SATP_SV39 | (L1_BASE >> 12)


def _code_dbg(image: FirmwareImage | None = None):
    """建立代码区已写入若干条 NOP 的调试器."""
    dbg, emu, buf = make_test_dbg_buffered(
        prog_cnt=CODE_PA, is_code_loaded=False, image=image
    )
    emu.bus.write(CODE_PA, NOP * 6)
    dbg.hart.pc = CODE_PA
    return dbg, emu, buf


def _sym_dbg():
    """建立内核符号表只含 k_main 的调试器."""
    dbg, emu, buf = _code_dbg()
    dbg._sym_symbols = {"k_main": CODE_PA}
    dbg._sym_ranges = []
    dbg._sym_symbols_pa = {"k_main": CODE_PA}
    dbg._sym_ranges_pa = []
    return dbg, emu, buf


def _vdasm_dbg(code: bytes = NOP * 4):
    """建立 Sv39 下 VA_TEXT 可读可执行的调试器."""
    dbg, emu, buf = make_test_dbg_buffered(
        prog_cnt=CODE_PA, is_code_loaded=False
    )
    emu.bus.write(DATA_PA, code)
    _map_page(emu.bus, VA_DATA, DATA_PA, r=True, x=True)
    _enable_sv39(dbg.hart)
    dbg.hart.pc = VA_DATA
    return dbg, emu, buf


# ============================================================
#  虚拟地址读取
# ============================================================


class TestTryReadVa:
    def test_size_zero_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._try_read_va(RAM_BASE, 0) is None

    def test_size_above_page_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._try_read_va(RAM_BASE, 4097) is None

    def test_bare_mode_treats_va_as_pa(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\x01\x02\x03\x04")
        assert dbg._try_read_va(DATA_PA, 4) == b"\x01\x02\x03\x04"

    def test_m_mode_with_sv39_treats_va_as_pa(self):
        """M 模式绕过 MMU, satp 已配置时仍按物理地址读取."""
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\xaa\xbb\xcc\xdd")
        hart = dbg.hart
        hart.mode = RiscvMode.M
        hart.satp_val = SATP_SV39 | (L1_BASE >> 12)
        assert dbg._try_read_va(DATA_PA, 4) == b"\xaa\xbb\xcc\xdd"

    def test_sv39_translates_before_read(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\x11\x22\x33\x44")
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True, w=True)
        _enable_sv39(dbg.hart)
        assert dbg._try_read_va(VA_DATA, 4) == b"\x11\x22\x33\x44"

    def test_sv39_unmapped_page_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        assert dbg._try_read_va(VA_DATA, 4) is None

    def test_sv39_x_only_page_is_readable(self):
        """调试器只做地址换算, 不判定 PTE.R; 只可执行的页面同样读出字节."""
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, NOP)
        _map_page(emu.bus, VA_DATA, DATA_PA, x=True)
        _enable_sv39(dbg.hart)
        assert dbg._try_read_va(VA_DATA, 4) == NOP

    def test_sv39_u_page_is_readable_in_s_mode(self):
        """调试器不判定 PTE.U 与 mstatus.SUM; S 模式可读出 U 模式页面."""
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\xde\xad\xbe\xef")
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True, w=True, u=True)
        _enable_sv39(dbg.hart)
        dbg.hart.mstatus_val = 0
        assert dbg._try_read_va(VA_DATA, 4) == b"\xde\xad\xbe\xef"

    def test_sv39_page_to_undefined_physical_address_returns_none(self):
        """页表把虚地址换到未定义的物理空间时, 读取失败而不是返回零字节."""
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _map_page(emu.bus, VA_DATA, HOLE_PA, r=True)
        _enable_sv39(dbg.hart)
        assert dbg._try_read_va(VA_DATA, 4) is None

    def test_read_spanning_two_pages_concatenates(self):
        """跨页读取逐页翻译, 两页的物理地址可以不连续."""
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        next_pa = DATA_PA + 0x2000
        emu.bus.write(DATA_PA + 0xFFC, b"\x01\x02\x03\x04")
        emu.bus.write(next_pa, b"\x05\x06\x07\x08")
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True)
        _map_page(emu.bus, VA_DATA + 0x1000, next_pa, r=True)
        _enable_sv39(dbg.hart)
        assert dbg._try_read_va(VA_DATA + 0xFFC, 8) == (
            b"\x01\x02\x03\x04\x05\x06\x07\x08"
        )


# ============================================================
#  物理读取
# ============================================================

UNDEFINED_PA_VALUES = (
    0,
    0x1,
    0x12,
    0x123,
    0x1234,
    0x12345,
    0x123456,
    -2,
    3.14159265358979323846264338327950288,
    b"",
    b"\x00",
    b"\x01",
    "",
    "abc",
    0x1234_5678_90AB_CDEF,
    (1 << 64) - 1,
)
DEVICE_SPECS = (
    ("clint", "clint_base", 0x0200_0000),
    ("plic", "plic_base", 0x0C00_0000),
    ("uart", "uart_base", 0x1000_0000),
    ("spi", "spi_base", 0x1000_1000),
    ("i2c", "i2c_base", 0x1000_2000),
    ("gpio", "gpio_base", 0x1000_3000),
    ("crng", "crng_base", 0x1000_6000),
)


class TestTryReadPa:
    def test_reads_physical_bytes(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\xde\xad\xbe\xef")
        assert dbg._try_read_pa(DATA_PA, 4) == b"\xde\xad\xbe\xef"

    @pytest.mark.parametrize("pa", UNDEFINED_PA_VALUES)
    def test_undefined_pa_returns_none(self, pa: int):
        """未落入主存与设备窗口的物理地址读取失败, 不返回零字节."""
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._try_read_pa(pa, 4) is None

    @pytest.mark.parametrize("dev_name, base_field, base", DEVICE_SPECS)
    def test_device_mem_is_readable(self, dev_name, base_field, base):
        """注册在总线上的设备窗口仍可从物理地址读取."""
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA,
            is_code_loaded=False,
            **{base_field: base},
        )
        dev = getattr(dbg._emu, dev_name)
        assert dev is not None
        assert dev.base_addr == base
        assert dbg._try_read_pa(base, 4) is not None

    def test_size_zero_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._try_read_pa(DATA_PA, 0) is None
        assert dbg._try_read_pa(DATA_PA, 4097) is None


class TestTryReadVaForced:
    def test_size_zero_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._try_read_va_forced(RAM_BASE, 0) is None

    def test_bare_mode_returns_va_as_pa(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\x01\x02")
        assert dbg._try_read_va_forced(DATA_PA, 2) == (DATA_PA, b"\x01\x02")

    def test_sv39_returns_translated_pa(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\x09\x08")
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True)
        _enable_sv39(dbg.hart)
        assert dbg._try_read_va_forced(VA_DATA, 2) == (DATA_PA, b"\x09\x08")

    def test_sv39_unmapped_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        assert dbg._try_read_va_forced(VA_DATA, 4) is None


# ============================================================
#  地址解析
# ============================================================


class TestResolveAddr:
    def test_pc_keyword_returns_program_counter(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.pc = DATA_PA
        assert dbg._resolve_addr("pc") == DATA_PA
        assert dbg._resolve_addr("PC") == DATA_PA

    def test_gpr_name_returns_register_value(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.write_gpr(10, 0x1234)
        assert dbg._resolve_addr("a0") == 0x1234

    def test_known_csr_name_with_zero_value_returns_zero(self):
        """CSR 名解析成功而取值为 0 时返回 0, 不退化为数值解析."""
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.csrs["mtvec"].val = 0
        assert dbg._resolve_addr("mtvec") == 0

    def test_known_csr_name_returns_csr_value(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.csrs["mtvec"].val = 0x5678
        assert dbg._resolve_addr("mtvec") == 0x5678

    def test_image_symbol_is_offset_by_load_offset(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA,
            is_code_loaded=False,
            image=_fw_image(symbols={"main": 0x1000}),
        )
        dbg._load_offset = 0x100
        assert dbg._resolve_addr("main") == 0x1100

    def test_kernel_symbol_is_offset_by_symbol_load_offset(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg._sym_symbols = {"k_main": 0x1000}
        dbg._sym_load_offset = 0x2000
        assert dbg._resolve_addr("k_main") == 0x3000

    def test_numeric_literal(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._resolve_addr("0x8000") == 0x8000

    def test_negative_literal_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._resolve_addr("-8") is None

    def test_literal_at_two_pow_64_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._resolve_addr("0x10000000000000000") is None

    def test_unknown_name_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._resolve_addr("nowhere") is None


# ============================================================
#  取指与反汇编辅助
# ============================================================


class TestFetchAndDisasm:
    def test_compressed_instruction_uses_16_bit_hex(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\x01\x00")  # c.nop
        result = dbg._fetch_and_disasm(DATA_PA)
        assert result is not None
        assert result[0] == "0001"

    def test_full_instruction_uses_32_bit_hex(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, NOP)
        result = dbg._fetch_and_disasm(DATA_PA)
        assert result is not None
        assert result[0] == "00000013"

    def test_unreadable_address_returns_none(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        assert dbg._fetch_and_disasm(VA_DATA) is None

    def test_valid_pc(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        result = dbg._fetch_and_disasm(TEST_PROG_PA)
        assert result is not None
        raw_hex, asm = result
        assert "13" in raw_hex  # NOP = 0x00000013
        assert "nop" in asm.lower() or "addi" in asm.lower()

    def test_invalid_pc(self):
        """未定义的物理地址返回 None, 不按全零字节反汇编."""
        dbg = make_test_dbg()
        result = dbg._fetch_and_disasm(0xFFFF0000)
        assert result is None


class TestColorizeAsm:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("", ""),
            ("[dim]x[/]", "[dim]x[/]"),
            ("(unknown)", "(unknown)"),
            ("ld", "[cyan]ld[/]"),
            ("sd a0, 8(sp)", "[cyan]sd[/] a0, [magenta]8[/](sp)"),
            ("beq a0, a1, 16", "[green]beq[/] a0, a1, [magenta]16[/]"),
            ("fence rw, rw", "[yellow]fence[/] rw, rw"),
            ("mret", "[red]mret[/]"),
            ("mv a0, a1", "mv a0, a1"),
        ],
    )
    def test_colorize_asm_matches_expected_markup(self, text, expected):
        assert colorize_asm(text) == expected

    def test_unknown_sentinel_escaped(self):
        """<unknown 开头的指令不做 Rich 标记, 原样返回."""
        result = Debugger._colorize_asm("<unknown>")
        # unknown sentinel 不做着色, 原样返回
        assert result == "<unknown>"
        assert "[green]" not in result
        assert "[yellow]" not in result

    def test_branch_is_green(self):
        """分支指令标记为绿色."""
        result = Debugger._colorize_asm("beq     x10,x11,0x1000")
        assert "[green]" in result

    def test_jump_is_green(self):
        """跳转指令标记为绿色."""
        result = Debugger._colorize_asm("jal     ra,0x80000000")
        assert "[green]" in result

    def test_fence_is_yellow(self):
        """fence/AMO 指令标记为黄色."""
        result = Debugger._colorize_asm("fence   iorw,iorw")
        assert "[yellow]" in result

    def test_amo_is_yellow(self):
        """AMO/LR/SC 指令标记为黄色."""
        result = Debugger._colorize_asm("lr.d    x5,(x6)")
        assert "[yellow]" in result

    def test_normal_is_plain(self):
        """普通指令不着色助记符."""
        result = Debugger._colorize_asm("addi    x5,x6,42")
        assert "[green]" not in result
        assert "[yellow]" not in result

    def test_immediate_colored_magenta(self):
        """立即数标记为品红."""
        result = Debugger._colorize_asm("addi    x5,x6,0x1000")
        assert "[magenta]0x1000[/]" in result

    def test_register_not_colored(self):
        """寄存器名不应被品红着色."""
        result = Debugger._colorize_asm("addi    x5,x6,42")
        # x5, x6 不应被着色
        assert "[magenta]x5[/]" not in result
        assert "[magenta]x6[/]" not in result

    def test_no_operands(self):
        """无操作数指令仅着色助记符."""
        result = Debugger._colorize_asm("ecall   ")
        assert "ecall" in result


class TestCtrlFlowKind:
    @pytest.mark.parametrize(
        ("instr", "expected"),
        [
            (0x0000006F, "jal"),
            (0x00000067, "jalr"),
            (0x00000063, "branch"),
            (0x00000073, "ecall"),
            ((0x001 << 20) | 0x73, "ebreak"),
            ((0x302 << 20) | 0x73, "mret"),
            ((0x102 << 20) | 0x73, "sret"),
            ((0x105 << 20) | 0x73, "wfi"),
            ((0xC00 << 20) | 0x73, "csr"),
            (0x0000000F, "fence"),
            (0x0000002F, "fence"),
            (0x00000013, "normal"),
        ],
    )
    def test_ctrl_flow_kind_matches_expected(self, instr, expected):
        assert ctrl_flow_kind(instr) == expected

    def test_jal_is_term(self):
        """JAL 为无条件终止."""
        # jal zero, 16
        instr = (16 << 21) | (0 << 12) | (0 << 7) | 0b1101111
        assert Debugger._ctrl_flow_kind(instr) == "jal"

    def test_jalr_is_term(self):
        """JALR 为无条件终止."""
        instr = (0 << 20) | (1 << 15) | (0b000 << 12) | (0 << 7) | 0b1100111
        assert Debugger._ctrl_flow_kind(instr) == "jalr"

    def test_beq_is_branch(self):
        """BEQ 为条件分支."""
        # beq x0, x0, 8
        instr = (
            (0 << 25)
            | (0 << 20)
            | (0 << 15)
            | (0b000 << 12)
            | (1 << 7)
            | 0b1100011
        )
        assert Debugger._ctrl_flow_kind(instr) == "branch"

    def test_ecall_is_term(self):
        """ECALL 为终止."""
        instr = 0x00000073  # ecall
        assert Debugger._ctrl_flow_kind(instr) == "ecall"

    def test_ebreak_is_term(self):
        """EBREAK 为终止."""
        instr = 0x00100073  # ebreak
        assert Debugger._ctrl_flow_kind(instr) == "ebreak"

    def test_mret_is_term(self):
        """MRET 为终止."""
        instr = 0x30200073  # mret
        assert Debugger._ctrl_flow_kind(instr) == "mret"

    def test_sret_is_term(self):
        """SRET 为终止."""
        instr = 0x10200073  # sret
        assert Debugger._ctrl_flow_kind(instr) == "sret"

    def test_addi_is_normal(self):
        """ADDI 为普通指令."""
        instr = (0 << 20) | (0 << 15) | (0b000 << 12) | (5 << 7) | 0b0010011
        assert Debugger._ctrl_flow_kind(instr) == "normal"

    def test_c_jal_is_term(self):
        """C.JAL 为终止."""
        # funct3=001, quad=01, rd=ra
        instr16 = (0b001 << 13) | (1 << 7) | 0b01
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "jal"

    def test_c_j_is_term(self):
        """C.J 为终止."""
        instr16 = (0b101 << 13) | 0b01
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "jal"

    def test_c_beqz_is_branch(self):
        """C.BEQZ 为条件分支."""
        instr16 = (0b110 << 13) | 0b01
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "branch"

    def test_c_bnez_is_branch(self):
        """C.BNEZ 为条件分支."""
        instr16 = (0b111 << 13) | 0b01
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "branch"

    def test_c_jr_is_term(self):
        """C.JR 为终止."""
        # funct3=100, quad=10, rs1≠0
        instr16 = (0b100 << 13) | (1 << 7) | 0b10  # c.jr ra
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "jalr"

    def test_c_addi_is_normal(self):
        """C.ADDI 为普通指令."""
        instr16 = (0b000 << 13) | (1 << 7) | 0b01
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "normal"

    def test_c_mv_is_normal_not_term(self):
        """C.MV (0x8512) 是 rs2≠0 的普通指令, 不应被误判为 C.JR/C.JALR 终止.

        C2 quad funct3=100 编码族内, rs2=0 才是跳转 (C.JR/C.JALR/C.EBREAK),
        rs2≠0 是 C.MV / C.ADD 普通指令.
        """
        instr16 = 0x8512  # c.mv x10, x4 — 真实触发 bug 的编码
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "normal"

    def test_c_add_is_normal_not_term(self):
        """C.ADD 是 rs2≠0 的普通指令, 不应被误判为终止."""
        # funct3=100, quad=10, rs1=x10, rs2=x6 -> c.add x10, x6
        instr16 = (0b100 << 13) | (10 << 7) | (6 << 2) | 0b10  # 0x9526
        assert Debugger._ctrl_flow_kind_compressed(instr16) == "normal"


class TestCtrlFlowKindCompressed:
    @pytest.mark.parametrize(
        ("instr", "expected"),
        [
            ((1 << 13) | 1, "jal"),
            ((5 << 13) | 1, "jal"),
            ((4 << 13) | 2, "jalr"),
            ((4 << 13) | 2 | (1 << 2), "normal"),
            ((6 << 13) | 2, "jalr"),
            ((6 << 13) | 2 | (1 << 2), "normal"),
            ((6 << 13) | 1, "branch"),
            ((7 << 13) | 1, "branch"),
            (0x0002, "ebreak"),
            (0x0001, "normal"),
        ],
    )
    def test_ctrl_flow_kind_compressed_matches_expected(self, instr, expected):
        assert ctrl_flow_kind_compressed(instr) == expected


class TestWarnPcIfSuspect:
    def _warns(self, dbg):
        messages: list[str] = []
        dbg._warn = messages.append
        return messages

    def test_odd_value_warns_alignment(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        messages = self._warns(dbg)
        dbg._warn_pc_if_suspect(dbg.hart, 0x1001)
        assert any("未对齐" in m for m in messages)

    def test_value_beyond_rv64_warns_range(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        messages = self._warns(dbg)
        dbg._warn_pc_if_suspect(dbg.hart, 1 << 64)
        assert any("超出 RV64" in m for m in messages)

    def test_aligned_value_in_range_is_silent(self):
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        messages = self._warns(dbg)
        dbg._warn_pc_if_suspect(dbg.hart, CODE_PA)
        assert messages == []


# ============================================================
#  pc 命令
# ============================================================


class TestCmdPc:
    def test_unresolvable_address_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_pc("nowhere")
        assert "无法解析地址" in buf.getvalue()

    def test_address_beyond_rv64_reports_error(self):
        """符号加装载偏移越过 2^64 时拒绝设置 PC."""
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg._image = _fw_image(symbols={"huge": 0xFFFF_FFFF_FFFF_FFF0})
        dbg._load_offset = 0x20
        dbg.cmd_pc("huge")
        assert "超出 RV64 范围" in buf.getvalue()
        assert dbg.hart.pc == CODE_PA

    def test_odd_address_warns_alignment(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.pc = CODE_PA
        dbg.cmd_pc(hex(CODE_PA + 1))
        assert "未对齐" in buf.getvalue()

    def test_unreadable_pc_prints_placeholder(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        dbg.hart.pc = VA_DATA
        dbg.cmd_pc()
        assert "无法读取" in buf.getvalue()

    def test_zero_mcause_prints_no_trap_table(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_pc()
        assert "Trap 上下文" not in buf.getvalue()

    def test_trap_table_is_printed_for_s_and_u_mode(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        hart = dbg.hart
        hart.csrs["mcause"].val = 2
        for mode in (RiscvMode.S, RiscvMode.U):
            dbg._trap_displayed_mcause = None
            hart.mode = mode
            buf.truncate(0)
            buf.seek(0)
            dbg.cmd_pc()
            assert "Trap 上下文" in buf.getvalue()

    def test_same_mcause_is_reported_only_once(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.csrs["mcause"].val = 2
        dbg.cmd_pc()
        assert "Trap 上下文" in buf.getvalue()
        buf.truncate(0)
        buf.seek(0)
        dbg.cmd_pc()
        assert "Trap 上下文" not in buf.getvalue()

    def test_interrupt_mcause_marks_context_as_interrupt(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.csrs["mcause"].val = (1 << 63) | 7
        dbg.cmd_pc()
        assert "中断" in buf.getvalue()

    def test_nonzero_scause_is_annotated_with_its_name(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.csrs["mcause"].val = 2
        dbg.hart.csrs["scause"].val = 13
        dbg.cmd_pc()
        assert "Trap 上下文" in buf.getvalue()

    def test_nonzero_sstatus_alone_is_annotated(self):
        """scause 为 0 而 sstatus 非 0 时不带异常名, 只报告使能位与特权级."""
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.csrs["mcause"].val = 2
        dbg.hart.csrs["scause"].val = 0
        # sstatus 由 mstatus 的对应位给出, 经 csrw 的写入路径设置.
        dbg.hart.write_csr(0x100, 0x100)
        dbg.cmd_pc()
        assert "SPP=1" in buf.getvalue()

    def test_waiting_hart_is_marked(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart._waiting = True
        dbg.cmd_pc()
        assert "WFI" in buf.getvalue()

    def test_show_pc(self):
        dbg = make_test_dbg()
        dbg.hart.pc = 0x1000
        dbg.cmd_pc()  # 应不抛异常

    def test_set_pc(self):
        dbg = make_test_dbg()
        dbg.cmd_pc("0x80000000")
        assert dbg.hart.pc == 0x80000000

    def test_set_pc_invalid_value(self):
        dbg = make_test_dbg()
        dbg.cmd_pc("not_a_number")  # decorator 捕获 ValueError

    def test_set_pc_clears_snapshot(self):
        dbg = make_test_dbg()
        dbg._snapshot = HartSnapshot(
            pc=0x1000,
            gpr_vals=[0] * 32,
            csr_vals={},
            mode=3,
            reservation_valid=False,
            reservation_addr=0,
        )
        dbg.cmd_pc("0x2000")
        assert dbg._snapshot is None
        assert dbg._mem_changes == []

    def test_set_pc_negative(self):
        """pc -1 被硬拒绝."""
        dbg = make_test_dbg()
        dbg.hart.pc = 0x1000
        dbg.cmd_pc("-1")
        assert dbg.hart.pc == 0x1000  # 未改变

    def test_set_pc_bare_out_of_ram(self):
        """Bare 模式下 PC 在 RAM 外时给出警告."""
        dbg = make_test_dbg()
        dbg.hart.pc = 0x1000
        dbg.cmd_pc("0xFFFFFFFF00000000")  # 大地址, Bare 模式警告但不阻止

    def test_set_pc_sv39_bad_sign_ext(self):
        """Sv39 下 bits[63:39] 不等于 bit 38 时警告."""
        dbg = make_test_dbg()
        dbg.hart.satp_val = (8 << 60) | 1  # Sv39 mode
        dbg.hart.pc = 0x1000
        # bits[63:39] 全 1, bit 38 = 0, 地址格式错误
        dbg.cmd_pc("0xFFFF800000010000")


# ============================================================
#  反汇编命令
# ============================================================


class TestCountInstrsBetween:
    def test_start_outside_ram_returns_none(self):
        """起始地址不在主存内时距离无法确定."""
        dbg, _, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        assert dbg._count_instrs_between(HOLE_PA, RAM_BASE + RAM_SIZE) is None

    def test_counts_mixed_compressed_and_full_instructions(self):
        dbg, emu, _ = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(CODE_PA, b"\x01\x00" + NOP)  # c.nop + nop = 6 字节
        assert dbg._count_instrs_between(CODE_PA, CODE_PA + 6) == 2


class TestCmdDisasm:
    def test_unresolvable_address_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_disasm("nowhere")
        assert "无法解析地址" in buf.getvalue()

    def test_instruction_count_out_of_range_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_disasm("0x1000", "0")
        assert "1-512" in buf.getvalue()

    def test_address_beyond_rv64_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg._image = _fw_image(symbols={"huge": 0xFFFF_FFFF_FFFF_FFF0})
        dbg._load_offset = 0x20
        dbg.cmd_disasm("huge")
        assert "超出 RV64 范围" in buf.getvalue()

    def test_odd_address_is_aligned_with_warning(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_disasm(hex(CODE_PA + 1), "1")
        assert "对齐" in buf.getvalue()

    def test_symbol_scope_line_is_printed_once(self):
        dbg, _, buf = _sym_dbg()
        dbg.cmd_disasm(hex(CODE_PA), "2")
        out = buf.getvalue()
        assert "k_main" in out
        assert out.count("k_main") == 1

    def test_scope_line_carries_segment_name(self):
        segment = FirmwareSegment(
            vaddr=CODE_PA, data=b"", memsz=0x1000, name=".text"
        )
        image = _fw_image(segments=[segment])
        dbg, _, buf = _sym_dbg()
        dbg._image = image
        dbg.cmd_disasm(hex(CODE_PA), "1")
        out = buf.getvalue()
        assert ".text" in out and "k_main" in out

    def test_terminator_at_reference_pc_ends_step_advance(self):
        """分支指令之后不再给出相对步数, 且基准步数不再前移."""
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(CODE_PA, JAL_ZERO + NOP)
        dbg.hart.pc = CODE_PA
        dbg.cmd_disasm(hex(CODE_PA), "2")
        assert "─" * 8 in buf.getvalue()
        assert dbg._disasm_base_step is None

    def test_forward_count_outside_ram_reports_unknown(self):
        """PC 不在 RAM 内且低于反汇编地址: 距离无法确定, 不显示步数."""
        dbg, _, buf = _code_dbg()
        dbg.hart.pc = 0
        dbg.cmd_disasm(hex(CODE_PA), "2")
        assert dbg._disasm_base_step is None
        assert "+" not in buf.getvalue().split("\n", 1)[1]

    def test_backward_count_outside_ram_reports_unknown(self):
        """PC 高于反汇编地址且不在 RAM 内: 距离无法确定."""
        dbg, _, _ = _code_dbg()
        dbg.hart.pc = HOLE_PA
        dbg.cmd_disasm(hex(CODE_PA), "1")
        assert dbg._disasm_base_step is None

    def test_relative_step_prefix_before_terminator(self):
        dbg, _, buf = _code_dbg()
        dbg.hart.pc = CODE_PA
        dbg.cmd_disasm(hex(CODE_PA + 8), "2")
        assert "+2" in buf.getvalue()

    def test_continue_from_next_address_keeps_step_base(self):
        dbg, _, _ = _code_dbg()
        dbg.cmd_disasm(hex(CODE_PA), "2")
        assert dbg._disasm_next_addr == CODE_PA + 8
        base = dbg._disasm_base_step
        dbg.cmd_disasm(hex(dbg._disasm_next_addr), "2")
        assert dbg._disasm_next_addr == CODE_PA + 16
        assert base == 2

    def test_read_window_is_not_cut_mid_instruction(self):
        """读取窗口长度为请求条数的四倍, 窗口内不会出现半个指令.

        窗口长为 4*inst_count, 而进入循环的每次迭代至多推进 4 字节, 且循环在
        收集到 inst_count 条时结束, 故已消费字节数不超过 4*(inst_count-1),
        剩余字节数不小于 4, 不小于任何一条指令的长度.
        """
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        cut_code = b"\x01\x00" * 3 + JAL_ZERO  # 三条压缩指令 + 一条四字节指令
        emu.bus.write(CODE_PA, cut_code)
        dbg.hart.pc = CODE_PA
        dbg.cmd_disasm(hex(CODE_PA), "2")
        out = buf.getvalue()
        assert "截断" not in out
        assert dbg._disasm_next_addr == CODE_PA + 4

    def test_image_symbol_address_is_disassembled(self):
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA,
            is_code_loaded=False,
            image=_fw_image(symbols={"main": CODE_PA}),
        )
        emu.bus.write(CODE_PA, NOP)
        dbg.cmd_disasm("main", "1")
        assert "00000013" in buf.getvalue()

    def test_disasm_default(self):
        dbg = make_test_dbg()
        # 在 0x1000 有 NOP
        dbg.cmd_disasm("0x1000")

    def test_disasm_custom_length(self):
        dbg = make_test_dbg()
        dbg.cmd_disasm("0x1000", "32")

    def test_disasm_invalid_addr(self):
        dbg = make_test_dbg()
        dbg.cmd_disasm("bad")

    def test_disasm_negative_addr(self):
        dbg = make_test_dbg()
        dbg.cmd_disasm("-1")

    def test_disasm_addr_overflow(self):
        dbg = make_test_dbg()
        dbg.cmd_disasm("1234567890123456789012345789")

    def test_disasm_sets_next_addr(self):
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        dbg._disasm_next_addr = None
        dbg.cmd_disasm(hex(TEST_PROG_PA), "32")
        assert dbg._disasm_next_addr is not None

    def test_disasm_zero_length(self):
        dbg = make_test_dbg()
        dbg.cmd_disasm("0x1000", "0")  # 报错

    def test_count_instrs_non_ram_addr_returns_none(self):
        """非 RAM 地址 (MMIO/空洞) 距离无法确定, 返回 None 且不做遍历."""
        dbg = make_test_dbg()
        # 0x10000000 是 UART MMIO, 不在 RAM 范围内
        assert dbg._count_instrs_between(0x10000000, 0x10000100) is None

    def test_count_instrs_iteration_limit_returns_none(self):
        """遍历条数超过扫描上限时停止遍历并返回 None."""
        dbg = make_test_dbg(ram_size=0x200000)  # 2 MiB RAM
        # RAM 范围内的大区间, 指令条数超过扫描上限
        ram_base = dbg._emu.bus.ram_base
        result = dbg._count_instrs_between(ram_base, ram_base + 0x100000)
        assert result is None

    def test_disasm_far_from_ref_no_hang(self):
        """ref_pc 与 disasm 地址相距甚远时不挂死, 且不显示步数."""
        dbg = make_test_dbg()
        dbg._disasm_ref_pc = 0x80000000  # kernel 入口
        dbg.cmd_disasm("0x10000000", "32")  # UART 地址 — 远在 ref_pc 之上
        # 不应挂死 — 到达这里即通过
        assert dbg._disasm_base_step is None

    def test_count_instrs_empty_range(self):
        """start >= end 时返回 0."""
        dbg = make_test_dbg()
        assert dbg._count_instrs_between(0x80001000, 0x80001000) == 0
        assert dbg._count_instrs_between(0x80002000, 0x80001000) == 0

    def test_disasm_step_accumulates_through_negative(self):
        """Enter 重复时负步数也累积推进, 抵达 ref_pc 后正确显示 +N."""
        dbg = make_test_dbg()
        # 将 hart PC 设在较远处, 从 ref_pc 之前开始 disasm
        dbg.hart.pc = 0x80001000

        # 第一段: ref_pc 之前, 写入 4 条 nop
        for off in range(0, 16, 4):
            dbg._emu.bus.write(0x80000FF0 + off, b"\x13\x00\x00\x00")
        dbg.cmd_disasm("0x80000ff0", "4")
        step_after_first = dbg._disasm_base_step
        # 4 条 nop 之后步数到达 ref_pc, next_base 应为 0
        assert step_after_first <= 0, (
            f"ref_pc 之前 base_step 应 <=0, 实际 {step_after_first}"
        )

        # 模拟 Enter 重复: 推进到 ref_pc 所在块
        dbg._disasm_next_addr = 0x80001000
        dbg._emu.bus.write(0x80001000, b"\x13\x00\x00\x00" * 4)
        dbg.cmd_disasm(hex(dbg._disasm_next_addr), "4")
        step_after_second = dbg._disasm_base_step
        # Enter 重复后, ref_pc 已过, 步数应为正
        assert step_after_second > 0, (
            f"过 ref_pc 后 base_step 应为正, 实际 {step_after_second}"
        )

    def test_disasm_odd_addr_auto_aligns(self):
        """非 2-字节对齐地址自动向下对齐并警告."""
        dbg = make_test_dbg()
        # 写入已知指令以便反汇编
        dbg._emu.bus.write(0x80000FF0, b"\x13\x00\x00\x00" * 4)
        # 奇数地址
        dbg.cmd_disasm("0x80000ff1", "16")
        # 不应挂死, 且 _disasm_next_addr 应从对齐后的地址计算
        assert dbg._disasm_next_addr is not None
        # 对齐后应从 0x80000FF0 开始, next_addr >= 0x80000FF0 + 4*nop
        assert dbg._disasm_next_addr >= 0x80000FF0 + 4, (
            f"应从对齐地址开始反汇编, next_addr=0x{dbg._disasm_next_addr:x}"
        )

    def test_disasm_aligned_addr_no_warning(self):
        """对齐地址不应触发警告."""
        dbg = make_test_dbg()
        dbg._emu.bus.write(0x80001000, b"\x13\x00\x00\x00" * 4)
        dbg.cmd_disasm("0x80001000", "16")
        # 正常完成
        assert dbg._disasm_next_addr is not None

    def test_disasm_always_uses_physical_address(self):
        """disasm 始终直读物理地址 (即使 MMU 使能)."""
        dbg = make_test_dbg(ram_size=0x200000)
        hart = dbg.hart
        bus = dbg._emu.bus

        # 在 PA 0x80010000 写入两条已知指令: NOP + ADDI a0,a0,1
        target_pa = 0x80010000
        code = (
            b"\x13\x00\x00\x00"  # nop
            b"\x13\x05\x15\x00"  # addi a0, a0, 1
        )
        bus.write(target_pa, code)

        # 切换到 S 模式并启用 Sv39 MMU
        hart.mode = RiscvMode.S
        hart.satp_val = (8 << 60) | 0x100  # 任意 root PPN, 不影响 PA 直读

        # disasm 物理地址 — 直接读 PA, 不翻译
        dbg.cmd_disasm(hex(target_pa), "2")

        # 验证下一条地址: 两条 4 字节指令 = 8 字节后
        assert dbg._disasm_next_addr is not None
        assert dbg._disasm_next_addr == target_pa + 8, (
            f"disasm PA: next_addr=0x{dbg._disasm_next_addr:x}, "
            f"期望 0x{target_pa + 8:x}"
        )

    def test_disasm_mmu_bare_falls_back_to_physical(self):
        """Bare 模式下 disasm 直接使用物理地址 (无翻译)."""
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        # 在 TEST_PROG_PA 处写两条指令
        dbg._emu.bus.write(TEST_PROG_PA, b"\x13\x00\x00\x00\x13\x05\x15\x00")
        dbg.hart.satp_val = 0  # Bare
        dbg.cmd_disasm(hex(TEST_PROG_PA), "2")
        # 两条 4 字节指令, next_addr 应在 TEST_PROG_PA + 8
        assert dbg._disasm_next_addr == TEST_PROG_PA + 8

    def test_vdisasm_2mib_megapage_ppn_to_pa(self):
        """vdisasm 在 2 MiB 超级页下正确计算 VA->PA.

        验证两项修复:
        1. PPN 掩码 9-bit (∼0x1FF) 而非 10-bit (∼0x3FF) — bit 9 保留.
        2. sv39_walk 返回 PPN, 调用方必须计算 PA = (ppn << 12) | page_off.
        """
        dbg = make_test_dbg(ram_size=0x400000)
        hart = dbg.hart
        bus = dbg._emu.bus

        # 2 MiB 超级页: L1 指针指向 L2 大页叶, PPN 的 bit 9 为 1
        target_va_2m = 0x200000  # VA 在 2 MiB 对齐边界
        vpn2 = (target_va_2m >> 30) & 0x1FF
        vpn1 = (target_va_2m >> 21) & 0x1FF  # 2 MiB 页: L2 索引为 vpn1

        def _write_pte(pa, ppn, **flags):
            pte = PTE()
            pte.ppn = ppn & 0xF_FFFF_FFFF
            for f, v in flags.items():
                setattr(pte, f, v)
            bus.write(pa, pte.to_int().to_bytes(8, "little"))

        # L1: 指针 -> L2 页表
        _write_pte(TEST_PT_L1_BASE + vpn2 * 8, TEST_PT_L2_BASE >> 12, v=True)
        # L2: 2 MiB 大页叶, PPN=0x80200, bit 9 为 1, bits[8:0] 全为 0
        mega_ppn = 0x80200
        _write_pte(
            TEST_PT_L2_BASE + vpn1 * 8, mega_ppn, v=True, r=True, w=True, x=True
        )

        # 在映射目标 PA 处写入两条已知指令
        target_pa = 0x80200000
        # nop + addi a0,a0,1
        bus.write(target_pa, b"\x13\x00\x00\x00\x13\x05\x15\x00")

        hart.mode = RiscvMode.S
        hart.satp_val = (8 << 60) | (TEST_PT_L1_BASE >> 12)
        hart.dtlb.flush_all()
        hart.itlb.flush_all()

        # vdisasm 经 _try_read_va_forced 与 sv39_walk,
        # PA 由 ppn << 12 | off 算出
        dbg.cmd_vdisasm(hex(target_va_2m), "2")

        # 验证 next_addr 正确 (两条 4 字节指令, 共 8 字节)
        assert dbg._vdisasm_next_addr is not None
        assert dbg._vdisasm_next_addr == target_va_2m + 8, (
            f"vdisasm 2M: next_addr=0x{dbg._vdisasm_next_addr:x}, "
            f"期望 0x{target_va_2m + 8:x}"
        )

    def test_vdisasm_ppn_not_pa(self):
        """sv39_walk 返回 PPN 而非 PA — vdisasm 必须经 << 12 | offset 换算.

        若调用方将 sv39_walk 的第二个返回值当作 PA 直接使用,
        读出的物理地址会少 12 个 bit, 读到全零或错误数据.
        """
        dbg = make_test_dbg(ram_size=0x200000)
        hart = dbg.hart
        bus = dbg._emu.bus

        # 在 PA 0x80005000 写入 NOP (与映射的 PPN 差 12 bit 位移)
        target_pa = 0x80005000
        bus.write(target_pa, b"\x13\x00\x00\x00")  # nop

        target_va_4k = 0x5000
        vpn2 = (target_va_4k >> 30) & 0x1FF
        vpn1 = (target_va_4k >> 21) & 0x1FF
        vpn0 = (target_va_4k >> 12) & 0x1FF

        def _write_pte(pa, ppn, **flags):
            pte = PTE()
            pte.ppn = ppn & 0xF_FFFF_FFFF
            for f, v in flags.items():
                setattr(pte, f, v)
            bus.write(pa, pte.to_int().to_bytes(8, "little"))

        _write_pte(TEST_PT_L1_BASE + vpn2 * 8, TEST_PT_L2_BASE >> 12, v=True)
        _write_pte(TEST_PT_L2_BASE + vpn1 * 8, TEST_PT_L3_BASE >> 12, v=True)
        _write_pte(
            TEST_PT_L3_BASE + vpn0 * 8,
            target_pa >> 12,
            v=True,
            r=True,
            w=True,
            x=True,
        )

        hart.mode = RiscvMode.S
        hart.satp_val = (8 << 60) | (TEST_PT_L1_BASE >> 12)
        hart.dtlb.flush_all()
        hart.itlb.flush_all()

        # 直接调 sv39_walk: 返回 PPN, 不是 PA
        root_ppn = satp_root_ppn(hart.satp_val)
        assert hart.mem_read_phy is not None
        ok, ppn, _perm, _ps = sv39_walk(
            root_ppn, target_va_4k, hart.mem_read_phy
        )
        assert ok, "sv39_walk 应成功"
        # PPN != PA: 若调用方把 PPN 当 PA 用, 会读到错误地址
        page_off = target_va_4k & 0xFFF
        actual_pa = (ppn << 12) | page_off
        assert actual_pa == target_pa, (
            f"PA 计算错误: ppn=0x{ppn:x}, 正确 PA=0x{target_pa:x}, "
            f"若把 PPN 当 PA 则会得到 0x{ppn:x}"
        )
        # 关键回归: PPN 本身 != 目标物理地址 (差异超过页内偏移)
        assert ppn != target_pa, (
            f"PPN=0x{ppn:x} 不应等于目标 PA=0x{target_pa:x}; "
            f"sv39_walk 返回的是 PPN, 调用方必须 << 12 | offset"
        )


# ============================================================
#  虚拟地址反汇编命令
# ============================================================


class TestCmdVdisasm:
    def test_unresolvable_address_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_vdisasm("nowhere")
        assert "无法解析地址" in buf.getvalue()

    def test_instruction_count_out_of_range_reports_error(self):
        dbg, _, buf = _vdasm_dbg()
        dbg.cmd_vdisasm(hex(VA_DATA), "0")
        assert "1-512" in buf.getvalue()

    def test_address_beyond_rv64_reports_error(self):
        dbg, _, buf = _vdasm_dbg()
        dbg._image = _fw_image(symbols={"huge": 0xFFFF_FFFF_FFFF_FFF0})
        dbg._load_offset = 0x20
        dbg.cmd_vdisasm("huge")
        assert "超出 RV64 范围" in buf.getvalue()

    def test_bare_mode_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_vdisasm(hex(DATA_PA), "1")
        assert "Bare 模式" in buf.getvalue()

    def test_pa_to_va_reverse_lookup_restores_virtual_address(self):
        """以物理地址提交时经 _pa_to_va 反查回虚地址再遍历页表."""
        dbg, _, buf = _vdasm_dbg()
        dbg._pa_to_va = {DATA_PA: VA_DATA}
        dbg.cmd_vdisasm(hex(DATA_PA), "1")
        assert "00000013" in buf.getvalue()

    def test_odd_address_is_aligned_with_warning(self):
        dbg, _, buf = _vdasm_dbg()
        dbg.cmd_vdisasm(hex(VA_DATA + 1), "1")
        assert "对齐" in buf.getvalue()

    def test_missing_memory_backend_reports_error(self):
        dbg, _, buf = _vdasm_dbg()
        dbg.hart.mem_read_phy = None
        dbg.cmd_vdisasm(hex(VA_DATA), "1")
        assert "内存后端未挂载" in buf.getvalue()

    def test_unmapped_va_reports_page_fault(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        dbg.cmd_vdisasm(hex(VA_DATA), "1")
        assert "页表翻译失败" in buf.getvalue()

    def test_symbol_scope_line_is_printed(self):
        dbg, _, buf = _vdasm_dbg()
        dbg._sym_symbols = {"k_main": VA_DATA}
        dbg._sym_ranges = []
        dbg.cmd_vdisasm(hex(VA_DATA), "2")
        assert "k_main" in buf.getvalue()

    def test_terminator_instruction_is_underlined(self):
        dbg, _, buf = _vdasm_dbg(JAL_ZERO + NOP)
        dbg.cmd_vdisasm(hex(VA_DATA), "2")
        assert "─" * 8 in buf.getvalue()

    def test_read_window_is_not_cut_mid_instruction(self):
        """读取窗口长度为请求条数的四倍, 循环在收满条数或读完窗口时结束."""
        dbg, _, buf = _vdasm_dbg(b"\x01\x00" * 3 + JAL_ZERO)
        dbg.cmd_vdisasm(hex(VA_DATA), "2")
        out = buf.getvalue()
        assert "截断" not in out
        assert dbg._vdisasm_next_addr == VA_DATA + 4

    def test_reference_pc_is_marked(self):
        dbg, _, buf = _vdasm_dbg()
        dbg.hart.pc = VA_DATA
        dbg.cmd_vdisasm(hex(VA_DATA), "2")
        assert "pc ->" in buf.getvalue()


# ============================================================
#  VA 到 PA 映射表头
# ============================================================


class TestShowVaMappingHeader:
    def test_walk_on_tlb_miss_then_hit(self):
        """首次遍历填充 TLB, 第二次由 TLB 命中取出 ppn 与权限位."""
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True)
        _enable_sv39(dbg.hart)
        dbg._show_va_mapping_header(VA_DATA, 4)
        first = buf.getvalue()
        assert f"VA 0x{VA_DATA:016x} -> PA 0x{DATA_PA:016x}" in first
        # 遍历成功后 TLB 命中, 输出内容不变
        dbg._show_va_mapping_header(VA_DATA, 4)
        assert (
            buf.getvalue().count(f"VA 0x{VA_DATA:016x} -> PA 0x{DATA_PA:016x}")
            == 2
        )

    def test_perm_letters_come_from_pte_bits(self):
        """权限字母取自 PTE 的 R/W/X/U 位, 不按下标推断."""
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True, w=True)
        _enable_sv39(dbg.hart)
        dbg._show_va_mapping_header(VA_DATA, 4)
        assert "[rw-s]" in buf.getvalue()

    def test_unmapped_page_is_reported_as_missing(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        dbg._show_va_mapping_header(VA_DATA, 4)
        assert "缺页" in buf.getvalue()

    def test_missing_memory_backend_is_reported(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.hart.mem_read_phy = None
        dbg._show_va_mapping_header(VA_DATA, 4)
        assert "内存后端未挂载" in buf.getvalue()

    def test_size_spanning_two_pages_reports_both(self):
        """起始地址在页内偏移 0x800 处, 4096 字节的区间跨过页边界."""
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        next_pa = DATA_PA + 0x1000
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True, w=True, x=True, u=True)
        _map_page(emu.bus, VA_DATA + 0x1000, next_pa, r=True)
        _enable_sv39(dbg.hart)
        dbg._show_va_mapping_header(VA_DATA + 0x800, 4096)
        out = buf.getvalue()
        assert f"VA 0x{VA_DATA:016x} -> PA 0x{DATA_PA:016x}" in out
        assert f"VA 0x{VA_DATA + 0x1000:016x} -> PA 0x{next_pa:016x}" in out


# ============================================================
#  物理内存显示命令
# ============================================================


class TestCmdMem:
    def test_hexdump_is_printed(self):
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"ABCD")
        dbg.cmd_mem(hex(DATA_PA), "16")
        assert "41 42 43 44" in buf.getvalue()

    def test_unresolvable_address_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_mem("nowhere")
        assert "无法解析地址" in buf.getvalue()

    def test_size_out_of_range_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_mem(hex(DATA_PA), "4097")
        assert "1-4096" in buf.getvalue()

    def test_address_beyond_rv64_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg._image = _fw_image(symbols={"huge": 0xFFFF_FFFF_FFFF_FFF0})
        dbg._load_offset = 0x20
        dbg.cmd_mem("huge")
        assert "超出 RV64 范围" in buf.getvalue()

    def test_non_integer_size_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_mem(hex(DATA_PA), "abc")
        assert "需为整数" in buf.getvalue()

    def test_mem_default_size(self):
        dbg = make_test_dbg()
        dbg._emu.bus.write(0x80000000, b"Hello, world!")
        dbg.cmd_mem("0x80000000")

    def test_mem_custom_size(self):
        dbg = make_test_dbg()
        dbg._emu.bus.write(0x1000, b"\x00" * 128)
        dbg.cmd_mem("0x1000", "32")

    def test_mem_invalid_addr(self):
        dbg = make_test_dbg()
        dbg.cmd_mem("bad")

    def test_mem_invalid_size(self):
        dbg = make_test_dbg()
        dbg.cmd_mem("0x1000", "bad")

    def test_mem_negative_addr(self):
        dbg = make_test_dbg()
        dbg.cmd_mem("-1")

    def test_mem_addr_overflow(self):
        dbg = make_test_dbg()
        dbg.cmd_mem("1234567890123456789012345789")


# ============================================================
#  虚拟内存显示命令
# ============================================================


class TestCmdVmem:
    def test_mapping_and_hexdump_are_printed(self):
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"ABCD")
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True, w=True)
        _enable_sv39(dbg.hart)
        dbg.cmd_vmem(hex(VA_DATA), "8")
        out = buf.getvalue()
        assert f"VA 0x{VA_DATA:016x} -> PA 0x{DATA_PA:016x}" in out
        assert "41 42 43 44" in out

    def test_unresolvable_address_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_vmem("nowhere")
        assert "无法解析地址" in buf.getvalue()

    def test_size_out_of_range_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_vmem(hex(VA_DATA), "0")
        assert "1-4096" in buf.getvalue()

    def test_address_beyond_rv64_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg._image = _fw_image(symbols={"huge": 0xFFFF_FFFF_FFFF_FFF0})
        dbg._load_offset = 0x20
        dbg.cmd_vmem("huge")
        assert "超出 RV64 范围" in buf.getvalue()

    def test_bare_mode_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        dbg.cmd_vmem(hex(DATA_PA), "8")
        assert "Bare 模式" in buf.getvalue()

    def test_pa_to_va_reverse_lookup_restores_virtual_address(self):
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"ABCD")
        _map_page(emu.bus, VA_DATA, DATA_PA, r=True)
        _enable_sv39(dbg.hart)
        dbg._pa_to_va = {DATA_PA: VA_DATA}
        dbg.cmd_vmem(hex(DATA_PA), "4")
        assert f"PA 0x{DATA_PA:016x}" in buf.getvalue()

    def test_missing_memory_backend_reports_error(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        dbg.hart.mem_read_phy = None
        dbg.cmd_vmem(hex(VA_DATA), "8")
        assert "内存后端未挂载" in buf.getvalue()

    def test_unmapped_va_reports_page_fault(self):
        dbg, _, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        _enable_sv39(dbg.hart)
        dbg.cmd_vmem(hex(VA_DATA), "8")
        assert "页表翻译失败" in buf.getvalue()

    def test_x_only_page_is_displayed_after_successful_walk(self):
        """页表遍历通过后即显示内容, 只可执行的页面同样按物理地址读出."""
        dbg, emu, buf = make_test_dbg_buffered(
            prog_cnt=CODE_PA, is_code_loaded=False
        )
        emu.bus.write(DATA_PA, b"\xde\xad\xbe\xef\x01\x02\x03\x04")
        _map_page(emu.bus, VA_DATA, DATA_PA, x=True)
        _enable_sv39(dbg.hart)
        dbg.cmd_vmem(hex(VA_DATA), "8")
        out = buf.getvalue()
        assert "翻译后物理读取失败" not in out
        assert "de ad be ef 01 02 03 04" in out


class TestDisasmCompressed:
    """反汇编压缩指令检测."""

    def test_compressed_detected(self):
        """压缩指令 (低 2 位 ≠ 3) 应被正确识别.

        _fetch_and_disasm 总是读取 4 字节; raw_hex 显示指令十六进制值,
        压缩指令 4 位/32-bit 8 位, 带 [dim] 灰色标记.
        """
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        # C.NOP = 0x0001 (16-bit 压缩指令)
        c_nop = b"\x01\x00"
        dbg._emu.load_code(TEST_PROG_PA, c_nop)
        result = dbg._fetch_and_disasm(TEST_PROG_PA)
        assert result is not None
        raw_hex, asm = result
        # 反汇编结果: 压缩指令显示 4 位十六进制指令值
        assert raw_hex == "0001", f"压缩指令 hex 应为 0001, 实际: {raw_hex}"

    def test_compressed_raw_hex_masked_to_16bit(self):
        """压缩指令 raw_hex 应掩码到低 16 位, 不混入后续指令字节.

        当 4 字节读取包含压缩指令 + 后续指令字节时,
        raw_hex 应只显示压缩指令的 2 字节 (4 hex digits).
        例如 c.addi16sp (0x7159) 后跟 c.sdsp (0xf486),
        4 字节为 0xf4867159, raw_hex 应为 "7159" 而非 "f4867159".
        """
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        # C.ADDI16SP sp, -112 编码 0x7159 后跟 C.SDSP x1, 104(sp) 编码 0xf486
        # 4 字节 little-endian: 59 71 86 f4 -> int = 0xf4867159
        code = b"\x59\x71\x86\xf4"
        dbg._emu.load_code(TEST_PROG_PA, code)
        result = dbg._fetch_and_disasm(TEST_PROG_PA)
        assert result is not None
        raw_hex, asm = result
        assert len(raw_hex) == 4, (
            f"压缩指令 hex 应为 4 位, 实际 {len(raw_hex)} 位: {raw_hex}"
        )
        assert raw_hex == "7159", f"应为 7159 (仅 C.ADDI16SP), 实际: {raw_hex}"
        assert "c.addi16sp" in asm.lower(), f"应为 C.ADDI16SP, 实际: {asm}"

    def test_32bit_raw_hex_unmasked_8_digits(self):
        """32-bit 指令 raw_hex 应显示完整 8 位十六进制."""
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA)
        # ADDI x2, x2, -112 (32-bit) = 0xf9010113
        code = b"\x13\x01\x01\xf9"
        dbg._emu.load_code(TEST_PROG_PA, code)
        result = dbg._fetch_and_disasm(TEST_PROG_PA)
        assert result is not None
        raw_hex, _ = result
        assert len(raw_hex) == 8, (
            f"32-bit 指令 hex 应为 8 位, 实际 {len(raw_hex)} 位: {raw_hex}"
        )
        assert raw_hex == "f9010113", f"应为 f9010113, 实际: {raw_hex}"


class TestParseTrapSaveOffsets:
    """测试 _parse_trap_save_offsets 对 c.sdsp 指令的识别.

    使用等价压缩/未压缩指令, 验证两者产生相同的 RA/FP 偏移.
    """

    @staticmethod
    def _encode_sd(rs2: int, rs1: int, imm: int) -> int:
        imm_4_0 = imm & 0x1F
        imm_11_5 = (imm >> 5) & 0x7F
        return (
            (imm_11_5 << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (0x3 << 12)
            | (imm_4_0 << 7)
            | 0x23
        )

    @staticmethod
    def _encode_c_sdsp(rs2: int, uimm: int) -> int:
        assert uimm % 8 == 0 and uimm < 512
        uimm5_3 = (uimm >> 3) & 0x7
        uimm8_6 = (uimm >> 6) & 0x7
        return (0x7 << 13) | (uimm5_3 << 10) | (uimm8_6 << 7) | (rs2 << 2) | 0x2

    @staticmethod
    def _make_tvec_dbg(raw_bytes: bytes):
        tvec = TEST_PROG_PA
        dbg = make_test_dbg(prog_cnt=TEST_PROG_PA, is_code_loaded=False)
        dbg._emu.load_code(tvec, raw_bytes)
        return dbg, tvec

    # ---- c.sdsp 测试 ----

    def test_c_sdsp_ra_only(self):
        """c.sdsp x1, 8(sp) -> (8, 0)"""
        code = self._encode_c_sdsp(1, 8).to_bytes(2, "little")
        dbg, tvec = self._make_tvec_dbg(code)
        result = dbg._parse_trap_save_offsets(tvec)
        assert result == (8, 0), f"expected (8, 0), got {result}"

    def test_c_sdsp_fp_only_returns_none(self):
        """仅保存 fp 无 ra -> None"""
        code = self._encode_c_sdsp(8, 64).to_bytes(2, "little")
        dbg, tvec = self._make_tvec_dbg(code)
        result = dbg._parse_trap_save_offsets(tvec)
        assert result is None, f"fp-only should return None, got {result}"

    def test_c_sdsp_both_ra_and_fp(self):
        """c.sdsp x1,8(sp) + c.sdsp x8,64(sp) -> (8, 64)"""
        code = self._encode_c_sdsp(1, 8).to_bytes(2, "little") + (
            self._encode_c_sdsp(8, 64).to_bytes(2, "little")
        )
        dbg, tvec = self._make_tvec_dbg(code)
        result = dbg._parse_trap_save_offsets(tvec)
        assert result == (8, 64), f"expected (8, 64), got {result}"

    def test_c_sdsp_fp_first_then_ra(self):
        """先保存 fp 后 ra 的顺序也应正确识别"""
        code = self._encode_c_sdsp(8, 64).to_bytes(2, "little") + (
            self._encode_c_sdsp(1, 8).to_bytes(2, "little")
        )
        dbg, tvec = self._make_tvec_dbg(code)
        result = dbg._parse_trap_save_offsets(tvec)
        assert result == (8, 64), f"expected (8, 64), got {result}"

    # ---- 32-bit sd 测试 ----

    def test_sd_ra_only(self):
        """sd x1, 8(sp) -> (8, 0)"""
        code = self._encode_sd(1, 2, 8).to_bytes(4, "little")
        dbg, tvec = self._make_tvec_dbg(code)
        result = dbg._parse_trap_save_offsets(tvec)
        assert result == (8, 0), f"expected (8, 0), got {result}"

    def test_sd_fp_only_returns_none(self):
        """sd x8, 64(sp) 但无 ra -> None"""
        code = self._encode_sd(8, 2, 64).to_bytes(4, "little")
        dbg, tvec = self._make_tvec_dbg(code)
        result = dbg._parse_trap_save_offsets(tvec)
        assert result is None, f"fp-only should return None, got {result}"

    def test_sd_both_ra_and_fp(self):
        """sd x1,8(sp) + sd x8,64(sp) -> (8, 64)"""
        code = self._encode_sd(1, 2, 8).to_bytes(4, "little") + self._encode_sd(
            8, 2, 64
        ).to_bytes(4, "little")
        dbg, tvec = self._make_tvec_dbg(code)
        result = dbg._parse_trap_save_offsets(tvec)
        assert result == (8, 64), f"expected (8, 64), got {result}"

    # ---- 等价性: 压缩 vs 未压缩 ----

    def test_equivalent_ra_offset(self):
        """c.sdsp 和 sd 对 ra 产生相同偏移"""
        c_code = self._encode_c_sdsp(1, 8).to_bytes(2, "little")
        sd_code = self._encode_sd(1, 2, 8).to_bytes(4, "little")

        dbg_c, tv_c = self._make_tvec_dbg(c_code)
        dbg_sd, tv_sd = self._make_tvec_dbg(sd_code)

        assert dbg_c._parse_trap_save_offsets(tv_c) == (
            dbg_sd._parse_trap_save_offsets(tv_sd)
        )

    def test_equivalent_fp_offset(self):
        """c.sdsp 和 sd 对 fp 产生相同偏移 (需同时有 ra)"""
        c_code = self._encode_c_sdsp(1, 8).to_bytes(2, "little") + (
            self._encode_c_sdsp(8, 64).to_bytes(2, "little")
        )
        sd_code = self._encode_sd(1, 2, 8).to_bytes(4, "little") + (
            self._encode_sd(8, 2, 64).to_bytes(4, "little")
        )

        dbg_c, tv_c = self._make_tvec_dbg(c_code)
        dbg_sd, tv_sd = self._make_tvec_dbg(sd_code)

        assert dbg_c._parse_trap_save_offsets(tv_c) == (
            dbg_sd._parse_trap_save_offsets(tv_sd)
        )

    # ---- 边界 ----

    def test_empty_tvec_returns_none(self):
        """空 trap entry -> None"""
        dbg, tvec = self._make_tvec_dbg(b"\x00\x00\x00\x00")
        result = dbg._parse_trap_save_offsets(tvec)
        assert result is None, f"empty entry should return None, got {result}"

    def test_max_instrs_bound(self):
        """max_instrs 限制查找范围"""
        c_ra = self._encode_c_sdsp(1, 8).to_bytes(2, "little")
        # 填充足够多的 NOP 使 c.sdsp 位于 max_instrs 范围外
        padding = b"\x01\x00" * 10  # c.nop × 10
        code = padding + c_ra
        dbg, tvec = self._make_tvec_dbg(code)
        # max_instrs=5, 每条压缩指令 2 字节, 最多读 10 字节
        # padding 10×2=20 字节, ra 在第 20 字节之后 -> 找不到
        result = dbg._parse_trap_save_offsets(tvec, max_instrs=5)
        assert result is None, (
            f"ra beyond max_instrs should return None, got {result}"
        )
