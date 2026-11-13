#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""mem_check_aux 的分支行为.

覆盖 counteren 计数器门控、PTE 权限判定、有效特权级的计算、页表遍历被 PMP 拒绝时
投递的故障类型、TLB 命中后的权限复核、跨页访问的分段与取指翻译的失败路径.
"""

import pytest

from pyremu.core.hart import HartWithRegs, RatifiedHartAttrs, RiscvMode
from pyremu.core.mem_check_aux import (
    AccessFaultError,
    PageFaultError,
)
from pyremu.core.priv_defs import (
    MSTATUS_MXR,
    MSTATUS_SUM,
)
from pyremu.core.registers import CsrAccessError
from pyremu.memory.bus import Bus
from pyremu.memory.mmu import (
    PTE_A,
    PTE_D,
    PTE_R,
    PTE_U,
    PTE_V,
    PTE_W,
    PTE_X,
    SATP_MODE_SV39,
)

RAM_BASE = 0x8000_0000
RAM_SIZE = 4 * 1024 * 1024
# 数据页所在的虚拟地址: 与页表自身占用的物理页 (RAM_BASE + 0x1000 起) 不重叠
DATA_VA = RAM_BASE + 0x10_0000
DATA_VPN0 = (DATA_VA >> 12) & 0x1FF
MTVEC = 0x8000_0100

RWX = PTE_R | PTE_W | PTE_X
# pmpcfg0: A=NAPOT (0x18) 分别与 R、R|X 组合
PMP_ALLOW_ALL = 0x1F
PMP_READ_ONLY = 0x1D
PMP_NAPOT_ALL = 0x003F_FFFF_FFFF_FFFF


def _encode_ppn(ppn: int) -> int:
    """RISC-V 连续 PPN 编码: PTE[53:10] = PPN[43:0]."""
    val = (ppn & 0x3FF) << 10
    val |= ((ppn >> 10) & 0x1FF) << 20
    val |= ((ppn >> 19) & 0x1FFF_FFFF) << 29
    return val


def _write_pte(hart: HartWithRegs, pa: int, value: int) -> None:
    assert hart.mem_write_phy is not None
    hart.mem_write_phy(pa, value.to_bytes(8, "little"))


def _install_tables(
    hart: HartWithRegs,
    leaves: dict[int, tuple[int, int]],
) -> None:
    """为 DATA_VA 所在的 2 MiB 区间安装三级页表.

    *leaves* 为 {vpn0: (物理页基址, 权限标志)}, 只写出的叶 PTE 才可翻译.
    """
    root_pa = RAM_BASE + 0x1000
    l2_pa = RAM_BASE + 0x2000
    l3_pa = RAM_BASE + 0x3000
    root_index = (DATA_VA >> 30) & 0x1FF
    l2_index = (DATA_VA >> 21) & 0x1FF
    _write_pte(hart, root_pa + root_index * 8, PTE_V | _encode_ppn(l2_pa >> 12))
    _write_pte(hart, l2_pa + l2_index * 8, PTE_V | _encode_ppn(l3_pa >> 12))
    for vpn0, (pa, flags) in leaves.items():
        value = flags | PTE_V | PTE_A | PTE_D | _encode_ppn(pa >> 12)
        _write_pte(hart, l3_pa + vpn0 * 8, value)
    hart.satp_val = (SATP_MODE_SV39 << 60) | (root_pa >> 12)


def _identity_leaves(
    page_count: int, flags: int = RWX
) -> dict[int, tuple[int, int]]:
    """从 DATA_VA 起 identity 映射 *page_count* 个 4 KiB 页."""
    return {
        DATA_VPN0 + i: (DATA_VA + i * 0x1000, flags) for i in range(page_count)
    }


def _make_hart(
    bus: Bus, mode: RiscvMode = RiscvMode.S, pmpcfg: int = PMP_ALLOW_ALL
):
    hart = HartWithRegs(id=0)
    hart.mem_read_phy = bus.read
    hart.mem_write_phy = bus.write
    hart.bus = bus
    hart.mode = mode
    hart.pc = MTVEC
    hart.csrs["mtvec"].val = MTVEC
    hart.csrs["pmpcfg0"].val = pmpcfg
    hart.csrs["pmpaddr0"].val = PMP_NAPOT_ALL
    return hart


@pytest.fixture
def bus() -> Bus:
    return Bus(ram_size=RAM_SIZE, ram_base=RAM_BASE)


@pytest.fixture
def hart(bus: Bus) -> HartWithRegs:
    return _make_hart(bus)


# ============================================================
#  counteren 计数器门控
# ============================================================


class TestCounterEnable:
    def test_counter_high_half_illegal_on_rv64(self, hart):
        """0xC80-0xC9F 的高半计数器在 RV64 上不存在, 访问触发 IllInstr."""
        hart.mode = RiscvMode.S
        hart.csrs["mcounteren"].val = 1
        with pytest.raises(CsrAccessError):
            hart.validate_csr(0xC80)
        hart.validate_csr(0xC00)

    def test_mmode_counter_read_ignores_counteren(self, hart):
        """M 模式读取计数器不受 mcounteren 约束."""
        hart.mode = RiscvMode.M
        hart.csrs["mcounteren"].val = 0
        hart.validate_csr(0xC00)

    def test_umode_requires_both_counteren_bits(self, hart):
        """U 模式要求 mcounteren 与 scounteren 的同一位同时置位."""
        hart.mode = RiscvMode.U
        hart.csrs["mcounteren"].val = 1
        with pytest.raises(CsrAccessError):
            hart.validate_csr(0xC00)

        hart.csrs["scounteren"].val = 1
        hart.validate_csr(0xC00)


# ============================================================
#  PTE 权限判定
# ============================================================


class TestPtePermissions:
    def test_umode_rejects_page_without_u_bit(self, hart):
        _install_tables(hart, _identity_leaves(1))
        hart.mode = RiscvMode.U
        ok, _ = hart.translate_addr(DATA_VA)
        assert not ok

    def test_smode_fetch_from_user_page_faults(self, hart):
        """S 模式从 U=1 页取指一律失败, 与 SUM 无关."""
        _install_tables(hart, _identity_leaves(1, RWX | PTE_U))
        hart.mstatus_val = MSTATUS_SUM
        ok, _ = hart.check_instruction_fetch(DATA_VA)
        assert not ok
        assert hart.mcause_val == 12
        assert hart.mtval_val == DATA_VA

    def test_smode_data_access_to_user_page_follows_sum(self, hart):
        _install_tables(hart, _identity_leaves(1, RWX | PTE_U))
        hart.mstatus_val = 0
        assert not hart.translate_addr(DATA_VA)[0]

        hart.mstatus_val = MSTATUS_SUM
        assert hart.translate_addr(DATA_VA)[0]

    def test_mxr_allows_reading_execute_only_page(self, hart):
        _install_tables(hart, _identity_leaves(1, PTE_X))
        hart.mstatus_val = 0
        assert not hart.translate_addr(DATA_VA)[0]

        hart.mstatus_val = MSTATUS_MXR
        assert hart.translate_addr(DATA_VA)[0]

    def test_write_requires_r_and_w(self, hart):
        _install_tables(hart, _identity_leaves(1, PTE_R))
        assert not hart.translate_addr(DATA_VA, is_write=True)[0]


# ============================================================
#  有效特权级 (MPRV / D 模式)
# ============================================================


class TestEffectiveMode:
    def test_debug_mode_bypasses_translation(self, hart):
        _install_tables(hart, _identity_leaves(1))
        hart.mode = RiscvMode.D
        ok, pa = hart.translate_addr(DATA_VA)
        assert ok and pa == DATA_VA

    def test_mprv_with_supervisor_mpp_translates(self, hart):
        mapped_pa = RAM_BASE + 0x20_0000
        _install_tables(hart, {DATA_VPN0: (mapped_pa, RWX)})
        hart.mode = RiscvMode.M
        hart.mstatus_val = (1 << 17) | (RiscvMode.S.value << 11)
        ok, pa = hart.translate_addr(DATA_VA)
        assert ok and pa == mapped_pa

    def test_mprv_with_machine_mpp_bypasses_translation(self, hart):
        _install_tables(hart, _identity_leaves(1))
        hart.mode = RiscvMode.M
        hart.mstatus_val = (1 << 17) | (RiscvMode.M.value << 11)
        ok, pa = hart.translate_addr(DATA_VA)
        assert ok and pa == DATA_VA


# ============================================================
#  页表遍历被 PMP 拒绝
# ============================================================


class TestPageWalkDenied:
    def test_load_reports_load_access_fault(self, bus):
        hart = _make_hart(bus, pmpcfg=0)
        _install_tables(hart, _identity_leaves(1))
        with pytest.raises(AccessFaultError):
            hart.mem_read(DATA_VA, 8)
        assert hart.mcause_val == 5
        assert hart.mtval_val == DATA_VA

    def test_store_reports_store_access_fault(self, bus):
        hart = _make_hart(bus, pmpcfg=0)
        _install_tables(hart, _identity_leaves(1))
        with pytest.raises(AccessFaultError):
            hart.mem_write(DATA_VA, bytes(8))
        assert hart.mcause_val == 7
        assert hart.mtval_val == DATA_VA

    def test_fetch_reports_instruction_access_fault(self, bus):
        hart = _make_hart(bus, pmpcfg=0)
        _install_tables(hart, _identity_leaves(1))
        ok, pa = hart.check_instruction_fetch(DATA_VA)
        assert not ok and pa == 0
        assert hart.mcause_val == 1
        assert hart.mtval_val == DATA_VA

    def test_accessed_write_denied_reports_load_access_fault(self, bus):
        """页表读取获准而 A 位置位写入被拒绝时, 按原访问类型投递访问故障.

        只读 PMP 条目放行页表页的读取, 拒绝遍历期间对页表页的写入; 根页表项
        尚未置位 A 位, 置位动作被拒绝后读取访问按 LdAccessFault 终止.
        """
        hart = _make_hart(bus, pmpcfg=PMP_READ_ONLY)
        _install_tables(hart, _identity_leaves(1))
        with pytest.raises(AccessFaultError):
            hart.mem_read(DATA_VA, 8)
        assert hart.mcause_val == 5
        assert hart.mtval_val == DATA_VA


class TestAccessedDirtyBits:
    """hart 级访存后页表项的 A 位与 D 位."""

    def test_load_sets_accessed_on_pointer_levels(self, bus, hart):
        """一次读取访问使根页表与二级页表项带上 A 位."""
        _install_tables(hart, _identity_leaves(1))
        root_pte = RAM_BASE + 0x1000 + ((DATA_VA >> 30) & 0x1FF) * 8
        before = int.from_bytes(hart.mem_read_phy(root_pte, 8), "little")
        assert not before & PTE_A

        hart.mem_read(DATA_VA, 8)

        after = int.from_bytes(hart.mem_read_phy(root_pte, 8), "little")
        assert after & PTE_A, "页表遍历后根页表项应置位 A 位"

    def test_store_sets_dirty_on_leaf(self, bus, hart):
        """写访问在叶子页表项上置位 D 位."""
        leaves = _identity_leaves(1)
        _install_tables(hart, leaves)
        leaf_pa = RAM_BASE + 0x3000 + DATA_VPN0 * 8
        raw = int.from_bytes(hart.mem_read_phy(leaf_pa, 8), "little")
        hart.mem_write_phy(leaf_pa, (raw & ~PTE_D).to_bytes(8, "little"))

        hart.mem_write(DATA_VA, bytes(8))

        after = int.from_bytes(hart.mem_read_phy(leaf_pa, 8), "little")
        assert after & PTE_D, "写访问后叶子页表项应置位 D 位"


# ============================================================
#  TLB 命中与缺少物理内存后端
# ============================================================


class TestTranslateEdges:
    def test_tlb_hit_without_write_permission_fails(self, hart):
        """TLB 命中后按本次访问重新校验权限, 只读条目拒绝写入."""
        _install_tables(hart, _identity_leaves(1))
        hart.dtlb.insert(DATA_VA >> 12, DATA_VA >> 12, perm=PTE_R)
        ok, pa = hart.translate_addr(DATA_VA, is_write=True)
        assert not ok and pa == 0

    def test_debugger_translation_without_backend_fails(self):
        """调试器路径不做 PMP 检查, 但没有物理读回调时仍无法遍历页表."""
        hart = HartWithRegs(id=0)
        hart.mode = RiscvMode.S
        hart.satp_val = (SATP_MODE_SV39 << 60) | ((RAM_BASE + 0x1000) >> 12)
        ok, pa = hart.translate_addr(DATA_VA, is_hart_access=False)
        assert not ok and pa == 0

    def test_read_without_backend_raises_not_implemented(self):
        hart = HartWithRegs(id=0)
        with pytest.raises(NotImplementedError):
            hart.mem_read(RAM_BASE, 8)

    def test_write_without_backend_raises_not_implemented(self):
        hart = HartWithRegs(id=0)
        with pytest.raises(NotImplementedError):
            hart.mem_write(RAM_BASE, bytes(8))

    def test_fetch_without_backend_reports_page_fault(self):
        hart = HartWithRegs(id=0)
        hart.mode = RiscvMode.S
        hart.csrs["mtvec"].val = MTVEC
        hart.satp_val = (SATP_MODE_SV39 << 60) | ((RAM_BASE + 0x1000) >> 12)
        ok, pa = hart.check_instruction_fetch(DATA_VA)
        assert not ok and pa == 0
        assert hart.mcause_val == 12
        assert hart.mtval_val == DATA_VA

    def test_fetch_with_invalid_pte_reports_page_fault(self, bus):
        hart = _make_hart(bus)
        hart.satp_val = (SATP_MODE_SV39 << 60) | ((RAM_BASE + 0x1000) >> 12)
        ok, pa = hart.check_instruction_fetch(DATA_VA)
        assert not ok and pa == 0
        assert hart.mcause_val == 12
        assert hart.mtval_val == DATA_VA


# ============================================================
#  跨页访问
# ============================================================


class TestCrossPage:
    def test_read_over_two_pages_concatenates_halves(self, bus, hart):
        _install_tables(hart, _identity_leaves(2))
        payload = bytes((i * 7) & 0xFF for i in range(0x2000))
        assert bus.try_write(DATA_VA, payload)
        assert hart.mem_read(DATA_VA, 0x2000) == payload

    def test_write_over_two_pages_splits_halves(self, bus, hart):
        _install_tables(hart, _identity_leaves(2))
        payload = bytes((i * 11) & 0xFF for i in range(0x2000))
        hart.mem_write(DATA_VA, payload)
        assert bus.try_read(DATA_VA, 0x2000) == payload

    def test_load_across_unmapped_page_reports_page_fault(self, bus, hart):
        _install_tables(hart, _identity_leaves(1))
        with pytest.raises(PageFaultError):
            hart.mem_read(DATA_VA, 0x2000)
        assert hart.mcause_val == 13
        assert hart.mtval_val == DATA_VA + 0x1000

    def test_store_across_unmapped_page_reports_page_fault(self, bus, hart):
        _install_tables(hart, _identity_leaves(1))
        with pytest.raises(PageFaultError):
            hart.mem_write(DATA_VA, bytes(0x2000))
        assert hart.mcause_val == 15
        assert hart.mtval_val == DATA_VA + 0x1000

    def test_store_across_read_only_pmp_reports_access_fault(self, bus):
        """存取权限按请求方向判定: 只读条目允许页表遍历, 拒绝写入."""
        hart = _make_hart(bus, pmpcfg=PMP_READ_ONLY)
        _install_tables(hart, _identity_leaves(2))
        with pytest.raises(AccessFaultError):
            hart.mem_write(DATA_VA, bytes(0x2000))
        assert hart.mcause_val == 7
        assert hart.mtval_val == DATA_VA

    def test_second_page_outside_ram_reports_access_fault(self, bus, hart):
        leaves = _identity_leaves(2)
        leaves[DATA_VPN0 + 1] = (0x9000_0000, RWX)
        _install_tables(hart, leaves)
        with pytest.raises(AccessFaultError):
            hart.mem_read(DATA_VA, 0x2000)
        assert hart.mcause_val == 5
        assert hart.mtval_val == DATA_VA


# ============================================================
#  Sstc 扩展的 CSR 存在性
# ============================================================


STIMECMP = 0x14D
STIMECMPH = 0x15D
STVEC = 0x105


def _make_hart_without_sstc(bus: Bus) -> HartWithRegs:
    """S 模式 hart, 平台声明的扩展集合不含 sstc."""
    hart = _make_hart(bus)
    hart.ratified_hart_attrs = RatifiedHartAttrs(
        isa_exts={"i": True, "m": True, "a": True, "c": True}
    )
    return hart


class TestSstcCsrExistence:
    def test_stimecmp_read_traps_without_sstc(self, bus):
        hart = _make_hart_without_sstc(bus)
        with pytest.raises(CsrAccessError):
            hart.validate_csr(STIMECMP, is_write=False)

    def test_stimecmp_write_traps_without_sstc(self, bus):
        hart = _make_hart_without_sstc(bus)
        with pytest.raises(CsrAccessError):
            hart.validate_csr(STIMECMP, is_write=True)

    def test_stimecmph_read_traps_without_sstc(self, bus):
        hart = _make_hart_without_sstc(bus)
        with pytest.raises(CsrAccessError):
            hart.validate_csr(STIMECMPH, is_write=False)

    def test_stimecmp_accessible_with_sstc(self, bus):
        """平台声明 sstc 时 stimecmp 可读可写."""
        hart = _make_hart(bus)
        hart.validate_csr(STIMECMP, is_write=False)
        hart.validate_csr(STIMECMP, is_write=True)

    def test_stimecmph_illegal_on_rv64(self, bus):
        """stimecmph 仅在 RV32 上存在, RV64 上访问触发 IllInstr."""
        hart = _make_hart(bus)
        with pytest.raises(CsrAccessError):
            hart.validate_csr(STIMECMPH, is_write=False)

    def test_other_scsr_unaffected_without_sstc(self, bus):
        """未被 sstc 门控的 S 模式 CSR 仍可读写."""
        hart = _make_hart_without_sstc(bus)
        hart.validate_csr(STVEC, is_write=True)
