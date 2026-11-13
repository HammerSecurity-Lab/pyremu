#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctypes struct definitions mirroring Rust ``#[repr(C)]`` layouts.

Separated from ``__init__.py`` to keep the loader thin.  Domain modules
(``pyremu.core.decoder``, ``pyremu.memory.mmu``, etc.) import these types
from ``pyremu._native`` just like the FFI wrapper functions.
"""

import ctypes

from pyremu.configs_gen import TLB_ENTRIES

#  Instruction decode


class DecodedFields(ctypes.Structure):
    """All standard RISC-V instruction fields extracted in a single pass.

    Field order mirrors ``decode::DecodedFields`` in Rust (64-byte aligned).
    """

    _fields_ = [
        ("imm12_se", ctypes.c_uint64),
        ("imm_s", ctypes.c_uint64),
        ("imm_b", ctypes.c_uint64),
        ("imm_j", ctypes.c_uint64),
        ("imm20_raw", ctypes.c_uint64),
        ("func12", ctypes.c_uint16),
        ("opcode", ctypes.c_uint8),
        ("rd", ctypes.c_uint8),
        ("func3", ctypes.c_uint8),
        ("rs1", ctypes.c_uint8),
        ("rs2", ctypes.c_uint8),
        ("func7", ctypes.c_uint8),
        ("is_compressed", ctypes.c_uint8),
        ("rs3", ctypes.c_uint8),
        ("fmt", ctypes.c_uint8),
    ]


class CompressedFields(ctypes.Structure):
    """All 16-bit compressed instruction fields, decoded in one pass.

    Field order mirrors ``decode::CompressedFields`` in Rust.
    """

    _fields_ = [
        ("imm", ctypes.c_uint64),
        ("imm2", ctypes.c_uint64),
        ("quadrant", ctypes.c_uint8),
        ("funct3", ctypes.c_uint8),
        ("rd", ctypes.c_uint8),
        ("rs1", ctypes.c_uint8),
        ("rs2", ctypes.c_uint8),
        ("rdp", ctypes.c_uint8),
        ("rs1p", ctypes.c_uint8),
        ("sf", ctypes.c_uint8),
        ("bit12", ctypes.c_uint8),
        ("bit65", ctypes.c_uint8),
    ]


#  ALU


class Alu64(ctypes.Structure):
    """ALU result with trap flag (0=ok, 1=invalid encoding -> IllInstr)."""

    _fields_ = [
        ("value", ctypes.c_uint64),
        ("trap", ctypes.c_uint8),
    ]


class FpOut(ctypes.Structure):
    """浮点运算结果 — mirrors Rust ``fpu::FpOut``.

    value: 结果 bits (FPR NaN-boxed / GPR 整数/布尔/分类掩码).
    fflags: 累积异常标志 (RISC-V fflags 位序).
    to_gpr: 1 = 写 rd 的 GPR, 0 = 写 rd 的 FPR.
    trap: 1 = 非法编码 -> IllInstr.
    """

    _fields_ = [
        ("value", ctypes.c_uint64),
        ("fflags", ctypes.c_uint8),
        ("to_gpr", ctypes.c_uint8),
        ("trap", ctypes.c_uint8),
    ]


#  Sv39 MMU


class Sv39Vpn(ctypes.Structure):
    """Decomposed Sv39 virtual address (VPN[2:0] + page offset)."""

    _fields_ = [
        ("vpn2", ctypes.c_uint64),
        ("vpn1", ctypes.c_uint64),
        ("vpn0", ctypes.c_uint64),
        ("offset", ctypes.c_uint64),
    ]


class PteFields(ctypes.Structure):
    """Parsed Sv39 page-table entry fields."""

    _fields_ = [
        ("ppn", ctypes.c_uint64),
        ("perm", ctypes.c_uint8),
        ("v", ctypes.c_uint8),
        ("is_leaf", ctypes.c_uint8),
        ("is_ptr", ctypes.c_uint8),
    ]


#  Hart state


class TlbEntry(ctypes.Structure):
    """TLB 条目, 字段与 Rust ``state::TlbEntry`` 一致."""

    _fields_ = [
        ("vpn", ctypes.c_uint64),
        ("ppn", ctypes.c_uint64),
        ("perm", ctypes.c_uint8),
        ("level", ctypes.c_uint8),
        ("valid", ctypes.c_uint8),
        ("mdid", ctypes.c_uint64),
        ("tlb_epoch", ctypes.c_uint32),
        ("dirty", ctypes.c_uint8),
        ("accessed", ctypes.c_uint8),
        ("asid", ctypes.c_uint16),
    ]


class ImsicFileC(ctypes.Structure):
    """该 hart 的一个 IMSIC 中断文件, 字段与 Rust ``ImsicFile`` 一致."""

    _fields_ = [
        ("eip", ctypes.c_uint32 * 64),
        ("eie", ctypes.c_uint32 * 64),
        ("eidelivery", ctypes.c_uint8),
        ("eithreshold", ctypes.c_uint8),
        ("select", ctypes.c_uint32),
        ("present", ctypes.c_uint8),
        ("eip_ext_any", ctypes.c_uint8),
    ]


class IsaExtsC(ctypes.Structure):
    """该 hart 声明的扩展开关, 字段与 Rust ``state::IsaExts`` 一致.

    每项一个布尔字段, 字段名与顺序必须与 Rust 侧相同;
    取值来源见 ``pyremu.utils.isa.encode_isa_exts``.
    """

    _fields_ = [
        ("is_i", ctypes.c_bool),
        ("is_m", ctypes.c_bool),
        ("is_a", ctypes.c_bool),
        ("is_f", ctypes.c_bool),
        ("is_d", ctypes.c_bool),
        ("is_c", ctypes.c_bool),
        ("is_b", ctypes.c_bool),
        ("is_h", ctypes.c_bool),
        ("is_v", ctypes.c_bool),
        ("is_zicsr", ctypes.c_bool),
        ("is_zifencei", ctypes.c_bool),
        ("is_zbb", ctypes.c_bool),
        ("is_zba", ctypes.c_bool),
        ("is_zbs", ctypes.c_bool),
        ("is_zfh", ctypes.c_bool),
        ("is_zihpm", ctypes.c_bool),
        ("is_zicntr", ctypes.c_bool),
        ("is_sstc", ctypes.c_bool),
        ("is_smaia", ctypes.c_bool),
        ("is_ssaia", ctypes.c_bool),
        ("is_smepmp", ctypes.c_bool),
    ]


class HartState(ctypes.Structure):
    """一个 hart 交给加速执行引擎的状态.

    字段顺序与类型必须与 Rust ``state::HartState`` 一致.
    """

    _fields_ = [
        # 通用整数寄存器: 32 个 u64
        ("gprs", ctypes.c_uint64 * 32),
        # 引擎用到的 CSR (u64)
        ("mstatus", ctypes.c_uint64),
        ("mtvec", ctypes.c_uint64),
        ("stvec", ctypes.c_uint64),
        ("mepc", ctypes.c_uint64),
        ("sepc", ctypes.c_uint64),
        ("mcause", ctypes.c_uint64),
        ("scause", ctypes.c_uint64),
        ("mtval", ctypes.c_uint64),
        ("stval", ctypes.c_uint64),
        ("satp", ctypes.c_uint64),
        ("mie", ctypes.c_uint64),
        ("mip", ctypes.c_uint64),
        ("medeleg", ctypes.c_uint64),
        ("mideleg", ctypes.c_uint64),
        ("pc", ctypes.c_uint64),
        ("reservation_addr", ctypes.c_uint64),
        ("reservation_value", ctypes.c_uint64),
        # 单字节字段, 紧随 u64 字段
        ("reservation_valid", ctypes.c_uint8),
        ("mode", ctypes.c_uint8),
        ("mmu_mode", ctypes.c_uint8),
        ("waiting", ctypes.c_uint8),
        ("wfi_woken", ctypes.c_uint8),
        ("halted", ctypes.c_uint8),
        # mdid 为完整的 64 位, 按 u64 对齐后偏移为 8, 字节块同时由 16 字节增至
        # 24 字节
        ("mdid", ctypes.c_uint64),
        ("pmpsplit", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 7),
        ("itlb", TlbEntry * int(TLB_ENTRIES)),
        ("dtlb", TlbEntry * int(TLB_ENTRIES)),
        ("mscratch", ctypes.c_uint64),
        ("sscratch", ctypes.c_uint64),
        ("mhartid", ctypes.c_uint64),
        ("mcounteren", ctypes.c_uint64),
        ("scounteren", ctypes.c_uint64),
        ("stimecmp", ctypes.c_uint64),
        ("_mmu_mode_pad", ctypes.c_uint64),
        ("total_instrs", ctypes.c_uint64),
        ("fprs", ctypes.c_uint64 * 32),
        ("fcsr", ctypes.c_uint32),
        ("_fpad", ctypes.c_uint8 * 4),
        ("imsic_m", ImsicFileC),
        ("imsic_s", ImsicFileC),
        # 该 hart 的定时器截止点, 写入 timecmp 时在本 hart 的指令计数空间内固定,
        # 0 表示未设定; 见 Rust 的 write_mtimecmp、write_stimecmp 与 sync_mtip
        ("stip_deadline", ctypes.c_uint64),
        ("mtip_deadline", ctypes.c_uint64),
        # 加速执行引擎的 TLB 计数, 只由引擎累加;
        # 编组时不写入, 解组之后只读出
        ("itlb_hits", ctypes.c_uint64),
        ("itlb_misses", ctypes.c_uint64),
        ("dtlb_hits", ctypes.c_uint64),
        ("dtlb_misses", ctypes.c_uint64),
        # 本 hart 的扩展开关; 由 Python 在状态数组分配时写入一次, 引擎只读.
        # 追加在末尾, 不移动上面各字段的偏移.
        ("isa_exts", IsaExtsC),
        # 软件写入的 mip.SEIP; mip 的位 9 保存外部中断线的取值.
        # 追加在末尾, 不移动上面各字段的偏移.
        ("software_seip", ctypes.c_uint8),
    ]


class InstrToBeExec(ctypes.Structure):
    """一次加速执行结束时的结果, 说明本次退出的原因."""

    _fields_ = [
        ("total_instrs", ctypes.c_uint64),
        ("exit_reason", ctypes.c_uint8),
        ("exit_hart_id", ctypes.c_uint8),
        ("exit_pc", ctypes.c_uint64),
        ("exit_instr", ctypes.c_uint32),
        ("trap_cause", ctypes.c_uint32),
        ("trap_tval", ctypes.c_uint64),
        ("trap_is_interrupt", ctypes.c_uint8),
        ("trap_delegated", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 6),
    ]
