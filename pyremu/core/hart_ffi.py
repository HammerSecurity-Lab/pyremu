#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""hart 与加速执行引擎之间的状态编组.

结构体定义在 ``pyremu._native._ctypes`` 中. 本模块的方法以 hart 自身为接收者,
由 ``HartWithRegs`` 组合进来.
"""

from __future__ import annotations

import ctypes
import struct

from pyremu._native import HartState
from pyremu.core.priv_defs import RiscvMode

# 线格式中的 u8 特权级取值到 RiscvMode 的映射.
_MODE_FROM_U8: dict[int, RiscvMode] = {
    0: RiscvMode.U,
    1: RiscvMode.S,
    2: RiscvMode.H,
    3: RiscvMode.M,
}

# IMSIC 的 eip 与 eie 各为 64 个 u32 字, 两处列表按小端序整体编组到 HartState.
_IMSIC_PACK_FORMAT = "<64I"
_IMSIC_PACK_BYTES = 64 * 4
# 第 0 个字中对应 S 模式与 M 模式软件中断的位, 不属于外部中断.
_IMSIC_IPI_WORD0_MASK = (1 << 1) | (1 << 3)


def _has_ext_interrupt(eip: list[int]) -> int:
    """判定 eip 中是否有中断编号不小于 6 的位."""
    if eip[0] & ~_IMSIC_IPI_WORD0_MASK:
        return 1
    return 1 if any(eip[1:]) else 0


def _merge_eip(
    engine_words: tuple[int, ...],
    before: bytes | None,
    current: list[int],
) -> list[int]:
    """合并引擎写回的 eip 与设备线程在单轮执行期间置位的位.

    ``before`` 为编组时刻的 eip; ``current`` 中不在 ``before`` 里的位由设备线程
    在编组之后置位, 合并结果必须保留. ``before`` 为 ``None`` 时没有可保留的位.
    """
    if before is None:
        return list(engine_words)
    before_words = struct.unpack(_IMSIC_PACK_FORMAT, before)
    return [
        e | (c & ~p) for e, c, p in zip(engine_words, current, before_words)
    ]


# 加速执行的退出原因, 取值必须与 Rust 侧一致
EXIT_NORMAL = 0
EXIT_TRAP = 1
EXIT_MMIO = 2
EXIT_ECALL = 3
EXIT_EBREAK = 4
EXIT_WFI_WAIT = 5
# 取指的目标物理地址不属于主存: 引擎只从主存读取指令字节, 本轮退出后由 Python
# 取指; 目标属于设备窗口时读取设备的存储, 属于空洞时投递访问故障
EXIT_NOT_MAINRAM = 6
EXIT_BREAKPOINT = 7
EXIT_TIMEOUT = 8
EXIT_RX_WAIT = 9


def mode_from_u8(raw: int) -> RiscvMode:
    """把线格式中的 u8 特权级取值转换为 RiscvMode, 未知取值按 M 模式处理."""
    return _MODE_FROM_U8.get(raw, RiscvMode.M)


class HartFfiOps:
    """把本 hart 的状态与 Rust ``HartState`` 互相拷贝."""

    def marshal_to(self, state: HartState) -> None:
        """把本 hart 的状态写入 Rust ``HartState``."""
        state.gprs[:] = self.gprs

        state.mstatus = self.mstatus_val
        state.mtvec = self.csrs["mtvec"].val
        state.stvec = self.csrs["stvec"].val
        state.mepc = self.mepc_val
        state.sepc = self.sepc_val
        state.mcause = self.mcause_val
        state.scause = self.scause_val
        state.mtval = self.mtval_val
        state.stval = self.stval_val
        state.satp = self.satp_val
        state.mie = self.mie_val
        # mip 的存储值只含硬件驱动的位; 软件位 SEIP 单独编组, 由引擎在读出时
        # 取或.
        state.mip = self.mip_raw_val
        state.software_seip = self._software_seip
        state.medeleg = self.csrs["medeleg"].val
        state.mideleg = self.csrs["mideleg"].val

        state.pc = self.pc
        state.mode = self.mode.value
        state.mmu_mode = self.mmu_mode

        state.reservation_valid = 1 if self.reservation_valid else 0
        state.reservation_addr = self.reservation_addr
        state.reservation_value = self._reservation_value

        state.waiting = 1 if self._waiting else 0
        state.wfi_woken = 1 if self._wfi_woken else 0
        state.halted = 1 if self._halted else 0

        state.mdid = self.mdid_val
        state.pmpsplit = self.pmpsplit_val

        state.mscratch = self.csrs["mscratch"].val
        state.sscratch = self.csrs["sscratch"].val
        state.mhartid = self.csrs["mhartid"].val
        state.mcounteren = self.csrs["mcounteren"].val
        state.scounteren = (
            self.csrs["scounteren"].val if "scounteren" in self.csrs else 0
        )
        state.stimecmp = (
            self.csrs["stimecmp"].val if "stimecmp" in self.csrs else 0
        )

        # 直接拷贝, 不经写入路径重算: 引擎的写入路径已在写入时刻固定截止点,
        # 经写入路径重算会把它置 0
        state.stip_deadline = self._stip_deadline
        state.mtip_deadline = self._mtip_deadline

        state.total_instrs = self._total_instrs

        state.fprs[:] = self.fpr_bits
        state.fcsr = self.csrs["fcsr"].val & 0xFF

        self._marshal_imsic(state)

    def unmarshal_from(self, state: HartState) -> None:
        """把 Rust ``HartState`` 写回本 hart."""
        self.gprs.assign(state.gprs[:])

        self.mstatus_val = state.mstatus
        self.csrs["mtvec"].val = state.mtvec
        self.csrs["stvec"].val = state.stvec
        self.mepc_val = state.mepc
        self.sepc_val = state.sepc
        self.mcause_val = state.mcause
        self.scause_val = state.scause
        self.mtval_val = state.mtval
        self.stval_val = state.stval
        # satp 取值与 Python 侧一致时保持指令 TLB 与数据 TLB 的既有条目;
        # 取值不同时经 satp_val 写回, 该属性写入时刷新两个 TLB.
        if state.satp != self.csrs["satp"].val:
            self.satp_val = state.satp
        self._csr_write_raw("mie", state.mie)
        self._csr_write_raw("mip", state.mip)
        self._software_seip = state.software_seip & 1
        self.csrs["medeleg"].val = state.medeleg
        self.csrs["mideleg"].val = state.mideleg

        self.pc = state.pc
        self.mode = mode_from_u8(state.mode)
        self._mmu_mode = state.mmu_mode

        self._reservation_valid = state.reservation_valid != 0
        self._reservation_addr = state.reservation_addr
        self._reservation_value = state.reservation_value

        self._waiting = state.waiting != 0
        self._wfi_woken = state.wfi_woken != 0
        self._halted = state.halted != 0

        self._mdid_val = state.mdid
        self._pmpsplit_val = state.pmpsplit

        # TLB 计数只读出, 由引擎自身累加
        self._speedup_itlb_hits = state.itlb_hits
        self._speedup_itlb_misses = state.itlb_misses
        self._speedup_dtlb_hits = state.dtlb_hits
        self._speedup_dtlb_misses = state.dtlb_misses

        self.csrs["mscratch"].val = state.mscratch
        self.csrs["sscratch"].val = state.sscratch
        self.csrs["mhartid"].val = state.mhartid
        self.csrs["mcounteren"].val = state.mcounteren
        if "scounteren" in self.csrs:
            self.csrs["scounteren"].val = state.scounteren
        self._csr_write_raw("stimecmp", state.stimecmp)

        # 与 marshal_to 对称, 保证往返之后取值不变
        self._stip_deadline = state.stip_deadline
        self._mtip_deadline = state.mtip_deadline

        self._total_instrs = state.total_instrs

        self.fpr_bits[:] = state.fprs[:]
        self.csrs["fcsr"].val = state.fcsr & 0xFF
        self.csrs["frm"].val = (state.fcsr >> 5) & 0x7
        self.csrs["fflags"].val = state.fcsr & 0x1F

        self._unmarshal_imsic(state)
        # state.isa_exts 不写回: 扩展开关取自平台声明, 引擎只读, 不产生新取值.

    def marshal_isa_exts(self, state: HartState) -> None:
        """把本 hart 的扩展开关写入 ``HartState`` 的 ``IsaExtsC``.

        扩展开关是平台的静态属性, 只在状态数组分配时写入一次; 逐轮编组不重复
        写入.
        """
        for field, val in self.ratified_hart_attrs.isa_ext_switches.items():
            setattr(state.isa_exts, field, val)

    def _marshal_imsic(self, state: HartState) -> None:
        """把本 hart 的 IMSIC 状态写入 ``HartState`` 的 IMSIC 字段."""
        imsic = self._imsic
        if imsic is None or self.id >= imsic.num_harts:
            # 该 hart 未接 IMSIC 时清 present, 使引擎的 MEIP/SEIP 清理不产生
            # 作用; ImsicFile::empty() 默认 present=1, 不清除时该步骤会在每条
            # 指令上执行, 外部中断无法排空, 守护线程置位的 eip 位会反复触发中断
            state.imsic_m.present = 0
            state.imsic_s.present = 0
            self._imsic_pre_m_eip = None
            self._imsic_pre_s_eip = None
            return
        # 持锁: 读取 eip/eie 快照与接收线程的置位互斥, 避免读到只改了一半的状态
        with imsic._lock:
            mf, sf = imsic._files[self.id]
            # 保存 eip 快照, 供 _unmarshal_imsic 识别加速期间由接收线程置位的位
            eip_m = struct.pack(_IMSIC_PACK_FORMAT, *mf.eip)
            eip_s = struct.pack(_IMSIC_PACK_FORMAT, *sf.eip)
            self._imsic_pre_m_eip = eip_m
            self._imsic_pre_s_eip = eip_s
            ctypes.memmove(state.imsic_m.eip, eip_m, _IMSIC_PACK_BYTES)
            ctypes.memmove(
                state.imsic_m.eie,
                struct.pack(_IMSIC_PACK_FORMAT, *mf.eie),
                _IMSIC_PACK_BYTES,
            )
            ctypes.memmove(state.imsic_s.eip, eip_s, _IMSIC_PACK_BYTES)
            ctypes.memmove(
                state.imsic_s.eie,
                struct.pack(_IMSIC_PACK_FORMAT, *sf.eie),
                _IMSIC_PACK_BYTES,
            )
            state.imsic_m.eidelivery = mf.eidelivery
            state.imsic_m.eithreshold = mf.eithreshold
            state.imsic_m.select = self._imsic_select_m
            state.imsic_m.present = 1
            state.imsic_m.eip_ext_any = _has_ext_interrupt(mf.eip)
            state.imsic_s.eidelivery = sf.eidelivery
            state.imsic_s.eithreshold = sf.eithreshold
            state.imsic_s.select = self._imsic_select_s
            state.imsic_s.present = 1
            state.imsic_s.eip_ext_any = _has_ext_interrupt(sf.eip)

    def _unmarshal_imsic(self, state: HartState) -> None:
        """把 ``HartState`` 的 IMSIC 字段写回本 hart 的 IMSIC.

        加速期间由接收线程置位的 eip 位保留: 这些位由 UART 接收经 APLIC 进入
        IMSIC, 引擎并不知道, 直接以引擎的取值覆盖会丢失.
        """
        imsic = self._imsic
        if imsic is None or self.id >= imsic.num_harts:
            self._imsic_select_m = state.imsic_m.select
            self._imsic_select_s = state.imsic_s.select
            return
        # 持锁: 写回 eip/eie 与接收线程的置位互斥; 不持锁时接收线程在编组到写回
        # 之间置位的位会被引擎写回的旧值覆盖, 或在计算时读到只改了一半的状态
        with imsic._lock:
            mf, sf = imsic._files[self.id]
            mf.eip[:] = _merge_eip(
                struct.unpack_from(_IMSIC_PACK_FORMAT, state.imsic_m.eip),
                self._imsic_pre_m_eip,
                mf.eip,
            )
            sf.eip[:] = _merge_eip(
                struct.unpack_from(_IMSIC_PACK_FORMAT, state.imsic_s.eip),
                self._imsic_pre_s_eip,
                sf.eip,
            )
            mf.eie[:] = struct.unpack_from(
                _IMSIC_PACK_FORMAT, state.imsic_m.eie
            )
            sf.eie[:] = struct.unpack_from(
                _IMSIC_PACK_FORMAT, state.imsic_s.eie
            )
            mf.eidelivery = state.imsic_m.eidelivery
            mf.eithreshold = state.imsic_m.eithreshold
            sf.eidelivery = state.imsic_s.eidelivery
            sf.eithreshold = state.imsic_s.eithreshold
            self._imsic_select_m = state.imsic_m.select
            self._imsic_select_s = state.imsic_s.select
            # 重新计算缓存, 接收线程可能置位了外部中断
            mf._update_any_ext()
            sf._update_any_ext()
