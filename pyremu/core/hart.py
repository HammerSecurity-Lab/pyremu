#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""
Hart (硬件线程) 的寄存器文件定义，包含:
- 通用整数寄存器 (GPR x0-x31)
- 浮点寄存器 (FPR f0-f31)
- 控制和状态寄存器 (CSR)
- mstatus 等关键 CSR 位字段的快捷属性

特权级与 mstatus 位字段定义位于 priv_defs, 本模块导入其中使用到的取值.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
import weakref

from pyremu.configs_gen import ISA, PMP_ENTRIES
from pyremu.core.hart_ffi import HartFfiOps
from pyremu.core.mem_check_aux import MemoryAccessOps
from pyremu.core.priv_defs import (
    MSTATUS_FS,
    MSTATUS_MIE,
    MSTATUS_MPIE,
    MSTATUS_MPP,
    MSTATUS_MPRV,
    MSTATUS_MXR,
    MSTATUS_SD,
    MSTATUS_SIE,
    MSTATUS_SPIE,
    MSTATUS_SPP,
    MSTATUS_SUM,
    MSTATUS_UBE,
    MSTATUS_VS,
    MSTATUS_XS,
    RiscvMode,
)
from pyremu.core.registers import (
    check_csr,
    csr_addr_from_name,
    gpr_idx_from_name,
    register_csr,
    register_fpr,
)
from pyremu.core.trap_handler import TrapOps
from pyremu.interrupt.controller import IntStateVersion
from pyremu.memory import TLB_SIZE
from pyremu.memory.pmp import Pmp
from pyremu.memory.tlb import TLB
from pyremu.utils.isa import (
    encode_isa_exts,
    encode_misa,
    ISA_EXT_FIELDS,
    isa_ext_list,
)
from pyremu.utils.mask import mask16, mask32, mask64

if TYPE_CHECKING:
    from pyremu.interrupt.controller import InterruptController
    from pyremu.interrupt.imsic import IMSIC
    from pyremu.interrupt.plic import PLIC
    from pyremu.memory.bus import Bus


class HartGroup:
    """一组 hart 的弱引用视图, 供广播操作 (如 mfence.did, SFENCE.VMA) 遍历.

    模拟器持有的 hart 列表若原样交给每个 hart, 列表与其中的 hart 互相引用, 该环使
    hart 与 hart 持有的总线不经引用计数释放. 本对象只保存弱引用, 已终止的成员在
    遍历时跳过, 成员数不随构造之后列表的增长而变化.
    """

    __slots__ = ("_refs",)

    def __init__(self, harts: Iterable[HartWithRegs]) -> None:
        self._refs = [weakref.ref(h) for h in harts]

    def __iter__(self) -> Iterator[HartWithRegs]:
        for ref in self._refs:
            hart = ref()
            if hart is not None:
                yield hart

    def __bool__(self) -> bool:
        """是否有成员仍然存活."""
        return any(ref() is not None for ref in self._refs)


class GprFile:
    """GPR 寄存器文件 — 32 个 64-bit 整数, x0 硬连线为 0.

    用法与 ``list[int]`` 一致: ``gprs[10]`` 读, ``gprs[10] = v`` 写.
    x0 (索引 0) 写入被静默丢弃, 读取恒返回 0.
    """

    __slots__ = ("_r",)

    def __init__(self) -> None:
        self._r = [0] * 32

    def __getitem__(self, idx: int) -> int:
        return self._r[idx & 0x1F]

    def __setitem__(self, idx: int, val: int) -> None:
        i = idx & 0x1F
        if i != 0:
            self._r[i] = mask64(val)

    def __iter__(self):
        return iter(self._r)

    def __len__(self) -> int:
        return 32

    def as_list(self) -> list[int]:
        return self._r.copy()


# sstatus 是 mstatus 的受限视图 (RISC-V 特权规范 §4.1.1).
# sstatus 的读写必须通过 mstatus 的对应位, 两者不可独立.
_SSTATUS_MASK = (
    MSTATUS_SIE
    | MSTATUS_SPIE
    | MSTATUS_UBE
    | MSTATUS_SPP
    | MSTATUS_VS
    | MSTATUS_FS
    | MSTATUS_XS
    | MSTATUS_MPRV
    | MSTATUS_SUM
    | MSTATUS_MXR
    | MSTATUS_SD
)
# writable sstatus mask 排除 VS (bits 9-10) 和 SD (bit 63)
_SSTATUS_WRITABLE_MASK = _SSTATUS_MASK & ~(MSTATUS_VS | MSTATUS_SD)


# IMSIC 的实现不提供 mireg2 至 mireg6 与 sireg2 至 sireg6, 读回零.
UNUSED_IMSIC_CSRS: frozenset[str] = frozenset(
    {
        "mireg2",
        "mireg3",
        "mireg4",
        "mireg5",
        "mireg6",
        "sireg2",
        "sireg3",
        "sireg4",
        "sireg5",
        "sireg6",
    }
)

# SPP / MPP 编码到 RiscvMode 的映射
_SPP_TO_MODE = {0: RiscvMode.U, 1: RiscvMode.S}
_MPP_TO_MODE = {0: RiscvMode.U, 1: RiscvMode.S, 2: RiscvMode.H, 3: RiscvMode.M}
_MODE_TO_MPP = {RiscvMode.U: 0, RiscvMode.S: 1, RiscvMode.H: 2, RiscvMode.M: 3}
_MODE_TO_SPP = {RiscvMode.U: 0, RiscvMode.S: 1}


@dataclass
class RatifiedHartAttrs:
    """经平台配置确认的 hart 属性.

    isa_exts 的键为扩展名, 取值为 True; 未声明的扩展不在表中.
    isa_ext_switches 由 isa_exts 算出, 是交给加速执行引擎的扩展开关,
    在构造时固定, 之后不再随 isa_exts 的原地修改更新.
    misa 同样由 isa_exts 算出, 是 misa CSR 的复位值.
    """

    pmp_entries: int = PMP_ENTRIES
    isa_exts: dict[str, bool] = field(
        default_factory=lambda: dict.fromkeys(isa_ext_list(ISA), True)
    )
    isa_ext_switches: dict[str, bool] = field(init=False, compare=False)
    misa: int = field(init=False, compare=False)

    def __post_init__(self) -> None:
        self.isa_ext_switches = encode_isa_exts(self.isa_exts)
        self.misa = encode_misa(self.isa_exts)

    def has_ext(
        self,
        name: str,
    ) -> bool:
        """扩展 name 的开关是否打开; 未登记的扩展名给出 False."""
        return self.isa_ext_switches.get(ISA_EXT_FIELDS.get(name, ""), False)

    @classmethod
    def from_platform(
        cls,
        pmp_entries: int,
        isa: str,
    ) -> RatifiedHartAttrs:
        """按平台给出的 PMP 条目数与 ISA 字符串构造属性."""
        return cls(
            pmp_entries=pmp_entries,
            isa_exts=dict.fromkeys(isa_ext_list(isa), True),
        )


class HartWithRegs(HartFfiOps, MemoryAccessOps, TrapOps):
    """硬件线程的寄存器文件。

    每个 hart 拥有独立的 GPR、FPR、CSR 以及指令/数据 TLB。
    本类提供寄存器读写方法以及 mstatus/mtvec 等关键 CSR 的
    快捷属性访问。

    与加速执行引擎的状态编组来自 hart_ffi 的 HartFfiOps, 访存与陷态处理
    分别来自 mem_check_aux 的 MemoryAccessOps 与 trap_handler 的 TrapOps,
    均以 hart 自身为接收者。
    """

    def __init__(
        self,
        id: int,
        ratified_hart_attrs: RatifiedHartAttrs | None = None,
    ):
        self.id = id
        # 未给出平台属性时取编译期配置的 PMP 条目数与 ISA 字符串.
        if ratified_hart_attrs is None:
            self.ratified_hart_attrs = RatifiedHartAttrs()
        else:
            self.ratified_hart_attrs = ratified_hart_attrs
        self.gprs = GprFile()
        self.fprs = register_fpr()
        # 浮点寄存器原始 bits (NaN-boxed u64) — FFI marshal 与位精确运算的真值源。
        # self.fprs (FPR float 对象) 供调试器展示; _fpr_bits 为权威存储。
        self._fpr_bits = [0] * 32
        self.csrs = register_csr()

        # 机器信息寄存器 — 只读, 复位时写入
        self.csrs["mhartid"].val = id
        self.csrs["mvendorid"].val = 0  # 非商业实现
        self.csrs["marchid"].val = 0  # 未指定架构 ID
        self.csrs["mimpid"].val = 1  # 实现版本
        self.csrs["misa"].val = self.ratified_hart_attrs.misa

        self.pc = 0
        self.mode = RiscvMode.M

        # TLB: 指令 TLB 和数据 TLB 分开
        # MMIO 地址禁止 CPU 缓存
        self.itlb = TLB(size=TLB_SIZE)
        self.dtlb = TLB(size=TLB_SIZE)

        # PMP: 物理内存保护 — 条目数为运行时只读的平台约束
        # 超范围 CSR 访问在 _check_csr 中通过 _pmp_csr_valid 触发 IllInstr
        self._pmp = Pmp(self.csrs, num_entries=self.ratified_hart_attrs.pmp_entries)

        # 物理内存后端 — 由装配方直接赋值
        # 调用约定: mem_read_phy(addr: int, size: int) -> bytes
        #           mem_write_phy(addr: int, data: bytes) -> None
        self.mem_read_phy: Callable[[int, int], bytes] | None = None
        self.mem_write_phy: Callable[[int, bytes], None] | None = None

        # 共享总线引用 — 用于判断 MMIO 地址和预留失效
        self._bus: Bus | None = None

        # 全 hart 引用 — 用于 mfence.did 等需要广播到所有 hart 的操作
        self._all_harts: HartGroup | None = None

        # 中断控制器引用 — 每条指令执行后在指令边界检查是否有待处理中断
        self._interrupt_ctrl: InterruptController | None = None

        # PLIC维护外部中断MEIP/SEIP
        self._plic: PLIC | None = None

        # AIA IMSIC 维护外部与通过MSI发出的软件中断
        self._imsic: IMSIC | None = None
        self._imsic_select_m: int = 0  # miselect (0x350) 缓存
        self._imsic_select_s: int = 0  # siselect (0x150) 缓存
        self._imsic_pre_m_eip: list[int] | None = None  # _marshal_imsic 快照
        self._imsic_pre_s_eip: list[int] | None = None  # _marshal_imsic 快照

        # LR/SC 预留
        # 执行 LR 时记录预留地址; 任何 hart 向该地址写入时清除预留;
        # SC 仅在预留有效时成功, 否则失败; trap 发生时也清除预留
        self._reservation_addr: int = 0
        self._reservation_valid: bool = False
        self._reservation_value: int = 0  # value loaded by LR, passed to SC for CAS

        # 页表遍历模式 — 由 satp CSR 的 MODE 字段决定
        # Bare=0, Sv39=8, Sv48=9, Sv57=10, Sv64=11
        self._mmu_mode = 0

        # 异常/陷态追踪
        self._halted: bool = False  # 进入不可恢复陷态后置位

        # mdid 缓存 — 与 csrs["mdid"] 同步, 供每次内存访问读取
        self._mdid_val: int = 0

        # pmpsplit 缓存 — PMP 条目拆分点: 低 [0, split) 归 host, 高 [split, N) 归飞地
        self._pmpsplit_val: int = 0

        # WFI 低功耗等待状态
        # 当 hart 执行 WFI 且无可处理中断时置位; 中断挂起且使能时硬件唤醒
        self._waiting: bool = False

        # WFI 唤醒标记 — 从 WFI 被中断唤醒后置位, mret/sret 或重新进入 WFI 时清零.
        # 此期间的指令不计入 _total_instrs, 以保证指令计数器反映的是
        # 固件实际执行的非中断上下文指令.
        self._wfi_woken: bool = False

        # 每 hart 指令计数 — 该 hart 实际执行的指令数.
        # 允许跨动态链接库调用时累加; 加速用动态链接库内通过 state.total_instrs 更新,
        # 纯 Python 路径中由 sync_counters 递增.
        self._total_instrs: int = 0

        # 与 Rust HartState.stip_deadline/mtip_deadline 一一对应.
        # Rust 侧由 write_stimecmp/write_mtimecmp 在写入 timecmp 时设定;
        # 仅随 marshal/unmarshal 往返保持与 Rust 一致。
        self._stip_deadline: int = 0
        self._mtip_deadline: int = 0

        # 加速执行引擎的 TLB 计数 — 由引擎在地址翻译时累加, 从不清零, 跨批处理保留.
        # 与 Python 侧 itlb/dtlb 的计数互不相干: 后者只统计本解释器完成的翻译.
        self._speedup_itlb_hits: int = 0
        self._speedup_itlb_misses: int = 0
        self._speedup_dtlb_hits: int = 0
        self._speedup_dtlb_misses: int = 0

        # 中断状态缓存 — 避免每条指令都做完整的 CLINT+CSR+PLIC 遍历 (~1272 ns).
        # int_state_version 在本 hart 写入敏感 CSR 与中断控制器状态变化时递增, 中断
        # 控制器与本 hart 持有的是同一个版本号对象.
        # check_pending_interrupts 发现版本未变且 timer 未到期时直接返回 False.
        self.int_state_version = IntStateVersion()
        self.int_cache_version: int = -1  # -1 = 首次调用强制全量检查
        self.int_cache_next_timer: int = 0  # 最近 timer 唤醒时间

    # ----------------------------------------------------------
    #  寄存器读写
    # ----------------------------------------------------------

    def _require_csr(self, csr_name: str) -> None:
        """检查 CSR 名称存在, 不存在时抛出 ValueError."""
        if csr_name not in self.csrs:
            raise ValueError(f"{csr_name!r} not found in hart {self.id}")

    def _csr_read_raw(self, csr_name: str) -> int:
        """读取 CSR 的存储值, 不检查特权级, 不合成 sstatus/sie/sip 视图."""
        self._require_csr(csr_name)
        return self.csrs[csr_name].val

    def read_csr(self, csr_id: int) -> int:
        check, csr_name = check_csr(csr_id)
        if not check:
            return -1
        # 硬件计数器 — 从 CLINT 动态读取
        # RISC-V 规范: time / timeh 是内存映射 CLINT mtime 的只读 CSR 镜像
        if csr_name in ("time", "timeh") and self._interrupt_ctrl:
            return self._read_time_csr(csr_name)
        # sstatus 是 mstatus 的受限视图, 读取 sstatus 时返回 mstatus 的对应位
        if csr_name == "sstatus":
            return self._csr_read_raw("mstatus") & _SSTATUS_MASK
        # sie 与 sip 是 mie 与 mip 的受限视图 — 只有 mideleg 委派的位在 S 模式可见
        if csr_name in ("sie", "sip"):
            base = "mie" if csr_name == "sie" else "mip"
            return self._csr_read_raw(base) & self._csr_read_raw("mideleg")
        # AIA IMSIC CSRs — indirect register access via miselect/mireg
        if self._imsic is not None:
            val = self._read_imsic_csr(csr_name)
            if val is not None:
                return val
        return self._csr_read_raw(csr_name)

    def _read_time_csr(self, csr_name: str) -> int:
        """读取 time/timeh: 取 CLINT mtime, timeh 取高 32 位."""
        mtime = self._interrupt_ctrl.get_mtime()
        return mtime if csr_name == "time" else mask32(mtime >> 32)

    def _read_imsic_csr(self, csr_name: str) -> int | None:
        """读取 IMSIC 间接访问 CSR; 非此类 CSR 返回 None."""
        if csr_name in ("miselect", "siselect"):
            return self._imsic_select_m if csr_name == "miselect" else self._imsic_select_s
        if csr_name in ("mireg", "sireg"):
            return self._read_imsic_reg(csr_name)
        if csr_name in ("mtopi", "stopi"):
            return self._imsic_read_topi(csr_name)
        if csr_name in ("mtopei", "stopei"):
            return self._read_imsic_topei(csr_name)
        if csr_name in UNUSED_IMSIC_CSRS:
            return 0
        return None

    def _read_imsic_reg(self, csr_name: str) -> int:
        """读取 mireg/sireg: 按 miselect/siselect 指定的寄存器."""
        if csr_name == "mireg":
            return self._imsic.csr_read(self.id, "M", self._imsic_select_m)
        return self._imsic.csr_read(self.id, "S", self._imsic_select_s)

    def _imsic_read_topi(self, csr_name: str) -> int:
        """读取 mtopi/stopi."""
        return self._read_mtopi() if csr_name == "mtopi" else self._read_stopi()

    def _read_imsic_topei(self, csr_name: str) -> int:
        """读取 mtopei/stopei, 并清除对应 IPI 的中断挂起位."""
        return self._read_mtopei() if csr_name == "mtopei" else self._read_stopei()

    def _read_mtopei(self) -> int:
        """读取 mtopei; IID=3 时清除 MSIP."""
        val = self._imsic.read_topei(self.id, "M")
        # Clear MSIP for IID=3 (mirrors Rust MTOPEI read handler).
        if val != 0 and mask16(val >> 16) == 3:
            self.mip_val &= ~(1 << 3)
        return val

    def _read_stopei(self) -> int:
        """读取 stopei; IID=1 时清除 SSIP."""
        val = self._imsic.read_topei(self.id, "S")
        if val != 0 and mask16(val >> 16) == 1:
            self.mip_val &= ~(1 << 1)
        return val

    # CSR names whose writes affect interrupt state and must invalidate the
    # check_pending_interrupts cache.
    _INT_SENSITIVE_CSRS: frozenset[str] = frozenset(
        {
            "mip",
            "mie",
            "mideleg",
            "mstatus",
            "stimecmp",
        }
    )

    def _csr_write_raw(self, csr_name: str, val: int) -> None:
        """写入 CSR 的存储值, 不检查特权级, 不触发 property setter 的副作用.

        中断敏感 CSR 写入后递增 int_state_version, 使中断状态缓存失效.
        """
        self._require_csr(csr_name)
        self.csrs[csr_name].val = mask64(val)
        if csr_name in self._INT_SENSITIVE_CSRS:
            self.int_state_version.bump()

    def write_csr(self, csr_id: int, val: int):
        check, csr_name = check_csr(csr_id)
        if not check:
            return
        if self._write_csr_side_effect(csr_name, val):
            return
        if self._imsic is not None and self._write_csr_imsic(csr_name, val):
            return
        self._csr_write_raw(csr_name, val)

    def _write_csr_side_effect(self, csr_name: str, val: int) -> bool:
        """处理带副作用的 CSR 写入; 返回是否已处理."""
        if csr_name == "satp":
            self.satp_val = val
            # satp 改写使投递到物理地址的映射全部改变, 加速执行引擎内既有的翻译
            # 条目随之作废. 计入刷新计数, 由引擎在下一轮开始处比较.
            self.note_tlb_flush()
        elif csr_name == "mdid":
            self.mdid_val = val
        elif csr_name == "pmpsplit":
            self.pmpsplit_val = val
        elif csr_name.startswith(("pmpcfg", "pmpaddr")):
            self._write_pmp_csr(csr_name, val)
        elif csr_name == "stimecmp":
            self._csr_write_raw(csr_name, val)
            self._eval_stip(val)
        elif csr_name == "stimecmph":
            self._write_stimecmph(csr_name, val)
        elif csr_name == "sstatus":
            self._write_sstatus(val)
        elif csr_name == "sie":
            self._write_sie(val)
        elif csr_name == "mip":
            self._write_mip(val)
        elif csr_name == "sip":
            self._write_sip(val)
        else:
            return False
        return True

    def _write_pmp_csr(self, csr_name: str, val: int) -> None:
        """PMP CSR 写入: 失效扁平缓存并同步到其他 hart."""
        self._csr_write_raw(csr_name, val)
        self._pmp.invalidate_cache()
        for h in self._all_harts or ():
            if h is not self:
                h._csr_write_raw(csr_name, val)
                h._pmp.invalidate_cache()

    def _write_stimecmph(self, csr_name: str, val: int) -> None:
        """写入 stimecmph (RV32 only): 合并到 stimecmp 的高 32 位."""
        cur = mask32(self._csr_read_raw("stimecmp"))
        merged = cur | (mask32(val) << 32)
        self._csr_write_raw("stimecmp", merged)
        self._csr_write_raw(csr_name, mask32(val))
        self._eval_stip(merged)

    def _write_sstatus(self, val: int) -> None:
        """写入 sstatus: 仅更新 mstatus 中 sstatus 可见且可写的位."""
        mstatus = self._csr_read_raw("mstatus")
        mstatus = (mstatus & ~_SSTATUS_WRITABLE_MASK) | (val & _SSTATUS_WRITABLE_MASK)
        self._csr_write_raw("mstatus", mstatus)
        self._csr_write_raw("sstatus", mstatus & _SSTATUS_MASK)

    def _write_sie(self, val: int) -> None:
        """写入 sie: 只有 mideleg 委派的位可通过 S 模式写."""
        mideleg = self._csr_read_raw("mideleg")
        old_mie = self._csr_read_raw("mie")
        new_mie = (old_mie & ~mideleg) | (val & mideleg)
        self._csr_write_raw("mie", new_mie)

    def _write_mip(self, val: int) -> None:
        """写入 mip: MSIP/MTIP/SEIP/MEIP 只读, SSIP/STIP 与 USIP 可被软件写入.

        STIP 可写: 设备树未声明 sstc 时, M 模式固件以 mtimecmp 承担 S 模式定时器,
        到期经 ``csrw mip`` 置位 STIP, 并重新装定 mtimecmp 时清除该位; S 模式一侧
        经 sip 只读地看到该位, 据此进入定时器陷态. SEIP 在本模拟器中恒由中断控制器
        驱动, 写入被忽略 (与 Rust csr.rs 的 ro_mask 一致).
        """
        ro_mask = (1 << 3) | (1 << 7) | (1 << 9) | (1 << 11)
        old_mip = self._csr_read_raw("mip")
        new_mip = (old_mip & ro_mask) | (val & ~ro_mask)
        self._csr_write_raw("mip", new_mip)

    def _write_sip(self, val: int) -> None:
        """写入 sip: 唯一可写位是 SSIP (bit 1)."""
        # sip 并非对所有 mideleg 委派位都可写: STIP (bit 5) 由 SSTC 定时器
        # 硬件驱动, SEIP (bit 9) 由 PLIC 硬件驱动, 均不得被 `csrw sip` 覆写.
        # 飞地上下文切换 (csr_write(CSR_SIP, saved)) 写回陈旧 sip, 覆写
        # SEIP/STIP 会丢失挂起的外设/定时器中断 (飞地回归测试后输入冻结).
        old_mip = self._csr_read_raw("mip")
        new_mip = (old_mip & ~(1 << 1)) | (val & (1 << 1))
        self._csr_write_raw("mip", new_mip)

    def _write_csr_imsic(self, csr_name: str, val: int) -> bool:
        """处理 IMSIC 间接访问 CSR 的写入; 返回是否已处理."""
        if csr_name == "miselect":
            self._imsic_select_m = mask32(val)
            self._csr_write_raw(csr_name, self._imsic_select_m)
        elif csr_name == "siselect":
            self._imsic_select_s = mask32(val)
            self._csr_write_raw(csr_name, self._imsic_select_s)
        elif csr_name == "mireg":
            self._imsic.csr_write(self.id, "M", self._imsic_select_m, val)
        elif csr_name == "sireg":
            self._imsic.csr_write(self.id, "S", self._imsic_select_s, val)
        elif csr_name in ("stopei", "mtopei"):
            self._write_topei(csr_name, val)
        elif csr_name in ("stopi", "mtopi"):
            self._write_topi(csr_name, val)
        else:
            return False
        return True

    def _write_topei(self, csr_name: str, val: int) -> None:
        """写入 stopei/mtopei: 按 AIA 规范 claim 指定的 IID."""
        iid = (val >> 16) & 0x7FF
        if iid == 0:
            return
        priv = "S" if csr_name == "stopei" else "M"
        self._imsic.clear_ip_number(self.id, priv, iid)
        # IPI IID 对应 MSIP/SSIP, 一并清除其挂起位 (与 _read_mtopei 同理).
        self.mip_val &= ~(1 << iid)

    def _write_topi(self, csr_name: str, val: int) -> None:
        """写入 stopi/mtopi: 按 AIA 规范 claim 指定的 IID."""
        iid = (val >> 16) & 0x7FF
        if csr_name == "mtopi":
            self._claim_mtopi(iid)
        else:
            self._claim_stopi(iid)

    def _claim_mtopi(self, iid: int) -> None:
        """claim mtopi; 定时器中断的 mtimecmp 已到期时推后 4 个周期."""
        mip_clr = self._imsic.claim_mtopi_iid(self.id, iid)
        self.mip_val &= ~mip_clr
        if iid != 7 or self._interrupt_ctrl is None:  # IRQ_M_TIMER: bump mtimecmp
            return
        now = self._interrupt_ctrl.get_mtime()
        mtc = self._interrupt_ctrl.get_mtimecmp(self.id)
        if 0 < mtc <= now:
            self._interrupt_ctrl.set_mtimecmp(self.id, now + 4)

    def _claim_stopi(self, iid: int) -> None:
        """claim stopi; 定时器中断的 stimecmp 已到期时推后 4 个周期."""
        mip_clr = self._imsic.claim_stopi_iid(self.id, iid)
        self.mip_val &= ~mip_clr
        if iid != 5:  # IRQ_S_TIMER: bump stimecmp
            return
        stc, now = 0, 0
        if "stimecmp" in self.csrs:
            stc = self._csr_read_raw("stimecmp")
        if self._interrupt_ctrl:
            now = self._interrupt_ctrl.get_mtime()
        if 0 < stc <= now:
            self._csr_write_raw("stimecmp", now + 4)

    def read_gpr(self, reg_id: int) -> int:
        return self.gprs[reg_id & 0x1F]

    def write_gpr(self, reg_id: int, val: int):
        self.gprs[reg_id & 0x1F] = val

    def read_fpr(self, reg_id: int) -> float:
        return self.fprs[reg_id & 0x1F].val

    def write_fpr(self, reg_id: int, val: float):
        self.fprs[reg_id & 0x1F].val = val

    def read_gpr_by_name(self, name: str) -> int:
        """按名称读取 GPR (例: x12, t0, a0, sp, zero). 未找到返回 0."""
        idx = gpr_idx_from_name(name)
        if idx is None:
            return 0
        return self.read_gpr(idx)

    def read_csr_by_name(self, name: str) -> int:
        """按名称读取 CSR (例: mtvec, mstatus, mepc, misa). 未找到返回 0."""
        addr = csr_addr_from_name(name)
        if addr is None:
            return 0
        return self.read_csr(addr)

    # ----------------------------------------------------------
    #  mstatus 字段快捷属性 (直接读写 CSR 中的 mstatus 值)
    # ----------------------------------------------------------

    @property
    def mstatus_val(self) -> int:
        """读取完整 mstatus CSR 值."""
        return self.csrs["mstatus"].val

    @mstatus_val.setter
    def mstatus_val(self, v: int):
        self.csrs["mstatus"].val = v

    # -- MIE / MPIE / MPP (Machine 级) --

    @property
    def mie(self) -> bool:
        return bool(self.mstatus_val & MSTATUS_MIE)

    @mie.setter
    def mie(self, en: bool):
        """设置 Machine 中断使能."""
        if en:
            self.mstatus_val |= MSTATUS_MIE
        else:
            self.mstatus_val &= ~MSTATUS_MIE

    @property
    def mpie(self) -> bool:
        return bool(self.mstatus_val & MSTATUS_MPIE)

    @mpie.setter
    def mpie(self, en: bool):
        if en:
            self.mstatus_val |= MSTATUS_MPIE
        else:
            self.mstatus_val &= ~MSTATUS_MPIE

    @property
    def mpp(self) -> RiscvMode:
        """从 mstatus.MPP 字段解码先前的特权级."""
        raw = (self.mstatus_val & MSTATUS_MPP) >> 11
        return _MPP_TO_MODE.get(raw, RiscvMode.U)

    @mpp.setter
    def mpp(self, mode: RiscvMode):
        """将当前特权级编码写入 mstatus.MPP."""
        raw = _MODE_TO_MPP.get(mode, 0)
        self.mstatus_val = (self.mstatus_val & ~MSTATUS_MPP) | (raw << 11)

    # -- SIE / SPIE / SPP (Supervisor 级) --

    @property
    def sie(self) -> bool:
        return bool(self.mstatus_val & MSTATUS_SIE)

    @sie.setter
    def sie(self, en: bool):
        if en:
            self.mstatus_val |= MSTATUS_SIE
        else:
            self.mstatus_val &= ~MSTATUS_SIE

    @property
    def spie(self) -> bool:
        return bool(self.mstatus_val & MSTATUS_SPIE)

    @spie.setter
    def spie(self, en: bool):
        if en:
            self.mstatus_val |= MSTATUS_SPIE
        else:
            self.mstatus_val &= ~MSTATUS_SPIE

    @property
    def spp(self) -> RiscvMode:
        """从 mstatus.SPP 字段解码 Supervisor 先前的特权级."""
        raw = (self.mstatus_val & MSTATUS_SPP) >> 8
        return _SPP_TO_MODE.get(raw, RiscvMode.U)

    @spp.setter
    def spp(self, mode: RiscvMode):
        raw = _MODE_TO_SPP.get(mode, 0)
        self.mstatus_val = (self.mstatus_val & ~MSTATUS_SPP) | (raw << 8)

    # ----------------------------------------------------------
    #  其他关键 CSR 的快捷属性
    # ----------------------------------------------------------

    @property
    def mtvec_val(self) -> int:
        """M 模式 trap 向量基址 (低 2 位为 MODE)."""
        return self.csrs["mtvec"].val

    @property
    def stvec_val(self) -> int:
        """S 模式 trap 向量基址."""
        return self.csrs["stvec"].val

    @property
    def mepc_val(self) -> int:
        return self.csrs["mepc"].val

    @mepc_val.setter
    def mepc_val(self, v: int):
        self.csrs["mepc"].val = v

    @property
    def sepc_val(self) -> int:
        return self.csrs["sepc"].val

    @sepc_val.setter
    def sepc_val(self, v: int):
        self.csrs["sepc"].val = v

    @property
    def mcause_val(self) -> int:
        return self.csrs["mcause"].val

    @mcause_val.setter
    def mcause_val(self, v: int):
        self.csrs["mcause"].val = v

    @property
    def scause_val(self) -> int:
        return self.csrs["scause"].val

    @scause_val.setter
    def scause_val(self, v: int):
        self.csrs["scause"].val = v

    @property
    def mtval_val(self) -> int:
        return self.csrs["mtval"].val

    @mtval_val.setter
    def mtval_val(self, v: int):
        self.csrs["mtval"].val = v

    @property
    def stval_val(self) -> int:
        return self.csrs["stval"].val

    @stval_val.setter
    def stval_val(self, v: int):
        self.csrs["stval"].val = v

    @property
    def satp_val(self) -> int:
        """satp CSR: MODE(4) | ASID(16) | PPN(44)."""
        return self.csrs["satp"].val

    @satp_val.setter
    def satp_val(self, v: int) -> None:
        """写入 satp 时同步更新缓存的 MMU 模式.

        ASID 字段即 bits[59:44], 按 WARL 硬连线为 0: 本实现的 TLB 在 Python 与
        加速执行用动态链接库两侧的查找均不带 ASID 标签。若允许 ASID 读回非零,
        Linux 探测到 ASID 支持后会启用 ASID 分配器, 上下文切换时仅改写
        satp.ASID 而不执行 sfence.vma — 前一地址空间的 TLB 表项残留命中,
        用户进程读到脏数据随机 SIGSEGV, 表现为 ld.so 崩溃。读回 0 则内核走
        no-ASID 路径, 每次 mm 切换显式 local_flush_tlb_all().

        每次 satp 写入均刷新 TLB — 不仅限 MODE 字段变化.
        约束: 飞地上下文切换经 alter_hart_ctx_for_enclave 恢复 host
        satp 时, host 与飞地均为 Sv39 使 MODE 相同, 若按 MODE 字段是否变化
        判断则跳过刷新, 飞地的 TLB 残留随后毒化内核地址空间, 导致缺页异常 +
        栈溢出; 该残留的 VPN2=0x180 与内核 VA 重叠.
        """
        v &= ~(0xFFFF << 44)
        self.csrs["satp"].val = mask64(v)
        # 必须无条件刷新: 两个不同 Sv39 页表之间切换时 MODE 不变,
        # 但 TLB 中 VPN 到 PPN 的旧映射已失效.
        self.itlb.flush_all()
        self.dtlb.flush_all()
        self._mmu_mode = (v >> 60) & 0xF

    # ----------------------------------------------------------
    #  页表遍历模式 (由 satp.MODE 字段驱动)
    # ----------------------------------------------------------

    @property
    def mmu_mode(self) -> int:
        """返回当前 MMU 翻译模式 (Bare=0, Sv39=8, Sv48=9).

        值由 satp_val setter 在每次写入 satp CSR 时同步更新.
        """
        return self._mmu_mode

    @property
    def satp_ppn(self) -> int:
        """返回 satp 中的根页表物理页号 (PPN)."""
        return self.satp_val & ((1 << 44) - 1)

    # ----------------------------------------------------------
    #  总线 / 中断控制器引用 (Emulator 初始化时注入)
    # ----------------------------------------------------------

    @property
    def bus(self):
        """共享总线 (用于 MMIO 地址检测)."""
        return self._bus

    @bus.setter
    def bus(self, b):
        self._bus = b

    def note_tlb_flush(self) -> None:
        """
        登记一次 TLB 刷新, 使加速执行引擎内既有的翻译条目作废.

        调用方须先刷新本 hart 在 Python 侧的两个 TLB; 本方法只负责让引擎在下一轮
        开始处判定条目已陈旧.
        """
        if self._bus is not None:
            self._bus.note_tlb_flush()

    @property
    def interrupt_ctrl(self):
        """中断控制器 (CLINT / 未来 IMSIC 等)."""
        return self._interrupt_ctrl

    @interrupt_ctrl.setter
    def interrupt_ctrl(self, ctrl):
        self._interrupt_ctrl = ctrl
        # 把本 hart 的中断状态版本号交给控制器 — 即使外部替换 CLINT 也不漏登记.
        # 交出对象而非本 hart 的通知方法, 以免控制器持有本 hart, 见 IntStateVersion.
        if ctrl:
            ctrl.attach_int_state(self.int_state_version)

    @property
    def plic(self):
        """PLIC 中断控制器 (外部中断 MEIP/SEIP)."""
        return self._plic

    @plic.setter
    def plic(self, p):
        self._plic = p

    @property
    def imsic(self):
        """AIA IMSIC 中断控制器 (MSI 外部 + 软件中断)."""
        return self._imsic

    @imsic.setter
    def imsic(self, im):
        self._imsic = im

    @property
    def all_harts(self) -> HartGroup | None:
        """所有 hart 的弱引用视图 (用于广播操作, 如 mfence.did)."""
        return self._all_harts

    @all_harts.setter
    def all_harts(self, harts: Iterable[HartWithRegs]):
        self._all_harts = HartGroup(harts)

    def _eval_stip(self, stimecmp_val: int) -> None:
        """Immediately re-evaluate mip.STIP after stimecmp write.

        Python 步骤路径: 单线程执行期间 mtime 不会被并发推进
        Rust native 路径由 csr.rs 的 write_stimecmp 承担同一语义并按自身的指令计数
        设定 deadline. 该行为决定内核的 stopi 循环能否退出.
        """
        self._stip_deadline = 0
        if self._interrupt_ctrl is None:
            return
        now = self._interrupt_ctrl.get_mtime()
        if stimecmp_val > 0 and now >= stimecmp_val:
            self.mip_val |= 1 << 5
        else:
            self.mip_val &= ~(1 << 5)

    @staticmethod
    def _timer_pending(mtime: int, cmp: int) -> bool:
        """True if *mtime* has reached the non-zero comparator *cmp*."""
        return cmp > 0 and mtime >= cmp

    def _read_mtopi(self) -> int:
        """
        Machine Top Interrupt (0xFB0).  Priority: MEI(11) > MSI(3) > MTI(7).

        Per AIA spec, mtopi returns the MAJOR identity.  ALL IMSIC M-file
        interrupts — external (IID >= 6) and the IPI (minor identity 1) — are
        delivered via MEIP and reported as IID=11 (MEI); the actual minor
        identity is read from MTOPEI.
        """
        if self._imsic:
            topei = self._imsic.peek_topei(self.id, "M")
            if topei != 0:
                # All IMSIC M-file interrupts (IPI + external) -> MEI=11.
                # The IPI minor identity (1) is NOT a major identity — the
                # IMSIC delivers it via MEIP, and the minor identity is
                # revealed only via MTOPEI.
                prio = topei & 0xFF
                return (11 << 16) | prio
        if (self.mip_val & self.mie_val) & (1 << 3):
            val = (3 << 16) | 1
            # Clear MSIP — mirrors Rust compute_mtopi.
            # Prevents re-delivery after the M-mode handler has claimed the IPI
            # via MTOPEI.  The handler must call sbi_ipi_raw_clear(0) to
            # clear the CLINT level bit for the next IPI.
            self.mip_val &= ~(1 << 3)
            return val
        if self._interrupt_ctrl and (self.mie_val & (1 << 7)):
            now = self._interrupt_ctrl.get_mtime()
            mtc = self._interrupt_ctrl.get_mtimecmp(self.id)
            if self._timer_pending(now, mtc):
                val = (7 << 16) | 1
                return val
        return 0

    def _read_stopi(self) -> int:
        """Supervisor Top Interrupt (0xDB0).  Priority: SEI(9) > SSI(1) > STI(5).

        Per AIA spec, stopi returns the MAJOR identity.  ALL IMSIC S-file
        interrupts — external (IID >= 6) and the IPI (minor identity 1) — are
        delivered via SEIP and reported as IID=9 (SEI); the actual minor
        identity is read from STOPEI.
        """
        if self._imsic:
            topei = self._imsic.peek_topei(self.id, "S")
            if topei != 0:
                # All IMSIC S-file interrupts (IPI + external) -> SEI=9.
                # The IPI minor identity (1) is NOT a major identity — the
                # IMSIC delivers it via SEIP, and the minor identity is
                # revealed only via STOPEI.
                prio = topei & 0xFF
                return (9 << 16) | prio
        if (self.mip_val & self.mie_val) & (1 << 1):
            val = (1 << 16) | 1
            # Clear SSIP — mirrors Rust compute_stopi.
            # In AIA mode SSIP normally comes through IMSIC S-file (eip[1] ->
            # STOPEI claim), but when falling through to this legacy path the
            # bit must be cleared to prevent re-delivery.
            self.mip_val &= ~(1 << 1)
            return val
        # STIP 对应 IID=5, 即 IRQ_S_TIMER. stimecmp 为 0 表示本 hart 未使用 sstc
        # 定时器, 例如设备树未声明 sstc 时固件以 mtimecmp 承担 S 模式定时器并经
        # ``csrw mip`` 置位 mip.STIP, 此时挂起状态取该位; stimecmp 不为 0 时挂起
        # 状态只取定时器比较结果, 固件上调 stimecmp 后不得因 mip.STIP 仍置位而
        # 再次返回 IID=5.
        if self.mie_val & (1 << 5):
            stc = self._csr_read_raw("stimecmp") if "stimecmp" in self.csrs else 0
            if stc == 0:
                if self.mip_val & (1 << 5):
                    return (5 << 16) | 1
            elif self._interrupt_ctrl and self._timer_pending(
                self._interrupt_ctrl.get_mtime(), stc
            ):
                return (5 << 16) | 1
        return 0

    @property
    def mdid_val(self) -> int:
        return self._mdid_val

    @mdid_val.setter
    def mdid_val(self, v: int):
        val = mask64(v)
        self._mdid_val = val
        self.csrs["mdid"].val = val

    @property
    def pmpsplit_val(self) -> int:
        """读取 pmpsplit CSR — PMP 条目拆分点.

        PMP 条目 [0, split) 归 host (mdid==0) 使用,
        [split, N) 归飞地 (mdid!=0) 使用.
        值为 0 时全部条目归 host (无飞地 PMP 隔离).
        """
        return self._pmpsplit_val

    @pmpsplit_val.setter
    def pmpsplit_val(self, v: int):
        val = mask64(v)
        self._pmpsplit_val = val
        self.csrs["pmpsplit"].val = val

    # ----------------------------------------------------------
    #  加速执行引擎的 TLB 计数 (只读)
    # ----------------------------------------------------------

    @property
    def speedup_itlb_counts(self) -> tuple[int, int]:
        """指令 TLB 的 (命中次数, 未命中次数) — 由加速执行引擎累计."""
        return self._speedup_itlb_hits, self._speedup_itlb_misses

    @property
    def speedup_dtlb_counts(self) -> tuple[int, int]:
        """数据 TLB 的 (命中次数, 未命中次数) — 由加速执行引擎累计."""
        return self._speedup_dtlb_hits, self._speedup_dtlb_misses

    # ----------------------------------------------------------
    #  mip 快捷属性 (中断挂起位)
    # ----------------------------------------------------------

    @property
    def mip_val(self) -> int:
        """读取 mip CSR (中断挂起寄存器)."""
        return self.csrs["mip"].val

    @mip_val.setter
    def mip_val(self, v: int):
        self._csr_write_raw("mip", v)

    @property
    def mie_val(self) -> int:
        """读取 mie CSR (中断使能寄存器)."""
        return self.csrs["mie"].val

    # ----------------------------------------------------------
    #  LR/SC 预留管理 (A-extension)
    # ----------------------------------------------------------

    def set_reservation(self, addr: int, value: int = 0) -> None:
        """设置 LR 预留地址和加载值 (原子 load-reserved 成功时调用)."""
        self._reservation_addr = addr
        self._reservation_valid = True
        self._reservation_value = value

    def clear_reservation(self) -> None:
        """清除 LR/SC 预留 (SC 失败 / 其他 hart 写入 / trap 时调用)."""
        self._reservation_valid = False
        self._reservation_addr = 0
        self._reservation_value = 0

    @property
    def reservation_valid(self) -> bool:
        return self._reservation_valid

    @property
    def reservation_addr(self) -> int:
        return self._reservation_addr
