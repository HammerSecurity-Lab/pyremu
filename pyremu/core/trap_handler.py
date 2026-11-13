#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""trap 投递与中断检查的操作类.

TrapOps 由 HartWithRegs 组合, 方法以 hart 自身为接收者.

Public methods:
    deliver_trap              — trap delivery with medeleg/mideleg delegation
    trap_ecall                — ECALL instruction trap
    trap_ebreak               — EBREAK instruction trap
    trap_mret                 — MRET return from M-mode trap
    trap_sret                 — SRET return from S-mode trap
    handle_wfi                — WFI wait-for-interrupt with TW check
    check_pending_interrupts  — instruction-boundary interrupt polling
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyremu.configs_gen import PYREMU_HAS_SEMIHOSTING
from pyremu.core.priv_defs import (
    MSTATUS_MIE,
    MSTATUS_MPIE,
    MSTATUS_MPP,
    MSTATUS_MPRV,
    MSTATUS_SIE,
    MSTATUS_SPIE,
    MSTATUS_SPP,
    MSTATUS_TSR,
    MSTATUS_TW,
    RiscvMode,
)
from pyremu.core.trap_def import (
    HW_MIP_MASK,
    INT_PRIORITY,
    MODE_S_VALUE,
    SEMIHOSTING_ERR,
    SEMIHOSTING_POST,
    SEMIHOSTING_PRE,
    SEMIHOSTING_SYS_EXIT,
    SEMIHOSTING_SYS_ISTTY,
    SEMIHOSTING_SYS_OPEN,
    SEMIHOSTING_SYS_WRITE,
    SEMIHOSTING_SYS_WRITEC,
    semihosting_write_stderr,
    trap_cause_code,
    TrapType,
)
from pyremu.interrupt.controller import INT_SOURCE_MIP_MASK, IntSource
from pyremu.utils.mask import mask64

if TYPE_CHECKING:
    from pyremu.interrupt.controller import InterruptController


class TrapOps:
    """trap 投递、特权指令、WFI 与中断检查的操作类."""

    def update_hw_mip(self, hw_mip_bits: int) -> None:
        """用当前硬件状态替换 mip CSR 中的硬件源位.

        与简单的 `current_mip | hw_mip_bits` 不同, 此函数**清除**已不再被
        硬件源断言的位, 防止中断源撤除后无限重投递 (如 CLINT MSIP 清零后
        mip.MSIP 仍残留导致 MmodeSoftInterrupt 风暴).
        """
        current = self._csr_read_raw("mip")
        merged = (current & ~HW_MIP_MASK) | hw_mip_bits
        # 硬件位未变化时省去一次 CSR 写入
        # 否则每条指令边界都会调用本函数.
        if merged != current:
            self._csr_write_raw("mip", merged)

    def _resolve_stip(
        self,
        mip_bits: int,
        ctrl: InterruptController,
    ) -> tuple[int, bool]:
        """按 sstc 定时器的状态合并 mip.STIP, 返回 (mip 位, 是否挂起).

        平台未声明 sstc 或 stimecmp 为 0 时, STIP 取软件写入的 mip.STIP, 定时器
        状态不得清除该位; 固件在这种情形下以 mtimecmp 承担 S 模式定时器. 否则
        STIP 由定时器决定: mtime 到达比较值即挂起, 未到达即不挂起.
        """
        sti_mask = INT_SOURCE_MIP_MASK[IntSource.STI]
        has_sstc = self.ratified_hart_attrs.has_ext("sstc")
        stimecmp_val = self._csr_read_raw("stimecmp") if has_sstc else 0
        if stimecmp_val == 0:
            is_pending = bool(self._csr_read_raw("mip") & sti_mask)
            return (
                (mip_bits | sti_mask) if is_pending else mip_bits
            ), is_pending
        if ctrl.get_mtime() >= stimecmp_val:
            return mip_bits | sti_mask, True
        return mip_bits, False

    #  Trap 处理

    def deliver_trap(
        self,
        cause: TrapType,
        tval: int = 0,
        is_interrupt: bool = False,
    ) -> None:
        """统一的 trap 入口 — 支持委派到 S 模式.

        根据 medeleg (异常委派) / mideleg (中断委派) 和当前特权级
        决定 trap 目标:
        - M 模式: 保存到 mepc/mcause/mtval, 跳转 mtvec
        - S 模式: 保存到 sepc/scause/stval, 跳转 stvec

        委派规则 (RISC-V Privileged Spec §3.1.9):
        - M 模式下发生的 trap 永不委派
        - 委派仅在 medeleg/mideleg 对应位为 1 时生效
        - 无需额外检查"不委派到更高特权级", S 是唯一委派目标且 < M

        Args:
            cause: trap 类型 (TrapType 枚举).
            tval: 关联的故障地址或附加信息.
            is_interrupt: 表示中断 (True) 还是异常 (False).
        """
        # trap 发生时清除 LR/SC 预留
        self.clear_reservation()

        # 记录是否从 WFI 唤醒 (用于排除中断 handler 的指令计数)
        was_wfi = self._waiting

        # 任何 trap 都会唤醒 WFI 等待中的 hart
        self._waiting = False
        if was_wfi:
            self._wfi_woken = True

        # 获取 cause 编码 (中断标志已嵌入)
        code = trap_cause_code(cause)
        exc_code = code & 0x7FFF_FFFF_FFFF_FFFF  # 去掉 bit 63

        # ---- 委派检查 ----
        # M 模式下永不委派; S/U 模式下根据 medeleg/mideleg 判断
        delegate = False
        if self.mode != RiscvMode.M:
            choice = (
                self.csrs["mideleg"].val
                if is_interrupt
                else self.csrs["medeleg"].val
            )
            delegate = bool(choice & (1 << exc_code))

        fn = self._trap_deliver_smode if delegate else self._trap_deliver_mmode
        fn(code, exc_code, tval, is_interrupt)

    # ---- S 模式 trap 投递 ----

    def _trap_deliver_smode(
        self,
        code: int,
        exc_code: int,
        tval: int,
        is_interrupt: bool,
    ) -> None:
        """将 trap 投递到 S 模式: 保存上下文到 S 模式 CSR 并跳转 stvec."""
        # 保存当前 PC 到 sepc
        self.sepc_val = self.pc

        # 设置 scause (中断标志位不变)
        self.scause_val = code

        # 设置 stval
        self.stval_val = tval

        # 更新 mstatus:
        #   SPIE <- SIE (保存进入 trap 前的中断使能)
        #   SIE  <- 0   (进入 trap 后关全局中断)
        #   SPP  <- 当前特权级
        mstatus = self.mstatus_val
        if mstatus & MSTATUS_SIE:
            mstatus |= MSTATUS_SPIE
        else:
            mstatus &= ~MSTATUS_SPIE
        mstatus &= ~MSTATUS_SIE

        # SPP <- 当前 mode (U=0, S=1)
        _spp_map = {RiscvMode.U: 0, RiscvMode.S: 1}
        spp_code = _spp_map.get(self.mode, 0)
        mstatus = (mstatus & ~MSTATUS_SPP) | (spp_code << 8)
        self.mstatus_val = mstatus

        # 切换到 S 模式
        self.mode = RiscvMode.S

        # 跳转到 stvec
        stvec = self.csrs["stvec"].val
        tvec_mode = stvec & 0x3
        tvec_base = stvec & ~0x3
        if tvec_mode == 0 or not is_interrupt:
            self.pc = tvec_base
        else:
            # vectored: 所有异常跳转 BASE, 中断跳转 BASE + 4 * exc_code
            self.pc = tvec_base + 4 * exc_code

    # ---- M 模式 trap 投递 ----

    def _trap_deliver_mmode(
        self,
        code: int,
        exc_code: int,
        tval: int,
        is_interrupt: bool,
    ) -> None:
        """将 trap 投递到 M 模式: 保存上下文到 M 模式 CSR 并跳转 mtvec."""
        # 保存当前 PC
        self.mepc_val = self.pc

        # 设置 mcause
        self.mcause_val = code

        # 设置 mtval
        self.mtval_val = tval

        # 更新 mstatus:
        #   MPIE <- MIE
        #   MIE  <- 0
        #   MPP  <- 当前特权级
        mstatus = self.mstatus_val
        if mstatus & MSTATUS_MIE:
            mstatus |= MSTATUS_MPIE
        else:
            mstatus &= ~MSTATUS_MPIE
        mstatus &= ~MSTATUS_MIE

        # MPP <- 当前 mode
        _mpp_map = {RiscvMode.U: 0, RiscvMode.S: 1, RiscvMode.M: 3}
        mpp_code = _mpp_map.get(self.mode, 0)
        mstatus = (mstatus & ~MSTATUS_MPP) | (mpp_code << 11)

        # RISC-V spec: MPRV is cleared on trap entry to M-mode so the
        # handler can safely access its own stack/data without going
        # through the MMU translation of the previous privilege mode.
        mstatus &= ~(1 << 17)  # clear MPRV

        self.mstatus_val = mstatus

        # 切换到 M 模式
        self.mode = RiscvMode.M

        # 跳转到 mtvec
        mtvec = self.csrs["mtvec"].val
        tvec_mode = mtvec & 0x3
        tvec_base = mtvec & ~0x3
        if tvec_mode == 0 or not is_interrupt:
            self.pc = tvec_base
        else:
            self.pc = tvec_base + 4 * exc_code

    #  ECALL / EBREAK / MRET / SRET

    def trap_ecall(
        self,
    ) -> None:
        """ECALL: 根据当前特权级触发相应的环境调用 trap."""
        _ecall_map: dict[RiscvMode, TrapType] = {
            RiscvMode.U: TrapType.EcallFromUmode,
            RiscvMode.S: TrapType.EcallFromSmode,
            RiscvMode.M: TrapType.EcallFromMmode,
        }
        cause = _ecall_map.get(self.mode)
        if cause is None:
            cause = TrapType.IllInstr
        self.deliver_trap(cause, tval=self.pc, is_interrupt=False)

    def _sh_read_ram(
        self,
        pa: int,
        size: int,
    ) -> bytes:
        """读物理 RAM *size* 字节; 越界返回全零, 与加速执行引擎的
        read_ram_u64/u8 一致.

        加速执行引擎仅在 ``[ram_base, ram_base + ram_size)`` 内读, 越界视为 0;
        设备 MMIO 地址不在此范围内, 一并视为越界.
        """
        bus = self._bus
        if bus is None or size < 1:
            return b"\x00" * size
        if not bus.is_ram_addr(pa) or not bus.is_ram_addr(pa + size - 1):
            return b"\x00" * size
        ram: bytearray = bus._ram
        off = pa - bus.ram_base
        return bytes(ram[off : off + size])

    def _semihosting_markers_match(
        self,
    ) -> bool:
        """检测 hart.pc 处的 ebreak 是否处于 semihosting marker 序列中.

        identity (VA=PA) 映射下 pc 即物理地址, 直接经 Bus 读取固件字节.
        """
        bus = self._bus
        if bus is None:
            return False
        data = bus.try_read(self.pc - 4, 12)
        if data is None or len(data) < 12:
            return False
        return (
            int.from_bytes(data[0:4], "little") == SEMIHOSTING_PRE
            and int.from_bytes(data[8:12], "little") == SEMIHOSTING_POST
        )

    def _semihosting_service(
        self,
    ) -> None:
        """服务带 marker 的 ebreak, 与加速执行引擎的 try_semihosting 语义一致.

        按 a0 操作码分发, 结果写回 a0, 并将 pc 前进 8 越过 ebreak 与退出 marker,
        使序列余下的 ``sext.w/bltz`` 等指令自然处理返回值. SYS_EXIT 除外: 置停机
        标记供 run() 返回, 与纯 Python 引擎原有的处理相同, 不投递断点 trap.
        """
        op = self.gprs[10]
        param = self.gprs[11]
        if op == SEMIHOSTING_SYS_EXIT:
            self._semihosting_sys_exit = True
            return
        if op == SEMIHOSTING_SYS_WRITEC:
            # 参数块指向单个字符
            ch = self._sh_read_ram(param, 1)[0]
            semihosting_write_stderr(bytes([ch]))
            self.gprs[10] = 0
        elif op == SEMIHOSTING_SYS_WRITE:
            # 参数块: fd / buf 物理地址 / 长度
            fd = int.from_bytes(self._sh_read_ram(param, 8), "little")
            buf_addr = int.from_bytes(self._sh_read_ram(param + 8, 8), "little")
            length = int.from_bytes(self._sh_read_ram(param + 16, 8), "little")
            bus = self._bus
            if length == 0:
                self.gprs[10] = 0
            elif fd not in (1, 2):
                self.gprs[10] = SEMIHOSTING_ERR
            elif (
                bus is None
                or not bus.is_ram_addr(buf_addr)
                or not bus.is_ram_addr(buf_addr + length - 1)
            ):
                self.gprs[10] = SEMIHOSTING_ERR
            else:
                semihosting_write_stderr(self._sh_read_ram(buf_addr, length))
                self.gprs[10] = 0
        elif op == SEMIHOSTING_SYS_OPEN:
            # 返回合法的 fd, 使固件探测时认为存在宿主, 与加速执行引擎一致
            self.gprs[10] = 1
        elif op == SEMIHOSTING_SYS_ISTTY:
            fd = int.from_bytes(self._sh_read_ram(param, 8), "little")
            self.gprs[10] = 1 if fd <= 2 else 0
        else:
            self.gprs[10] = SEMIHOSTING_ERR
        self.pc = mask64(self.pc + 8)

    def trap_ebreak(
        self,
    ) -> None:
        """EBREAK: 断点异常."""
        # semihosting marker 序列不投递断点 trap, 由 _semihosting_service
        # 内联服务, SYS_EXIT 置停机标记供 run() 返回. 加速执行引擎的处理与此
        # 一致, 详见上方注释. PYREMU_HAS_SEMIHOSTING=0 时该序列按普通 ebreak
        # 投递断点 trap, 固件的探测因此判定宿主不支持, 控制台回落到 UART.
        if PYREMU_HAS_SEMIHOSTING and self._semihosting_markers_match():
            self._semihosting_service()
            return
        self.deliver_trap(TrapType.Breakpoint, tval=self.pc, is_interrupt=False)

    def trap_mret(
        self,
    ) -> None:
        """MRET: 从 M 模式 trap 返回.

        恢复进入 M 模式 trap 前保存的特权级和中断使能状态.
        仅在 M 模式下合法; 否则触发 IllInstr.
        """
        if self.mode != RiscvMode.M:
            self.deliver_trap(
                TrapType.IllInstr, tval=0x30200073, is_interrupt=False
            )
            return
        mstatus = self.mstatus_val

        # 恢复特权级
        mpp = (mstatus & MSTATUS_MPP) >> 11
        _mpp_to_mode = {0: RiscvMode.U, 1: RiscvMode.S, 3: RiscvMode.M}
        self.mode = _mpp_to_mode.get(mpp, RiscvMode.U)

        # 返回特权级低于 M 时清除 MPRV (RISC-V 特权规范 §3.3.2)
        if self.mode != RiscvMode.M:
            mstatus &= ~MSTATUS_MPRV

        # 恢复中断使能: MIE <- MPIE, 然后 MPIE <- 1
        if mstatus & MSTATUS_MPIE:
            mstatus |= MSTATUS_MIE
        else:
            mstatus &= ~MSTATUS_MIE
        mstatus |= MSTATUS_MPIE

        # MPP设置为U模式
        mstatus &= ~MSTATUS_MPP
        self.mstatus_val = mstatus

        self.pc = mask64(self.mepc_val)

        # 不在此处清除 _wfi_woken.
        # _wfi_woken 由 deliver_trap 在从 WFI 唤醒时置位, 意在让紧随其后的
        # handle_wfi 将 WFI 视为 NOP 并推进 PC, 从而允许 while (...) wfi()
        # 轮询循环在 trap handler 返回后重新检查状态条件.
        # 若在此处提前清除, handle_wfi 将看不到该标记, hart 立即重回睡眠.

    def trap_sret(
        self,
    ) -> None:
        """SRET: 从 S 模式 trap 返回.

        恢复进入 S 模式 trap 前保存的特权级和中断使能状态.
        在 S/M 模式下合法; U 模式下触发 IllInstr.
        mstatus.TSR=1 时 S 模式执行触发 IllInstr, M 模式不受该位约束.
        """
        if self.mode == RiscvMode.U:
            self.deliver_trap(
                TrapType.IllInstr, tval=0x10200073, is_interrupt=False
            )
            return
        if self.mode == RiscvMode.S and self.mstatus_val & MSTATUS_TSR:
            self.deliver_trap(
                TrapType.IllInstr, tval=0x10200073, is_interrupt=False
            )
            return
        mstatus = self.mstatus_val

        # 恢复特权级
        spp = (mstatus & MSTATUS_SPP) >> 8
        self.mode = RiscvMode.U if spp == 0 else RiscvMode.S

        # 返回特权级低于 M 时清除 MPRV (RISC-V 特权规范 §3.3.2)
        mstatus &= ~MSTATUS_MPRV

        # 恢复中断使能: SIE <- SPIE, 然后 SPIE <- 1
        if mstatus & MSTATUS_SPIE:
            mstatus |= MSTATUS_SIE
        else:
            mstatus &= ~MSTATUS_SIE
        mstatus |= MSTATUS_SPIE

        # SPP <- U
        mstatus &= ~MSTATUS_SPP
        self.mstatus_val = mstatus

        # PC <- sepc
        self.pc = mask64(self.sepc_val)

        # 不在此处清除 _wfi_woken (同 trap_mret 的注释说明).

    #  WFI (Wait For Interrupt) — 低功耗等待

    def handle_wfi(
        self,
        instr: int,
    ) -> None:
        """WFI 指令: 若已有待处理的使能中断则立即返回 (NOP);
        否则 hart 进入等待状态, 由中断唤醒.

        RISC-V Privileged Spec §3.3.5:
        - WFI 是一个 hint; 实现可将其视为 NOP
        - 若中断已挂起且使能, WFI 不等待, 继续执行
        - 等待状态下中断挂起且使能时 hart 被唤醒
        - 唤醒后 PC 指向 WFI 下一条指令; 若中断可被响应则走正常中断处理
        - mstatus.TW=1 且非 M 模式时执行 WFI -> IllInstr

        注意: 等待期间不检查 mstatus.MIE, 仅 mip & mie 非零即可唤醒.
        """
        # 超时等待位 TW 检查: 非 M 模式下 mstatus.TW=1 则触发非法指令异常
        if self.mode != RiscvMode.M and self.mstatus_val & MSTATUS_TW:
            self.deliver_trap(TrapType.IllInstr, tval=instr, is_interrupt=False)
            return

        # 刚被中断唤醒 (MRET 回到 WFI): 视为 NOP, 推进 PC 以允许
        # while (state != READY) wfi() 轮询循环在 trap handler 返回后
        # 重新检查状态条件. 若仍不满足, 下次 WFI 会正常进入等待.
        if self._wfi_woken:
            self._wfi_woken = False
            return

        # 检查是否已有待处理且使能的中断
        # 若 mip & mie 非零, 立即返回 (NOP, PC 将 +4)
        if self.mip_val & self.mie_val:
            return  # 正常返回, 调用方会将 PC+4

        # 无可处理中断则进入等待状态, 重置唤醒标记
        self._waiting = True
        self._wfi_woken = False

    def sync_pending_interrupts(self) -> None:
        """把全部硬件中断源的挂起状态写入 mip CSR.

        中断源包括 CLINT 的 MSIP/MTIP、STIP, 以及 IMSIC 或 PLIC 给出的
        MEIP/SEIP. STIP 取 sstc 的 stimecmp 比较结果; 未使用 sstc 时取软件
        写入的 mip.STIP. mip 中由硬件驱动的位被当前状态替换, 已撤除的中断源
        不会残留. mie 的使能位由受调试程序自行设置, 同步时不改变.
        """
        ctrl = self._interrupt_ctrl
        if ctrl is None:
            return

        # 将 CLINT 中断状态同步到 mip CSR
        _, mip_bits, _ = ctrl.check_interrupt(self.id)

        # STIP: sstc 的 stimecmp, 或未使用 sstc 时软件写入的 mip.STIP.
        # CLINT.check_interrupt 只返回 MSIP/MTIP, 不含 STIP, 故需在此补齐.
        mip_bits, _ = self._resolve_stip(mip_bits, ctrl)

        # AIA IMSIC 或 PLIC 外部中断 (MEIP/SEIP). IMSIC 存在时总是查询它:
        # get_pending_mip 的原始 eip 回退在 eidelivery=0 时仍能报告 IPI.
        ext_mip = 0
        if self._imsic is not None:
            ext_mip = self._imsic.get_pending_mip(self.id)
        if ext_mip == 0 and self._plic is not None:
            ext_mip = self._plic.get_pending_mip(self.id)
        mip_bits |= ext_mip

        self.update_hw_mip(mip_bits)

    def wake_hart_from_wfi(self) -> bool:
        """判定 hart 是否应退出 WFI 等待, 命中时清除等待状态.

        调用前须先经 sync_pending_interrupts 把硬件中断源写入 mip.

        WFI 的 NOP 条件 (RISC-V spec §3.6.1) 只要求任一中断挂起且该中断源在 mie
        CSR 中使能, 不要求全局中断使能 mstatus.MIE. 没有任何中断源挂起, 或挂起
        的中断源均未使能时, hart 继续等待.

        唤醒时置位 _wfi_woken, 供紧随其后执行的第一条 WFI 按 NOP 处理, 使
        while (cond) wfi(); 形式的循环得以重新检查条件.
        """
        if not self._waiting or self._halted or self._interrupt_ctrl is None:
            return False

        hw_mip_bits = self.mip_val & HW_MIP_MASK
        # 没有任何硬件中断源挂起时不唤醒
        if hw_mip_bits == 0:
            return False
        # 唤醒条件取 mip & mie
        if (self.mip_val & self.mie_val) == 0:
            return False

        self._waiting = False
        self._wfi_woken = True
        return True

    def check_pending_interrupts(self) -> bool:
        """在指令边界检查是否有待处理且使能的中断.

        若有, 则通过 _take_trap 注入中断并返回 True;
        否则返回 False.

        优先级: MEI > MSI > MTI > SEI > SSI > STI
        (RISC-V Privileged Spec §3.1.9)

        支持通过 mideleg 将中断委派到 S 模式处理:
        - M 模式 + MIE=0: 全局关中断, 不响应任何中断
        - S 模式 + SIE=0: 仅非委派 (M 级) 中断可抢占; 已委派中断被阻塞
        - U 模式: 全部中断全局使能
        """
        if self._interrupt_ctrl is None:
            return False

        ctrl = self._interrupt_ctrl

        # 1. CLINT: 定时器 + 软件中断
        has_pending, mip_bits, _ = ctrl.check_interrupt(self.id)

        # 2. STIP: sstc 的 stimecmp, 或未使用 sstc 时软件写入的 mip.STIP
        mip_bits, has_sti = self._resolve_stip(mip_bits, ctrl)
        has_pending = has_pending or has_sti

        # 3. 外部中断: IMSIC (AIA) 或 PLIC (legacy) — MEIP/SEIP
        #    IMSIC 通过 eidelivery 控制当前谁在驱动外部中断线:
        #    eidelivery=1 -> MSI 模式, IMSIC eip/eie 驱动 MEIP/SEIP.
        #    eidelivery=0 -> legacy 模式, ext_irq drain 驱动 MEIP/SEIP.
        ext_mip = 0
        if self._imsic is not None:
            ext_mip = self._imsic.get_pending_mip(self.id)
        if ext_mip == 0 and self._plic is not None:
            ext_mip = self._plic.get_pending_mip(self.id)

        # 合并全部硬件中断源
        mip_bits = mip_bits | ext_mip

        # 更新 mip CSR: 用当前硬件状态替换硬件源位, 保留软件写入位.
        # 必须在 early return 之前执行 — 即使无 pending 中断, 也要清除已撤除的
        # 硬件源位, 如 MSIP 清零后 mip.MSIP 需同步为 0, 否则旧位残留
        # 导致下次 mip & mie 仍命中, 随后出现 MSIP 风暴.
        self.update_hw_mip(mip_bits)

        if not has_pending and ext_mip == 0:
            return False

        # M 模式且 MIE=0 则关闭全局中断
        if self.mode == RiscvMode.M and not self.mie:
            return False

        mie = self.mie_val
        masked = self.mip_val & mie
        if masked == 0:
            return False

        # S 模式全局中断使能 (用于已委派的中断).
        # 用预计算 mode int 替代 .value property 访问.
        mode_int = self.mode.value
        mideleg = self.csrs["mideleg"].val
        s_mode_global = mode_int < MODE_S_VALUE or (
            self.mode == RiscvMode.S and self.sie
        )

        ret = False
        # 按优先级找最高优先级的使能中断.
        # 使用模块级预计算常量, 避免每条指令分配 list + 6 tuple.
        for mask, trap_type in INT_PRIORITY:
            if not (masked & mask):
                continue
            # 已委派到 S 的中断: 需检查 S 模式全局使能
            if (mideleg & mask) and not s_mode_global:
                continue
            self.deliver_trap(trap_type, tval=0, is_interrupt=True)
            ret = True
            break
        return ret

    #  Nested-interrupt-enabled 变体

    def deliver_trap_nested_enabled(
        self,
        cause: TrapType,
        tval: int = 0,
        is_interrupt: bool = False,
    ) -> None:
        """deliver_trap 的嵌套中断变体.

        与 deliver_trap 相同, 但用于嵌套中断投递场景 (中断 handler 内再次触发
        中断).
        """
        self.clear_reservation()
        was_wfi = self._waiting
        self._waiting = False
        if was_wfi:
            self._wfi_woken = True

        code = trap_cause_code(cause)
        exc_code = code & 0x7FFF_FFFF_FFFF_FFFF

        delegate = False
        if self.mode != RiscvMode.M:
            choice = (
                self.csrs["mideleg"].val
                if is_interrupt
                else self.csrs["medeleg"].val
            )
            delegate = bool(choice & (1 << exc_code))

        fn = self._trap_deliver_smode if delegate else self._trap_deliver_mmode
        fn(code, exc_code, tval, is_interrupt)

    def check_pending_interrupts_nested_enabled(
        self,
    ) -> bool:
        """check_pending_interrupts 的嵌套中断变体.

        使用 deliver_trap_nested_enabled 而非 deliver_trap,
        使得嵌套中断不会触发连续 trap 计数.
        由开启嵌套中断的 trap handler (如汇编中的 s_trap_handler_nested_enabled)
        通过重新使能 SIE 后交由指令边界的本函数处理.
        """
        if self._interrupt_ctrl is None:
            return False

        ctrl = self._interrupt_ctrl

        # 1. CLINT: 定时器 + 软件中断
        has_pending, mip_bits, _ = ctrl.check_interrupt(self.id)

        # 2. STIP: sstc 的 stimecmp, 或未使用 sstc 时软件写入的 mip.STIP
        mip_bits, has_sti = self._resolve_stip(mip_bits, ctrl)
        has_pending = has_pending or has_sti

        # 3. 外部中断: IMSIC (AIA) 或 PLIC (legacy) — MEIP/SEIP
        #    IMSIC 通过 eidelivery 控制当前谁在驱动外部中断线:
        #    eidelivery=1 -> MSI 模式, IMSIC eip/eie 驱动 MEIP/SEIP.
        #    eidelivery=0 -> legacy 模式, ext_irq drain 驱动 MEIP/SEIP.
        ext_mip = 0
        if self._imsic is not None:
            ext_mip = self._imsic.get_pending_mip(self.id)
        if ext_mip == 0 and self._plic is not None:
            ext_mip = self._plic.get_pending_mip(self.id)

        # 合并全部硬件中断源
        mip_bits = mip_bits | ext_mip

        # 更新 mip CSR: 用当前硬件状态替换硬件源位, 保留软件写入位.
        self.update_hw_mip(mip_bits)

        if not has_pending and ext_mip == 0:
            return False

        if self.mode == RiscvMode.M and not self.mie:
            return False

        masked = self.mip_val & self.mie_val
        if masked == 0:
            return False

        mideleg = self.csrs["mideleg"].val
        s_mode_global = self.mode.value < RiscvMode.S.value or (
            self.mode == RiscvMode.S and self.sie
        )

        # 使用模块级预计算常量, 避免每条指令分配 list + 6 tuple.
        ret = False
        for mask, trap_type in INT_PRIORITY:
            if not (masked & mask) or ((mideleg & mask) and not s_mode_global):
                continue
            self.deliver_trap_nested_enabled(
                trap_type,
                tval=0,
                is_interrupt=True,
            )
            ret = True
            break
        return ret
