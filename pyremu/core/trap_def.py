#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
# Created at 2026/06/06 星期六 23:19:24
# Last modified at 2026/06/08 星期一

"""
RISC-V 特权架构定义的 trap 类型及对应的 mcause/scause 编码。

另收录中断优先级、硬件中断源占用的 mip 位与 semihosting 序列常数。
"""

from enum import Enum
import os

from pyremu.core.priv_defs import RiscvMode
from pyremu.interrupt.controller import INT_SOURCE_MIP_MASK, IntSource

TrapType = Enum(
    "TrapType",
    (
        # === 异常 (Exception) ===
        "InstrAddrMisaligned",  # 0: 指令地址未对齐
        "InstrAccessFault",  # 1: 指令访问错误
        "IllInstr",  # 2: 非法指令
        "Breakpoint",  # 3: 断点 (ebreak)
        "LdAddrMisaligned",  # 4: 载入地址未对齐
        "LdAccessFault",  # 5: 载入访问错误
        "StAddrMisaligned",  # 6: 存储地址未对齐
        "StAccessFault",  # 7: 存储访问错误
        "EcallFromUmode",  # 8: U 模式 ecall
        "EcallFromSmode",  # 9: S 模式 ecall  (also VS-mode)
        "EcallFromHmode",  # 10: HS-mode ecall (reserved)
        "EcallFromMmode",  # 11: M 模式 ecall
        "InstrPageFault",  # 12: 指令页错误
        "LdPageFault",  # 13: 载入页错误
        "StPageFault",  # 15: 存储页错误
        # H-extension guest-page faults (RISC-V privileged spec §8.6.2)
        "InstrGuestPageFault",  # 20: 指令 guest-physical 地址页错误
        "LdGuestPageFault",  # 21: 载入 guest-physical 地址页错误
        "VirtualInstruction",  # 22: 虚拟指令 (HLVID emulation)
        "StGuestPageFault",  # 23: 存储 guest-physical 地址页错误
        # === 中断 (Interrupt) — mcause bit 63 置 1 ===
        "SoftInterrupt",  # 软件中断 (通用)
        "UmodeSoftInterrupt",  # 0: U 模式软件中断
        "SmodeSoftInterrupt",  # 1: S 模式软件中断
        "MmodeSoftInterrupt",  # 3: M 模式软件中断
        "UmodeTimerInterrupt",  # 4: U 模式定时器中断
        "SmodeTimerInterrupt",  # 5: S 模式定时器中断
        "MmodeTimerInterrupt",  # 7: M 模式定时器中断
        "UmodeExternInterrupt",  # 8: U 模式外部中断
        "SmodeExternInterrupt",  # 9: S 模式外部中断
        "MmodeExternInterrupt",  # 11: M 模式外部中断
        "HmodeSoftInterrupt",  # 2 (interrupt):  HS-mode 软件中断
        "HmodeTimerInterrupt",  # 6 (interrupt):  HS-mode 定时器中断
        "HmodeExternInterrupt",  # 10 (interrupt): HS-mode 外部中断
        "VSmodeSoftInterrupt",  # 2 (interrupt):  VS-mode 软件中断
        "VSmodeTimerInterrupt",  # 6 (interrupt):  VS-mode 定时器中断
        "VSmodeExternInterrupt",  # 10 (interrupt): VS-mode 外部中断
    ),
)


#  TrapType -> mcause/scause 编码映射
#  异常: code = 直接编号, bit 63 = 0
#  中断: code = 直接编号, bit 63 = 1


# 每个 TrapType 对应的 mcause 异常/中断编号
_TRAP_CAUSE_CODE: dict[TrapType, int] = {
    # 异常
    TrapType.InstrAddrMisaligned: 0,
    TrapType.InstrAccessFault: 1,
    TrapType.IllInstr: 2,
    TrapType.Breakpoint: 3,
    TrapType.LdAddrMisaligned: 4,
    TrapType.LdAccessFault: 5,
    TrapType.StAddrMisaligned: 6,
    TrapType.StAccessFault: 7,
    TrapType.EcallFromUmode: 8,
    TrapType.EcallFromSmode: 9,
    # HS-mode ecall -> 10 (reserved in spec; used here)
    TrapType.EcallFromHmode: 10,
    TrapType.EcallFromMmode: 11,
    TrapType.InstrPageFault: 12,
    TrapType.LdPageFault: 13,
    TrapType.StPageFault: 15,
    # H-extension guest-page faults
    TrapType.InstrGuestPageFault: 20,
    TrapType.LdGuestPageFault: 21,
    TrapType.VirtualInstruction: 22,
    TrapType.StGuestPageFault: 23,
    # 中断
    TrapType.SoftInterrupt: 1 | (1 << 63),
    TrapType.UmodeSoftInterrupt: 0 | (1 << 63),
    TrapType.SmodeSoftInterrupt: 1 | (1 << 63),
    TrapType.MmodeSoftInterrupt: 3 | (1 << 63),
    TrapType.HmodeSoftInterrupt: 2 | (1 << 63),
    TrapType.VSmodeSoftInterrupt: 2 | (1 << 63),
    TrapType.UmodeTimerInterrupt: 4 | (1 << 63),
    TrapType.SmodeTimerInterrupt: 5 | (1 << 63),
    TrapType.MmodeTimerInterrupt: 7 | (1 << 63),
    TrapType.HmodeTimerInterrupt: 6 | (1 << 63),
    TrapType.VSmodeTimerInterrupt: 6 | (1 << 63),
    TrapType.UmodeExternInterrupt: 8 | (1 << 63),
    TrapType.SmodeExternInterrupt: 9 | (1 << 63),
    TrapType.MmodeExternInterrupt: 11 | (1 << 63),
    TrapType.HmodeExternInterrupt: 10 | (1 << 63),
    TrapType.VSmodeExternInterrupt: 10 | (1 << 63),
}


def trap_cause_code(trap: TrapType) -> int:
    """返回 TrapType 对应的 mcause/scause 编码值 (含中断标志位)."""
    return _TRAP_CAUSE_CODE.get(trap, 0)


def trap_is_interrupt(trap: TrapType) -> bool:
    """判断该 TrapType 是否为中断 (而非异常)."""
    code = _TRAP_CAUSE_CODE.get(trap, 0)
    return (code >> 63) & 1 == 1


#  中断优先级与硬件中断源的 mip 位


# 中断优先级列表, 按优先级从高到低排列.
# 预计算为模块级常量, 避免每条指令分配 list 与 6 个 tuple.
INT_PRIORITY: list[tuple[int, TrapType]] = [
    (1 << 11, TrapType.MmodeExternInterrupt),  # MEI
    (1 << 3, TrapType.MmodeSoftInterrupt),  # MSI
    (1 << 7, TrapType.MmodeTimerInterrupt),  # MTI
    (1 << 9, TrapType.SmodeExternInterrupt),  # SEI
    (1 << 1, TrapType.SmodeSoftInterrupt),  # SSI
    (1 << 5, TrapType.SmodeTimerInterrupt),  # STI
]

# 硬件源管理的 mip 位掩码 (只读位, 反映外部中断信号).
# 这些位在中断检查中必须用硬件当前状态替换, 不能与旧值按位或累加,
# 否则硬件源撤除后旧位仍留在 mip CSR 中, 引起无限重投递.
HW_MIP_MASK: int = (
    INT_SOURCE_MIP_MASK[IntSource.MSI]  # bit 3 — CLINT _msip[hart_id]
    | INT_SOURCE_MIP_MASK[IntSource.MTI]  # bit 7 — CLINT _mtimecmp
    | INT_SOURCE_MIP_MASK[IntSource.STI]  # bit 5 — sstc stimecmp 或软件写入
    | INT_SOURCE_MIP_MASK[IntSource.MEI]  # bit 11 — PLIC
    | INT_SOURCE_MIP_MASK[IntSource.SEI]  # bit 9 — PLIC
)

# S 模式编码, 供中断检查比较特权级数值时免去枚举成员取值.
MODE_S_VALUE: int = RiscvMode.S.value


#  RISC-V semihosting 序列

# 调用序列为 ``slli x0,x0,0x1f; ebreak; srai x0,x0,7``, a0 存放操作码, a1 存放
# 参数块指针; marker 指令编码与加速执行引擎 handlers.rs 的 SEMIHOSTING_PRE/POST
# 一致.
# 带 marker 的 ebreak 内联服务 SYS_WRITE / SYS_WRITEC / SYS_OPEN / SYS_ISTTY,
# SYS_EXIT 置停机标记供 run() 返回; 两者都不投递断点 trap.

SEMIHOSTING_SYS_OPEN: int = 0x01
SEMIHOSTING_SYS_WRITEC: int = 0x03
SEMIHOSTING_SYS_WRITE: int = 0x05
SEMIHOSTING_SYS_ISTTY: int = 0x09
SEMIHOSTING_SYS_EXIT: int = 0x18
SEMIHOSTING_PRE: int = 0x01F01013  # slli x0, x0, 0x1f
SEMIHOSTING_POST: int = 0x40705013  # srai x0, x0, 7
# 加速执行引擎的 semihosting_dispatch 对不可识别的操作码与非法参数一律返回 -1.
SEMIHOSTING_ERR: int = 0xFFFF_FFFF_FFFF_FFFF  # -1 的 64 位表示


def semihosting_write_stderr(data: bytes) -> None:
    """把 semihosting 输出写到 stderr (fd 2), 与加速执行引擎的处理一致.

    写到 stderr 可避免污染 stdout 上的调试器界面与 UART 转发行; os.write 绕过
    Python 的 stdio 缓冲, 与 Rust 侧 write(2, ...) 等价.
    """
    try:
        os.write(2, data)
    except OSError, ValueError:
        pass


# mcause/scause 编码到 TrapType 名称的逆向映射
_CAUSE_CODE_NAME: dict[int, str] = {
    code: trap.name for trap, code in _TRAP_CAUSE_CODE.items()
}


def trap_cause_name(mcause_val: int) -> str:
    """将 mcause/scause 寄存器值翻译为可读的 trap 类型名称.

    Args:
        mcause_val: mcause/scause CSR 的原始值 (含 bit-63 中断标志).

    Returns:
        TrapType 成员名 (如 "IllInstr", "MmodeTimerInterrupt"),
        若未精确匹配则返回 ``"异常#N"`` 或 ``"中断#N"``.
    """
    name = _CAUSE_CODE_NAME.get(mcause_val)
    if name:
        return name
    is_irq = (mcause_val >> 63) & 1
    exc_code = mcause_val & 0x7FFF_FFFF_FFFF_FFFF
    prefix = "中断" if is_irq else "异常"
    return f"{prefix}#{exc_code}"
