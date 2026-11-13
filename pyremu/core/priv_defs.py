#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""特权级与 mstatus 位字段定义.

hart 的操作类与 hart.py 都依赖这些定义, 单独成模块以避免相互导入.
"""

from __future__ import annotations

from enum import Enum


class RiscvMode(Enum):
    """RISC-V 特权级模式。

    数值按标准 RISC-V 特权级编码:
        U=0 (用户), S=1 (监管), H=2 ( hypervisor ),
        M=3 (机器), D=8 (调试).
    """

    U = 0
    S = 1
    H = 2
    M = 3
    D = 8


#  mstatus / sstatus 位字段定义 (RV64)

# 这些常量用于按位读写 mstatus CSR 中的关键控制位。

MSTATUS_SIE = 1 << 1  # Supervisor 中断使能
MSTATUS_MIE = 1 << 3  # Machine 中断使能
MSTATUS_SPIE = 1 << 5  # Supervisor 先前中断使能 (进入 trap 前)
MSTATUS_UBE = 1 << 6  # 用户模式大端 (通常为 0)
MSTATUS_MPIE = 1 << 7  # Machine 先前中断使能 (进入 trap 前)
MSTATUS_SPP = 1 << 8  # Supervisor 先前特权级 (0=U, 1=S)
MSTATUS_VS = 0b11 << 9  # 虚拟化状态 (H 扩展)
MSTATUS_MPP = 0b11 << 11  # Machine 先前特权级 (0=U, 1=S, 3=M)
MSTATUS_FS = 0b11 << 13  # 浮点单元状态
MSTATUS_XS = 0b11 << 15  # 用户扩展状态
MSTATUS_MPRV = 1 << 17  # 修改特权级下的内存访问特权
MSTATUS_SUM = 1 << 18  # 允许 S 模式访问 U 模式页
MSTATUS_MXR = 1 << 19  # 使能可执行内存的可读
MSTATUS_TVM = 1 << 20  # 陷入 S 模式访问 satp
MSTATUS_TW = 1 << 21  # 陷入 WFI
MSTATUS_TSR = 1 << 22  # 陷入 SRET
MSTATUS_UXL = 0b11 << 32  # 用户级 XLEN 字段, RV64 上只读
MSTATUS_UXL_64 = 0b10 << 32  # mstatus.UXL 的读出值, 表示 U 模式为 64 位
MSTATUS_SD = 1 << 63  # 状态脏位, 由 FS、VS、XS 是否为 3 算出
