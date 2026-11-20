# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""加速执行 Ops — 调用方唯一入口, 不区分后端是动态库还是纯 Python.

各子模块按功能域组织:
- decode: 指令字段解码
- compressed: 16 位压缩指令的处理方法与象限分发
- ext_isa: 扩展判定
- alu / fpu: 整数与浮点计算
- mmu: Sv39 页表项拆解、合成与页大小
- pmp: PMP 访问检查
- mem: 主存直接读写
- engine: 连续执行的配置与 run_parallel 调用
- hart_ffi: hart 与加速执行引擎之间的状态编组

依赖方向: 本包只导入实现后端 (``pyremu._native`` 与 ``pyremu.decoder``)、
``pyremu.core.priv_defs`` 的枚举与公共工具; 消费方 (``pyremu.emu``、调试器与
用例) 导入本包, 实现后端不导入本包.
"""

from __future__ import annotations

from pyremu._native import (
    CompressedFields,
    DecodedFields,
    FfiExtIrqCtx,
    FfiUartCtx,
    HartState,
    InstrToBeExec,
    native_available,
    PteFields,
    Sv39Vpn,
    termio_attach,
    termio_available,
    termio_is_running,
    termio_set_emu_stop_flag,
    termio_stop,
    TermIoHandle,
)
from pyremu.generic_ops import (
    alu,
    compressed,
    decode,
    engine,
    ext_isa,
    fpu,
    mem,
    mmu,
    pmp,
)
from pyremu.generic_ops.alu import (
    exec_alu,
    exec_op32,
    exec_op_imm,
    exec_op_imm32,
)
from pyremu.generic_ops.compressed import CompressedInstrOps
from pyremu.generic_ops.decode import decode_compressed, decode_fields
from pyremu.generic_ops.engine import (
    ClintInfo,
    DevInfo,
    PlicInfo,
    PmpInfo,
    run_parallel,
    RunConfig,
    TlbFlushCounter,
    UartInfo,
    VirtIOInfo,
)
from pyremu.generic_ops.ext_isa import check_ext_isa
from pyremu.generic_ops.fpu import fp_exec_fma, fp_exec_op
from pyremu.generic_ops.hart_ffi import HartFfiOps
from pyremu.generic_ops.mem import RamView, read_ram
from pyremu.generic_ops.mmu import (
    pte_assemble_pa,
    pte_parse,
    sv39_decompose_va,
    sv39_page_size,
)

__all__ = [
    "alu",
    "check_ext_isa",
    "ClintInfo",
    "compressed",
    "CompressedFields",
    "CompressedInstrOps",
    "decode",
    "decode_compressed",
    "decode_fields",
    "DecodedFields",
    "DevInfo",
    "engine",
    "exec_alu",
    "exec_op_imm",
    "exec_op_imm32",
    "exec_op32",
    "ext_isa",
    "FfiExtIrqCtx",
    "FfiUartCtx",
    "fp_exec_fma",
    "fp_exec_op",
    "fpu",
    "HartFfiOps",
    "HartState",
    "InstrToBeExec",
    "mem",
    "mmu",
    "native_available",
    "pmp",
    "PmpInfo",
    "pte_assemble_pa",
    "PteFields",
    "pte_parse",
    "PlicInfo",
    "RamView",
    "read_ram",
    "run_parallel",
    "RunConfig",
    "sv39_decompose_va",
    "sv39_page_size",
    "Sv39Vpn",
    "TermIoHandle",
    "termio_attach",
    "termio_available",
    "termio_is_running",
    "termio_set_emu_stop_flag",
    "termio_stop",
    "TlbFlushCounter",
    "UartInfo",
    "VirtIOInfo",
]


def __dir__() -> list[str]:
    return sorted(__all__)
