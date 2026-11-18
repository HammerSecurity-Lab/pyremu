# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""加速执行 Ops — 调用方唯一入口, 不区分后端是动态库还是纯 Python.

各子模块按功能域组织, 由本包按需导入: 子模块会连带导入 ``pyremu.memory`` 等
上层模块, 逐个在包初始化时导入会与 ``memory.bus`` 对 Ops 的引用形成循环, 故
属性一律在首次访问时导入.

- decode: 指令字段解码
- ext_isa: 扩展判定
- alu / fpu: 整数与浮点计算
- mmu: Sv39 页表项拆解、合成与页大小
- pmp: PMP 访问检查
- mem: 主存直接读写
- engine: 连续执行的配置与 run_parallel 调用
"""

from __future__ import annotations

import importlib

# 子模块名到模块路径
_SUBMODULES: dict[str, str] = {
    "alu": "pyremu.generic_ops.alu",
    "decode": "pyremu.generic_ops.decode",
    "engine": "pyremu.generic_ops.engine",
    "ext_isa": "pyremu.generic_ops.ext_isa",
    "fpu": "pyremu.generic_ops.fpu",
    "mem": "pyremu.generic_ops.mem",
    "mmu": "pyremu.generic_ops.mmu",
    "pmp": "pyremu.generic_ops.pmp",
}

# 成员名到所在子模块的模块路径
_ATTRIBUTES: dict[str, str] = {
    "read_ram": "pyremu.generic_ops.mem",
    "check_ext_isa": "pyremu.generic_ops.ext_isa",
    "ClintInfo": "pyremu.generic_ops.engine",
    "DevInfo": "pyremu.generic_ops.engine",
    "PlicInfo": "pyremu.generic_ops.engine",
    "PmpInfo": "pyremu.generic_ops.engine",
    "RunConfig": "pyremu.generic_ops.engine",
    "UartInfo": "pyremu.generic_ops.engine",
    "VirtIOInfo": "pyremu.generic_ops.engine",
    "run_parallel": "pyremu.generic_ops.engine",
    "decode_compressed": "pyremu.generic_ops.decode",
    "decode_fields": "pyremu.generic_ops.decode",
    "exec_alu": "pyremu.generic_ops.alu",
    "exec_op_imm": "pyremu.generic_ops.alu",
    "exec_op_imm32": "pyremu.generic_ops.alu",
    "exec_op32": "pyremu.generic_ops.alu",
    "fp_exec_fma": "pyremu.generic_ops.fpu",
    "fp_exec_op": "pyremu.generic_ops.fpu",
    "pmp_check": "pyremu.generic_ops.pmp",
    "pte_assemble_pa": "pyremu.generic_ops.mmu",
    "pte_parse": "pyremu.generic_ops.mmu",
    "sv39_decompose_va": "pyremu.generic_ops.mmu",
    "sv39_page_size": "pyremu.generic_ops.mmu",
}

__all__ = list(_SUBMODULES) + list(_ATTRIBUTES)


def __getattr__(name: str):
    """按名字导入对应的子模块或成员, 结果缓存在本模块命名空间."""
    module_path = _SUBMODULES.get(name)
    if module_path is not None:
        value = importlib.import_module(module_path)
        globals()[name] = value
        return value
    module_path = _ATTRIBUTES.get(name)
    if module_path is not None:
        value = getattr(importlib.import_module(module_path), name)
        globals()[name] = value
        return value
    try:
        value = getattr(importlib.import_module("pyremu._native"), name)
    except AttributeError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from None
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
