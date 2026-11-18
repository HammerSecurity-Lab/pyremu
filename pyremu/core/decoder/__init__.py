# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""RISC-V 指令解码与执行.

各文件按职责拆分:
- hart.py: Hart 类, 32 位指令的分发表与各处理器, 以及 exec_instr 入口
- alu.py: 纯 Python 的算术指令实现
- fields.py: 纯 Python 的指令字段解码
- compressed.py: CompressedInstrOps, 16 位压缩指令的 C0 / C1 / C2 三个象限
- sys_ops.py: SysInstrOps, 特权指令与 CSR 指令
- mem_ops.py: 访存指令的操作数解码与取值辅助

``hart`` 依赖 ``pyremu.generic_ops``, 而该包又需要本包的纯实现;
为断开这层循环,
导出的名字一律在首次访问时导入.
"""

from __future__ import annotations

import importlib

__all__ = ["Hart", "decode_c_sdsp", "decode_sd_sp"]


def __getattr__(name: str):
    """按名字导入对应的实现, 结果缓存在本模块命名空间."""
    if name == "Hart":
        value = importlib.import_module("pyremu.core.decoder.hart").Hart
    elif name in ("decode_c_sdsp", "decode_sd_sp"):
        value = getattr(
            importlib.import_module("pyremu.core.decoder.mem_instr"), name
        )
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
