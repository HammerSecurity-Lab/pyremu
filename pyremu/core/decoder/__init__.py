# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""RISC-V 指令解码与执行.

各文件按职责拆分:
- hart.py: Hart 类, 32 位指令的分发表与各处理器, 以及 exec_instr 入口
- alu.py: 纯 Python 的算术指令实现, 以及加速执行引擎与纯 Python 之间的选择
- compressed.py: CompressedInstrOps, 16 位压缩指令的 C0 / C1 / C2 三个象限
- sys_ops.py: SysInstrOps, 特权指令与 CSR 指令
- mem_ops.py: 访存指令的操作数解码与取值辅助
"""

from __future__ import annotations

from pyremu.core.decoder.hart import Hart
from pyremu.core.decoder.mem_ops import decode_c_sdsp, decode_sd_sp

__all__ = ["Hart", "decode_c_sdsp", "decode_sd_sp"]
