# SPDX-LICENSE-IDENTIFIER: MIT
"""扩展判定 — 判定指令所属扩展是否在平台声明之内.

纯 Python 实现在 ``pyremu.core.decoder.check_ext_isa``; 加速执行引擎在
``cpu/src/instr/check_ext_isa.rs`` 内做同一判定, 目前没有导出为 FFI 函数,
故本模块直接转调纯 Python 实现. 若将来把该判定导出, 只需在此按
``native_available()`` 增加分支, 调用方无需改动.
"""

from __future__ import annotations

from pyremu.core.decoder.check_ext_isa import check_ext_isa

__all__ = ["check_ext_isa"]
