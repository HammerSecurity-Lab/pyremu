# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""RISC-V 指令的解码定义与执行辅助.

本包只给出纯 Python 的定义

各文件按职责拆分, 调用方直接从对应子模块导入:
- alu.py: 纯 Python 的算术指令实现
- compressed_imm.py: 压缩指令的立即数位段解码
- sys_instr.py: SysInstrOps, 特权指令与 CSR 指令
- mem_instr.py: 访存指令的操作数解码与取值辅助
"""
