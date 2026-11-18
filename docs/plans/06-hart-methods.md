# 计划六 以 hart 为首个参数的独立函数改为 hart 的方法, 支持跨文件定义

**状态**: 待确认

## Context

[pyremu/core/mem_check_aux.py](../../pyremu/core/mem_check_aux.py) 与
[pyremu/core/trap_handler.py](../../pyremu/core/trap_handler.py) 中的函数以 hart 为第一个位置参数:

- `mem_read(hart, va, size)`、`mem_write(hart, va, data)`、`translate_addr(hart, va, ...)`、
  `validate_csr(hart, addr, write)`、`check_instruction_fetch(hart, va)`;
- `deliver_trap(hart, cause, ...)`、`trap_ecall(hart)`、`trap_mret(hart)`、`trap_sret(hart)`、
  `handle_wfi(hart)`、`check_pending_interrupts(hart)`、`update_hw_mip(hart, bits)`。

调用点必须自行持有 hart 并逐层传递。用户于 2026-10-31 提出改为 hart 的方法, 并要求方法的
定义可以留在原模块, 即支持跨文件定义。

## 已确认的约束

- 改为方法时, 方法定义必须支持跨文件: 在原模块内定义, 由 hart 类组合进来。
- 跨文件定义不可行时, 保留独立函数的调用点必须能显式修改 hart 的状态。
- 不接受改参数位置、也不接受只改测试用例来回避该改动。
- 暂不涉及 `pyremu/_native` 的 Rust 加速执行库。

## 待办

- 确认跨文件定义的可行方案: `pyremu/debug/` 已按操作类组合实现同类需求, 需核对操作类与
  `HartWithRegs` / `Hart` 的继承结构、`__init__` 与 ctypes 布局是否兼容。
- 处理循环导入: 两个模块都导入 `pyremu/core/hart.py` 的常量与类型; 若 `core/hart.py` 反向
  组合这两个模块的操作类, 需先拆分常量所在模块, 并保持既有导入路径可用。
- 逐个函数迁移并更新全部调用点 (pyremu、tests、examples), 不改变行为与异常语义。
- 验证: 相关测试串行运行, `uv run ruff check .` 与 `uv run ruff format --check .`。

## 未定

- `pyremu/core/decoder/` 中的 `exec_compressed(hart, instr)` 与 `exec_sys(hart, f, instr)`
  是否一并转为方法, 以及方法归属 `Hart` 还是 `HartWithRegs`。

---
