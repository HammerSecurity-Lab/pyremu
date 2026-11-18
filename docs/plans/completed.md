# 已完成的计划

已完成的计划不再占用编号, 只按完成时间记一条结果; 细节见当年变更记录与提交。

- rvdb 多来源调试符号: 目录列举、选择加载、部署地址与内存校验 — 已完成 (b91ad46), 用户于 2026-10-22 提出。
- `pyremu/emulator.py` 按职责拆分 — 已完成 (b91ad46), 用户于 2026-10-24 提出。
- 评测入口 `regress.sh` 从 `local-build.sh` 抽出 — 已完成, 用户于 2026-10-28 提出。
- `pyremu/core/decoder.py` 拆为 `pyremu/core/decoder/` 包 — 已完成, 用户于 2026-10-29 提出。
- 调试命令列出本次运行注册的全部虚拟设备及其总线区间 — 已完成, 由 `devices` 与 `dev` 命令实现, 用户于 2026-11-12 提出。
- rvdb restart 一致性缺陷与客机文件读取损坏 — 已完成, restart 按冷启动语义重建, 客机读取损坏由压缩访存跨页修复, 用户于 2026-10-31 报告。
- `tests/test_native.py` 拆分为按内容命名的测试目录 — 已完成 2026-11-17, 用户于 2026-11-17 提出。

## `tests/test_native.py` 拆分的实施结果 (2026-11-17)

拆为 `tests/test_native/`, 按内容分 6 个文件, 用例总数与拆分前一致, 为 357:

| 文件 | 用例数 |
|------|-------|
| test_alu.py | 147 |
| test_ffi_layout.py | 69 |
| test_trap_isa.py | 65 |
| test_mem.py | 44 |
| test_compressed.py | 20 |
| test_engine_diff.py | 12 |

共享常量与 `assert_ill_instr` 移入 `tests/test_native/common.py`, 夹具移入
`tests/test_native/conftest.py`。同批删除了 `handlers.rs` 中无调用点的
`handle_load` / `handle_store` / `handle_fp_load` / `handle_fp_store`, 原有的
`handlers.rs` 同时拆为 `instr/handlers/` 包。

## `devices` 命令的实施结果

- [pyremu/memory/bus.py](../../pyremu/memory/bus.py) 的 `device_entries()` 按基址升序返回
  已注册设备的副本, 未注册任何设备时返回空元组; 调用方不接触内部设备表。
- [pyremu/debug/device_map.py](../../pyremu/debug/device_map.py) 的 `cmd_devices` 把存储区间
  与设备区间合成一张按基址升序的表, 列出名称、类别、基址、字节数与上界; 基址取 0 而未
  注册的设备不出现在表中; 设备持有公开的 `irq` 属性时在中断源一列给出编号, 未持有者写
  `-`; 引导只读存储器同时属于存储区间与设备表, 只按存储区间列出一次。
- 用例见 [tests/test_dbg/test_device_map.py](../../tests/test_dbg/test_device_map.py),
  10 条: 主存与已注册设备、未注册设备省略、区间上下界、引导只读存储器只列一次、
  无设备时的提示、中断源编号、按基址排序、命令分发与帮助.

## restart 与客机读取损坏的实施结果

restart 一致性:

- `cmd_restart` 清空 CLINT 计数与 msip、撤销关机与复位请求, 调用
  [pyremu/emu/setup.py](../../pyremu/emu/setup.py) 的 `reset_internal_state`
  (清空 L2 缓存、递增 TLB 刷新计数、重置 virtio 队列与中断控制器、复位引擎镜像的
  CLINT 边沿与指令计数), 再调用 `rebuild_harts` 按构造时的接线重建 hart,
  恢复 IMSIC 引用、UART 写包装与 PMP 缓冲区绑定。
- restart 随后按原地址重写设备树与内核镜像, 清除断点地址, 并把终端恢复到 REPL 模式。
- 用例见 [tests/test_dbg/test_exec.py](../../tests/test_dbg/test_exec.py) 的 10 条
  `test_restart_*`: 重写设备树、撤销关机请求、PMP 缓冲区重绑、UART 写包装、IMSIC 引用、
  L2 失效、PLIC 与 IMSIC 挂起位、virtio 队列重置。

客机文件读取损坏:

- 根因是加速执行引擎的压缩访存未按两页拆分, 已修复并补 `TestCompressedCrossPage`,
  详见 [2026-11 变更记录](../changelogs/2026-11.md)。实机复测: 逐行比对用例无差异,
  `/sbin/adduser` 输出与 QEMU 一致。
