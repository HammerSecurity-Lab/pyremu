# Known Issues

## 1. 多 hart WFI / TLB-shootdown IPI 死锁

**现象**: 多 hart 长时间卡在 `cpu_do_idle` (WFI) / `tlb_process_once` (OpenSBI)，
一个 hart 在 M-mode 自旋等待另一 hart 的 TLB 同步确认 (525M vs 126M 指令计数差异)。

**2026-07-31 修复**:
- `sync_msip` 改为 level-triggered (plain `load(Acquire)` 替代 `fetch_and(0xFE, AcqRel)`)，
  匹配真实 SiFive CLINT 硬件行为。`msip_pending` atomic channel 独立提供
  edge-triggered 交付，防止连续 MSIP 边沿塌陷。
- `wfi_spin` 移除 `std::thread::yield_now()`，改为连续 `spin_loop()`，
  消除接收 hart 主动让出 CPU 后被发送 hart 饿死、MSIP atomic channel 无法被检测的问题。

**待验证**: Linux 多核启动 IPI 压力测试、`PnP ACPI: disabled` 后 PLIC 中断稳定性。

---

## 2. 终端输入延迟 + Ctrl+C 不生效

**现象**:
- 键入后有可感知的字符回显延迟
- Ctrl+C 在客机 zsh 中不产生 SIGINT

**当前状态**:
- 终端 ISIG/IXON 已关闭，Ctrl+C 作为 raw 0x03 注入 UART RX FIFO
- `FfiExtIrqCtx` 跨 FFI 外部中断通知机制已实现（daemon 注入后置 pending -> Rust 内联设置 SEIP/MEIP -> guest 处理）
- 端到端延迟和 TTY VINTR 处理待验证

---

## 3. 宿主 Linux 未开 CONFIG_FPU → 硬浮点用户程序 SIGILL

**现象**: 在宿主 Linux shell 中直接运行 fn_apps（musl 静态硬浮点，
`-march=rv64gc -mabi=lp64d`，如 `./cfrac`）立即 `unhandled signal 4 (SIGILL)`，
cause=2 (Illegal instruction)，故障指令为任意 F/D 指令（如 `C.FSDSP`, 0xb8a2）。

**根因**: 非 emulator 缺陷。emulator 的 F/D 模拟正确实现且按规范在
`mstatus.FS == Off` 时对 FP 指令抛 Illegal instruction。宿主 Linux 内核
[head.S:145](bsp/linux/arch/riscv/kernel/head.S#L145) 启动时主动清 FS/VS
（`csrc CSR_STATUS, SR_FS_VS`，用于探测内核空间非法使用 FP）；而内核 `.config`
为 `# CONFIG_FPU is not set`，导致 `has_fpu()` 恒假、`start_thread()` 永远不给
用户进程置 `SR_FS_INITIAL`（[process.c:149](bsp/linux/arch/riscv/kernel/process.c#L149)），
于是所有用户进程以 FS=Off 运行，任何 F/D 指令必 SIGILL。

**修复 (2026-09-03)**: `bsp/linux/.config` 设 `CONFIG_FPU=y`（Kconfig 无依赖、
`default y`），重新构建内核 Image。`riscv-march` 自动追加 `fd`，`__fstate_save` /
`__fstate_restore` 编入 vmlinux，exec 时 `start_thread()` 恢复 `SR_FS_INITIAL`。

**注意**: `.config` 为本地生成文件；若以 defconfig/distclean 重新生成需再次确保
`CONFIG_FPU=y`。飞地内路径不受此影响：`init_enclave_ctx` 单独给飞地上下文置
`MSTATUS_FS_INIT`（FS=Initial），与宿主内核是否开 FP 无关。

---

## 4. AIA 模式: 空闲后首次输入的响应慢于连续输入

**现象**: AIA 模式 (`PYREMU_AIA=1` 构建, 即 `configs_gen.rs` 中 `CFG_AIA = true`)
下, 客机空闲一段时间后首次键入的字符, 其回显延迟明显大于持续键入时的延迟;
同一操作在 legacy PLIC 模式 (`PYREMU_AIA=0`) 下未见此延迟 (用户实测对比)。

**已确认**:
- 差异候选取自 RX 中断的注入与可见性: AIA 下 UART RX 经 APLIC 转入 IMSIC,
  而加速执行只在每轮 batch 起始读取 `imsic_m` / `imsic_s` 的快照, batch 期间
  由 Python 侧注入的 `eip` 对该轮不可见; 唯一逃逸是 `uart_rx_notify` 触发的
  `RX_WAIT` 退出 (见 `hart_sched.rs` 的 hart_worker)。legacy 模式走 PLIC
  持久数组, 每轮 batch 前同步, 无此缺口。
- 前次修复 (2026-09-13, "恢复加速引擎的 TermIO RX 通知退出") 已把该延迟从
  数秒量级降到当前量级, 故本条是那次修复的残留而非新缺陷。

**待验证**:
- 延迟是否随空闲时长增长。若随空闲时长增长, 指向 `_wfi_sleep_if_idle` 睡醒后
  的 mtime 补偿 (`clint.tick`) 与定时器快进路径; 若恒定, 指向唤醒链的固定开销
  (Rust termio 写入 ring, RX daemon 搬运至 UART FIFO, 主循环被 `_wake_event`
  唤醒, 下一轮 batch 经 `RX_WAIT` 退出)。
- 空闲 1 秒 / 10 秒 / 60 秒三档下, 记录键入时刻与首次回显时刻的间隔。

---

## 5. `restart` 之后 Ctrl+Q 不能暂停执行, 客机不再有输出

**现象** (2026-10-31): S 模式程序访问 `0x83000000` 后长时间停留在 M 模式的陷态
处理中, 按 Ctrl+Q 回到调试器并执行 `restart`; 重启后执行到内核注册块设备

```
[    1.179290] virtio_blk virtio0: 1/0/0 default/read/poll queues
[    1.181270] virtio_blk virtio0: [vda] 8388608 512-byte logical blocks (4.29 GB/4.00 GiB)
```

之后不再有任何内核输出与输入回显, 再次按 Ctrl+Q 不能回到调试器接受命令,
最终进程被宿主以 `SIGKILL` 终止 (`Killed`, `make` 报错误 137, 即 128 加 9).

**已确认**:
- Ctrl+Q 由 `pyremu/_native/termio/src/lib.rs` 的 `scan_rx` 识别 0x11, 经
  `notify_emu_stop` 直接写 `_init_termio` 注入的 `_native_stop_flag`; 该路径不置位
  `Emulator._wake_event`.
- 加速执行引擎在每条指令开头检查该标志 (`hart_sched.rs` 的 `hart_worker`), 因此该
  检查只在引擎运行期间发生.
- 全部存活 hart 处于 WFI 时, `_native_finalize` 调用 `_wfi_sleep_if_idle`, 阻塞在
  `_wake_event.wait(timeout=sleep_sec)`, 等待期间不检查 `_native_stop_flag`.
  `sleep_sec` 取最早到期的定时器与运行超时截止时刻中较小者, 运行超时取
  `mk/emu-feats.mk` 的 `DEFAULT_TIMEOUT`, 即 36000 秒.
- 键盘字节由接收守护线程在 `drain_rx` 中置位 `_wake_event`; Ctrl+Q 在写入接收环形
  缓冲区之前已由 `scan_rx` 消费, 不经过该路径.

**待验证**:
- 停顿时全部存活 hart 是否都处于 WFI, 以及该时刻 `mtimecmp` 与 `stimecmp` 的取值.
- `cmd_restart` 只重置 CLINT 的 mtime、mtimecmp 与 msip; 需确认加速执行引擎内
  `HartState` 的 `mtip_deadline`、`stip_deadline` 与 `mip` 是否一并复位.

**修复** (2026-10-31): 接收通知管道同时承载停机请求. `notify_emu_stop` 置位停止
标志后, 向该管道写 1 字节; 接收守护线程阻塞在 `poll(_rx_notify_r)` 上, 收到该字节
即置位 `_wake_event`, 并照常执行一次 `drain_rx`. 该守护线程只在通知到达时置位,
`_wfi_sleep_if_idle` 的单次等待仍由同一事件唤醒, 等待期间不检查停止标志.
回归测试为 `tests/test_peripheral/test_uart.py` 的
`TestRxDaemonStopNotify::test_stop_notify_sets_wake_event`, 以及
`pyremu/_native/termio/src/lib.rs` 的 `test_notify_emu_stop_wakes_python_daemon`.
