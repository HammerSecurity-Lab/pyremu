# 计划四 看门狗改为时钟计数并经 PLIC/APLIC 投递中断

**状态**: 待确认

## Context

[pyremu/peripheral/watchdog.py](../../pyremu/peripheral/watchdog.py) 的 `HartWatchdog` 有四处与真实硬件不符:

1. 计数单位是"单轮加速执行", 见该文件第 6 行与第 51 行, 不是时钟周期;
2. 到期向 CLINT 写 MSIP, 见 `_do_recover`。MSIP 是软件写入的寄存器, 看门狗不是总线主设备, 没有这条通路;
3. 模拟器每轮按"本轮是否有指令进展"自动重装计数, 见 [pyremu/emu/native.py:654-657](pyremu/emu/native.py#L654-L657), 等于宿主替客机重装计数;
4. 设备恒创建, 见 [pyremu/emu/setup.py:224](pyremu/emu/setup.py#L224) 的 `p.watchdog_base or 0x1000_4000`: 基址取 0 也回落到默认地址; 设备树恒生成节点, 见 [pyremu/utils/dev_tree/build.py:682](pyremu/utils/dev_tree/build.py#L682)。这与 [mk/peripherals.mk:3](mk/peripherals.mk#L3) 声明的"基址取 0 表示该设备不注册"相反。

客机侧没有驱动绑定 `pyremu,hart-watchdog-1.0`, 现有行为对客机的唯一作用是周期性 MSIP, 真实硬件不产生这样的中断。

已确认的两项: `WATCHDOG_BASE` 的默认值保持 `0x1000_4000`, 只修正"基址取 0 仍创建"与"设备树恒生成节点"; 调试器停在 REPL 期间计数继续推进。

## QEMU 参照

- 看门狗模型不用独立线程维护时钟: 以 `ptimer` 或 `timer_new_ns(QEMU_CLOCK_VIRTUAL)` 挂在虚拟时钟上, 由主循环在到期时回调。
  - [vendor/qemu-10.2.0/hw/watchdog/cmsdk-apb-watchdog.c:296-305](vendor/qemu-10.2.0/hw/watchdog/cmsdk-apb-watchdog.c#L296-L305): 第一次到期置中断状态, 第二次到期请求复位;
  - [vendor/qemu-10.2.0/hw/watchdog/allwinner-wdt.c:296-299](vendor/qemu-10.2.0/hw/watchdog/allwinner-wdt.c#L296-L299): 到期调用 `watchdog_perform_action()`, 由 [vendor/qemu-10.2.0/hw/watchdog/watchdog.c:44-80](vendor/qemu-10.2.0/hw/watchdog/watchdog.c#L44-L80) 决定复位、停机或暂停。
- 虚拟时钟取宿主时间: [vendor/qemu-10.2.0/util/qemu-timer.c:626-627](vendor/qemu-10.2.0/util/qemu-timer.c#L626-L627) 的 `QEMU_CLOCK_VIRTUAL` 由 `cpus_get_virtual_clock()` 给出, 虚拟机运行期间按宿主真实时间推进, 暂停时冻结。
- 据此, pyremu 的计数依据取宿主单调时钟, 不取按指令折算的 `mtime`: 后者在加速执行期间由 Rust 侧持有, Python 侧要到批次结束才看得到, 设备线程无法读取实时值。

pyremu 需要一条设备自带的线程, 原因: 加速执行的一次批次在 ECALL、MMIO、断点或停机之前不返回 Python, 轮次时长没有上界; 只在轮次边界判定的看门狗会被推迟到批次结束。[pyremu/interrupt/irq_sink.py](../../pyremu/interrupt/irq_sink.py) 的 `DeviceIrqSink` 允许设备线程置位, termio 的接收线程即采用同一形态。

## 目标行为

### 寄存器

每 hart 一段, stride 0x10, 布局不变:

| 偏移 | 名称 | 语义 |
|------|------|------|
| 0x00 | CTRL | bit0 使能; bit1 到期后自动重装。复位值为 0, 即复位后不使能 |
| 0x04 | TIMEOUT | 到期 tick 数, 时钟频率取 `TIMER_FREQ` |
| 0x08 | COUNT | 只读, 剩余 tick |
| 0x0C | KICK | 写入任意值: 重装该 hart 的计数并撤销其到期标志 |

### 计数与中断

- 设备持有可替换的 `clock_ns` 函数, 默认 `time.monotonic_ns`。`tick(now_ns)` 只推进状态, 不睡眠: 按流逝的 tick 数递减使能 hart 的计数, 归零时置该 hart 的到期标志。
- 守护线程每 `WATCHDOG_POLL_MS` 调用一次 `tick`。任一 hart 到期时经 `irq_sink` 拉高中断线; 全部到期标志清除后拉低。电平语义与 UART 相同, 中断由 PLIC 或 APLIC 投递; 不写 MSIP, 不调用 `notify_processor`。`DeviceIrqSink` 同时置 `ext_irq.pending`, 使正在运行的一轮加速执行退出到 Python 侧并检查中断, 与串口接收中断的路径相同。
- CTRL 的 bit1 置位时, 到期后自动重装并保持中断线为高, 形成周期性请求; 清零时计数停在 0, 中断线保持为高直至软件 KICK 或关闭使能。

### 接线、配置与设备树

- 构造参数改为 `irq_sink`、`base`、`num_harts`、`clock_ns`; `irq_sink` 取
  [pyremu/peripheral/virtio_blk.py](../../pyremu/peripheral/virtio_blk.py) 的二元组形式
  `(中断源编号, DeviceIrqSink)`, 由设备自己持有中断源编号。模块常量 `WATCHDOG_IRQ = 4`,
  因为 1、2、3 与 10 已被占用。
- `WATCHDOG_BASE` 的默认值保持 `0x1000_4000`, `PeripheralConfig.watchdog_base` 不变; 置 0 即不注册, 与其余外设一致, [pyremu/configs_gen.py](../../pyremu/configs_gen.py) 无需重新生成。
- [pyremu/emu/setup.py](../../pyremu/emu/setup.py) 仅在基址非 0 时创建并注册该设备, 类型标注改为 `HartWatchdog | None`。
- 删除 [pyremu/emu/native.py:654-657](pyremu/emu/native.py#L654-L657) 的 `kick_all()` 与 `tick()` 调用, 删除 `_do_recover`; [pyremu/emulator.py](../../pyremu/emulator.py) 的 `notify_processor` 文档字符串去掉看门狗。
- 设备树: `_dtb_watchdog` 增加设备存在性判断, 与 `_dtb_crng` 相同; 节点补充 `status`、`interrupts-extended` 与 `clock-frequency`, `interrupts-extended` 在 PLIC 下为 `<phandle source>`, 在 AIA 下为 `<phandle source LEVEL_HIGH>`, 与 `_dtb_uart` 一致, 但 AIA 与否取自 `_dtb_soc` 已经算出的 `is_aia`, 不取模块常量 `PYREMU_AIA`, 以免与 `cfg.interrupt_mode` 给出的实际装配不一致。`clock-frequency` 取 `TIMER_FREQ`, 与 `TIMEOUT` 的计数单位相同。不补 `clocks`: `_dtb_uart` 已在 `/soc` 下生成一个 `clock` 节点并且没有为它递增 `next_phandle`, 再生成一个会与同级节点重名; 该设备也没有必须取得时钟句柄的驱动。
- `Emulator.close()` 先停止看门狗线程, 再停止 `TerminalIO` 与关闭 UART 日志: 线程一旦退出就不可能再触碰已经拆开的中断控制器与串口。

### 计数精度与边界

- 流逝的纳秒按 `tick_ns = TIMER_FREQ * dt_ns // 1_000_000_000` 整算, 只把已计入的整数个 tick
  对应的纳秒加回 `_last_ns`, 余数留到下一次, 长期不产生累计偏差。
- 自动重装时把超出量带到下一周期: 计数减到不大于 0 后反复加 `TIMEOUT`, 直至大于 0, 周期不随
  轮询频率漂移。`TIMEOUT` 取 0 时该 hart 在每个 tick 都到期, 不回装。
- `CTRL` 的 bit0 由 0 变为 1 时装载计数并撤销到期标志; 由 1 变为 0 时计数归 0 并撤销到期标志。
  写 `TIMEOUT` 只改周期, 不回装当前计数。
- 中断线电平取"任一 hart 的到期标志置位", 只在电平变化时调用 `irq_sink`: 未使能且未到期的
  设备不产生任何一次调用, 因此不会置 `ext_irq.pending` 或唤醒 WFI 等待的 hart。

### 并发

- `_lock` 保护 `_ctrl` / `_timeout_val` / `_count` / `_expired` / `_last_ns` / 电平, 覆盖 MMIO
  读写与 `tick`。
- `tick` 在锁内算出新的电平与是否变化, 释放锁之后再调用 `irq_sink`: 后者会写 PLIC 或 APLIC
  (各自持锁) 并置 `ext_irq.pending`, 在持有 `_lock` 时调用会与 hart 侧的中断检查形成相反的
  锁序。

### 线程

- `start()` 幂等创建守护线程 `pyremu-watchdog`, 循环体为 `_stop_event.wait(WATCHDOG_POLL_MS / 1000)`
  之后调用 `tick(self._clock_ns())`; 启动时在状态锁内置 `_last_ns`, 并以一次性标志调用
  `atexit.register(self.stop)`。
- `stop()` 幂等: 置事件, 在**不持有状态锁**的前提下 `join(timeout=1.0)`, 清空 `_thread`, 并
  `atexit.unregister`。线程自身调用 `stop()` 时直接返回, 不 join 自己。`is_running` 只读属性
  返回线程是否存活。
- `start()` / `stop()` 的幂等判定由独立的 `_lifecycle_lock` 保护, 与保护寄存器状态的 `_lock`
  分开: 在持有 `_lock` 时 join 会与等待 `_lock` 的轮询线程互相等待, 直到 `join` 超时。
- `atexit` 登记必须成对撤销: 绑定的 `stop` 会持有设备, 不撤销时进程内的每个 `Emulator` 及其
  中断控制器、FFI 数组都留到进程退出才释放, 测试套件构造多个实例时占用持续增长。
- 线程在 `Emulator` 的整个生命周期内运行, 只在 `close()` 时停止: 看门狗时钟取独立振荡器,
  调试器停住 CPU 期间照常计数, 恢复运行后可能立即到期。用例与无 `Emulator` 的调用方直接调用
  `tick(now_ns)`, 不启动线程。

### 已知局限

- APLIC 在中断源的 `sourcecfg` 为 `SM_INACTIVE` 时丢弃 `set_irq` 的写入, 且只有在已经记录过
  输入状态的前提下才重新挂起。软件若在中断线已经拉高之后才配置该中断源, 这次挂起会丢失,
  直到下一次到期。不为此改成每轮重复投递: 中断线持续为高时每 `WATCHDOG_POLL_MS` 都会置
  `ext_irq.pending` 并唤醒 WFI 等待的 hart, 加速执行的轮次会被打断。
- AIA 模式下 `_setup_interrupt_controllers` 只为 `VIRTIO_NET_M_IRQ` 预绑定 APLIC 中断源;
  中断源 4 由客机软件自行配置。M 模式固件若要在 S 域软件接手之前使用该中断, 需自行预绑定。
- 计数依据是宿主单调时钟, 与按指令折算的 `mtime` 不成比例: 模拟速度低于真实硬件时, 客机
  视角的到期时间早于按指令数推算的时间。这是取宿主时钟的必然结果, 与真实外接看门狗一致。
- 窗口大小取 `num_harts * 0x10`, 而不是整页: `Bus.add_device` 的重叠校验按精确区间进行,
  客机驱动若要求整页资源需自行取整。

## 实现落点

| 文件 | 改动 |
|------|------|
| [pyremu/peripheral/watchdog.py](../../pyremu/peripheral/watchdog.py) | 按上文重写: 时钟计数、电平投递、线程与锁; 删除 `kick_all`、`tick(harts)`、`_do_recover` 与对 `CLINT` 的依赖 |
| [pyremu/emu/setup.py](../../pyremu/emu/setup.py) | 去掉 `or 0x1000_4000`; 基址非 0 时以 `irq_sink=(WATCHDOG_IRQ, self._irq_sink)` 构造、注册并 `start()`; `_declare_device_slots` 的标注改为 `HartWatchdog \| None`; 更新第 146 行与第 162 行两处文档字符串 |
| [pyremu/emu/native.py](../../pyremu/emu/native.py) | 只删除 `_native_finalize` 中的 `kick_all()` / `tick()` 分支, 文档字符串去掉"并推进看门狗"; 第 140 行的 `_watchdog_timeout_ns` 是宿主侧执行超时机制, 与本设备无关, 不改 |
| [pyremu/emulator.py](../../pyremu/emulator.py) | `close()` 在 `_termio` 之前停止看门狗线程并更新文档字符串; `notify_processor` 文档字符串删去看门狗; 第 162 行注释的"看门狗恒创建"改为"基址取 0 时不创建" |
| [pyremu/utils/dev_tree/build.py](../../pyremu/utils/dev_tree/build.py) | `_dtb_watchdog` 增加 `watchdog` 与 `is_aia` 参数, `if watchdog is None: return`, 基址取 `watchdog.base_addr`, `reg` 大小取 `watchdog.size`, hart 数取 `watchdog.num_harts`, 补 `status`、`interrupts-extended` 与 `clock-frequency`; 第 682 行传入 `devices.watchdog` 与 `is_aia` |
| [pyremu/emu/load.py](../../pyremu/emu/load.py) | 无改动, 第 40 行已传 `watchdog=self.watchdog` |
| [pyremu/debug/cli.py](../../pyremu/debug/cli.py) | `_periph_from_chip` 改为在构造 `PeripheralConfig` 时传 `watchdog_base=_tree_base(p.watchdog)`, 删除第 641-642 行的覆盖与第 620 行"看门狗恒创建"的说明 |
| [tests/test_peripheral/test_watchdog.py](../../tests/test_peripheral/test_watchdog.py) | 重写, 见下节 |

`_dtb_watchdog` 只补 `clock-frequency`, 不新增 `clocks`: `_dtb_uart` 已在 `/soc` 下生成一个
`clock` 节点, 再生成一个会使同级节点重名; 且没有驱动绑定该设备。

`WATCHDOG_BASE` 的默认值保持 `0x1000_4000`, `pyremu/configs_gen.py` 无需重新生成;
"可选"体现为置 0 即不注册, 与其余外设一致。

## 用例

重写 [tests/test_peripheral/test_watchdog.py](../../tests/test_peripheral/test_watchdog.py).
时间经注入的 `clock_ns` 与直接调用 `tick(now_ns)` 给出, 不睡眠、不启动线程.

夹具: `FakeClock` (`__call__` 返回当前纳秒, `advance_ms` 推进); `IrqRecorder` 记录
`(source, pending)` 调用序列; `wdog` 以 `irq_sink=(WATCHDOG_IRQ, recorder)` 构造.

寄存器与计数:

1. 复位后 `CTRL` 为 0, `COUNT` 为 0, `TIMEOUT` 为构造参数给出的值.
2. 设备大小为 hart 数乘以 `0x10`.
3. 每个 hart 的寄存器块互相独立.
4. `KICK` 读出为 0; 未落在 4 字节边界上的偏移与超出 hart 数的偏移读出为 0; 超出范围的写无作用.
5. 写 `COUNT` 被忽略.
6. 使能位置 1 时计数装载为 `TIMEOUT`; 置 0 时计数归 0.
7. 流逝 1 秒使计数按 `TIMER_FREQ` 递减, 余数留在下一次: 两次各推进 0.6 秒后的计数等于一次推进
   1.2 秒的计数.
8. 未使能的 hart 不递减, 不置到期标志.
9. 写 `KICK` 重装计数并撤销到期标志.
10. 写 `TIMEOUT` 不回装当前计数.

中断投递:

11. 未到期时不调用 `irq_sink`; 未使能的设备连续推进多个轮询周期, 记录序列为空.
12. 到期时计数归 0, 记录到 `(WATCHDOG_IRQ, True)`, 且只记录一次: 再推进一个 tick 不再重复.
13. 投递目标在回调内读本设备的寄存器不会死锁: 以在回调中调用 `read(0, 4)` 的投递目标构造,
    `tick` 在限定时间内返回.
14. 任一 hart 到期即拉高; 另一未到期 hart 继续递减.
15. `CTRL` 的 bit1 置位时到期后计数回到大于 0 的值, 电平保持为高, 周期按 `TIMEOUT` 重复.
16. `CTRL` 的 bit1 清零时到期后计数停在 0, 电平保持为高, 直到 `KICK` 或关闭使能, 此时记录到
    `(WATCHDOG_IRQ, False)`.
17. 关闭使能撤销到期标志并拉低电平.

回归:

18. 到期不写 `CLINT` 的 MSIP: 以 `Emulator` 装配 (`watchdog_base=0x1000_4000`, `uart_base=0`,
    避免创建终端线程), 用 `monkeypatch` 记录 `CLINT.send_ipi` 与落到 MSIP 区间的
    `CLINT.write`, 经 `emu.bus.write` 使能并令 `TIMEOUT` 为 1, 再直接调用
    `emu.watchdog.tick(now)` 使 hart 0 到期; 断言两处记录均为空, 各 hart 的
    `emu.clint.read(h * 4, 4)` 的 bit0 为 0, 且该设备没有 `clint` 属性. 该用例在旧实现写 MSIP
    时失败.
19. 线程: `start()` 两次只有一个线程, `stop()` 之后 `is_running` 为假, 重复 `stop()` 无作用;
    `Emulator.close()` 之后 `emu.watchdog.is_running` 为假.

装配与设备树:

20. 基址非 0 时 `Emulator` 创建该设备, 经 `Bus` 读写落到设备.
21. 基址为 0 时 `emu.watchdog is None`, `bus.is_device_addr(0)` 为假, `_peripherals` 中没有
    `"watchdog"`; 设备树中没有 `watchdog@` 节点.
22. 基址非 0 时设备树节点存在, `compatible` 为 `pyremu,hart-watchdog-1.0`, `reg` 的基址与
    大小为 `base` 与 `num_harts * 0x10`, `clock-frequency` 为 `TIMER_FREQ`, `status` 为
    `okay`.
23. `interrupts-extended` 在 legacy 模式下为 2 个单元格 `<parent, 4>`.
24. `interrupts-extended` 在 `interrupt_mode` 为 AIA 时为 3 个单元格 `<parent, 4, 0x4>`.
25. `PeripheralConfig().watchdog_base` 仍为 `0x1000_4000`.

## 验证

1. 串行运行受影响的用例:

   ```bash
   uv run pytest tests/test_peripheral/test_watchdog.py tests/test_dtb.py \
     tests/test_emulator.py -q
   ```

2. 静态检查 (改动文件全部通过):

   ```bash
   uv run ruff check pyremu/ tests/test_peripheral/test_watchdog.py
   uv run ruff format --check pyremu/ tests/test_peripheral/test_watchdog.py
   ```

3. 配置确认: `pyremu/configs_gen.py` 未改动, `WATCHDOG_BASE` 仍为 `0x1000_4000`;
   `mk/peripherals.mk` 未改动.

4. 端到端 (需另行确认后运行模拟器): 以既有固件启动, 确认默认配置下看门狗线程随 `Emulator`
   创建并在 `close()` 之后退出; 以不带 `watchdog` 节点的 `--chip-dts` 启动, 确认设备树中没有
   该节点、`0x1000_4000` 不是设备地址, 固件与内核运行结果不变.

5. 文档同步: [CLAUDE.md](../../CLAUDE.md) 的实现清单、类层次图与"Peripheral devices"一节中的看门狗
   说明, [docs/README.md](../README.md) 的外设条目; 只改描述当前行为的语句.

---
