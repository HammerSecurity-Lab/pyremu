# 计划三 依芯片设备树配置模拟器、总线补充与客机输出串行化

**状态**: 实现中

## Context

`output/chip.dts` 描述的目标平台与模拟器的默认配置不同: 串口在 `0x64000000`, RAM 为 512 MiB,
另有启动地址寄存器 `boot-address-reg@1000` 与引导只读存储器 `rom@10000`; 默认配置的串口在
`0x10000000`, RAM 为 128 MiB, 后两个设备未建模. 需要让模拟器按这份描述装配平台与总线, 并在
代码层面拒绝互相冲突的入参.

同时, 多个 hart 共享同一串口时, 每字节一次 `os.write` 使两个 hart 的输出在字节处交错
(`>> regre` 与内核日志相互插入), 控制台无法直接阅读; 宿主 stdout 写满时该写入还会阻塞执行
线程, 使固件与 Linux 驱动同时停住.

## 步骤

### 1. 客机输出的行原子性与宿主写入不阻塞

- 每个 hart 一个待写缓冲; 收到 `\n` 时把该行以一次 `os.write` 提交. 缓冲达到上限或该 hart
  的缓冲在提交周期内没有再增长时, 提交其剩余字节, 使不含换行的提示符仍能显示.
- 宿主写入改为非阻塞: 先 poll, 超时 0, 不可写时丢弃该行并计数, 与
  `pyremu/_native/cpu/src/peripheral/uart.rs` 的 `try_write_fd` 的既有做法一致.
- 加速执行引擎直写 stdout 的路径同样经行缓冲提交, 否则该路径仍会在字节处交错.
- hart 日志按 hart 分流, 逐字节写入的顺序不变, 不受该改动影响.
- 丢弃计数在退出时报告, 使输出缺失可见.

### 2. 总线与设备补充

- 新增启动地址寄存器外设: 每 hart 一个 64 位寄存器, 偏移 `8 * hartid`, 可读可写; 区间内其余
  偏移读回 0, 写入丢弃.
- `PeripheralConfig` 增加启动地址寄存器的基址与大小, 取 0 表示不注册, 默认 0, 既有配置不受影响.
- 引导只读存储器的基址与大小可由设备树给出, 仍经 `Bus.add_boot_rom` 注册.
- 装载固件后把入口地址写入各 hart 的启动地址寄存器, 供引导只读存储器中的代码读取.

### 3. 设备树解析与 `--chip-dts`

- 新增读取 DTB 的模块: 取 `/memory` 的 reg, `/cpus` 的子节点数与 `timebase-frequency`,
  serial、clint、plic、crng、virtio、boot-address-reg、rom 的 reg, 产出 `PlatformConfig` 与
  `PeripheralConfig` 的覆盖值.
- `.dts` 先经 `dtc -I dts -O dtb` 转换; 解析在构造 `PlatformConfig` 与 `Emulator` 之前完成,
  因为外设在 `Emulator.__init__` 中注册, RAM 区间还影响固件装载与 ROM 启动判定.
- 命令行显式给出的 `--ram`、`--ram-base`、`--harts`、`--rom-base`、`--rom-size` 优先, 默认值
  改为 None 哨兵; 未给出时取文件中的值.
- 交给客机的设备树即该文件的 blob, 不再经 `dtb.py` 生成.
- 树中未建模的节点忽略: `debug-controller@0`、`error-device@3000`、`clock-gater@100000`、
  `cache-controller@2010000`、各 `fixed-clock`、`memory@8000000`.

### 4. 冲突断言

- 参数: `--chip-dts`、`--fdt-file`、`--no-fdt` 入同一互斥组; `--fdt` 只决定设备树的装载地址,
  留在组外.
- 地址窗口: `PlatformConfig.__post_init__` 断言 RAM、引导只读存储器、启动地址寄存器与全部
  外设窗口两两不重叠; 基址取 0 的设备不参与.
- 设备树给出的取值与命令行取值合并之后作同一组断言, 不区分来源.

### 5. 固件侧对齐 (登记, 不在本次改动内)

- `CONFIG_RAND_DEV_BASE`、`CONFIG_ENCLAVE_NET_BASE`、`CONFIG_POOL_BASE` 与
  `CONFIG_POOL_SIZE` 需与 `--chip-dts` 同源; 当前前者为 0, 后三者取 mk/ 下的默认值.

## 落点

| 文件 | 改动 |
|------|------|
| pyremu/peripheral/uart.py | 每 hart 行缓冲、非阻塞写入、丢弃计数 |
| pyremu/peripheral/termio.py | 归档路径按整行提交 |
| pyremu/_native/cpu/src/peripheral/uart.rs | 直写路径改经行缓冲 |
| pyremu/peripheral/boot_addr.py | 新增启动地址寄存器 |
| pyremu/platform/ | 新增字段与窗口不重叠断言 |
| pyremu/emu/setup.py | 注册启动地址寄存器 |
| pyremu/utils/dev_tree/ | 新增 DTB 读取 |
| pyremu/debug/cli.py | `--chip-dts`、互斥组、取值优先级 |

## 验证

- 新增用例: 宿主管道写满时丢弃而不阻塞; 两个 hart 交替写同一串口时控制台按整行出现;
  启动地址寄存器的读写与越界; 设备树取值覆盖与命令行优先; 参数冲突与地址窗口冲突各一条.
- 既有相关用例: `tests/test_peripheral/test_uart.py`、`tests/test_dbg/test_cli.py`、
  `tests/test_emulator.py`、`tests/test_dev_tree/test_dtb.py`.
- 静态检查: `uv run ruff check .` 与 `uv run ruff format --check .`.
- 手工: 以 chip.dts 启动, 控制台按整行输出, hart 日志与原顺序一致.

---
