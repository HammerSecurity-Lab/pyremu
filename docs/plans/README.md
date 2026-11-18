# 计划索引

未完成的计划每条一份文件存放于本目录, 已完成的计划只保留在
[completed.md](completed.md) 中。

## 编号规则

- 本目录内的计划按"最小且未被其他计划使用的正整数"编号, 编号连续, 不留空缺。
- 计划完成后不再占用编号: 正文并入 [completed.md](completed.md) 的无序列表,
  原文件删除, 释放出的编号留给下一条新计划。
- 新增计划取当前未被使用的正整数中最小的一个, 并在下表追加一行。
- 跨计划引用按同一编号书写, 编号变更时一并更新引用。

## 待办计划

| 编号 | 计划 | 当前状态 |
|------|------|---------|
| 计划一 | 代码内使用者可见字符串的国际化 | 搁置, [01-internationalization.md](01-internationalization.md) |
| 计划二 | `pyremu/_native` 内与项目规范相悖的注释重写 | 待确认, [02-native-comment-rewrite.md](02-native-comment-rewrite.md) |
| 计划三 | 依芯片设备树配置模拟器、总线补充与客机输出串行化 | 实现中, [03-chip-dts-platform.md](03-chip-dts-platform.md) |
| 计划四 | 看门狗改为时钟计数并经 PLIC/APLIC 投递中断 | 待确认, [04-watchdog-clock-interrupt.md](04-watchdog-clock-interrupt.md) |
| 计划五 | 设备树未配置块设备时取默认镜像, 镜像缺失则报错终止 | 待确认, [05-default-disk-image.md](05-default-disk-image.md) |
| 计划六 | 以 hart 为首个参数的独立函数改为 hart 的方法 | 待确认, [06-hart-methods.md](06-hart-methods.md) |
| 计划七 | 以 `--chip-dts` 启动时飞地无法运行 | 待复现, [07-chip-dts-enclave.md](07-chip-dts-enclave.md) |
| 计划八 | H 扩展与两阶段地址翻译 | 待确认, [08-hypervisor-extension.md](08-hypervisor-extension.md) |
