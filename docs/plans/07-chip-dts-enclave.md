# 计划七 以 `--chip-dts` 启动时飞地无法运行

**状态**: 待复现

## Context

以 `--chip-dts=output/chip.dts` 启动时飞地无法运行。该树只有 cpus、memory、clint、plic、
serial、rom、boot-address-reg 等节点, 没有 CRNG、virtio-net 宿主侧与飞地侧、virtio-blk 等节点。

[pyremu/debug/cli.py](../../pyremu/debug/cli.py) 的 `_periph_from_chip` 对树中缺失的外设取 0,
即不注册该设备; `_supplement_devices` 只补充块设备节点。固件侧的飞地内存池与飞地侧网卡由
[mk/opensbi.mk](../../mk/opensbi.mk) 的 `CONFIG_POOL_BASE`、`CONFIG_POOL_SIZE`、
`CONFIG_ENCLAVE_NET_BASE` 给出, 与 `--chip-dts` 不同源。

## 已收集的现象 (2026-10-31)

`regress.sh` 的输出表明驱动侧已完成打开与模块枚举, 随后 hart 停在 M 模式的定时器处理路径:

```
[regress] opened /dev/tee_enclave
[regress] module dir '/modules' (3 modules, images are read on request)
[regress]   module id=7 path=/modules/attest.signed.bin
[regress]   module id=3 path=/modules/fs.signed.bin
[regress]   module id=4 path=/modules/net.signed.bin
```

rvdbg 停在 `pc=0x8002e94a`, 该地址属于 `.text:find_enclave_meta_info_by_id`。栈回溯:

```
#01 M  .text:find_enclave_meta_info_by_id   pc=0x8002e94a  ra=0x8002d33e
#02 M  .text:enclave_ext_proc_sched_expiry  pc=0x8002d33a
#03 M  .text:sbi_trap_handler               pc=0x80013e08  ra=0x80013e0c
#04 S                                       pc=0x83000000
```

陷态上下文: `mcause=0x8000000000000007` 即机器定时器中断, `mepc=0x83000000` (S 模式代码
地址), `mstatus=0x8000000000042802` 中 `MIE=0`、`MPP=1` 即产生中断时处于 S 模式, 另
`MPIE=0`、`MPRV=1`、`SIE=1`、`SD=1`。两次 `info` 之间指令计数由 2.822B 增至 7.134B, 该路径
在持续执行, 不是停在 WFI 等待。

据此, 失败表现为固件在 `sbi_trap_handler` 处理定时器中断时进入
`enclave_ext_proc_sched_expiry` 与 `find_enclave_meta_info_by_id` 的循环, 飞地域始终未进入。

## 待办

- 复现并确定失败位置: 飞地内存池、飞地侧网卡、CRNG 或其余资源。
- 决定缺失设备的处理方式: 按块设备的同一规则在树中补充节点并注册, 还是拒绝启动并报告缺失项。
- 固件侧取值与模拟器装配同源, 避免 PMP 条目与设备区间不一致。
- 用例覆盖树中缺少飞地所需设备时的各情形; 该计划尚未复现, 失败原因以上面列出的配置差距为
  线索, 不作结论。

---
