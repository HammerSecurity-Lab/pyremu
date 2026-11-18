# 计划五 设备树未配置块设备时取默认镜像, 镜像缺失则报错终止

**状态**: 待确认

## Context

以 `--chip-dts` 启动时, [pyremu/utils/dev_tree/chip.py](../../pyremu/utils/dev_tree/chip.py) 的 `ChipPeriph` 按树中顺序
认领 virtio-mmio 区间, 但设备树只能给出 `compatible = "virtio,mmio"`, 无法说明某个节点是块设备
还是网卡; 设备类型要读 MMIO 偏移 0x008 的 device ID 才能确定。当前
[pyremu/emu/setup.py:192](pyremu/emu/setup.py#L192) 只在 `--disk` 给出时才注册块设备, 于是树中
有 virtio 节点而无 `--disk` 时内核拿不到 `/dev/vda`, 出现 `VFS: Cannot open root device` 与
`Kernel panic - not syncing`。

## 已确认的行为

1. 设备树配置了块设备时, 按传入的路径提供模拟块设备。
2. 设备树未配置块设备时, 取默认镜像 `bsp/setup-rootfs/debootstrap/riscv-sd.ext4`。
3. 该默认镜像同样不存在时, 向使用者报告错误并终止模拟, 不静默跳过。

## 根因 (2026-11-16 定稿)

restart 之后内核仍在 `sifive_serial_probe` 处抛 store access fault. 依据
`output/to-read.txt`: 重启后 `show pmp` 显示 64 条 PMP 全为 OFF; 而重启后的固件
完整走 coldboot 并打印 Domain0 区间, 说明固件确实配置过 PMP.

原因是模拟器内部状态未随 hart 重建更新: 每个 hart 的 PMP 条目数组在构造时经
`_bind_pmp_buffers` 绑定到加速执行引擎共享缓冲区的切片, `rebuild_harts` 新建
hart 后没有重新绑定. 于是固件在引擎内写入的条目落在共享缓冲区 (引擎侧生效, 内核
得以继续运行), 而 `_native_unmarshal_pmp` 只把变化同步回新 hart 自己的空数组,
Python 侧的 PMP 始终为空. 设备 MMIO 的访问必须退回 Python 检查, 无匹配条目的
S 模式写被按规范拒绝, 投递 StoreAccessFault.

## 修复 (2026-11-16)

`rebuild_harts` 重建 hart 之后重新调用 `_bind_pmp_buffers`, 刷新 PMP 快照, 并按
新 hart 重新写入 ISA 扩展开关. 回归用例见 `tests/test_dbg/test_exec.py` 的
`test_restart_rebinds_pmp_buffers`.

## 待办

- 判定入口: `--disk` 给出的路径优先; 未给出且树中存在 virtio-mmio 节点时取默认路径。
- 默认路径相对项目根目录解析, 不依赖当前工作目录; 复用
  [pyremu/utils/file_ops.py](../../pyremu/utils/file_ops.py) 的路径辅助。
- 文件不存在时报错并终止: 错误文本给出解析后的绝对路径与 `--disk` 选项名。
- 用例: 树中无 virtio 节点时不取默认镜像; 有节点而无 `--disk` 时取默认路径; 默认路径不存在
  时构造 `Emulator` 失败并给出该路径; `--disk` 给出的路径始终优先。

---
