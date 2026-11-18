# 计划八 H 扩展与两阶段地址翻译

**状态**: 待确认

## Context

模拟器目前实现 U、S、M 三级特权级与 Sv39 单阶段地址翻译。
[pyremu/interrupt/](../../pyremu/interrupt/) 已具备 CLINT 的 `mtime`/`mtimecmp`/`msip`、
PLIC (legacy 模式) 与 AIA 模式的 IMSIC 与 APLIC；
[pyremu/_native/cpu/src/peripheral/](../../pyremu/_native/cpu/src/peripheral/) 提供加速执行引擎
内的同等多路处理。

H 扩展要求新增 HS 模式与 VS/VU 客户上下文、`hgatp` 两阶段地址翻译、
虚拟化 CSR 与客户中断文件。这些能力目前都缺失, 内核无法以 hypervisor 身份运行客户。

## 目标

- 两个阶段翻译: VS-stage (`vsatp`) 之后再经 G-stage (`hgatp`), 任一级缺页按
  `medeleg`/`hedeleg` 分流; TLB 条目带 VMID, 刷新区分 `HFENCE.VVMA` 与 `HFENCE.GVMA`。
- 虚拟化 CSR 与陷态: `hstatus`、`hedeleg`、`hideleg`、`hvip`、`hie`、`hcounteren`、
  `hgatp` 与 `vsstatus`/`vsatp`/`vstvec`/`vsscratch`/`vsepc`/`vscause`/`vstval`/`vstimecmp`
  等; HS 与 VS 之间的 trap 进出与 `SRET`/`MRET` 语义。
- 客户中断: IMSIC 客户中断文件与 APLIC 的 S 域、M 域之外的客户域投递。
- 指令: `HFENCE.VVMA`、`HFENCE.GVMA`; 若客户侧驱动需要, 再补 `HLV.*`/`HSV.*`。
- 设备: virtio-mmio 与 UART 由 HS 侧代表客户处理, 客户访问经 VS-stage 翻译后的
  物理地址进入设备窗口。

## 步骤

1. 数据模型: `HartState` 增加 `mode` 的 VS/VU 取值、`hgatp`/`vmid`/`vsatp` 与客户 CSR。
   同步更新 Python ctypes `_fields_`、`marshal_to`/`unmarshal_from` 与 `#[repr(C)]`
   两侧布局, 并按现有用例锁定结构体大小与对齐。
2. G-stage 遍历: [translate.rs](../../pyremu/_native/cpu/src/mem/translate.rs) 与
   [mmu.py](../../pyremu/memory/mmu.py) 各增加一层遍历, 复用既有叶子页与超级页规则;
   TLB 条目增加 VMID 字段。
3. 陷态与 CSR: 扩展 `deliver_trap`、`trap_sret`/`trap_mret` 与
   [csr.rs](../../pyremu/_native/cpu/src/csr.rs) 的读写掩码; 加入 `hedeleg`/`hideleg` 分流。
4. 中断: IMSIC 客户中断文件的 `seteipnum`/`clreipnum` 与 `hstatus` 相关位;
   APLIC 客户域配置。
5. 用例: 两阶段翻译的页级与超级页用例、`HFENCE` 刷新、VS 缺页经 `hedeleg` 注入、
   HS 与 VS 之间的 trap 往返、客户中断投递; 加速执行引擎与纯 Python 路径各一份。

## 落点

| 文件 | 改动 |
|------|------|
| pyremu/core/hart.py | `HartState` 字段与客户端 CSR 快捷属性 |
| pyremu/_native/cpu/src/state.rs | 同名字段的 `#[repr(C)]` 定义 |
| pyremu/_native/cpu/src/mem/translate.rs | G-stage 遍历与 TLB 条目 |
| pyremu/memory/mmu.py | 纯 Python 路径的同层遍历 |
| pyremu/_native/cpu/src/csr.rs | 虚拟化 CSR 与读写掩码 |
| pyremu/core/trap_handler.py | `hedeleg` 分流与 VS 陷态 |
| pyremu/interrupt/imsic.py | 客户中断文件 |

## 依赖与前置

- 与 [aia-imsic-hypervisor-plan.md](aia-imsic-hypervisor-plan.md) 中的 TOML 配置方案
  无先后依赖: 该方案尚未实施, 本计划按现有 `mk/` 生成的配置进行。
- FFI 结构体字段的新增必须先改 Python 与 Rust 两侧并同步布局用例, 否则加速执行引擎
  会在错误偏移处读写。
