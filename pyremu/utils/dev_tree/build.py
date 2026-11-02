#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""
Flat Device Tree (DTB) 生成器 — 基于 libfdt 构建设备树 blob.

将平台配置和外设映射序列化为符合 Devicetree 规范的二进制格式,
供固件通过 a1 寄存器接收。
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import struct
from typing import TYPE_CHECKING

import libfdt

from pyremu.configs_gen import PYREMU_AIA, TIMER_FREQ
from pyremu.platform import InterruptMode, PlatformConfig
from pyremu.utils.isa import isa_ext_list
from pyremu.utils.mask import mask32

if TYPE_CHECKING:
    from pyremu.interrupt.aplic import APLIC
    from pyremu.interrupt.imsic import IMSIC
    from pyremu.interrupt.plic import PLIC
    from pyremu.peripheral import CRNG, GPIO, I2C, SPI, UART, VirtIOBlock, VirtIONet
    from pyremu.peripheral.watchdog import HartWatchdog

# APLIC 有线中断触发类型:
# UART0 / virtio 均为 IRQ_TYPE_LEVEL_HIGH (0x4), 非 0 (NONE).
# 写 0 会让内核 aplic_irq_set_type 配成 SM_INACTIVE, 完成中断永不投递.
_IRQ_TYPE_LEVEL_HIGH = 0x4


@dataclass
class Initrd:
    """已加载的 initramfs 物理内存范围 (供 DTB /chosen 使用).

    start/end 为物理地址; Linux 读取 /chosen/linux,initrd-start 与
    linux,initrd-end 后将该区间的 cpio[.gz] 解包为 rootfs。
    """

    start: int
    end: int


# ============================================================
#  内存区域编码辅助
# ============================================================


def _encode_reg_4mib(
    addr: int,
    size: int,
) -> bytes:
    """将 64-bit 地址/大小编码为 4 个大端 u32 (addr_hi, addr_lo, size_hi, size_lo)."""
    return struct.pack(
        ">IIII",
        addr >> 32,
        mask32(addr),
        size >> 32,
        mask32(size),
    )


# ============================================================
#  各节点构建 (build_default_dtb 的分解: 每个函数写入一个/一组节点)
# ============================================================


def _dtb_chosen(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    uart: UART | None,
    bootargs: str | None,
    initrd: Initrd | None,
) -> None:
    """/chosen — stdout-path、内核命令行及initrd 范围."""
    if not (bootargs or initrd is not None):
        return
    p = cfg.periph
    sw.begin_node("chosen")
    if uart is not None:
        sw.property_string("stdout-path", f"/soc/serial@{p.uart_base:x}")
    if bootargs:
        sw.property_string("bootargs", bootargs)

    # 引导期熵种子 —— 使内核在启动即完成 CRNG 初始化, 避免用户态早期阻塞在
    # getrandom()/wait_for_random_bytes() (详见文件顶部注释)。
    # /chosen/rng-seed — 引导期熵种子 (供内核初始化 CRNG).
    #
    # 为什么需要: 无此属性时, 内核启动到用户态早期会阻塞在 wait_for_random_bytes()
    # 直到 CRNG 完成初始化。真实硬件靠中断/设备抖动积累熵，但目前没有实现这一随机数生成器设备
    #
    # 修复原理: drivers/of/fdt.c 的 early_init_dt_scan_chosen 读取 /chosen/rng-seed,
    # 调用 add_bootloader_randomness(); 配合 random.trust_bootloader=on 内核参数,
    # credit_init_bits(len*8) 直接完成 CRNG 初始化。
    # 种子 >= 32 字节 (256 bit) 即可;
    # 使用宿主 os.urandom(64) 提供 512 bit 真随机熵
    sw.property("rng-seed", os.urandom(64))
    if initrd is not None:
        sw.property("linux,initrd-start", struct.pack(">Q", initrd.start))
        sw.property("linux,initrd-end", struct.pack(">Q", initrd.end))
    sw.end_node()


def _dtb_aliases(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    uart: UART | None,
) -> None:
    """/aliases — 串口别名 (SiFive UART 驱动 probe 需要 serialN)."""
    if uart is None:
        return
    sw.begin_node("aliases")
    sw.property_string("serial0", f"/soc/serial@{cfg.periph.uart_base:x}")
    sw.end_node()  # aliases


def _dtb_cpus(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    *,
    is_aia: bool = False,
) -> list[int]:
    """/cpus — 每 hart 一个 cpu@N 节点; 返回各 hart intc 的 phandle 列表."""
    sw.begin_node("cpus")
    sw.property_u32("#address-cells", 1)
    sw.property_u32("#size-cells", 0)
    sw.property_u32("timebase-frequency", cfg.timebase_freq)

    # 构建 riscv,isa 与 riscv,isa-extensions 列表 (Linux 6.x+ 优先使用)
    # AIA 模式下追加 smaia/ssaia 扩展, 使内核 IMSIC 驱动通过
    # riscv_isa_extension_available(NULL, SxAIA) 检查后正常初始化.
    isa_str = cfg.isa
    if is_aia and "_smaia" not in isa_str:
        isa_str = f"{isa_str}_smaia_ssaia"
    isa_extensions = isa_ext_list(isa_str)
    isa_ext_bytes = b"".join(e.encode("ascii") + b"\x00" for e in isa_extensions)

    cpu_phandles: list[int] = []
    for i in range(cfg.num_harts):
        sw.begin_node(f"cpu@{i}")
        sw.property_string("device_type", "cpu")
        sw.property_u32("reg", i)
        sw.property_string("compatible", "riscv")
        # 保留 riscv,isa, 供不识别 riscv,isa-extensions 的旧版本内核使用
        sw.property_string("riscv,isa", isa_str)
        # 新式 riscv,isa-extensions — 消除 "Falling back to deprecated" 警告
        sw.property("riscv,isa-extensions", isa_ext_bytes)
        sw.property_string("mmu-type", "riscv,sv39")
        sw.property_string("status", "okay")

        # 中断控制器子节点 (供 CLINT interrupts-extended 引用)
        sw.begin_node("interrupt-controller")
        sw.property_string("compatible", "riscv,cpu-intc")
        sw.property_u32("#interrupt-cells", 1)
        sw.property("interrupt-controller", b"")
        phandle = i + 1
        sw.property_u32("phandle", phandle)
        cpu_phandles.append(phandle)
        sw.end_node()  # interrupt-controller
        sw.end_node()  # cpu@i
    sw.end_node()  # cpus
    return cpu_phandles


def _dtb_reserved_memory(
    sw: libfdt.FdtSw,
    ranges: list[tuple[int, int]],
) -> None:
    """/reserved-memory — 以 no-map 属性从 Linux 中移除物理区域.

    用于 enclave 内存池等需要从内核线性映射中完全移除的区域,
    与 PMP 隔离策略保持一致: 内核无法访问这些物理地址, 因此不会分配其中页面.
    """
    if not ranges:
        return
    sw.begin_node("reserved-memory")
    sw.property_u32("#address-cells", 2)
    sw.property_u32("#size-cells", 2)
    sw.property("ranges", b"")
    for idx, (base, size) in enumerate(ranges):
        sw.begin_node(f"reserved-{idx}@{base:x}")
        sw.property("no-map", b"")
        sw.property("reg", _encode_reg_4mib(base, size))
        sw.end_node()
    sw.end_node()  # reserved-memory


def _dtb_memory(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
) -> None:
    """/memory — 主 RAM 区间."""
    sw.begin_node("memory")
    sw.property_string("device_type", "memory")
    sw.property("reg", _encode_reg_4mib(cfg.ram_base, cfg.ram_size))
    sw.end_node()  # memory


def _dtb_clint(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    cpu_phandles: list[int],
) -> None:
    """clint@ — 每 hart 两条中断 <&cpu_intc 3 (MSI) &cpu_intc 7 (MTI)>."""
    clint_base = cfg.periph.clint_base
    sw.begin_node(f"clint@{clint_base:x}")
    sw.property_string("compatible", "riscv,clint0")
    sw.property("reg", _encode_reg_4mib(clint_base, 0x10000))
    ie_cells: list[int] = []
    for ph in cpu_phandles:
        ie_cells.extend([ph, 3, ph, 7])  # M-SW-IRQ=3, M-TIMER-IRQ=7
    sw.property(
        "interrupts-extended",
        struct.pack(">" + "I" * len(ie_cells), *ie_cells),
    )
    sw.end_node()  # clint


def _dtb_plic(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    plic: PLIC | None,
    plic_phandle: int | None,
    cpu_phandles: list[int],
) -> None:
    """plic@ — 每 hart 双 context (M+S): <&cpu_intc 11>, <&cpu_intc 9>.

    context 序号: 0=hart0 M, 1=hart0 S, 2=hart1 M, 3=hart1 S, ...
    OpenSBI 初始化 M-context,
    Linux 认领 S-context.
    """
    if plic is None:
        return
    plic_base = cfg.periph.plic_base
    sw.begin_node(f"plic@{plic_base:x}")
    sw.property_u32("phandle", plic_phandle)
    sw.property_string("compatible", "riscv,plic0")
    sw.property_u32("#interrupt-cells", 1)
    sw.property("interrupt-controller", b"")  # 布尔属性必须零长度
    sw.property("reg", _encode_reg_4mib(plic_base, plic.size))
    sw.property_u32("riscv,ndev", 128)
    plic_ie: list[int] = []
    for ph in cpu_phandles:
        plic_ie.extend([ph, 11, ph, 9])  # M-EXT-IRQ=11, S-EXT-IRQ=9
    sw.property(
        "interrupts-extended",
        struct.pack(">" + "I" * len(plic_ie), *plic_ie),
    )
    sw.end_node()  # plic


# ============================================================
#  IMSIC 节点 — 拆分为 M/S 两个独立节点
#
#  针对每个特权级各创建一个 IMSIC 节点, 且
#  interrupts-extended 仅含该特权级对应的中断号码, M 为 11, S 为 9。
#
# ============================================================

# M/S 模式对应的 CPU intc 中断号.
_IMSIC_IRQ_M = 11  # MEIP
_IMSIC_IRQ_S = 9  # SEIP

_PAGE_STRIDE_DTB = 0x1000  # IMSIC_MMIO_PAGE_SZ


@dataclass(slots=True)
class DefaultDtbDev:
    """构建设备树时使用的设备实例集合; 未给出的成员对应的节点省略."""

    uart: UART | None = None
    spi: SPI | None = None
    i2c_gen: I2C | None = None
    gpio: GPIO | None = None
    virtio_blk: VirtIOBlock | None = None
    virtio_net_s: VirtIONet | None = None
    watchdog: HartWatchdog | None = None
    crng: CRNG | None = None
    plic: PLIC | None = None
    imsic: IMSIC | None = None
    aplic_s: APLIC | None = None


@dataclass(frozen=True, slots=True)
class ImsicNodeSpec:
    """单个 IMSIC 节点的中断号、基址与区域大小."""

    cpu_intc_irq: int
    base_addr: int
    size: int


def _dtb_imsic_file(
    sw: libfdt.FdtSw,
    devices: DefaultDtbDev,
    phandle: int | None,
    cpu_phandles: list[int],
    spec: ImsicNodeSpec,
) -> None:
    """生成单个 IMSIC 节点 — 参数化 M/S 以消除重复."""
    if devices.imsic is None:
        return
    cpu_intc_irq = spec.cpu_intc_irq
    base_addr = spec.base_addr
    size = spec.size
    sw.begin_node(f"imsic@{base_addr:x}")
    sw.property_u32("phandle", phandle)
    sw.property_string("compatible", "riscv,imsics")
    sw.property_u32("#interrupt-cells", 0)
    sw.property_u32("#msi-cells", 0)
    sw.property("interrupt-controller", b"")
    sw.property("msi-controller", b"")
    sw.property_u32("riscv,num-ids", 255)  # must satisfy (num_ids & 63) == 63
    sw.property_u32("riscv,guest-index-bits", 0)
    # 不设 hart-index-bits
    # 内核默认 stride = PAGE_SIZE << guest_index_bits = 0x1000,
    # 必须与 decode_imsic_addr 的实际布局一致, 即连续排列, 每个 hart 一页.
    # hart-index-bits != 0 会使内核算出更大的 stride, 如 0x2000、0x4000 等,
    # 导致写 seteipnum 偏移到错误的 hart, 进而 IPI 丢失与 SMP 死锁.
    sw.property("reg", _encode_reg_4mib(base_addr, size))
    # 该 privilege level 对应的中断 — 每种各一个 per hart.
    ie: list[int] = []
    for ph in cpu_phandles:
        ie.extend([ph, cpu_intc_irq])
    sw.property(
        "interrupts-extended",
        struct.pack(">" + "I" * len(ie), *ie),
    )
    sw.end_node()  # imsic


def _dtb_aplic(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    aplic_s: APLIC | None,
    aplic_phandle: int | None,
    imsic_phandle: int | None,
) -> None:
    """aplic@ — 把有线中断转换为 MSI 消息, 经 msi-parent=<&imsic> 投递.

    APLIC does NOT have interrupts-extended because all interrupts are
    delivered as MSIs through the IMSIC identified by msi-parent.

    本函数只建 S 域这一个节点。固件的 APLIC 驱动对树中每个 riscv,aplic 节点执行
    aplic_init, 该函数把 DOMAINCFG 清零, 并把全部 sourcecfg 与 target 复位; 树中
    再出现一个 msi-parent 指向 IMSIC M 节点的 aplic 节点, 会令模拟器预置的 M 域
    源配置被复位, 该域的源退回 inactive 而丢弃全部中断。
    """
    if aplic_s is None:
        return
    p = cfg.periph
    aplic_s_base = p.aplic_s_base
    sw.begin_node(f"aplic@{aplic_s_base:x}")
    sw.property_u32("phandle", aplic_phandle)
    sw.property_string("compatible", "riscv,aplic")
    sw.property_u32("#interrupt-cells", 2)
    sw.property("interrupt-controller", b"")
    sw.property_u32("riscv,num-sources", 128)
    sw.property("reg", _encode_reg_4mib(aplic_s_base, aplic_s.size))
    # msi-parent: route through IMSIC
    sw.property_u32("msi-parent", imsic_phandle)
    sw.end_node()  # aplic_s


def _dtb_uart(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    uart: UART | None,
    ext_irq_handle_prop: int | None,
    clock_phandle: int,
) -> None:
    """serial@ (+ fixed-clock) — SiFive NS16550A 兼容串口."""
    if uart is None:
        return
    p = cfg.periph
    # 固定时钟 — 使 SiFive 串口驱动在无 CCF 时钟控制器的 DTB 中也能 probe.
    # 内核 CONFIG_COMMON_CLK=y 时 devm_clk_get() 若找不到 clocks 属性
    # 返回 EPROBE_DEFER, 驱动永不匹配; 提供 fixed-clock 解决此问题.
    sw.begin_node("clock")
    sw.property_u32("phandle", clock_phandle)
    sw.property_string("compatible", "fixed-clock")
    sw.property_u32("#clock-cells", 0)
    sw.property_u32("clock-frequency", cfg.timebase_freq)
    sw.end_node()  # clock

    sw.begin_node(f"serial@{p.uart_base:x}")
    sw.property_string("compatible", "sifive,uart0")
    sw.property_string("status", "okay")
    sw.property("reg", _encode_reg_4mib(p.uart_base, 0x1000))
    sw.property("clocks", struct.pack(">I", clock_phandle))
    sw.property_u32("clock-frequency", cfg.timebase_freq)
    # APLIC expects #interrupt-cells=2: <source flags>
    # PLIC  expects #interrupt-cells=1: <irq>
    irq_parent = ext_irq_handle_prop if ext_irq_handle_prop is not None else 1
    if PYREMU_AIA:
        sw.property(
            "interrupts-extended",
            struct.pack(">III", irq_parent, p.uart_irq, _IRQ_TYPE_LEVEL_HIGH),
        )
    else:
        sw.property(
            "interrupts-extended",
            struct.pack(">II", irq_parent, p.uart_irq),
        )
    sw.end_node()  # serial


def _dtb_virtio_node(
    sw: libfdt.FdtSw,
    base: int,
    irq: int,
) -> None:
    """一个 virtio-mmio 节点, 中断由 /soc 的 interrupt-parent 转达.

    中断单元数随中断模式变化: AIA 下 APLIC 取 ``<中断源编号 flags>`` 两格,
    legacy 下 PLIC 取 ``<中断源编号>`` 一格.
    """
    sw.begin_node(f"virtio@{base:x}")
    sw.property_string("compatible", "virtio,mmio")
    sw.property("reg", _encode_reg_4mib(base, 0x200))
    if PYREMU_AIA:
        sw.property("interrupts", struct.pack(">II", irq, _IRQ_TYPE_LEVEL_HIGH))
    else:
        sw.property_u32("interrupts", irq)
    sw.end_node()  # virtio


def _dtb_spi(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    spi: SPI | None,
) -> None:
    """spi@ — SPI 主控."""
    if spi is None:
        return
    base = cfg.periph.spi_base
    sw.begin_node(f"spi@{base:x}")
    sw.property_string("compatible", "spi0")
    sw.property("reg", _encode_reg_4mib(base, 0x1000))
    sw.end_node()  # spi


def _dtb_i2c(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    i2c: I2C | None,
) -> None:
    """i2c@ — I2C 主控."""
    if i2c is None:
        return
    base = cfg.periph.i2c_base
    sw.begin_node(f"i2c@{base:x}")
    sw.property_string("compatible", "i2c0")
    sw.property("reg", _encode_reg_4mib(base, 0x1000))
    sw.end_node()  # i2c


def _dtb_gpio(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    gpio: GPIO | None,
) -> None:
    """gpio@ — 通用输入输出控制器."""
    if gpio is None:
        return
    base = cfg.periph.gpio_base
    sw.begin_node(f"gpio@{base:x}")
    sw.property_string("compatible", "gpio0")
    sw.property("reg", _encode_reg_4mib(base, 0x1000))
    sw.end_node()  # gpio


def _dtb_virtio_blk(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    blk: VirtIOBlock | None,
) -> None:
    """virtio@ — 虚拟块设备."""
    if blk is None:
        return
    _dtb_virtio_node(sw, cfg.periph.virtio_blk_base, cfg.periph.virtio_blk_irq)


def _dtb_virtio_net_s(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    net_s: VirtIONet | None,
) -> None:
    """virtio@ — 宿主侧虚拟网卡.

    M 模式一侧的网卡实例不进设备树: 内核会为树中出现的中断源在自己的 S context
    上使能它, 该中断源一置位即产生 SEIP, 而 SEIP 由宿主 S 模式支配.
    """
    if net_s is None:
        return
    _dtb_virtio_node(sw, cfg.periph.virtio_net_s_base, cfg.periph.virtio_net_s_irq)


def _dtb_watchdog(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    watchdog: HartWatchdog | None,
    ext_irq_handle_prop: int | None,
    is_aia: bool,
) -> None:
    """watchdog@ — 每个 hart 一段倒计数器的看门狗.

    `clock-frequency` 取 TIMER_FREQ, 与 WDOG_TIMEOUT 的计数单位相同. 不写
    `clocks`: `_dtb_uart` 已在 /soc 下生成 fixed-clock 节点, 再生成一个会与同级
    节点重名.
    """
    if watchdog is None:
        return
    irq = cfg.periph.watchdog_irq
    base = watchdog.base_addr
    irq_parent = ext_irq_handle_prop if ext_irq_handle_prop is not None else 1
    sw.begin_node(f"watchdog@{base:x}")
    sw.property_string("compatible", "pyremu,hart-watchdog-1.0")
    sw.property_string("status", "okay")
    sw.property("reg", _encode_reg_4mib(base, watchdog.size))
    sw.property_u32("clock-frequency", TIMER_FREQ)
    sw.property_u32("pyremu,num-harts", watchdog.num_harts)
    # APLIC 取 <中断源编号 flags> 两格, PLIC 取 <中断源编号> 一格.
    if is_aia:
        sw.property(
            "interrupts-extended",
            struct.pack(">III", irq_parent, irq, _IRQ_TYPE_LEVEL_HIGH),
        )
    else:
        sw.property(
            "interrupts-extended",
            struct.pack(">II", irq_parent, irq),
        )
    sw.end_node()  # watchdog


def _dtb_crng(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    crng: CRNG | None,
) -> None:
    """crng@ — 模拟随机数生成器, 基址取自 PeripheralConfig."""
    if crng is None:
        return
    base = cfg.periph.crng_base
    sw.begin_node(f"crng@{base:x}")
    sw.property_string("compatible", "crng")
    sw.property("reg", _encode_reg_4mib(base, 0x1000))
    sw.end_node()  # crng


# ============================================================
#  DTB 构建入口
# ============================================================


def build_default_dtb(
    cfg: PlatformConfig,
    *,
    devices: DefaultDtbDev | None = None,
    bootargs: str | None = None,
    initrd: Initrd | None = None,
    reserved_ranges: list[tuple[int, int]] | None = None,
) -> bytes:
    """基于平台配置和外设映射构建完整的 DTB blob.

    Args:
        cfg: 平台配置, 描述 CPU 拓扑、内存布局和 ISA 特性.
        devices: 设备实例集合, 未给出的成员对应的节点省略.
        bootargs: 内核命令行参数, 写入 /chosen/bootargs.
        initrd: 初始内存盘 (None 则 /chosen 不写 initrd 相关属性).
        reserved_ranges: (base, size) 列表, 生成 /reserved-memory no-map 子节点.

    Returns:
        完整的 DTB blob 字节串, 可直接写入 RAM 供固件使用.
    """
    devices = devices or DefaultDtbDev()
    is_aia = cfg.interrupt_mode == InterruptMode.AIA

    sw = libfdt.FdtSw(8192)
    sw.finish_reservemap()

    # ---- 根节点 ----
    sw.begin_node("")
    sw.property_u32("#address-cells", 2)
    sw.property_u32("#size-cells", 2)
    sw.property_string("compatible", "riscv64")
    sw.property_string("model", cfg.isa)

    _dtb_chosen(sw, cfg, devices.uart, bootargs, initrd)
    _dtb_aliases(sw, cfg, devices.uart)
    cpu_phandles = _dtb_cpus(sw, cfg, is_aia=is_aia)
    _dtb_memory(sw, cfg)
    _dtb_reserved_memory(sw, reserved_ranges or [])
    _dtb_soc(sw, cfg, devices, cpu_phandles, is_aia)

    sw.end_node()  # root

    return bytes(sw.as_fdt().as_bytearray())


def _dtb_soc(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    devices: DefaultDtbDev,
    cpu_phandles: list[int],
    is_aia: bool,
) -> None:
    """生成 /soc 节点: 分配 intc phandle 并挂载全部 MMIO 外设."""
    # phandle 分配: CPU intc 占 [1..num_harts].
    # 随后 AIA 模式下 IMSIC_M、IMSIC_S、APLIC 各分配一个; legacy 模式下分配 PLIC.
    next_phandle = len(cpu_phandles) + 1
    imsic_m_phandle: int | None = None
    imsic_s_phandle: int | None = None
    aplic_phandle: int | None = None
    ext_irq_handle_prop: int | None = None
    if is_aia:
        if devices.imsic is not None:
            imsic_m_phandle = next_phandle
            next_phandle += 1
            imsic_s_phandle = next_phandle
            next_phandle += 1
        if devices.aplic_s is not None:
            aplic_phandle = next_phandle
            next_phandle += 1
            ext_irq_handle_prop = aplic_phandle
    elif devices.plic is not None:
        ext_irq_handle_prop = next_phandle
        next_phandle += 1

    sw.begin_node("soc")
    sw.property_u32("#address-cells", 2)
    sw.property_u32("#size-cells", 2)
    sw.property_string("compatible", "simple-bus")
    sw.property("ranges", b"")  # 透传
    if ext_irq_handle_prop is not None:
        sw.property_u32("interrupt-parent", ext_irq_handle_prop)

    _dtb_clint(sw, cfg, cpu_phandles)
    if is_aia:
        _dtb_imsic_nodes(sw, cfg, devices, cpu_phandles, (imsic_m_phandle, imsic_s_phandle))
        _dtb_aplic(sw, cfg, devices.aplic_s, aplic_phandle, imsic_s_phandle)
    else:
        _dtb_plic(sw, cfg, devices.plic, ext_irq_handle_prop, cpu_phandles)
    _dtb_uart(sw, cfg, devices.uart, ext_irq_handle_prop, next_phandle)
    _dtb_spi(sw, cfg, devices.spi)
    _dtb_i2c(sw, cfg, devices.i2c_gen)
    _dtb_gpio(sw, cfg, devices.gpio)
    _dtb_virtio_blk(sw, cfg, devices.virtio_blk)
    _dtb_virtio_net_s(sw, cfg, devices.virtio_net_s)
    _dtb_watchdog(sw, cfg, devices.watchdog, ext_irq_handle_prop, is_aia)
    _dtb_crng(sw, cfg, devices.crng)

    sw.end_node()  # soc


def _dtb_imsic_nodes(
    sw: libfdt.FdtSw,
    cfg: PlatformConfig,
    devices: DefaultDtbDev,
    cpu_phandles: list[int],
    phandles: tuple[int | None, int | None],
) -> None:
    """生成 M 与 S 两个 IMSIC 节点."""
    imsic_m_phandle, imsic_s_phandle = phandles
    page_stride = _PAGE_STRIDE_DTB
    m_base = cfg.periph.imsic_m_base
    # OpenSBI imsic_data_check 要求 reg size 对齐到
    # 2^hart_index_bits * PAGE_SIZE.  hart_index_bits =
    # ceil(log2(num_harts)), 即 (num_harts-1).bit_length().
    # 非 2 的幂 hart 数, 如 3、5、6、7, 若不补齐,
    # 则 OpenSBI imsic_cold_irqchip_init 失败, irqchip 未注册,
    # 此后 sbi_irqchip_process 返回 SBI_ENODEV, 即 -1000.
    if cfg.num_harts > 1:
        hart_index_bits = (cfg.num_harts - 1).bit_length()
    else:
        hart_index_bits = 0
    padded_count = 1 << hart_index_bits  # >= num_harts 的 2 的幂
    m_size = padded_count * page_stride
    # M 节点: M-files 范围, MEIP(11) 专用.
    _dtb_imsic_file(
        sw,
        devices,
        imsic_m_phandle,
        cpu_phandles,
        ImsicNodeSpec(_IMSIC_IRQ_M, m_base, m_size),
    )
    # S 节点: S-files 范围 (M-base + padded_count*0x1000), SEIP(9) 专用.
    _dtb_imsic_file(
        sw,
        devices,
        imsic_s_phandle,
        cpu_phandles,
        ImsicNodeSpec(_IMSIC_IRQ_S, m_base + padded_count * page_stride, m_size),
    )
