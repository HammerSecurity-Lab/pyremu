#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""CLI 入口 — 解析参数、加载固件并启动交互调试器."""

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

from loguru import logger

from pyremu import configs_gen
from pyremu.debug import Debugger
from pyremu.debug.types import ImageKind, LoadedImage
from pyremu.debug.utils import fmt_size, parse_size
from pyremu.emulator import Emulator
from pyremu.env_inject import Preloader
from pyremu.peripheral.virtio_mmio import VIRTIO_MMIO_SIZE
from pyremu.platform import PeripheralConfig, PlatformConfig
from pyremu.utils import dev_tree
from pyremu.utils.parse_bin import FirmwareImage, parse_firmware

# 设备树未声明块设备时交给它的镜像, 相对仓库根目录解析, 不依赖当前工作目录.
DEFAULT_DISK_IMAGE = (
    Path(__file__).resolve().parent.parent.parent
    / "bsp"
    / "setup-rootfs"
    / "debootstrap"
    / "riscv-sd.ext4"
)

# 芯片设备树缺少块设备时补充的节点: 节点名前缀, compatible 与 reg 的大小.
VIRTIO_BLK_DEVICE = dev_tree.DtDeviceRequest("virtio", "virtio,mmio", VIRTIO_MMIO_SIZE)

# ============================================================
#  Argument parser
# ============================================================


def _build_arg_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器."""
    p = argparse.ArgumentParser(
        description="RISC-V Interactive Debugger (rvdb)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  %(prog)s firmware.bin\n"
        "  %(prog)s firmware.elf --entry-symbol main\n"
        "  %(prog)s app.elf --preload crt0.bin --entry-symbol main\n"
        "  %(prog)s firmware.bin --harts 4 --ram 256M",
    )
    p.add_argument("firmware", help="固件文件路径 (ELF / PE / raw binary)")
    p.add_argument(
        "--base-addr",
        type=lambda x: int(x, 0),
        default=0x80000000,
        help="raw binary 的加载基址 (ELF/PE 时忽略, 默认 0x80000000)",
    )
    p.add_argument(
        "--prog-cnt",
        type=lambda x: int(x, 0),
        default=None,
        help="程序计数器 — 每个 hart 的开始执行地址",
    )
    p.add_argument(
        "--ram-base",
        type=lambda x: int(x, 0),
        default=None,
        help="物理内存基址",
    )
    p.add_argument(
        "--rom-base",
        type=lambda x: int(x, 0),
        default=None,
        help="引导只读存储器基址",
    )
    p.add_argument(
        "--rom-size",
        type=lambda x: int(x, 0),
        default=None,
        help="引导只读存储器大小",
    )
    p.add_argument(
        "--fdt",
        type=lambda x: int(x, 0) if x else None,
        default=-1,
        nargs="?",
        const=-1,
        help="设备树加载地址",
    )
    fdt_source = p.add_mutually_exclusive_group()
    fdt_source.add_argument(
        "--fdt-file",
        type=str,
        default=None,
        metavar="PATH[:ADDR]",
        help="加载预编译 DTB 文件",
    )
    fdt_source.add_argument(
        "--chip-dts",
        type=str,
        default=None,
        metavar="PATH",
        help="按芯片的 DTS 描述装配平台, 并把同一棵树的 blob 交给受调试程序",
    )
    fdt_source.add_argument(
        "--no-fdt",
        action="store_true",
        default=False,
        help="禁用设备树",
    )
    p.add_argument(
        "--harts",
        type=int,
        default=None,
        help="hart 数量",
    )
    p.add_argument(
        "--ram",
        type=str,
        default=None,
        help="RAM 大小",
    )
    p.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=[
            "TRACE",
            "DEBUG",
            "INFO",
            "SUCCESS",
            "WARNING",
            "ERROR",
            "CRITICAL",
        ],
        help="日志级别",
    )
    p.add_argument(
        "--preload",
        type=str,
        default=None,
        help="预加载载荷的文件路径",
    )
    p.add_argument(
        "--preload-addr",
        type=lambda x: int(x, 0),
        default=None,
        help=(
            "预加载载荷的加载地址, 默认 ram_base + ram_size - RAM_PRELOAD_OFFSET; "
            "落在引导只读存储器的范围内时加载该设备"
        ),
    )
    p.add_argument(
        "--entry-symbol",
        type=str,
        default=None,
        help="目标程序入口符号名，如 'main'",
    )
    p.add_argument(
        "--sym-dir",
        type=str,
        default=None,
        metavar="DIR",
        help="符号文件所在目录, 作为 sym 命令的初始候选目录",
    )
    p.add_argument(
        "--kernel",
        type=str,
        default=None,
        metavar="PATH",
        help="内核 Image 二进制文件, 预载到 RAM",
    )
    p.add_argument(
        "--kernel-addr",
        type=lambda x: int(x, 0),
        default=None,
        metavar="ADDR",
        help="内核 Image 加载地址",
    )
    p.add_argument(
        "--bootargs",
        type=str,
        default=None,
        metavar="ARGS",
        help="内核命令行参数, 写入 DTB /chosen/bootargs",
    )
    p.add_argument(
        "--initrd",
        type=str,
        default=None,
        metavar="PATH",
        help="initramfs 文件, 加载到 RAM 并写入 DTB /chosen",
    )
    p.add_argument(
        "--initrd-addr",
        type=lambda x: int(x, 0),
        default=None,
        metavar="ADDR",
        help="initramfs 加载地址",
    )
    p.add_argument(
        "--disk",
        type=str,
        default=None,
        metavar="PATH",
        help="virtio-blk 磁盘镜像, 挂载为 /dev/vda; 无写权限时只读打开",
    )
    p.add_argument(
        "--hart-logs",
        type=str,
        default=None,
        metavar="DIR",
        help="将各 hart 的串口输出另存到 DIR/hart<N>.log",
    )
    return p


# ============================================================
#  CLI 工具函数
# ============================================================


def _setup_logger(level: str) -> None:
    """配置 loguru: 彩色输出到 stdout."""
    logger.remove()
    logger.add(
        sys.stdout,
        format=(
            "<green>{time:HH:mm:ss}</green> "
            "[<yellow>{file}:{line}</yellow>|<level>{level}</level>] "
            "<level>{message}</level>"
        ),
        colorize=True,
        level=level,
    )


@dataclass(frozen=True)
class PlatformParams:
    """装配平台所需的取值, 按命令行、芯片设备树、configs_gen 的顺序取得."""

    num_harts: int
    ram_base: int
    ram_size: int
    rom_base: int
    rom_size: int
    timebase_freq: int
    pmp_entries: int
    # 平台声明的扩展集合; 芯片设备树声明了扩展时取树中的声明.
    isa: str


def _load_chip_dts(
    path: str | None,
) -> dev_tree.ChipDt | None:
    """读取 --chip-dts 给出的芯片设备树; 未给出时返回 None."""
    if path is None:
        return None
    try:
        chip = dev_tree.parse_chip_dts(path)
    except Exception as exc:
        logger.error(f"无法解析芯片设备树 {path}: {exc}")
        sys.exit(1)
    logger.info(
        f"芯片设备树: {path}, hart 数={chip.num_harts}, "
        f"RAM={dev_tree.region_text(chip.ram)}, "
        f"引导只读存储器={dev_tree.region_text(chip.rom)}, "
        f"启动地址寄存器={dev_tree.region_text(chip.boot_addr)}"
    )
    return chip


def _pick(
    *values: int | None,
    default: int,
) -> int:
    """取第一个非 None 的取值; 全部为 None 时取 default."""
    for value in values:
        if value is not None:
            return value
    return default


def _resolve_platform(
    ns: argparse.Namespace,
    chip: dev_tree.ChipDt | None,
) -> PlatformParams:
    """合并命令行与芯片设备树的取值.

    命令行显式给出的取值优先, 其次是芯片设备树中的描述, 两者都没有时取
    configs_gen 给出的平台默认值. 树中没有描述某项时按未给出处理.

    hart 数取 min(max(1, 命令行或默认值给出的请求值), max(1, 树中 CPU 节点数)):
    客机看到的 CPU 数由交给它的设备树决定, 装配多于该数的 hart 无法被启动.
    未给出芯片设备树时不设该上限.

    PMP 条目数取芯片设备树与 configs_gen 中的较大者, 使实际实现的条目数不低于
    任一来源的声明. 模拟器的 PMP 寄存器由 configs_gen 的取值定义, 设备树声明的
    条目数超过该值时无法装配, 报告冲突后终止模拟.

    设备树为各 hart 声明了不同的取值时, 模拟器只支持各 hart 相同的配置, 同样
    报告冲突后终止模拟.
    """
    tree_harts: int | None = None
    tree_ram_base: int | None = None
    tree_ram_size: int | None = None
    tree_rom_base: int | None = None
    tree_rom_size: int | None = None
    tree_timebase: int | None = None
    tree_pmp: int | None = None
    if chip is not None:
        tree_harts = chip.num_harts if chip.num_harts > 0 else None
        tree_timebase = chip.timebase_freq
        tree_pmp = chip.pmp_entries
        if chip.ram is not None:
            tree_ram_base = chip.ram.base
            tree_ram_size = chip.ram.size
        if chip.rom is not None:
            tree_rom_base = chip.rom.base
            tree_rom_size = chip.rom.size
    cli_ram_size = parse_size(ns.ram) if ns.ram is not None else None
    requested_harts = max(1, _pick(ns.harts, tree_harts, default=1))
    if chip is not None:
        requested_harts = min(requested_harts, max(1, chip.num_harts))
        _reject_per_hart_difference(chip)
    pmp_entries = max(tree_pmp or 0, configs_gen.PMP_ENTRIES)
    if pmp_entries > configs_gen.PMP_ENTRIES:
        logger.error(
            f"芯片设备树声明了 {pmp_entries} 项 PMP, 模拟器按配置实现 "
            f"{configs_gen.PMP_ENTRIES} 项, 无法装配该平台"
        )
        sys.exit(1)
    return PlatformParams(
        num_harts=requested_harts,
        ram_base=_pick(ns.ram_base, tree_ram_base, default=configs_gen.RAM_BASE),
        ram_size=_pick(cli_ram_size, tree_ram_size, default=configs_gen.RAM_SIZE),
        rom_base=_pick(ns.rom_base, tree_rom_base, default=configs_gen.ROM_BASE),
        rom_size=_pick(ns.rom_size, tree_rom_size, default=configs_gen.ROM_SIZE),
        timebase_freq=_pick(tree_timebase, default=configs_gen.TIMER_FREQ),
        pmp_entries=pmp_entries,
        isa=_pick(_chip_isa(chip), default=configs_gen.ISA),
    )


def _chip_isa(
    chip: dev_tree.ChipDt | None,
) -> str | None:
    """芯片设备树声明的扩展集合, 以旧式 ISA 字符串给出.

    ``riscv,isa`` 与 ``riscv,isa-extensions`` 两处声明合并为一项: 前者作首段,
    后者的各扩展名以 ``_`` 相接. 两处都未声明时返回 None, 由调用方取平台默认值.
    """
    if chip is None:
        return None
    parts = [part for part in (chip.isa, chip.isa_extensions) if part]
    if not parts:
        return None
    return "_".join(part.replace(" ", "_") for part in parts)


def _reject_per_hart_difference(
    chip: dev_tree.ChipDt,
) -> None:
    """设备树为各 hart 声明了不同取值时报告冲突并终止.

    模拟器对全部 hart 使用同一份配置, 无法按 hart 分别实现.
    """
    differing = chip.differing_attrs()
    for name, values in differing.items():
        detail = ", ".join(f"hart{hid}={val}" for hid, val in sorted(values.items()))
        logger.error(f"芯片设备树为各 hart 声明了不同的 {name}: {detail}")
    if differing:
        logger.error("模拟器只支持各 hart 相同的配置, 无法装配该平台")
        sys.exit(1)


def _is_rom_addr(addr: int, rom_base: int, rom_size: int) -> bool:
    """判断物理地址是否属于引导只读存储器的窗口; rom_base 取 0 时恒为 False."""
    return bool(rom_base) and rom_base <= addr < rom_base + rom_size


def _image_in_rom(
    image: FirmwareImage,
    rom_base: int,
    rom_size: int,
) -> bool:
    """判断固件的全部段是否落在引导只读存储器的窗口内."""
    if not rom_base:
        return False
    if not image.segments:
        return _is_rom_addr(image.entry_point, rom_base, rom_size)
    start = min(seg.vaddr for seg in image.segments)
    end = max(seg.vaddr + seg.memsz for seg in image.segments)
    return rom_base <= start and end <= rom_base + rom_size


def _load_firmware_image(
    fw_path: str,
    base_addr: int,
    ram_base: int,
    rom_base: int = configs_gen.ROM_BASE,
    rom_size: int = configs_gen.ROM_SIZE,
) -> tuple[FirmwareImage, int]:
    """解析固件并计算装载偏移.

    返回 (image, load_offset). 段的链接地址最小值不低于 ram_base, 或全部段落在
    引导只读存储器的窗口内时偏移为 0; 其余 ELF 固件按链接地址加 ram_base 装入.
    """
    if not Path(fw_path).exists():
        logger.error(f"文件不存在: {fw_path}")
        sys.exit(1)

    logger.info(f"正在解析固件: {fw_path}")
    image = parse_firmware(fw_path, base_addr=base_addr)
    if image is None:
        logger.error(f"无法解析固件: {fw_path}")
        sys.exit(1)

    logger.info(
        f"格式={image.format}, 入口=0x{image.entry_point:x}, 段数={len(image.segments)}"
    )
    max_name = max((len(seg.name) for seg in image.segments), default=6)
    max_name = max(max_name, 6)
    for seg in image.segments:
        logger.info(
            f"  {seg.name:<{max_name}s}  vaddr=0x{seg.vaddr:016x}"
            f"  size={fmt_size(len(seg.data)):>10s}"
            f"  memsz={fmt_size(seg.memsz):>10s}"
        )

    load_offset = 0
    if image.format == "elf":
        # 段落在引导只读存储器的窗口内时按链接地址装入, 不施加装载偏移.
        if _image_in_rom(image, rom_base, rom_size):
            logger.info(
                f"固件段位于引导只读存储器 [0x{rom_base:x}, "
                f"0x{rom_base + rom_size:x}) 内, 不施加装载偏移"
            )
            return image, load_offset
        min_vaddr = min(seg.vaddr for seg in image.segments)
        if min_vaddr >= ram_base:
            return image, load_offset
        load_offset = ram_base
        logger.info(
            f"PIE 固件段偏移 +0x{load_offset:x}"
            f" (min vaddr=0x{min_vaddr:x} < ram_base=0x{ram_base:x})"
        )
    return image, load_offset


def _default_fdt_addr(
    ram_base: int,
    ram_size: int,
    rom_base: int,
    is_rom_boot: bool,
) -> int:
    """设备树的默认加载地址.

    从引导只读存储器启动时, 设备树随该存储器的镜像位于基址加 ROM_DTB_OFFSET, 与
    零阶段引导程序按 _start + 0x10000 算出的地址一致. 其余情形由模拟器交付设备树,
    取 ram_base + ram_size - RAM_DTB_OFFSET, 见 mk/memory.mk.
    """
    if is_rom_boot:
        return rom_base + configs_gen.ROM_DTB_OFFSET
    return ram_base + ram_size - configs_gen.RAM_DTB_OFFSET


def _fdt_load_addr(
    ns: argparse.Namespace,
    default_addr: int,
) -> int | None:
    """本次启动的设备树装载地址; 不装载设备树时为 None.

    --no-fdt 不装载. 给出 --fdt-file 时取文件名后缀的地址, 没有后缀时取
    default_addr. 给出 --fdt 时取其值, 取值 -1 表示取 default_addr, 取值 0 表示
    未给出.
    """
    if ns.no_fdt:
        return None
    if ns.fdt_file:
        parts = ns.fdt_file.rsplit(":", 1)
        return int(parts[1], 0) if len(parts) > 1 else default_addr
    if ns.fdt:
        return default_addr if ns.fdt == -1 else ns.fdt
    return None


def _load_fdt(
    emu: Emulator,
    ns: argparse.Namespace,
    addr: int | None,
) -> None:
    """按 CLI 参数把设备树写入 addr; addr 为 None 时不装载.

    --fdt-file 装载文件中的 blob, 其余情形装载默认设备树. addr 由 _fdt_load_addr
    给出.
    """
    if addr is None:
        return
    if ns.fdt_file:
        emu.load_dtb_file(ns.fdt_file.rsplit(":", 1)[0], addr=addr)
        return
    emu.load_default_dtb(addr)


def _load_chip_fdt(
    emu: Emulator,
    chip: dev_tree.ChipDt,
    addr: int | None,
) -> None:
    if addr is None:
        return
    cfg = emu.config
    initrd = emu.initrd
    try:
        blob = dev_tree.chip_dt_to_dtb(
            chip,
            dev_tree.DeliveredTree(
                ram=dev_tree.DtRegion(cfg.ram_base, cfg.ram_size),
                bootargs=emu.bootargs,
                initrd=None if initrd is None else (initrd.start, initrd.end),
                reserved_ranges=cfg.reserved_memory_ranges,
                devices=_supplement_devices(cfg, chip),
                num_harts=cfg.num_harts,
            ),
            report=logger.warning,
        )
    except ValueError as exc:
        logger.error(f"无法改写芯片设备树: {exc}")
        sys.exit(1)
    emu.load_dtb_blob(addr, blob)


def _supplement_devices(
    cfg: PlatformConfig,
    chip: dev_tree.ChipDt,
) -> tuple[dev_tree.DtDeviceNode, ...]:
    """本次启动要补充到设备树中的设备节点.

    芯片树中没有块设备节点而模拟器注册了块设备时, 补充一个 virtio-mmio 节点, 使
    受调试程序能在树中找到它. 树中已声明该设备或本次启动没有启用块设备时为空.
    """
    if (
        chip.periph.virtio_blk is not None
        or not cfg.periph.virtio_blk_base
        or cfg.disk_image is None
    ):
        return ()
    region = dev_tree.DtRegion(cfg.periph.virtio_blk_base, VIRTIO_MMIO_SIZE)
    return (VIRTIO_BLK_DEVICE.placed(region, cfg.periph.virtio_blk_irq),)


def _setup_preload(
    emu: Emulator,
    ns: argparse.Namespace,
) -> tuple[int, int] | None:
    """预加载载荷, 返回 (入口地址, 字节数); 未给出 --preload 时为 None."""
    if ns.preload is None:
        return None
    preloader = Preloader(emu)
    preload_entry = preloader.inject_file(ns.preload, addr=ns.preload_addr)
    size = Path(ns.preload).stat().st_size
    logger.info(f"预加载载荷: {ns.preload} -> 0x{preload_entry:x} ({fmt_size(size)})")
    for h in emu.harts:
        h.csrs["misa"].val = (2 << 62) | (1 << 18) | (1 << 20)
    return preload_entry, size


def _setup_entry_symbol(
    emu: Emulator,
    image: FirmwareImage,
    entry_symbol: str,
) -> int | None:
    """将 *entry_symbol* 的地址写入 a0 (x10), 返回符号 VA."""
    target_entry = image.symbols.get(entry_symbol)
    if target_entry is None:
        logger.error(f"符号不存在: {entry_symbol}")
        sys.exit(1)
    for h in emu.harts:
        h.write_gpr(10, target_entry)
    logger.info(f"a0 <- {entry_symbol} = 0x{target_entry:x}")
    return target_entry


def _initrd_default_addr(
    path: str,
    platform: PlatformParams,
    fdt_addr: int | None,
    preload_addr: int | None,
) -> int:
    """未给出 --initrd-addr 时的装载地址.

    取 RAM 窗口的上界减去 RAM_PRELOAD_OFFSET 字节为上界, 该位置低于设备树与预加载
    载荷的默认位置; 设备树或预加载载荷的装载地址落在 RAM 窗口内且更低时, 改取其中
    较低者, 使 initramfs 的区间范围与两者不重叠. 自该上界减去文件字节数, 再向下
    对齐到 2 MiB, 得到区间范围的下界.
    """
    top = platform.ram_base + platform.ram_size - configs_gen.RAM_PRELOAD_OFFSET
    for start in (fdt_addr, preload_addr):
        if start is not None and platform.ram_base <= start < top:
            top = start
    size = Path(path).stat().st_size
    return (top - size) & ~0x1FFFFF


def _load_boot_images(
    emu: Emulator,
    ns: argparse.Namespace,
    platform: PlatformParams,
    chip: dev_tree.ChipDt | None,
    prog_cnt: int,
) -> tuple[int | None, tuple[int, int] | None]:
    """装载 initramfs、设备树与预加载载荷, 返回设备树地址与预加载信息.

    initramfs 必须先于设备树装入, 其区间范围写入 /chosen. 装载位置越出窗口或与
    已装入内容的区间范围重叠时报告原因并终止进程.
    """
    # 复位地址取预加载载荷的地址, 未给出载荷或其地址时取固件入口. 复位地址落在
    # 引导只读存储器的窗口内时从该存储器启动.
    is_preload_boot = ns.preload is not None and ns.preload_addr is not None
    reset_addr = ns.preload_addr if is_preload_boot else prog_cnt
    is_rom_boot = _is_rom_addr(reset_addr, platform.rom_base, platform.rom_size)
    default_fdt_addr = _default_fdt_addr(
        platform.ram_base,
        platform.ram_size,
        platform.rom_base,
        is_rom_boot,
    )
    try:
        fdt_addr = _fdt_load_addr(ns, default_fdt_addr)
        # initramfs 必须先于设备树装入, 其区间范围写入 /chosen.
        if ns.initrd is not None:
            initrd_addr = ns.initrd_addr
            if initrd_addr is None:
                initrd_addr = _initrd_default_addr(
                    ns.initrd,
                    platform,
                    fdt_addr,
                    ns.preload_addr,
                )
            emu.load_initrd(ns.initrd, initrd_addr)
        if chip is not None:
            _load_chip_fdt(emu, chip, fdt_addr)
        else:
            _load_fdt(emu, ns, fdt_addr)
        preload_info = _setup_preload(emu, ns)
    except (ValueError, FileNotFoundError) as e:
        logger.error(str(e))
        sys.exit(1)

    if fdt_addr is not None:
        fdt_note = f", FDT=0x{fdt_addr:x}"
    else:
        fdt_note = ", DTB=off" if ns.no_fdt else ""
    logger.info(
        f"固件已写入物理内存, {platform.num_harts} hart(s) 就绪, PC=0x{prog_cnt:x}{fdt_note}"
    )
    return fdt_addr, preload_info


def _firmware_span(image: FirmwareImage, load_offset: int) -> tuple[int, int]:
    """固件装入 RAM 后的物理区间; 映像没有段时取入口地址处的空区间."""
    if not image.segments:
        start = image.entry_point + load_offset
        return start, start
    start = min(seg.vaddr for seg in image.segments) + load_offset
    end = max(seg.vaddr + seg.memsz for seg in image.segments) + load_offset
    return start, end


def _record_loaded_images(
    dbg: Debugger,
    ns: argparse.Namespace,
    image: FirmwareImage,
    preload_info: tuple[int, int] | None,
) -> None:
    """把各入参装入的映像登记到调试器, 供 bins-info 与 restart 使用."""
    emu = dbg._emu
    start, end = _firmware_span(image, dbg._load_offset)
    dbg._bins_images[ImageKind.FIRMWARE] = LoadedImage(ns.firmware, start, end - start)
    if preload_info is not None and ns.preload:
        entry, size = preload_info
        dbg._bins_images[ImageKind.PRELOAD] = LoadedImage(ns.preload, entry, size)
    initrd = emu.initrd
    if initrd is not None and ns.initrd:
        dbg._bins_images[ImageKind.INITRD] = LoadedImage(
            ns.initrd, initrd.start, initrd.end - initrd.start
        )
    if ns.fdt_file and dbg._fdt_addr is not None and emu.dtb_addr == dbg._fdt_addr:
        dbg._bins_images[ImageKind.FDT] = LoadedImage(
            ns.fdt_file.rsplit(":", 1)[0], dbg._fdt_addr, emu.dtb_size
        )


def _load_kernel_image(
    emu: Emulator,
    kernel_path: str,
    kernel_addr: int | None,
    default_addr: int,
) -> tuple[str, int, int] | None:
    """预载内核 Image 到 RAM, 返回 (path, addr, 字节数)."""
    if kernel_path is None:
        return None
    addr = kernel_addr if kernel_addr is not None else default_addr
    data = Path(kernel_path).read_bytes()
    emu.bus.write_ram_direct(addr, data)
    logger.info(f"内核已预载: {kernel_path} -> PA 0x{addr:x} ({fmt_size(len(data))})")
    return kernel_path, addr, len(data)


def _periph_from_chip(
    chip: dev_tree.ChipDt,
) -> PeripheralConfig:
    """把芯片设备树中的外设区间与中断源编号填入外设配置.

    树中没有的节点置 0, 即不注册该设备; 节点声明了 interrupts 时中断源编号取树中
    的取值, 未声明时取平台默认值.
    """
    p = chip.periph
    boot_addr_size = 0
    if chip.boot_addr is not None:
        boot_addr_size = chip.boot_addr.size
    periph = PeripheralConfig(
        uart_base=_tree_base(p.uart),
        spi_base=_tree_base(p.spi),
        i2c_base=_tree_base(p.i2c),
        gpio_base=_tree_base(p.gpio),
        clint_base=_tree_base(p.clint),
        plic_base=_tree_base(p.plic),
        virtio_blk_base=_tree_base(p.virtio_blk),
        virtio_net_s_base=_tree_base(p.virtio_net_s),
        virtio_net_m_base=_tree_base(p.virtio_net_m),
        crng_base=_tree_base(p.crng),
        boot_addr_base=_tree_base(chip.boot_addr),
        boot_addr_size=boot_addr_size,
        watchdog_base=_tree_base(p.watchdog),
    )
    irq = chip.irq_vec
    if irq.uart is not None:
        periph.uart_irq = irq.uart
    if irq.watchdog is not None:
        periph.watchdog_irq = irq.watchdog
    if irq.virtio_blk is not None:
        periph.virtio_blk_irq = irq.virtio_blk
    if irq.virtio_net_s is not None:
        periph.virtio_net_s_irq = irq.virtio_net_s
    if irq.virtio_net_m is not None:
        periph.virtio_net_m_irq = irq.virtio_net_m
    return periph


def _resolve_disk_image(
    ns: argparse.Namespace,
    chip: dev_tree.ChipDt | None,
) -> str | None:
    """本次启动交给块设备的镜像路径.

    不使用芯片设备树时只有 --disk 给出才启用块设备. 使用芯片设备树时树中的块设备
    一律启用, 镜像取 --disk 给出的路径, 未给出时取默认镜像.

    Raises:
        SystemExit: 镜像文件不存在.
    """
    if chip is None:
        return ns.disk
    path = Path(ns.disk) if ns.disk else DEFAULT_DISK_IMAGE
    if not path.is_file():
        logger.error(f"磁盘镜像不存在: {path.resolve()}; 用 --disk 指定其他镜像")
        sys.exit(1)
    return str(path)


def _enable_chip_block_device(
    periph: PeripheralConfig,
    chip: dev_tree.ChipDt,
    platform: PlatformParams,
) -> None:
    """为芯片设备树中缺少的块设备选定 MMIO 区间与中断源编号.

    树中声明了该设备时按树, 不改动. 树中没有该设备时按补充设备节点的通用规则给出
    区间与中断源编号, 即地址空间中的第一段可用区间与树中最小的未占用编号.

    Raises:
        ValueError: 树中没有 PLIC 节点, 或没有可用的区间与中断源编号.
    """
    if periph.virtio_blk_base:
        return
    platform_regions = [(platform.ram_base, platform.ram_base + platform.ram_size)]
    if platform.rom_base and platform.rom_size:
        platform_regions.append((platform.rom_base, platform.rom_base + platform.rom_size))
    device = chip.place_device(VIRTIO_BLK_DEVICE, reserved=platform_regions)
    periph.virtio_blk_base = device.region.base
    periph.virtio_blk_irq = device.irq


def _tree_base(
    region: dev_tree.DtRegion | None,
) -> int:
    """区间的基址; 树中没有该节点时取 0, 即不注册该设备."""
    return 0 if region is None else region.base


def _build_peripheral_config(
    ns: argparse.Namespace,
    chip: dev_tree.ChipDt | None,
    platform: PlatformParams,
) -> tuple[PeripheralConfig, str | None, str | None]:
    """按芯片设备树或 CLI 参数创建外设配置、内核命令行参数与块设备镜像.

    给出芯片设备树时外设区间全部取自该树, 树中没有块设备节点时按块设备镜像在树中
    未占用的窗口补充一个; 否则各设备的基址取 mk/ 下生成的平台默认值, --disk 给出
    时按该镜像启用 virtio-blk. 未显式给出 --bootargs 且启用了 virtio-blk 时提供
    默认根挂载参数, 只读, 根文件系统位于 ext4 分区.
    """
    disk_image = _resolve_disk_image(ns, chip)
    if chip is not None:
        periph = _periph_from_chip(chip)
        _enable_chip_block_device(periph, chip, platform)
        return periph, ns.bootargs, disk_image
    periph = PeripheralConfig()
    if not disk_image:
        return periph, ns.bootargs, disk_image
    if ns.bootargs is not None:
        return periph, ns.bootargs, disk_image
    # debootstrap 的 minbase 变体不创建 /sbin/init, 而它是指向 systemd 的符号
    # 链接; 内核按序查找 init 会落到 /bin/sh 并阻塞在无输入的 stdin 读取上, 表现
    # 为指令计数器攀升但无输出. 显式指定 systemd 路径可避开. 打开 systemd 的调试
    # 输出并转发到串口, 便于观察它静默失败时的输出.
    bootargs = (
        "earlycon=sbi console=ttySIF0 "
        "root=/dev/vda ro "
        "init=/usr/lib/systemd/systemd "
        "random.trust_bootloader=on "
        "deferred_probe_timeout=10 "
        "systemd.log_level=debug systemd.log_target=console "
        "systemd.journald.forward_to_console=1"
    )
    return periph, bootargs, disk_image


# ============================================================
#  main
# ============================================================


def debugger(args: list[str] | None = None) -> None:
    """命令行入口: 加载固件并启动交互调试器."""
    parser = _build_arg_parser()
    ns = parser.parse_args(args)

    _setup_logger(ns.log_level)

    chip = _load_chip_dts(ns.chip_dts)
    platform = _resolve_platform(ns, chip)
    image, load_offset = _load_firmware_image(
        ns.firmware,
        ns.base_addr,
        platform.ram_base,
        platform.rom_base,
        platform.rom_size,
    )

    effective_entry = image.entry_point + load_offset
    # 判定用 None 比较: 入口地址 0 是合法入参 (sifive_u54 预设即取 0), 用真值判定
    # 会把这一取值当作未给出而改用映像入口.
    prog_cnt = ns.prog_cnt if ns.prog_cnt is not None else effective_entry

    try:
        periph, bootargs, disk_image = _build_peripheral_config(ns, chip, platform)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    plat_cfg = PlatformConfig(
        num_harts=platform.num_harts,
        ram_size=platform.ram_size,
        ram_base=platform.ram_base,
        rom_base=platform.rom_base,
        rom_size=platform.rom_size,
        prog_cnt=prog_cnt,
        periph=periph,
        disk_image=disk_image,
        timebase_freq=platform.timebase_freq,
        pmp_entries=platform.pmp_entries,
        isa=platform.isa,
    )
    emu = Emulator(plat_cfg, bootargs=bootargs)
    emu.load_firmware(image, load_offset=load_offset)
    if ns.hart_logs and emu.uart:
        emu.uart.set_hart_log_dir(ns.hart_logs)
        logger.info(f"各 hart 串口输出另存至: {ns.hart_logs}hart<N>.log")
    for h in emu.harts:
        h.pc = prog_cnt

    fdt_addr, preload_info = _load_boot_images(emu, ns, platform, chip, prog_cnt)

    target_entry = None
    if ns.entry_symbol:
        target_entry = _setup_entry_symbol(emu, image, ns.entry_symbol)

    # 判定用 None 比较: 预加载载荷与入口符号都可以落在地址 0.
    if preload_info is not None:
        for h in emu.harts:
            h.pc = preload_info[0]
    elif target_entry is not None:
        for h in emu.harts:
            h.pc = target_entry
        logger.warning("无 --preload, 直接跳转到入口 (未设置 sp/gp, 可能出错)")
    emu.set_boot_addrs()

    dbg = Debugger(emulator=emu, hart_id=0, image=image)
    dbg._fdt_addr = fdt_addr
    dbg._load_offset = load_offset
    _record_loaded_images(dbg, ns, image, preload_info)

    kernel_info = _load_kernel_image(
        emu,
        ns.kernel,
        ns.kernel_addr,
        default_addr=platform.ram_base + configs_gen.FW_RESERVED_MEM_SIZE,
    )
    if kernel_info:
        kernel_path, kernel_addr, kernel_size = kernel_info
        dbg._bins_images[ImageKind.KERNEL] = LoadedImage(kernel_path, kernel_addr, kernel_size)

    if ns.sym_dir:
        dbg._sym_mod_dir = str(Path(ns.sym_dir).expanduser().resolve())
        logger.info(f"符号候选目录: {dbg._sym_mod_dir}")

    dbg.repl()


if __name__ == "__main__":
    debugger()
