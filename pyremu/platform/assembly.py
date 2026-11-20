# SPDX-LICENSE-IDENTIFIER: MIT
"""芯片设备树到外设配置的装配."""

from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from pyremu import configs_gen
from pyremu.interrupt.clint import CLINT_SIZE
from pyremu.interrupt.plic import plic_mem_range
from pyremu.platform.specs import (
    DEVICE_SPECS,
    DeviceSpec,
    PeripheralConfig,
    spec_named,
)

if TYPE_CHECKING:
    from pyremu.utils.dev_tree.chip import ChipDt, DtRegion


def _chip_region(
    chip: ChipDt,
    source: tuple[str, str],
) -> DtRegion | None:
    """取芯片设备树中该设备对应的区间."""
    host, field = source
    if host == "chip":
        return getattr(chip, field)
    return getattr(chip.periph, field)


def _place_controller(
    chip: ChipDt,
    periph: PeripheralConfig,
    spec: DeviceSpec,
    size: int,
    reserved: list[tuple[int, int]],
) -> None:
    """树中缺失的中断控制器在空闲区间放置, 并把基址写入配置."""
    if getattr(periph, f"{spec.name}_base"):
        return
    region = chip.first_avail_mmio_region(size, reserved=reserved)
    reserved.append((region.base, region.end))
    logger.warning(
        "芯片设备树未声明 {} 节点, 已在 {} 处放置模拟的 {}; "
        "如需固定地址, 请在设备树中声明该节点",
        spec.name.upper(),
        region,
        spec.name.upper(),
    )
    setattr(periph, f"{spec.name}_base", region.base)


def _warn_unsupported(
    periph: PeripheralConfig,
) -> None:
    """列出树中声明、但本模拟器未提供模型的设备."""
    if not periph.unsupported_devices:
        return
    grouped: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for path, compatible, base, size in periph.unsupported_devices:
        grouped.setdefault((path, compatible), []).append((base, size))
    definitions = [
        f'    {path}: compatible = "{compatible or "-"}"; '
        f"reg = {_reg_text(regions)};"
        for (path, compatible), regions in grouped.items()
    ]
    logger.warning(
        "芯片设备树中的以下设备 pyremu 未提供模型:\n{}",
        "\n".join(definitions),
    )


def _reg_text(
    regions: list[tuple[int, int]],
) -> str:
    """把若干 (基址, 字节数) 写成 DTS 的 reg 属性形式."""
    return ", ".join(f"<0x{base:x} 0x{size:x}>" for base, size in regions)


def periph_from_chip(
    chip: ChipDt,
    is_aia: bool | None = None,
) -> PeripheralConfig:
    """把芯片设备树中的外设区间与中断源编号填入外设配置.

    树中没有的节点置 0, 即不注册该设备; 节点声明了 interrupts 时中断源编号取树中
    的取值, 未声明时取平台默认值. 树中没有 CLINT 节点, 或非 AIA 模式下没有 PLIC
    节点时, 在树中未被占用的地址区间里选取一段放置模拟的中断控制器, 并给出警告.
    AIA 模式不放置 PLIC, 外部中断经 IMSIC 与 APLIC 投递.
    """
    if is_aia is None:
        is_aia = bool(configs_gen.PYREMU_AIA)
    periph = PeripheralConfig()
    for spec in DEVICE_SPECS:
        if spec.chip_source is None:
            continue
        region = _chip_region(chip, spec.chip_source)
        setattr(
            periph,
            f"{spec.name}_base",
            0 if region is None else region.base,
        )
        if spec.name == "boot_addr":
            periph.boot_addr_size = 0 if region is None else region.size
        if spec.irq_source is not None:
            irq = getattr(chip.irq_vec, spec.irq_source)
            if irq is not None:
                setattr(periph, f"{spec.name}_irq", irq)
    # 芯片设备树没有关机与复位请求设备的节点.
    periph.power_base = 0
    reserved: list[tuple[int, int]] = []
    _place_controller(chip, periph, spec_named("clint"), CLINT_SIZE, reserved)
    if not is_aia:
        _place_controller(
            chip,
            periph,
            spec_named("plic"),
            plic_mem_range(2 * max(1, chip.num_harts)),
            reserved,
        )
    periph.unsupported_devices = tuple(
        (item.path, item.compatible, item.region.base, item.region.size)
        for item in chip.unsupported_devices
    )
    _warn_unsupported(periph)
    return periph
