#!/usr/bin/env python3
# -*- coding: utf-8
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""芯片设备树的读取 — 从 DTS 文本提取模拟器装配所需的平台参数.

解析使用内置的设备树解析器, 该解析器来自 Zephyr Project 的 python-devicetree.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pyremu.utils.dev_tree.dts_props import (
    base_name,
    cell_count,
    cells_of,
    first_cell,
    has_compat,
    is_enabled,
    node_named,
    strings_of,
)
from pyremu.utils.dev_tree.fdt_node import (
    decode_cells,
    DEFAULT_ADDR_CELLS,
    DEFAULT_SIZE_CELLS,
)
from pyremu.utils.dev_tree.parser import DT, Node

# 同一类设备在各类芯片上的 compatible 写法不止一种, 命中任一即按该类认领.
_COMPAT_UART = ("sifive,uart0", "ns16550a", "snps,dw-apb-uart")
_COMPAT_CLINT = ("riscv,clint0", "sifive,clint0")
# 回写时也要按该取值查找 PLIC 节点, 故不作私有命名.
COMPAT_PLIC = ("riscv,plic0", "sifive,plic-1.0.0")
_COMPAT_ROM = ("sifive,rom0",)
_COMPAT_CRNG = ("pyremu,crng",)
_COMPAT_SPI = ("pyremu,spi0",)
_COMPAT_I2C = ("pyremu,i2c0",)
_COMPAT_GPIO = ("pyremu,gpio0",)
_COMPAT_WATCHDOG = ("pyremu,hart-watchdog-1.0",)
_COMPAT_VIRTIO = ("virtio,mmio",)

# 启动地址寄存器不带 compatible, 按节点名称认领.
_NODE_BOOT_ADDR = "boot-address-reg"

# 本平台实例化的 PLIC 有 128 个中断源, 可用编号为 1 至 127.
_MAX_IRQ_SOURCE = 128

# 补充的地址区间按 4 KiB 对齐.
MMIO_ALIGN = 0x1000


@dataclass(frozen=True)
class DtRegion:
    """设备树中一段寄存器的物理区间 [base, base + size)."""

    base: int
    size: int

    @property
    def end(self) -> int:
        """区间的结束地址, 不含该地址本身."""
        return self.base + self.size

    def __str__(self) -> str:
        """区间的基址与大小."""
        return f"0x{self.base:x}+0x{self.size:x}"


def region_text(
    region: DtRegion | None,
) -> str:
    """区间的可读形式; 未给出区间时写作“未提供”."""
    return "未提供" if region is None else str(region)


@dataclass(frozen=True)
class DtDeviceRequest:
    """要补充到设备树中的设备: 节点名前缀, compatible 与 reg 的大小.

    节点名为前缀加区间基址, 形如 virtio@2000;
    中断编号在有中断控制器时由树中未占用的取值给出.
    """

    name: str
    compatible: str
    size: int

    def placed(
        self,
        region: DtRegion,
        irq: int,
    ) -> DtDeviceNode:
        """给出该设备在树中的区间与中断源编号."""
        return DtDeviceNode(self.name, self.compatible, region, irq)


@dataclass(frozen=True)
class DtDeviceNode:
    """补充到设备树中的设备节点参数."""

    name: str
    compatible: str
    region: DtRegion
    irq: int


@dataclass
class ChipPeriph:
    """树中各外设的区间; 树中没有对应节点时取 None."""

    uart: DtRegion | None = None
    clint: DtRegion | None = None
    plic: DtRegion | None = None
    spi: DtRegion | None = None
    i2c: DtRegion | None = None
    gpio: DtRegion | None = None
    crng: DtRegion | None = None
    watchdog: DtRegion | None = None
    # 三段 virtio 区间按树中顺序认领: 依次为块设备、宿主侧网卡与飞地侧网卡.
    virtio_blk: DtRegion | None = None
    virtio_net_s: DtRegion | None = None
    virtio_net_m: DtRegion | None = None


@dataclass
class ChipIrq:
    """树中各外设的中断源编号; 没有对应节点或节点未声明该属性时取 None.

    编号取该设备节点的 interrupts 属性的第一格: 中断单元数为 1 时只有该格, 为 2
    时其后一格是触发类型.
    """

    uart: int | None = None
    watchdog: int | None = None
    # 三段 virtio 节点的编号按树中顺序认领, 与 ChipPeriph 的区间逐一对应.
    virtio_blk: int | None = None
    virtio_net_s: int | None = None
    virtio_net_m: int | None = None


@dataclass
class ChipDt:
    """从芯片设备树读出的平台参数; 树中没有的项取 None."""

    tree: DT
    num_harts: int
    periph: ChipPeriph
    irq_vec: ChipIrq
    ram: DtRegion | None = None
    rom: DtRegion | None = None
    boot_addr: DtRegion | None = None
    timebase_freq: int | None = None
    pmp_entries: int | None = None
    isa: str | None = None
    # riscv,isa-extensions: 扩展名以空格分隔; 树中未声明时为 None.
    isa_extensions: str | None = None
    # 各 CPU 节点逐属性声明的取值: 属性名 -> {hart 编号: 取值}.
    # 各项属性在 hart 之间是否一致, 经 differing_attrs() 读出.
    per_hart: dict[str, dict[int, int | str]] = field(default_factory=dict)

    @classmethod
    def from_tree(
        cls,
        tree: DT,
    ) -> ChipDt:
        """遍历整棵树, 填入各字段."""
        nodes = list(tree.node_iter())
        cpus = node_named(nodes, "cpus")
        cpu_nodes = _cpu_nodes(cpus) if cpus is not None else []
        virtio_nodes = [node for node in nodes if _is_virtio(node)]
        virtio = [region for node in virtio_nodes for region in _regions(node)]
        virtio_irqs = _virtio_irqs(virtio_nodes)

        chip = cls(
            tree=tree,
            num_harts=len(cpu_nodes),
            periph=ChipPeriph(
                uart=_first_region(nodes, compatibles=_COMPAT_UART),
                clint=_first_region(nodes, compatibles=_COMPAT_CLINT),
                plic=_first_region(nodes, compatibles=COMPAT_PLIC),
                spi=_first_region(nodes, compatibles=_COMPAT_SPI),
                i2c=_first_region(nodes, compatibles=_COMPAT_I2C),
                gpio=_first_region(nodes, compatibles=_COMPAT_GPIO),
                crng=_first_region(nodes, compatibles=_COMPAT_CRNG),
                watchdog=_first_region(nodes, compatibles=_COMPAT_WATCHDOG),
                virtio_blk=_region_at(virtio, 0),
                virtio_net_s=_region_at(virtio, 1),
                virtio_net_m=_region_at(virtio, 2),
            ),
            irq_vec=ChipIrq(
                uart=_first_irq(nodes, compatibles=_COMPAT_UART),
                watchdog=_first_irq(nodes, compatibles=_COMPAT_WATCHDOG),
                virtio_blk=_region_at(virtio_irqs, 0),
                virtio_net_s=_region_at(virtio_irqs, 1),
                virtio_net_m=_region_at(virtio_irqs, 2),
            ),
            ram=_first_region(nodes, device_type="memory"),
            rom=_first_region(nodes, compatibles=_COMPAT_ROM),
            boot_addr=_first_region(nodes, name=_NODE_BOOT_ADDR),
            timebase_freq=_timebase_freq(cpus, cpu_nodes),
        )
        if len(cpu_nodes) == 0:
            return chip
        for hid, node in enumerate(cpu_nodes):
            pmp = cells_of(node, "riscv,pmpregions")
            if pmp:
                chip.per_hart.setdefault("riscv,pmpregions", {})[hid] = pmp[0]
            # 扩展名列表按空格拼接为一项, 使 hart 之间的差异比对沿同一字段进行.
            for name in ("riscv,isa", "riscv,isa-extensions"):
                values = strings_of(node, name)
                if values:
                    chip.per_hart.setdefault(name, {})[hid] = " ".join(
                        str(v) for v in values
                    )
        pmp_counts = chip.per_hart.get("riscv,pmpregions", {})
        if pmp_counts:
            chip.pmp_entries = max(pmp_counts.values())
        chip.isa = chip.per_hart.get("riscv,isa", {}).get(0)
        chip.isa_extensions = chip.per_hart.get("riscv,isa-extensions", {}).get(
            0
        )
        return chip

    def differing_attrs(self) -> dict[str, dict[int, int | str]]:
        """在 hart 之间取值不一致的属性, 按属性名给出各 hart 的取值."""
        return {
            name: dict(values)
            for name, values in self.per_hart.items()
            if len(set(values.values())) > 1
        }

    def regions(self) -> list[DtRegion]:
        """树中全部有效节点声明的 reg 区间."""
        out: list[DtRegion] = []
        for node in self.tree.node_iter():
            if is_enabled(node):
                out.extend(_regions(node))
        return out

    def first_free_irq_source(
        self,
        start: int = 1,
    ) -> int:
        """返回不小于 start 且树中节点未声明的最小中断源编号.

        interrupts 属性的每个格子都按中断源编号处理: 中断单元数为 2 时触发类型的
        取值也计入, 多计入的取值只使本函数跳过该编号.

        Raises:
            ValueError: 可用的中断源编号都已被声明.
        """
        used: set[int] = set()
        for node in self.tree.node_iter():
            cells = cells_of(node, "interrupts")
            if cells:
                used.update(cells)
        irq = max(start, 1)
        while irq in used:
            irq += 1
        if irq >= _MAX_IRQ_SOURCE:
            raise ValueError("芯片设备树已声明全部可用的中断源编号")
        return irq

    def first_avail_mmio_region(
        self,
        size: int,
        start: int = 0,
        reserved: Sequence[tuple[int, int]] = (),
    ) -> DtRegion:
        """返回不小于 start 且与树中区间、reserved 都不重叠的一段 MMIO 区间.

        reserved 中每个元素为一段区间 [下界, 上界),
        用于给出树中没有声明、但是同样不可占用的地址区间.
        基址按 4 KiB 对齐; 与某个区间重叠时改取该区间上界之上对齐后的地址.
        两处区间都是有限段, 搜索在越过最后一段之后结束.
        基址 0 不作分配: 基址取 0 表示该设备不注册.
        """
        occupied = [(region.base, region.end) for region in self.regions()]
        occupied.extend(reserved)
        base = max(start, MMIO_ALIGN)
        while True:
            end = base + size
            for low, high in occupied:
                if low < end and base < high:
                    base = (high + MMIO_ALIGN - 1) & ~(MMIO_ALIGN - 1)
                    break
            else:
                return DtRegion(base, size)

    def place_device(
        self,
        request: DtDeviceRequest,
        reserved: Sequence[tuple[int, int]] = (),
    ) -> DtDeviceNode:
        """为树中没有声明的设备给出补充节点的区间与中断源编号.

        区间取地址空间中第一段能容纳该设备、
        且与树中全部区间及 reserved 都不重叠的位置,
        中断源取树中未声明的最小可用编号.

        Raises:
            ValueError: 树中没有 PLIC 节点, 或没有可用的区间与中断源编号.
        """
        if self.periph.plic is None:
            raise ValueError(
                f"芯片设备树中没有 PLIC 节点, 无法为 {request.name} 声明中断"
            )
        region = self.first_avail_mmio_region(request.size, reserved=reserved)
        return request.placed(region, self.first_free_irq_source())


def parse_chip_dts(
    path: str | Path,
) -> ChipDt:
    """读取并解析 DTS 源文件."""
    text = Path(path).read_text(encoding="utf-8")
    return ChipDt.from_tree(DT.from_text(_dts_text(text), filename=str(path)))


def parse_chip_dts_text(
    text: str,
) -> ChipDt:
    """解析 DTS 源文本."""
    return ChipDt.from_tree(DT.from_text(_dts_text(text)))


_DTS_HEADER = "/dts-v1/;"


def _dts_text(
    text: str,
) -> str:
    """补齐 DTS 源文本的文件头与根节点名称.

    要求源文本必须以 /dts-v1/; 开头, 且根节点写作 `/ { ... };`.
    由 DTB 导出的文本两者都没有: 文件头缺失, 根节点是裸的 `{`.
    缺少文件头时在文本开头补上,
    根节点为裸的 `{` 时在它之前补上 `/ `, 其余内容不变.
    """
    root = _root_start(text)
    if root < 0:
        return _dts_text(_DTS_HEADER + "\n" + text)
    if text.startswith("{", root):
        return text[:root] + "/ " + text[root:]
    return text


def _root_start(
    text: str,
) -> int:
    """返回文件头之后根节点的位置; 文本没有文件头时返回 -1."""
    pos = _trivia_end(text, 0)
    if not text.startswith(_DTS_HEADER, pos):
        return -1
    return _trivia_end(text, pos + len(_DTS_HEADER))


def _trivia_end(
    text: str,
    start: int,
) -> int:
    """返回从 start 起跳过空白与注释后的位置."""
    pos = start
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            if end < 0:
                return len(text)
            pos = end + 2
        elif text.startswith("//", pos):
            end = text.find("\n", pos + 2)
            if end < 0:
                return len(text)
            pos = end + 1
        else:
            return pos
    return pos


def _regions(
    node: Node,
    compatibles: tuple[str, ...] = (),
) -> list[DtRegion]:
    """按父节点的 #address-cells 与 #size-cells 把 reg 属性分成若干区间.

    给出 compatibles 时, 节点须为有效节点且 compatible 命中其一, 否则返回空列表.
    """
    if compatibles and (
        not is_enabled(node) or not has_compat(node, compatibles)
    ):
        return []
    cells = cells_of(node, "reg")
    if not cells:
        return []
    addr_cells = cell_count(node.parent, "#address-cells", DEFAULT_ADDR_CELLS)
    size_cells = cell_count(node.parent, "#size-cells", DEFAULT_SIZE_CELLS)
    step = addr_cells + size_cells
    return [
        DtRegion(
            decode_cells(cells[start : start + addr_cells]),
            decode_cells(cells[start + addr_cells : start + step]),
        )
        for start in range(0, len(cells) - step + 1, step)
    ]


def _is_virtio(
    node: Node,
) -> bool:
    """节点有效且 compatible 声明为 virtio-mmio 设备."""
    return is_enabled(node) and has_compat(node, _COMPAT_VIRTIO)


def _region_at(
    regions: list[DtRegion],
    index: int,
) -> DtRegion | None:
    """按序号取一段区间, 序号越界时返回 None."""
    if index < len(regions):
        return regions[index]
    return None


def _virtio_irqs(
    nodes: list[Node],
) -> list[int | None]:
    """virtio-mmio 节点的中断源编号, 按区间展开的顺序逐项给出.

    节点声明多段 reg 时, 其编号在列表中重复出现, 与 _regions 展开的区间一一对应.
    """
    irqs: list[int | None] = []
    for node in nodes:
        irq = first_cell(node, "interrupts")
        irqs.extend(irq for _ in _regions(node))
    return irqs


def _first_region(
    nodes: list[Node],
    compatibles: tuple[str, ...] = (),
    name: str | None = None,
    device_type: str | None = None,
) -> DtRegion | None:
    """取第一个有效且命中给定条件的节点的第一段区间.

    条件取 compatible 交集、节点名与 device_type 三者之一, 同时给出时须全部命中.
    """
    for node in nodes:
        if _matches(node, compatibles, name, device_type):
            return _regions(node)[0]
    return None


def _first_irq(
    nodes: list[Node],
    compatibles: tuple[str, ...] = (),
    name: str | None = None,
    device_type: str | None = None,
) -> int | None:
    """取第一个有效且命中给定条件的节点声明的中断源编号.

    条件与 _first_region 相同, 编号与区间取自同一个节点; 该节点未声明 interrupts
    时返回 None.
    """
    for node in nodes:
        if _matches(node, compatibles, name, device_type):
            return first_cell(node, "interrupts")
    return None


def _matches(
    node: Node,
    compatibles: tuple[str, ...],
    name: str | None,
    device_type: str | None,
) -> bool:
    """节点有效、命中给定条件且声明了 reg."""
    if (
        not is_enabled(node)
        or compatibles
        and not has_compat(node, compatibles)
    ):
        return False
    if name is not None and base_name(node) != name:
        return False
    if device_type is not None and device_type not in strings_of(
        node, "device_type"
    ):
        return False
    return bool(_regions(node))


def _cpu_nodes(
    cpus: Node,
) -> list[Node]:
    """取 cpus 节点下有效的 cpu 子节点."""
    return [
        child
        for child in cpus.nodes.values()
        if base_name(child) == "cpu" and is_enabled(child)
    ]


def _timebase_freq(
    cpus: Node | None,
    cpu_nodes: list[Node],
) -> int | None:
    """取 /cpus 的 timebase-frequency, 缺失时取第一个 cpu 子节点的同名属性."""
    if cpus is not None:
        value = first_cell(cpus, "timebase-frequency")
        if value is not None:
            return value
    if cpu_nodes:
        return first_cell(cpu_nodes[0], "timebase-frequency")
    return None
