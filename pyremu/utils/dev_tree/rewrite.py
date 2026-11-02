#!/usr/bin/env python3
# -*- coding: utf-8
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""芯片设备树的回写 — 把已解析的芯片树改写为交给受调试程序的 DTB blob.

回写使用 pyfdt. 交给受调试程序的设备树以芯片树为底, 由 `chip_dt_to_dtb` 按
`DeliveredTree` 写入模拟器装配出的 RAM 窗口、保留区间、/chosen 的内容与芯片树未声明
的设备节点, 不由 build.py 重新生成.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import os
import struct

from pyfdt.pyfdt import (
    Fdt,
    FdtNode,
    FdtPropertyBytes,
    FdtPropertyStrings,
    FdtPropertyWords,
)

from pyremu.utils.dev_tree.chip import ChipDt, COMPAT_PLIC, DtDeviceNode, DtRegion
from pyremu.utils.dev_tree.fdt_node import (
    cells_for,
    cells_of_node,
    child_node,
    decode_cells,
    DEFAULT_ADDR_CELLS,
    DEFAULT_SIZE_CELLS,
    encode_cells,
    find_node,
    is_enabled_node,
    iter_nodes,
    node_property,
    parent_of,
    phandle_of,
    reg_words,
    set_property,
)
from pyremu.utils.dev_tree.parser import Node


@dataclass(frozen=True)
class DeliveredTree:
    """模拟器写入交付设备树的内容.

    ram 为实际装配的主存窗口, 改写 /memory; num_harts 为实际装配的 hart 数, 改写
    CPU 节点的 hart 编号; reserved_ranges 为平台保留区间, 追加到 /reserved-memory;
    bootargs 与 initrd 写入 /chosen; devices 为芯片树没有声明、由模拟器补充的设备
    节点, 按给出的顺序追加到中断控制器所在的节点下.
    """

    ram: DtRegion | None = None
    bootargs: str | None = None
    initrd: tuple[int, int] | None = None
    reserved_ranges: Sequence[tuple[int, int]] = ()
    devices: tuple[DtDeviceNode, ...] = ()
    num_harts: int | None = None


def chip_dt_to_dtb(
    chip: ChipDt,
    delivered: DeliveredTree | None = None,
    report: Callable[[str], None] | None = None,
) -> bytes:
    """把已解析的树回写为 DTB blob, 供受调试程序读取.

    模拟器自己决定的内容取自 delivered, 与 build.py 生成的树一致: 主存窗口改写
    /memory 的区间范围, 保留区间补充为 /reserved-memory 的 no-map 节点, 命令行与
    initramfs 写入 /chosen, 补充的设备按给定参数追加为节点. 树中已有的同名内容由
    delivered 的取值取代. 根节点声明的单元格数不足以描述这些区间时改为 2 与 2,
    并同步改写根节点的直接子节点的 reg 与 ranges, 使各属性的含义不变.

    delivered.num_harts 给出时, 各处理器节点的 reg 改写为装配的 hart 编号, 列出
    处理器中断控制器的 interrupts-extended 补全到全部装配的 hart. 后者决定 OpenSBI
    为哪些 hart 配置 MSIP、定时器与 PLIC 上下文.

    report 为修正项的报告入口, 每项以一条文本给出; 未给出时不报告. 修正无法完成时
    抛出 ValueError, 不写出语义错误的 blob.
    """
    if delivered is None:
        delivered = DeliveredTree()
    root = _to_fdt_node(chip.tree.root)
    addr_cells = cells_of_node(root, "#address-cells", DEFAULT_ADDR_CELLS)
    size_cells = cells_of_node(root, "#size-cells", DEFAULT_SIZE_CELLS)
    need_addr, need_size = _needed_cells(delivered.ram, delivered.reserved_ranges)
    if need_addr > addr_cells or need_size > size_cells:
        new_addr = max(addr_cells, need_addr)
        new_size = max(size_cells, need_size)
        _rewrite_root_cells(root, addr_cells, size_cells, new_addr, new_size)
        addr_cells, size_cells = new_addr, new_size
    if delivered.ram is not None:
        _rewrite_memory(root, delivered.ram, addr_cells, size_cells)
    if delivered.num_harts is not None:
        for message in _rewrite_cpus(root, delivered.num_harts):
            if report is not None:
                report(message)
        for message in _rewrite_intc_hart_lists(root, delivered.num_harts):
            if report is not None:
                report(message)
    if delivered.reserved_ranges:
        _add_reserved_memory(
            root,
            delivered.reserved_ranges,
            addr_cells,
            size_cells,
        )
    if delivered.bootargs is not None or delivered.initrd is not None:
        _rewrite_chosen(root, delivered.bootargs, delivered.initrd)
    for device in delivered.devices:
        _add_device_node(root, device)
    fdt = Fdt()
    fdt.add_rootnode(root)
    return fdt.to_dtb()


def _to_fdt_node(node: Node) -> FdtNode:
    """把解析出的一棵子树转换为 pyfdt 的节点.

    每个属性按原字节写入: pyfdt 依字节内容决定属性的表示类, 各表示类写出的
    blob 字节与属性原文一致.
    """
    out = FdtNode(node.name)
    for prop in node.props.values():
        out.add_raw_attribute(prop.name, prop.value)
    for child in node.nodes.values():
        out.append(_to_fdt_node(child))
    return out


def _needed_cells(
    ram: DtRegion | None,
    reserved_ranges: Sequence[tuple[int, int]],
) -> tuple[int, int]:
    """描述 ram 与 reserved_ranges 所需的最少地址单元格数与大小单元格数."""
    need_addr = 1
    need_size = 1
    values = list(reserved_ranges)
    if ram is not None:
        values.append((ram.base, ram.size))
    for base, size in values:
        need_addr = max(need_addr, cells_for(base))
        need_size = max(need_size, cells_for(size))
    return need_addr, need_size


def _rewrite_root_cells(
    root: FdtNode,
    addr_cells: int,
    size_cells: int,
    new_addr: int,
    new_size: int,
) -> None:
    """改写根节点的单元格数, 并同步改写直接子节点的 reg 与 ranges."""
    for sub in root.subdata:
        if not isinstance(sub, FdtNode):
            continue
        _rewrite_child_reg(sub, addr_cells, size_cells, new_addr, new_size)
        _rewrite_child_ranges(sub, addr_cells, new_addr)
    set_property(root, FdtPropertyWords("#address-cells", [new_addr]))
    set_property(root, FdtPropertyWords("#size-cells", [new_size]))


def _rewrite_child_reg(
    node: FdtNode,
    addr_cells: int,
    size_cells: int,
    new_addr: int,
    new_size: int,
) -> None:
    """按新的单元格数改写节点的 reg.

    属性的长度与该节点原先的单元格数不相容时报告原因, 不写出含义改变的 blob.
    """
    prop = node_property(node, "reg")
    if not isinstance(prop, FdtPropertyWords):
        return
    step = addr_cells + size_cells
    if len(prop.words) % step:
        raise ValueError(f"{node.get_name()} 的 reg 长度不是 {step} 个单元格的整数倍")
    words: list[int] = []
    for start in range(0, len(prop.words), step):
        base = decode_cells(prop.words[start : start + addr_cells])
        size = decode_cells(prop.words[start + addr_cells : start + step])
        words.extend(reg_words(base, size, new_addr, new_size))
    set_property(node, FdtPropertyWords("reg", words))


def _rewrite_child_ranges(
    node: FdtNode,
    parent_addr_cells: int,
    new_parent_addr: int,
) -> None:
    """按新的父节点地址单元格数改写节点的 ranges.

    ranges 由父节点地址、子节点地址与子节点大小三段组成, 后两段的单元格数取自
    该节点自身, 不随根节点的改写而改变.
    """
    prop = node_property(node, "ranges")
    if not isinstance(prop, FdtPropertyWords):
        return
    child_addr = cells_of_node(node, "#address-cells", DEFAULT_ADDR_CELLS)
    child_size = cells_of_node(node, "#size-cells", DEFAULT_SIZE_CELLS)
    step = parent_addr_cells + child_addr + child_size
    if len(prop.words) % step:
        raise ValueError(f"{node.get_name()} 的 ranges 长度不是 {step} 个单元格的整数倍")
    words: list[int] = []
    for start in range(0, len(prop.words), step):
        parent = decode_cells(prop.words[start : start + parent_addr_cells])
        words.extend(encode_cells(parent, new_parent_addr))
        words.extend(prop.words[start + parent_addr_cells : start + step])
    set_property(node, FdtPropertyWords("ranges", words))


def _is_memory_node(node: FdtNode) -> bool:
    """节点名为 memory 或带 unit-address 的 memory@... 时按主存节点认领."""
    name = node.get_name()
    return name == "memory" or name.startswith("memory@")


def _rewrite_memory(
    root: FdtNode,
    ram: DtRegion,
    addr_cells: int,
    size_cells: int,
) -> None:
    """把各有效 memory 节点的区间范围改写为 ram; 没有有效节点时新建一个.

    模拟器只装配一段连续的主存, 树中的多个 memory 节点改写为同一段区间范围.
    """
    words = reg_words(ram.base, ram.size, addr_cells, size_cells)
    found = False
    for sub in root.subdata:
        if not isinstance(sub, FdtNode) or not _is_memory_node(sub):
            continue
        if not is_enabled_node(sub):
            continue
        set_property(sub, FdtPropertyWords("reg", words))
        found = True
    if found:
        return
    node = FdtNode("memory")
    node.append(FdtPropertyStrings("device_type", ["memory"]))
    node.append(FdtPropertyWords("reg", words))
    root.append(node)


def _is_cpu_node(node: FdtNode) -> bool:
    """节点的 device_type 取值为 cpu 时按处理器节点认领."""
    prop = node_property(node, "device_type")
    return isinstance(prop, FdtPropertyStrings) and prop.strings[:1] == ["cpu"]


def _rewrite_cpus(
    root: FdtNode,
    num_harts: int,
) -> list[str]:
    """把处理器节点的 hart 编号改写为模拟器装配的编号, 返回被改写的节点说明.

    模拟器按 /cpus 子节点的顺序装配 hart 0 至 hart num_harts-1, 与树中 reg 给出的
    取值无关. 从 reg 读出 hart 编号, 编号重复或不连续时会为同一 hart 重复建立
    处理器, 或启动不存在的 hart. 超出装配数量的 CPU 节点标记为 disabled, 不把
    不存在的 hart 列入处理器集合.

    Raises:
        ValueError: CPU 节点的地址单元格数无法容纳 hart 编号.
    """
    cpus = child_node(root, "cpus")
    if cpus is None:
        return []
    addr_cells = cells_of_node(cpus, "#address-cells", DEFAULT_ADDR_CELLS)
    messages: list[str] = []
    index = 0
    for sub in cpus.subdata:
        if not isinstance(sub, FdtNode) or not _is_cpu_node(sub):
            continue
        name = sub.get_name()
        if index >= num_harts:
            set_property(sub, FdtPropertyStrings("status", ["disabled"]))
            messages.append(
                f"CPU 节点 {name} 超出装配的 hart 数 {num_harts}, 已标记为 disabled"
            )
            index += 1
            continue
        try:
            reg = encode_cells(index, addr_cells)
        except ValueError as exc:
            raise ValueError(f"{name} 的 hart 编号无法写入 {addr_cells} 个地址单元格") from exc
        declared = _declared_hart_id(sub)
        if declared != index:
            text = "未声明" if declared is None else f"0x{declared:x}"
            messages.append(
                f"CPU 节点 {name} 的 reg 为 {text}, 与装配的 hart 编号 {index} 不一致, 已改写"
            )
        set_property(sub, FdtPropertyWords("reg", reg))
        index += 1
    return messages


def _declared_hart_id(
    node: FdtNode,
) -> int | None:
    """节点 reg 声明的 hart 编号; 没有 reg 时为 None."""
    prop = node_property(node, "reg")
    if not isinstance(prop, FdtPropertyWords) or not prop.words:
        return None
    return decode_cells(prop.words)


def _cpu_intc_node(
    cpu: FdtNode,
) -> FdtNode | None:
    """处理器节点的中断控制器子节点; 没有时为 None."""
    for sub in cpu.subdata:
        if isinstance(sub, FdtNode) and node_property(sub, "interrupt-controller") is not None:
            return sub
    return None


def _cpu_nodes(
    root: FdtNode,
) -> list[tuple[FdtNode, FdtNode | None]]:
    """按 /cpus 子节点顺序给出各处理器节点与其中断控制器子节点."""
    cpus = child_node(root, "cpus")
    if cpus is None:
        return []
    return [
        (sub, _cpu_intc_node(sub))
        for sub in cpus.subdata
        if isinstance(sub, FdtNode) and _is_cpu_node(sub)
    ]


def _hart_hwirq_pattern(
    pairs: Sequence[tuple[int, int]],
) -> list[int] | None:
    """每个 hart 列出的中断号序列; 各 hart 的序列不一致时为 None."""
    groups: dict[int, list[int]] = {}
    for phandle, hwirq in pairs:
        groups.setdefault(phandle, []).append(hwirq)
    sequences = list(groups.values())
    if any(sequence != sequences[0] for sequence in sequences[1:]):
        return None
    return sequences[0]


def _rewrite_intc_hart_lists(
    root: FdtNode,
    num_harts: int,
) -> list[str]:
    """把列出处理器中断控制器的 interrupts-extended 补全到全部装配的 hart.

    OpenSBI 依这一属性为各 hart 配置 MSIP、定时器与 PLIC 上下文. 只列出部分 hart 时,
    其余 hart 没有可写入的 MSIP 寄存器, sbi_hsm_hart_start 报告成功后目标 hart 仍在
    WFI 等待, 受调试程序的多 hart 启动停在这一步.

    只改写每一对都由处理器中断控制器组成、且各 hart 的中断号序列一致的属性; 设备节点
    指向 PLIC 的同类属性不在改写范围.

    Raises:
        ValueError: 处理器节点不足 num_harts 个, 其中有节点未启用, 或其无法给出
            中断控制器 phandle.
    """
    if num_harts < 1:
        return []
    nodes = _cpu_nodes(root)
    if len(nodes) < num_harts:
        raise ValueError(f"处理器节点只有 {len(nodes)} 个, 少于装配的 hart 数 {num_harts}")
    for index, (cpu, intc) in enumerate(nodes[:num_harts]):
        if not is_enabled_node(cpu):
            raise ValueError(
                f"处理器节点 {cpu.get_name()} 未启用, 无法为 hart {index} 列出中断控制器"
            )
        if intc is None:
            raise ValueError(f"处理器节点 {cpu.get_name()} 没有中断控制器子节点")
    phandles = [phandle_of(intc) for _, intc in nodes[:num_harts]]
    known = {phandle_of(intc) for _, intc in nodes if intc is not None}
    messages: list[str] = []
    for node in iter_nodes(root):
        prop = node_property(node, "interrupts-extended")
        if not isinstance(prop, FdtPropertyWords) or len(prop.words) % 2:
            continue
        pairs = list(zip(prop.words[0::2], prop.words[1::2], strict=True))
        if not pairs or any(phandle not in known for phandle, _ in pairs):
            continue
        pattern = _hart_hwirq_pattern(pairs)
        if pattern is None:
            continue
        words = [
            word for phandle in phandles for hwirq in pattern for word in (phandle, hwirq)
        ]
        if words == prop.words:
            continue
        set_property(node, FdtPropertyWords("interrupts-extended", words))
        name = node.get_name()
        listed = len({phandle for phandle, _ in pairs})
        if listed < num_harts:
            messages.append(
                f"节点 {name} 的 interrupts-extended 只列出 {listed} 个 hart, "
                f"已按装配的 {num_harts} 个 hart 列出中断控制器"
            )
        else:
            messages.append(
                f"节点 {name} 的 interrupts-extended 的 hart 顺序与装配顺序不一致, "
                f"已按装配顺序改写"
            )
    return messages


def _add_reserved_memory(
    root: FdtNode,
    ranges: Sequence[tuple[int, int]],
    addr_cells: int,
    size_cells: int,
) -> None:
    """把 ranges 以 no-map 区间追加到 /reserved-memory, 节点不存在时新建."""
    node = child_node(root, "reserved-memory")
    if node is None:
        node = FdtNode("reserved-memory")
        node.append(FdtPropertyWords("#address-cells", [addr_cells]))
        node.append(FdtPropertyWords("#size-cells", [size_cells]))
        node.add_raw_attribute("ranges", b"")
        root.append(node)
    else:
        node_addr = cells_of_node(node, "#address-cells", DEFAULT_ADDR_CELLS)
        node_size = cells_of_node(node, "#size-cells", DEFAULT_SIZE_CELLS)
        if (node_addr, node_size) != (addr_cells, size_cells):
            raise ValueError(
                f"/reserved-memory 的单元格数为 ({node_addr}, {node_size}), "
                f"与根节点的 ({addr_cells}, {size_cells}) 不一致"
            )
    offset = sum(1 for sub in node.subdata if isinstance(sub, FdtNode))
    for index, (base, size) in enumerate(ranges):
        child = FdtNode(f"reserved-{offset + index}@{base:x}")
        child.add_raw_attribute("no-map", b"")
        child.append(FdtPropertyWords("reg", reg_words(base, size, addr_cells, size_cells)))
        node.append(child)


def _rewrite_chosen(
    root: FdtNode,
    bootargs: str | None,
    initrd: tuple[int, int] | None,
) -> None:
    """把内核命令行、引导期熵种子与 initramfs 的区间范围写入 /chosen."""
    node = child_node(root, "chosen")
    if node is None:
        node = FdtNode("chosen")
        root.append(node)
    if bootargs:
        set_property(node, FdtPropertyStrings("bootargs", [bootargs]))
    set_property(node, FdtPropertyBytes.init_raw("rng-seed", os.urandom(64)))
    if initrd is not None:
        start, end = initrd
        set_property(
            node,
            FdtPropertyBytes.init_raw("linux,initrd-start", struct.pack(">Q", start)),
        )
        set_property(
            node,
            FdtPropertyBytes.init_raw("linux,initrd-end", struct.pack(">Q", end)),
        )


def _add_device_node(
    root: FdtNode,
    device: DtDeviceNode,
) -> None:
    """在中断控制器所在的节点下追加一个设备节点.

    芯片树没有声明该设备时使用: 模拟器注册了该设备, 受调试程序须能在树中找到它.
    节点的 reg 按父节点声明的单元格数编码, PLIC 的 riscv,ndev 抬高到覆盖该中断源
    编号, 使内核为它建立中断描述.

    Raises:
        ValueError: 树中没有 PLIC 节点, 或 PLIC 节点没有 phandle.
    """
    plic = find_node(root, COMPAT_PLIC)
    if plic is None:
        raise ValueError(f"芯片设备树中没有 PLIC 节点, 无法为 {device.name} 声明中断")
    parent = parent_of(root, plic)
    if parent is None:
        parent = root
    addr_cells = cells_of_node(parent, "#address-cells", DEFAULT_ADDR_CELLS)
    size_cells = cells_of_node(parent, "#size-cells", DEFAULT_SIZE_CELLS)
    node = FdtNode(f"{device.name}@{device.region.base:x}")
    node.append(FdtPropertyStrings("compatible", [device.compatible]))
    reg = reg_words(device.region.base, device.region.size, addr_cells, size_cells)
    node.append(FdtPropertyWords("reg", reg))
    node.append(FdtPropertyWords("interrupt-parent", [phandle_of(plic)]))
    node.append(FdtPropertyWords("interrupts", [device.irq]))
    parent.append(node)
    _raise_plic_ndev(plic, device.irq)


def _raise_plic_ndev(
    plic: FdtNode,
    irq: int,
) -> None:
    """把 PLIC 的 riscv,ndev 抬高到不小于中断源编号 irq."""
    prop = node_property(plic, "riscv,ndev")
    current = prop.words[0] if isinstance(prop, FdtPropertyWords) and prop.words else 0
    if current < irq:
        set_property(plic, FdtPropertyWords("riscv,ndev", [irq]))
