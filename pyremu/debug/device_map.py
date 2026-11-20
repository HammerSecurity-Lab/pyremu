#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""DeviceMapOps — 列出本次运行注册的虚拟设备与存储区间."""

from rich.table import Table

from pyremu.debug.attrs import SharedAttrs
from pyremu.utils.str_aux import fmt_size, hex_addr


class DeviceMapOps(SharedAttrs):
    """物理地址区间显示."""

    def cmd_devices(self) -> None:
        """列出主存、存储区间与全部虚拟设备的总线区间.

        区间按基址升序排列; 基址取 0 而未注册的设备不出现. 设备持有公开的
        ``irq`` 属性时在中断源一列给出其编号, 未持有者写 ``-``.
        芯片设备树中声明、但本模拟器未提供模型的设备按 ``未支持`` 类别列出.

        引导只读存储器同时属于存储区间与设备表, 只按存储区间列出一次.
        """
        storage = self._emu.bus.storage_intervals
        listed = {(base, size) for _name, base, size in storage}
        rows: list[tuple[str, str, int, int, str]] = [
            (name, "存储", base, size, "-") for name, base, size in storage
        ]
        for base, dev in self._emu.bus.device_entries():
            if (base, dev.size) in listed:
                continue
            irq = getattr(dev, "irq", 0)
            rows.append(
                (
                    type(dev).__name__,
                    "设备",
                    base,
                    dev.size,
                    str(irq) if irq else "-",
                )
            )
        config = getattr(self._emu, "config", None)
        periph = getattr(config, "periph", None)
        for path, _compat, base, size in getattr(
            periph, "unsupported_devices", ()
        ):
            rows.append((path, "未支持", base, size, "-"))
        rows.sort(key=lambda row: row[2])

        tbl = Table(title="物理地址区间", border_style="blue")
        tbl.add_column("名称", style="cyan")
        tbl.add_column("类别", style="dim", width=6)
        tbl.add_column("基址", style="green")
        tbl.add_column("字节数", justify="right")
        tbl.add_column("上界", style="yellow")
        tbl.add_column("中断源", justify="right", width=6)

        for name, kind, base, size, irq in rows:
            tbl.add_row(
                name,
                kind,
                hex_addr(base),
                fmt_size(size),
                hex_addr(base + size),
                irq,
            )
        self._console.print(tbl)

        if all(row[1] == "存储" for row in rows):
            self._console.print("  [dim]未注册任何虚拟设备[/]")
