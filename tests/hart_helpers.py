#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""多 hart 用例共用的 hart 与中断源构造辅助."""

from pyremu.core.hart import HartWithRegs, RatifiedHartAttrs
from pyremu.interrupt.clint import CLINT
from pyremu.memory.bus import Bus
from pyremu.memory.pmp import Pmp


def make_hart(hid: int, bus: Bus, clint: CLINT, pmp: Pmp) -> HartWithRegs:
    """创建配置就绪的 hart (HartWithRegs 而非 decoder.Hart)."""
    hart = HartWithRegs(
        id=hid, ratified_hart_attrs=RatifiedHartAttrs(pmp_entries=64)
    )
    hart.mem_read_phy = bus.read
    hart.mem_write_phy = bus.write
    hart.bus = bus
    hart.interrupt_ctrl = clint
    hart._pmp = pmp
    hart.csrs["misa"].val = (2 << 62) | (1 << 18) | (1 << 20)
    hart.csrs["mscratch"].val = 0x80100000 + hid * 0x10000
    return hart


def make_pmp() -> Pmp:
    """创建 64 条目的 PMP."""
    return Pmp(csrs={}, num_entries=64)


def set_mie(hart: HartWithRegs, val: int) -> None:
    """写 mie CSR (mie_val 无 setter, 用底层方法)."""
    hart._csr_write_raw("mie", val)


def set_mip(hart: HartWithRegs, val: int) -> None:
    """写 mip CSR."""
    hart.mip_val = val


def set_msip(clint: CLINT, hart_id: int, val: int) -> None:
    """写 CLINT 的 MSIP[hart_id]."""
    clint._msip[hart_id] = val
