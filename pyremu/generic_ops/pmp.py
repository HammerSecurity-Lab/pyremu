# SPDX-LICENSE-IDENTIFIER: MIT
"""PMP 访问检查 — 有动态链接库时经加速执行引擎, 否则走 Pmp 的纯 Python 实现."""

from __future__ import annotations

import ctypes

from pyremu._native import loaded_lib, native_available


def check(pmp, info) -> bool:
    """检查物理地址访问是否允许.

    *pmp* 为 ``pyremu.memory.pmp.Pmp`` 实例, 本模块只读取它的平面快照,
    不直接访问其私有字段; *info* 给出本次访问的物理地址、宽度与属性.
    """
    if not native_available():
        return pmp.check_py(info)
    pmp.ensure_cache()
    cfg_bytes = pmp.flat_cfg_bytes()
    addr_array = pmp.flat_addr_array()
    cfg_buf = (ctypes.c_uint8 * len(cfg_bytes)).from_buffer_copy(cfg_bytes)
    addr_buf = (ctypes.c_uint64 * len(addr_array))(*addr_array)
    return bool(
        loaded_lib().pmp_check(
            ctypes.addressof(cfg_buf),
            ctypes.addressof(addr_buf),
            pmp.num_entries,
            info.pa,
            info.size,
            int(info.is_write),
            int(info.is_execute),
            info.mode_val,
            info.mstatus_val,
            info.pmpsplit,
            info.mdid,
        )
    )


__all__ = ["check"]
