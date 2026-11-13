#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""
Physical Memory Protection (PMP) — RISC-V Privileged Spec §3.7.

PMP 在物理地址翻译完成后检查每次访存的合法性.
支持三种地址匹配模式: OFF (禁用), TOR (地址范围), NA4 (4 字节), NAPOT (2 的幂).

入口数由 mk/processor.mk 的 PMP_ENTRIES 给出, 上限 64.
RV64 编码: pmpcfgN 覆盖 8 个条目, 仅偶数编号的 pmpcfg 可用.
"""

from __future__ import annotations

from array import array
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any

from pyremu._native import (
    native_available,
    pmp_check,
)
from pyremu.configs_gen import PMP_ENTRIES
from pyremu.utils.mask import mask64

# PMP 配置位 (每 8-bit 条目中的位偏移)
PMP_R = 0b0000_0001
PMP_W = 0b0000_0010
PMP_X = 0b0000_0100
PMP_A_MASK = 0b0001_1000  # A[1:0]
PMP_A_OFF = 0b0000_0000  # 禁用
PMP_A_TOR = 0b0000_1000  # Top of Range
PMP_A_NA4 = 0b0001_0000  # Naturally Aligned 4-byte
PMP_A_NAPOT = 0b0001_1000  # Naturally Aligned Power-of-Two
PMP_L = 0b1000_0000  # 锁定位

# RiscvMode 的 M 模式取值: 有效特权级为 M 时只有锁定条目参与检查
_MODE_M = 3


def _decode_pmpcfg(cfg_val: int, entry_idx: int) -> int:
    """从 pmpcfgN 的值中提取第 *entry_idx* 个条目的 8-bit 配置."""
    shift = (entry_idx & 0x7) * 8
    return (cfg_val >> shift) & 0xFF


def decode_napot(pmpaddr_val: int) -> tuple[int, int]:
    """解码 NAPOT 格式的 pmpaddr -> (base, size).

    算法: 统计 pmpaddr 中从 LSB 开始的连续 1 的个数 k,
        则 size = 2^(k+3), base = (pmpaddr & ~mask_k) << 2.

    pmpaddr 全 1 时覆盖整个地址空间 (size=0, 作无穷大处理).
    """
    # 计算末尾连续 1 的个数
    val = pmpaddr_val & 0x003F_FFFF_FFFF_FFFF  # 54-bit PMP 地址域
    trailing = 0
    temp = val
    while temp & 1:
        trailing += 1
        temp >>= 1
        if trailing >= 54:
            break

    if trailing >= 54:
        # 全 1: 覆盖整个地址空间
        return 0, 0x1_0000_0000_0000_0000  # 2^64 (实际不限)
    if trailing == 0:
        # 无末尾 1: 8 字节区域
        return (val >> 0) << 2, 8
    size = 1 << (trailing + 3)
    mask = (1 << trailing) - 1  # trailing 个 1
    base = mask64(((val & ~mask) << 2))
    return base, size


def _decode_tor(
    pmpaddr_prev: int,
    pmpaddr_cur: int,
    entry_idx: int,
) -> tuple[int, int]:
    """TOR: 范围为 [prev << 2, cur << 2). 条目 0 的下界为 0."""
    lo = 0 if entry_idx == 0 else (pmpaddr_prev << 2)
    hi = pmpaddr_cur << 2
    return lo, hi - lo


def _addr_in_range(addr: int, size: int, base: int, rsize: int) -> bool:
    """检查 [addr, addr+size) 是否完全落在 [base, base+rsize) 内."""
    if rsize == 0:
        return False
    end = mask64((addr + size - 1))
    rend = mask64((base + rsize - 1))
    return addr >= base and end <= rend


def _check_perm(cfg: int, is_write: bool, is_execute: bool) -> bool:
    """检查单条目权限: 执行只要求 X; 读要求 R; 写入另要求 W.
    R 为 0 且 W 为 1 是保留组合, 读与写均被拒绝.
    """
    if is_execute:
        return bool(cfg & PMP_X)
    if not (cfg & PMP_R):
        return False
    if is_write and not (cfg & PMP_W):
        return False
    return True


@dataclass
class PmpAccessInfo:
    """PMP 检查所需的全部访问信息.

    pa / size 描述访存操作的物理地址和大小;
    mode_val / mstatus_val 提供当前 hart 的特权级和状态;
    is_write / is_execute 区分读/写/执行;
    pmpsplit / mdid 提供 TEE 飞地 PMP 虚拟化参数.
    """

    pa: int
    size: int
    mode_val: int
    mstatus_val: int
    is_write: bool = False
    is_execute: bool = False
    pmpsplit: int = 0
    mdid: int = 0


class Pmp:
    """Physical Memory Protection 检查器.

    直接读取 hart CSRs, 每次 check() 调用时重新计算.
    条目数组可按 hart 指向共享缓冲区中的切片, 与加速执行引擎读写同一份存储;
    条目由 CSR 重建, 引擎的改动经 ``sync_from_flat()`` 写回 CSR.
    """

    def __init__(
        self,
        csrs: MutableMapping[str, Any],
        num_entries: int = PMP_ENTRIES,
    ) -> None:
        self._csrs = csrs
        if num_entries < 0 or num_entries > 64:
            raise ValueError("num_entries must be 0..64")
        self._num_entries = num_entries

        # 按条目编号排列的 pmpcfg 字节数组与 pmpaddr 数组, 默认不与其他
        # hart 共享
        self._flat_cfg: bytearray = bytearray(64)
        self._flat_addr: array = array("Q", [0] * 64)
        self._cache_dirty: bool = True
        self._use_native: bool = native_available()

    # ---- 属性 ----

    @property
    def num_entries(self) -> int:
        return self._num_entries

    @property
    def flat_cfg(self):
        """本 hart 的 pmpcfg 字节数组, 按条目编号排列, 长度为
        ``num_entries``.
        """
        return self._flat_cfg

    @property
    def flat_addr(self):
        """本 hart 的 pmpaddr 数组, 按条目编号排列, 长度为 ``num_entries``."""
        return self._flat_addr

    @property
    def is_cache_dirty(self) -> bool:
        """条目数组是否需要按 CSR 重建."""
        return self._cache_dirty

    # ---- 缓存管理 ----

    def invalidate_cache(self) -> None:
        """PMP CSR 写入后标记缓存失效."""
        self._cache_dirty = True

    def bind_flat_buffers(self, flat_cfg, flat_addr) -> None:
        """把条目数组指向外部持有的缓冲区切片.

        加速执行引擎直接读写该切片, 本对象不再另行复制. 新切片的内容未知,
        故标记缓存失效, 由下一次 ``rebuild_cache()`` 按 CSR 重建.
        """
        self._flat_cfg = flat_cfg
        self._flat_addr = flat_addr
        self._cache_dirty = True

    def rebuild_cache(self) -> None:
        """按条目编号从 CSR 重建 pmpcfg 与 pmpaddr 数组."""
        for i in range(self._num_entries):
            self._flat_cfg[i] = self._read_cfg(i)
            self._flat_addr[i] = self._read_addr(i)
        # 数组可能只是更大缓冲区中的一个切片, 只清除其中剩余的条目
        for i in range(self._num_entries, len(self._flat_cfg)):
            self._flat_cfg[i] = 0
        for i in range(self._num_entries, len(self._flat_addr)):
            self._flat_addr[i] = 0
        self._cache_dirty = False

    def sync_from_flat(self) -> None:
        """把加速执行引擎修改后的条目数组写回 CSR.

        逐字节写回 pmpcfg 寄存器: 先读 CSR 当前值, 替换目标字节,
        写回, 确保同一寄存器内其他条目不受影响.
        """
        for i in range(self._num_entries):
            cfg_reg = (i // 8) * 2
            reg_name = f"pmpcfg{cfg_reg}"
            if reg_name not in self._csrs:
                continue
            cfg_val = self._csrs[reg_name].val
            byte_idx = i & 0x7
            shift = byte_idx * 8
            byte_mask = 0xFF << shift
            cfg_val = (cfg_val & ~byte_mask) | (self._flat_cfg[i] << shift)
            self._csrs[reg_name].val = cfg_val
        for i in range(self._num_entries):
            reg_name = f"pmpaddr{i}"
            if reg_name in self._csrs:
                self._csrs[reg_name].val = self._flat_addr[i]
        self._cache_dirty = False

    # ---- 权限检查入口 ----

    def check(self, info: PmpAccessInfo) -> bool:
        """检查物理地址访问是否允许. 返回 True 表示通过."""
        pmpsplit, mdid = info.pmpsplit, info.mdid

        # 飞地 split 超限预检 (在所有路径前, 避免无谓的缓存重建)
        if mdid != 0 and pmpsplit > 0 and pmpsplit >= self._num_entries:
            return False

        # 加速执行路径: 由加速执行引擎处理 M 模式旁路、MPRV、pmpsplit 等全部逻辑
        if self._use_native:
            if self._cache_dirty:
                self.rebuild_cache()
            return pmp_check(
                bytes(self._flat_cfg),
                self._flat_addr,
                self._num_entries,
                info,
            )

        # 加速执行库不可用时的纯 Python 路径
        return self._check_py(info)

    def _check_py(self, info: PmpAccessInfo) -> bool:
        """纯 Python PMP 检查, 加速执行库缺失时使用."""
        pa, size = info.pa, info.size
        mode_val, mstatus_val = info.mode_val, info.mstatus_val
        is_write, is_execute = info.is_write, info.is_execute
        pmpsplit, mdid = info.pmpsplit, info.mdid

        # MPRV 不作用于取指; M 模式的数据访问在 MPRV=1 且 MPP 不为 M 时
        # 按 MPP 检查
        eff_mode = mode_val
        if mode_val == _MODE_M and not is_execute:
            mprv = (mstatus_val >> 17) & 1
            if mprv:
                mpp = (mstatus_val >> 11) & 3
                mpp_map = {0: 0, 1: 1, 3: 3}
                eff_mode = mpp_map.get(mpp, 3)

        # 有效特权级为 M 时只有锁定条目参与检查, 未命中条目时放行
        is_mmode = eff_mode == _MODE_M
        if self._num_entries == 0:
            return is_mmode

        enclave_mode = mdid != 0

        # 按优先级遍历 PMP 条目 (低编号优先)
        for i in range(self._num_entries):
            if enclave_mode and pmpsplit > 0 and i < pmpsplit:
                continue

            cfg = self._read_cfg(i)
            if is_mmode and not (cfg & PMP_L):
                continue
            if not (cfg & PMP_A_MASK):
                continue

            addr_field = self._read_addr(i)
            if not self._match(i, cfg, addr_field, pa, size):
                continue

            ok = _check_perm(cfg, is_write, is_execute)
            return ok

        return is_mmode

    def is_entry_locked(self, idx: int) -> bool:
        """第 *idx* 个条目的 L 位是否置位; 编号越界时返回 False."""
        if idx < 0 or idx >= self._num_entries:
            return False
        return bool(self._read_cfg(idx) & PMP_L)

    def is_cfg_group_locked(self, cfg_reg: int) -> bool:
        """pmpcfg*cfg_reg* 覆盖的条目中任一 L 置位时返回 True."""
        base = (cfg_reg // 2) * 8
        return any(self.is_entry_locked(i) for i in range(base, base + 8))

    # ---- 内部 ----

    def _read_cfg(self, idx: int) -> int:
        """读取第 *idx* 个 PMP 条目的 8-bit 配置."""
        # 每个 pmpcfg 存 4 个条目 (RV32), 或 8 个 (RV64) <-> idx // 4
        # RV64: 仅偶数编号的 pmpcfg 有效 (存储 8 条目)
        # 简化: 统一用 RV64 模型 — 按 8 条目编组
        cfg_reg = (idx // 8) * 2  # pmpcfg0, pmpcfg2, pmpcfg4, ...
        reg_name = f"pmpcfg{cfg_reg}"
        if reg_name not in self._csrs:
            return PMP_A_OFF
        cfg_val = self._csrs[reg_name].val
        return _decode_pmpcfg(cfg_val, idx & 0x7)

    def _read_addr(self, idx: int) -> int:
        """读取 pmpaddr[idx] 的值."""
        reg_name = f"pmpaddr{idx}"
        if reg_name not in self._csrs:
            return 0
        return mask64(self._csrs[reg_name].val)

    def _match(
        self,
        idx: int,
        cfg: int,
        addr_field: int,
        pa: int,
        size: int,
    ) -> bool:
        """检查地址是否匹配条目 *idx*."""
        a_mode = cfg & PMP_A_MASK
        if a_mode == PMP_A_TOR:
            prev = self._read_addr(idx - 1) if idx > 0 else 0
            base, rsize = _decode_tor(prev, addr_field, idx)
        elif a_mode == PMP_A_NA4:
            base = addr_field << 2
            rsize = 4
        elif a_mode == PMP_A_NAPOT:
            base, rsize = decode_napot(addr_field)
        else:
            return False  # OFF 或其他非法值

        return _addr_in_range(pa, size, base, rsize)
