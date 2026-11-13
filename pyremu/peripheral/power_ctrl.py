#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""关机与复位请求设备.

寄存器布局:
  偏移    名称     读写    描述
  0x00    CTRL     W      写入 0x5555 请求关机, 写入 0x7777 请求复位

设备树中该设备的节点声明为 syscon, syscon-poweroff 与 syscon-reboot 两个子节点
给出要写入的取值, 由 OpenSBI 或 Linux 的同名驱动经 regmap 写入.
"""

import ctypes
from enum import IntEnum
import threading

from pyremu.memory.bus import Device

REG_CTRL = 0x00  # 控制寄存器


class PowerRequest(IntEnum):
    """受调试程序经控制寄存器给出的请求."""

    SHUTDOWN = 0x5555
    REBOOT = 0x7777


class PowerCtrl(Device):
    """关机与复位请求设备.

    控制寄存器写入 ``PowerRequest`` 的取值后置位对应请求并保持, 由执行循环读取;
    其余取值以及其他偏移的写入被忽略. 控制寄存器读出为 0.
    """

    def __init__(
        self,
        base: int = 0x0010_0000,
        size: int = 0x1000,
        *,
        stop_flag: ctypes.c_uint8 | None = None,
        wake_event: threading.Event | None = None,
    ) -> None:
        self.base_addr = base
        self.size = size
        # 置位停止标志使正在运行的加速执行轮次尽快退出到 Python 侧, 置位唤醒事件
        # 使全部 hart 处于 WFI 等待的轮次不再阻塞.
        self._stop_flag = stop_flag
        self._wake_event = wake_event
        self._request: PowerRequest | None = None

    @property
    def request(self) -> PowerRequest | None:
        """已置位的请求; 没有请求时返回 None."""
        return self._request

    def clear_request(self) -> None:
        """撤销已置位的请求, 使设备重新接受控制寄存器的写入."""
        self._request = None

    # ---- Device 接口 ----

    def read(
        self,
        offset: int,
        size: int,
    ) -> bytes:
        return b"\x00" * size

    def write(
        self,
        offset: int,
        data: bytes,
    ) -> None:
        if offset != REG_CTRL or self._request is not None:
            return
        val = int.from_bytes(data[:4].ljust(4, b"\x00"), "little")
        try:
            request = PowerRequest(val)
        except ValueError:
            return
        self._request = request
        if self._stop_flag is not None:
            self._stop_flag.value = 1
        if self._wake_event is not None:
            self._wake_event.set()
