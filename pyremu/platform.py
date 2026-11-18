#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""
平台配置 — 描述 CPU 拓扑、内存布局、外设映射和 ISA 特性.

配置与预设分离: 每个预设是独立的工厂函数, 返回填充了合理默认值的
PlatformConfig 实例. 也支持从 JSON / TOML / YAML 文件反序列化.

Usage:
    # 使用预设
    cfg = PlatformConfig.sifive_u54()
    emu = Emulator(cfg)

    # 从配置文件加载
    cfg = PlatformConfig.from_json("platforms/virt.json")
    cfg = PlatformConfig.from_toml("platforms/virt.toml")
    cfg = PlatformConfig.from_yaml("platforms/virt.yaml")

    # 程序化定制
    cfg = PlatformConfig.sifive_u54()
    cfg.periph.uart_base = 0x2000_0000
    emu = Emulator(cfg)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
import tomllib
from typing import Any

import yaml

from pyremu import configs_gen
from pyremu.check_configs import check_limits, DevRange, parse_dev_range
from pyremu.interrupt.clint import CLINT_SIZE
from pyremu.interrupt.plic import PLIC_CONTEXT_BASE, PLIC_CONTEXT_STRIDE
from pyremu.peripheral.uart import UART_IRQ
from pyremu.peripheral.virtio_blk import VIRTIO_BLK_IRQ
from pyremu.peripheral.virtio_mmio import VIRTIO_MMIO_SIZE
from pyremu.peripheral.virtio_net import VIRTIO_NET_M_IRQ, VIRTIO_NET_S_IRQ
from pyremu.peripheral.watchdog import WATCHDOG_IRQ

# 各设备窗口的字节数. 与设备构造时的 size 保持一致,
# 由 tests/test_utils/test_configs_check.py 对照实际注册的设备校验.
_PAGE_SIZE = 0x1000
_APLIC_RANGE_SIZE = 0x6000


class InterruptMode(Enum):
    """中断子系统模式."""

    LEGACY = "legacy"  # CLINT 维持软件中断与时钟中断，PLIC 维持所有外部中断
    # CLINT 只提供 MTIP, IMSIC 提供 MSIP+MEIP+SEIP, APLIC 把有线中断转为 MSI
    AIA = "aia"


@dataclass
class PeripheralConfig:
    """外设 MMIO 基址. 默认值由 mk/ 下的配置生成为 configs_gen."""

    uart_base: int = configs_gen.UART_BASE
    uart_irq: int = UART_IRQ  # 串口的中断源编号
    spi_base: int = configs_gen.SPI_BASE
    i2c_base: int = configs_gen.I2C_BASE
    gpio_base: int = configs_gen.GPIO_BASE
    clint_base: int = configs_gen.CLINT_BASE
    plic_base: int = configs_gen.PLIC_BASE
    virtio_blk_base: int = configs_gen.VIRTIO_BLK_BASE
    virtio_blk_irq: int = VIRTIO_BLK_IRQ  # 块设备的中断源编号
    # 宿主侧网卡: 中断由 S 模式接受
    virtio_net_s_base: int = configs_gen.VIRTIO_NET_S_BASE
    virtio_net_s_irq: int = VIRTIO_NET_S_IRQ  # 宿主侧网卡的中断源编号
    # 飞地侧网卡: 中断由 M 模式接受
    virtio_net_m_base: int = configs_gen.VIRTIO_NET_M_BASE
    virtio_net_m_irq: int = VIRTIO_NET_M_IRQ  # 飞地侧网卡的中断源编号
    watchdog_base: int = configs_gen.WATCHDOG_BASE
    watchdog_irq: int = WATCHDOG_IRQ  # 看门狗的中断源编号
    crng_base: int = configs_gen.CRNG_BASE
    power_base: int = configs_gen.POWER_BASE  # 关机与复位请求设备
    imsic_m_base: int = configs_gen.IMSIC_M_BASE
    imsic_s_base: int = configs_gen.IMSIC_S_BASE
    aplic_s_base: int = configs_gen.APLIC_S_BASE
    aplic_m_base: int = configs_gen.APLIC_M_BASE
    boot_addr_base: int = configs_gen.BOOT_REGS_ADDR
    boot_addr_size: int = configs_gen.BOOT_REGS_SIZE


@dataclass
class PlatformConfig:
    """模拟平台完整配置.

    字段:
        num_harts: hart 数量.
        ram_size: 物理 RAM 大小 (字节).
        ram_base: 物理 RAM 起始地址.
        rom_base: 引导只读存储器起始地址; 取 0 表示不注册该设备.
        rom_size: 引导只读存储器大小 (字节).
        prog_cnt: 程序计数器 — 上电复位入口地址.
        l2_size: L2 缓存大小 (字节).
        isa: RISC-V ISA 字符串，例: 'rv64ima'.
        timebase_freq: mtime 计数器频率 (Hz).
        periph: 外设基址配置.
    """

    num_harts: int = configs_gen.NUM_HARTS
    ram_size: int = configs_gen.RAM_SIZE
    ram_base: int = configs_gen.RAM_BASE
    rom_base: int = configs_gen.ROM_BASE
    rom_size: int = configs_gen.ROM_SIZE
    prog_cnt: int = configs_gen.PROG_CNT
    l2_size: int = configs_gen.L2_SIZE

    isa: str = configs_gen.ISA
    timebase_freq: int = configs_gen.TIMER_FREQ
    pmp_entries: int = configs_gen.PMP_ENTRIES
    interrupt_mode: InterruptMode = InterruptMode.LEGACY
    disk_image: str | None = None

    # DTB /reserved-memory no-map 区域列表.
    # 默认值经 mk/memory.mk 生成 pyremu/configs_gen.py 注入.
    reserved_memory_ranges: list[tuple[int, int]] = field(
        default_factory=lambda: [
            (
                configs_gen.FW_RESERVED_MEM_BASE,
                configs_gen.FW_RESERVED_MEM_SIZE,
            ),
            (configs_gen.RESERVED_MEM_BASE, configs_gen.RESERVED_MEM_SIZE),
        ]
    )
    periph: PeripheralConfig = field(default_factory=PeripheralConfig)

    def __post_init__(self) -> None:
        """编译期 AIA 开关: PYREMU_AIA=1 时强制启用 IMSIC+APLIC.

        基址从 configs_gen读取. 仅在 legacy 模式下
        覆盖, 显式指定 AIA 的预设不受影响. 任何构造路径
        均经由此处统一解析, 故 Emulator 无需再对 interrupt_mode 做二次判断.
        """
        if (
            configs_gen.PYREMU_AIA
            and self.interrupt_mode == InterruptMode.LEGACY
        ):
            self.interrupt_mode = InterruptMode.AIA
            self.periph.imsic_m_base = configs_gen.IMSIC_M_BASE
            self.periph.imsic_s_base = configs_gen.IMSIC_S_BASE
            self.periph.aplic_s_base = configs_gen.APLIC_S_BASE
            self.periph.aplic_m_base = configs_gen.APLIC_M_BASE
        assert self.timebase_freq >= 1_000, (
            f"timebase_freq={self.timebase_freq} < 1000 Hz!"
        )
        # 引导只读存储器与 RAM 的范围不允许重叠，同一物理地址只能有一条访问路径.
        if self.rom_base:
            assert self.rom_size > 0, f"rom_size={self.rom_size} 须大于 0"
        self.validate()

    def validate(self) -> None:
        """检查配置取值与设备区间, 冲突的设备区间就地重新分配.

        构造时调用一次; 调用方在修改 ``periph`` 的基址之后可再次调用, 使
        ``Emulator`` 装配前拿到一致的布局. 重新分配过的基址写回本配置.
        """
        self._check_limits()
        self._apply_dev_ranges()
        self._check_overlap()

    def _check_limits(self) -> None:
        """检查 RAM 大小、PMP 条目数与 hart 数是否在允许范围内."""
        check_limits(
            ram_size=self.ram_size,
            pmp_entries=self.pmp_entries,
            num_harts=self.num_harts,
        )

    def _dev_ranges(self) -> list[DevRange]:
        """按当前配置给出 RAM、引导只读存储器与各设备的地址区间.

        区间名与其基址字段同名去掉 ``_base`` 后缀, 重新分配时据此写回.
        基址取 0 的设备不参与, 与注册规则一致.
        """
        ranges = [DevRange("ram", self.ram_base, self.ram_size, is_fixed=True)]
        if self.rom_base:
            ranges.append(
                DevRange("rom", self.rom_base, self.rom_size, is_fixed=True)
            )
        periph = self.periph
        imsic_size = self._imsic_range_size()
        candidates: list[tuple[str, int, int, int]] = [
            ("uart", periph.uart_base, _PAGE_SIZE, _PAGE_SIZE),
            ("spi", periph.spi_base, _PAGE_SIZE, _PAGE_SIZE),
            ("i2c", periph.i2c_base, _PAGE_SIZE, _PAGE_SIZE),
            ("gpio", periph.gpio_base, _PAGE_SIZE, _PAGE_SIZE),
            ("crng", periph.crng_base, _PAGE_SIZE, _PAGE_SIZE),
            ("power", periph.power_base, _PAGE_SIZE, _PAGE_SIZE),
            ("clint", periph.clint_base, CLINT_SIZE, _PAGE_SIZE),
            (
                "boot_addr",
                periph.boot_addr_base,
                periph.boot_addr_size,
                _PAGE_SIZE,
            ),
            (
                "watchdog",
                periph.watchdog_base,
                self.num_harts * 0x10,
                _PAGE_SIZE,
            ),
            (
                "virtio_net_s",
                periph.virtio_net_s_base,
                VIRTIO_MMIO_SIZE,
                _PAGE_SIZE,
            ),
            (
                "virtio_net_m",
                periph.virtio_net_m_base,
                VIRTIO_MMIO_SIZE,
                _PAGE_SIZE,
            ),
        ]
        if self.disk_image is not None:
            candidates.append(
                (
                    "virtio_blk",
                    periph.virtio_blk_base,
                    VIRTIO_MMIO_SIZE,
                    _PAGE_SIZE,
                )
            )
        if self.interrupt_mode == InterruptMode.AIA:
            candidates.extend(
                [
                    ("imsic_m", periph.imsic_m_base, imsic_size, imsic_size),
                    (
                        "aplic_s",
                        periph.aplic_s_base,
                        _APLIC_RANGE_SIZE,
                        _PAGE_SIZE,
                    ),
                    (
                        "aplic_m",
                        periph.aplic_m_base,
                        _APLIC_RANGE_SIZE,
                        _PAGE_SIZE,
                    ),
                ]
            )
        else:
            candidates.append(
                (
                    "plic",
                    periph.plic_base,
                    self._plic_range_size(),
                    _PAGE_SIZE,
                )
            )
        for name, base, size, align in candidates:
            if base:
                ranges.append(DevRange(name, base, size, align=align))
        return ranges

    def _plic_range_size(self) -> int:
        """PLIC 的窗口字节数: 到最后一个 context 末尾再加一页."""
        contexts = 2 * self.num_harts
        return (
            PLIC_CONTEXT_BASE
            + (contexts - 1) * PLIC_CONTEXT_STRIDE
            + _PAGE_SIZE
        )

    def _imsic_range_size(self) -> int:
        """IMSIC 的窗口字节数: M 区与 S 区各按 2 的幂对齐."""
        power = (self.num_harts - 1).bit_length() if self.num_harts > 1 else 0
        return 2 * (1 << power) * _PAGE_SIZE

    def _apply_dev_ranges(self) -> None:
        """检查设备区间是否冲突; 冲突者重新分配并把新基址写回配置."""
        ranges = self._dev_ranges()
        resolved = parse_dev_range(ranges)
        for wanted, got in zip(ranges, resolved, strict=True):
            if wanted.base == got.base:
                continue
            setattr(self.periph, f"{wanted.name}_base", got.base)

    def _check_overlap(self) -> None:
        """断言 RAM、引导只读存储器与启动地址寄存器的地址范围两两不重叠.

        外设由 Bus.add_device 在注册时与全部已注册的地址范围一并校验.
        """
        windows = [("RAM", self.ram_base, self.ram_size)]
        if self.rom_base:
            windows.append(("引导只读存储器", self.rom_base, self.rom_size))
        if self.periph.boot_addr_base:
            windows.append(
                (
                    "启动地址寄存器",
                    self.periph.boot_addr_base,
                    self.periph.boot_addr_size,
                )
            )
        for index, (name_a, base_a, size_a) in enumerate(windows):
            for name_b, base_b, size_b in windows[index + 1 :]:
                assert base_a + size_a <= base_b or base_a >= base_b + size_b, (
                    f"{name_a} [0x{base_a:x}, 0x{base_a + size_a:x}) 与 "
                    f"{name_b} [0x{base_b:x}, 0x{base_b + size_b:x}) 重叠"
                )

    @classmethod
    def from_dict(
        cls,
        d: dict[str, Any],
    ) -> PlatformConfig:
        """从嵌套字典构建模拟器配置.

        ``periph`` 子字典映射到 PeripheralConfig 字段,
        其余键映射到 PlatformConfig 字段.
        """
        periph_dict: dict[str, Any] = d.get("periph", {})
        periph_fields = set(PeripheralConfig.__dataclass_fields__)
        periph = PeripheralConfig(
            **{k: v for k, v in periph_dict.items() if k in periph_fields}
        )

        plat_fields = set(cls.__dataclass_fields__) - {"periph"}
        plat_kw: dict[str, Any] = {
            k: v for k, v in d.items() if k in plat_fields
        }
        # 枚举转换: interrupt_mode 从 string 反序列化
        if "interrupt_mode" in plat_kw and isinstance(
            plat_kw["interrupt_mode"], str
        ):
            plat_kw["interrupt_mode"] = InterruptMode(plat_kw["interrupt_mode"])
        return cls(periph=periph, **plat_kw)

    @classmethod
    def from_json(
        cls,
        path: str | Path,
    ) -> PlatformConfig:
        """从 JSON 文件加载配置."""
        with open(path, "r") as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def from_toml(
        cls,
        path: str | Path,
    ) -> PlatformConfig:
        """从 TOML 文件加载配置."""
        with open(path, "rb") as fh:
            return cls.from_dict(tomllib.load(fh))

    @classmethod
    def from_yaml(
        cls,
        path: str | Path,
    ) -> PlatformConfig:
        """从 YAML 文件加载配置."""
        with open(path, "r") as fh:
            return cls.from_dict(yaml.safe_load(fh))

    # ---- 预设平台 ----
    @classmethod
    def sifive_u54(cls) -> PlatformConfig:
        """SiFive Freedom U54 风格布局.

        DRAM @ 0x8000_0000, CLINT @ 0x0200_0000,
        外设在 0x1000_0000 区域.
        """
        return cls(
            num_harts=4,
            periph=PeripheralConfig(
                uart_base=0x1000_0000,
                spi_base=0x1001_0000,
                i2c_base=0x1002_0000,
                gpio_base=0x1006_0000,
                clint_base=0x0200_0000,
            ),
        )

    @classmethod
    def basic_machine(cls) -> PlatformConfig:
        return cls()

    @classmethod
    def minimal(cls) -> PlatformConfig:
        """最小化单核平台 — 仅 CLINT + UART.

        RAM 自 0x0000_0000 起始并覆盖 0x0200_0000 处的 CLINT,
        """
        return cls(
            num_harts=1,
            ram_base=0x0000_0000,
            prog_cnt=0x0000_0000,
            periph=PeripheralConfig(
                uart_base=0x1000_0000,
                spi_base=0,
                i2c_base=0,
                gpio_base=0,
                clint_base=0x0200_0000,
                crng_base=0,
                power_base=0,
            ),
        )

    @classmethod
    def basic_aia_machine(cls) -> PlatformConfig:
        cfg = cls.basic_machine()
        cfg.interrupt_mode = InterruptMode.AIA
        return cfg
