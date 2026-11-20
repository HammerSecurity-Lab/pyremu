# SPDX-LICENSE-IDENTIFIER: MIT
"""平台配置 — 描述 CPU 拓扑、内存布局、外设映射和 ISA 特性.

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

from pyremu.platform.assembly import periph_from_chip
from pyremu.platform.config import PlatformConfig
from pyremu.platform.specs import (
    DEVICE_SPECS,
    DeviceSpec,
    InterruptMode,
    PeripheralConfig,
)

__all__ = [
    "DEVICE_SPECS",
    "DeviceSpec",
    "InterruptMode",
    "periph_from_chip",
    "PeripheralConfig",
    "PlatformConfig",
]
