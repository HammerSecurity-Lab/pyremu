# SPDX-LICENSE-IDENTIFIER: MIT
"""设备定义 — 各外设的配置字段、窗口大小与芯片设备树来源.

每类外设由一条 :class:`DeviceSpec` 描述; 区间的分配、芯片设备树的取值与
中断源编号的读取都按这些定义进行.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from pyremu import configs_gen
from pyremu.check_configs import DevRange
from pyremu.interrupt.clint import CLINT_SIZE
from pyremu.interrupt.plic import plic_mem_range
from pyremu.peripheral.uart import UART_IRQ
from pyremu.peripheral.virtio_blk import VIRTIO_BLK_IRQ
from pyremu.peripheral.virtio_mmio import VIRTIO_MMIO_SIZE
from pyremu.peripheral.virtio_net import VIRTIO_NET_M_IRQ, VIRTIO_NET_S_IRQ
from pyremu.peripheral.watchdog import WATCHDOG_IRQ

if TYPE_CHECKING:
    from pyremu.platform.config import PlatformConfig

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
    # 芯片设备树中声明、但本模拟器未提供模型的设备
    # (节点路径, compatible, 基址, 字节数). 由芯片设备树定义.
    unsupported_devices: tuple[tuple[str, str, int, int], ...] = ()


def _watchdog_window(
    cfg: PlatformConfig,
) -> int:
    """看门狗窗口字节数: 每个 hart 一段 16 字节的寄存器."""
    return cfg.num_harts * 0x10


def _plic_window(
    cfg: PlatformConfig,
) -> int:
    """PLIC 窗口字节数: 到最后一个 context 末尾再加一页."""
    return plic_mem_range(2 * max(1, cfg.num_harts))


def _imsic_window(
    cfg: PlatformConfig,
) -> int:
    """IMSIC 窗口字节数: M 区与 S 区各按 2 的幂对齐."""
    power = (cfg.num_harts - 1).bit_length() if cfg.num_harts > 1 else 0
    return 2 * (1 << power) * _PAGE_SIZE


@dataclass(frozen=True)
class DeviceSpec:
    """一种外设的配置字段与它在总线上的窗口.

    name 给出区间名: 配置中的基址字段为 ``f"{name}_base"``, 窗口大小字段为
    ``f"{name}_size"``, 中断源字段为 ``f"{name}_irq"``.

    size 为窗口字节数; 取 None 时读配置中的大小字段, 取可调用对象时按配置计算.
    align 为区间重新分配时的对齐字节数, 同样可为可调用对象.

    chip_source 给出芯片设备树中的来源, 形如 ``("periph", 字段名)`` 或
    ``("chip", 字段名)``; 取 None 表示树中没有对应节点. irq_source 为
    ``ChipIrq`` 中的字段名.

    modes 限定该设备参与的中断模式; requires_disk_image 为真时仅在配置了
    块设备镜像后参与区间分配.
    """

    name: str
    size: int | Callable[[PlatformConfig], int] | None = _PAGE_SIZE
    align: int | Callable[[PlatformConfig], int] = _PAGE_SIZE
    chip_source: tuple[str, str] | None = None
    irq_source: str | None = None
    modes: frozenset[InterruptMode] | None = None
    requires_disk_image: bool = False

    def base_of(
        self,
        cfg: PlatformConfig,
    ) -> int:
        """该设备在配置中的基址."""
        return getattr(cfg.periph, f"{self.name}_base")

    def window_size(
        self,
        cfg: PlatformConfig,
    ) -> int:
        """该设备的窗口字节数."""
        if self.size is None:
            return getattr(cfg.periph, f"{self.name}_size")
        return self.size(cfg) if callable(self.size) else self.size

    def alignment(
        self,
        cfg: PlatformConfig,
    ) -> int:
        """区间重分配时的对齐字节数."""
        return self.align(cfg) if callable(self.align) else self.align

    def dev_range(
        self,
        cfg: PlatformConfig,
    ) -> DevRange | None:
        """该设备的地址区间; 未启用或不属于当前模式时返回 None."""
        if self.modes is not None and cfg.interrupt_mode not in self.modes:
            return None
        if self.requires_disk_image and cfg.disk_image is None:
            return None
        base = self.base_of(cfg)
        if not base:
            return None
        return DevRange(
            self.name, base, self.window_size(cfg), align=self.alignment(cfg)
        )


# 各外设的区间、芯片设备树来源与中断源字段.
# 中断控制器的区间仅在对应模式下参与分配.
DEVICE_SPECS: tuple[DeviceSpec, ...] = (
    DeviceSpec("uart", chip_source=("periph", "uart"), irq_source="uart"),
    DeviceSpec("spi", chip_source=("periph", "spi")),
    DeviceSpec("i2c", chip_source=("periph", "i2c")),
    DeviceSpec("gpio", chip_source=("periph", "gpio")),
    DeviceSpec("crng", chip_source=("periph", "crng")),
    # 芯片设备树没有关机与复位请求设备的节点.
    DeviceSpec("power"),
    DeviceSpec("clint", CLINT_SIZE, chip_source=("periph", "clint")),
    DeviceSpec("boot_addr", None, chip_source=("chip", "boot_addr")),
    DeviceSpec(
        "watchdog",
        _watchdog_window,
        chip_source=("periph", "watchdog"),
        irq_source="watchdog",
    ),
    DeviceSpec(
        "virtio_net_s",
        VIRTIO_MMIO_SIZE,
        chip_source=("periph", "virtio_net_s"),
        irq_source="virtio_net_s",
    ),
    DeviceSpec(
        "virtio_net_m",
        VIRTIO_MMIO_SIZE,
        chip_source=("periph", "virtio_net_m"),
        irq_source="virtio_net_m",
    ),
    DeviceSpec(
        "virtio_blk",
        VIRTIO_MMIO_SIZE,
        chip_source=("periph", "virtio_blk"),
        irq_source="virtio_blk",
        requires_disk_image=True,
    ),
    DeviceSpec(
        "plic",
        _plic_window,
        chip_source=("periph", "plic"),
        modes=frozenset({InterruptMode.LEGACY}),
    ),
    DeviceSpec(
        "imsic_m",
        _imsic_window,
        align=_imsic_window,
        modes=frozenset({InterruptMode.AIA}),
    ),
    DeviceSpec(
        "aplic_s", _APLIC_RANGE_SIZE, modes=frozenset({InterruptMode.AIA})
    ),
    DeviceSpec(
        "aplic_m", _APLIC_RANGE_SIZE, modes=frozenset({InterruptMode.AIA})
    ),
)


def spec_named(
    name: str,
) -> DeviceSpec:
    """按区间名取设备定义."""
    for spec in DEVICE_SPECS:
        if spec.name == name:
            return spec
    raise KeyError(name)
