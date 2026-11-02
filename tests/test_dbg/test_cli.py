#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""测试 pyremu.debug.cli — 参数解析、固件加载与启动流程."""

import argparse
from pathlib import Path
import types

from loguru import logger
import pytest

from pyremu import configs_gen
from pyremu.debug import cli, Debugger
from pyremu.debug.types import ImageKind
from pyremu.emulator import Emulator
from pyremu.interrupt.plic import PLIC_PENDING_BASE
from pyremu.peripheral.uart import IP_RXWM, REG_IE, UART_IRQ
from pyremu.peripheral.virtio_mmio import VIRTIO_MMIO_SIZE
from pyremu.peripheral.watchdog import WATCHDOG_IRQ
from pyremu.platform import PlatformConfig
from pyremu.utils.isa import isa_ext_list
from pyremu.utils.parse_bin import FirmwareImage, FirmwareSegment
from tests.conftest import make_test_emu

RAM_BASE = 0x8000_0000
RAM_SIZE = 0x0040_0000  # 4 MiB, 容纳默认 DTB 与 initramfs 地址算式
DEFAULT_FDT_ADDR = RAM_BASE + RAM_SIZE - configs_gen.RAM_DTB_OFFSET

# 带 PLIC 与串口的芯片设备树, 串口占用中断源 1.
CHIP_DTS = """
{
	#address-cells = <1>;
	#size-cells = <1>;
	memory@80000000 {
		device_type = "memory";
		reg = <0x80000000 0x20000000>;
	};
	soc {
		#address-cells = <1>;
		#size-cells = <1>;
		ranges;
		serial@64000000 {
			compatible = "sifive,uart0";
			interrupts = <1>;
			reg = <0x64000000 0x1000>;
		};
		interrupt-controller@c000000 {
			#interrupt-cells = <1>;
			compatible = "riscv,plic0";
			interrupt-controller;
			reg = <0xc000000 0x4000000>;
			riscv,ndev = <1>;
			phandle = <6>;
		};
	};
};
"""

# 只声明 CPU 节点与 PMP 条目数的芯片树中的单个 CPU 节点.
_CPU_NODE = """
		cpu@%d {
			device_type = "cpu";
			reg = <%d>;
			riscv,pmpregions = <%d>;
			status = "okay";
		};"""


def _chip_dts_cpus(num_cpus: int = 1, pmp_entries: int | list[int] = 64) -> str:
    """建立只声明 *num_cpus* 个 CPU 节点与 PMP 条目数的芯片树.

    *pmp_entries* 为单个整数时全部节点取同一值, 为列表时按节点顺序取用.
    """
    values = [pmp_entries] * num_cpus if isinstance(pmp_entries, int) else pmp_entries
    nodes = "".join(_CPU_NODE % (i, i, values[i]) for i in range(num_cpus))
    return (
        "{\n"
        "\t#address-cells = <1>;\n"
        "\t#size-cells = <1>;\n"
        "\tcpus {\n"
        "\t\t#address-cells = <1>;\n"
        "\t\t#size-cells = <0>;\n"
        "\t\ttimebase-frequency = <1000000>;\n" + nodes + "\n\t};\n};\n"
    )


def _chip_dts_isa(*nodes: str) -> str:
    """建立只含 CPU 节点的芯片树, 每个参数是一个 CPU 节点内的属性文本."""
    body = []
    for hid, props in enumerate(nodes):
        lines = "".join(
            f"\t\t\t{line.strip()}\n" for line in props.splitlines() if line.strip()
        )
        body.append(
            f"\t\tcpu@{hid} {{\n"
            '\t\t\tdevice_type = "cpu";\n'
            f"\t\t\treg = <{hid}>;\n"
            f"{lines}"
            '\t\t\tstatus = "okay";\n'
            "\t\t};"
        )
    return (
        "{\n"
        "\t#address-cells = <1>;\n"
        "\t#size-cells = <1>;\n"
        "\tcpus {\n"
        "\t\t#address-cells = <1>;\n"
        "\t\t#size-cells = <0>;\n"
        "\t\ttimebase-frequency = <1000000>;\n" + "\n".join(body) + "\n\t};\n};\n"
    )


# 在 CHIP_DTS 的 /soc 下再声明一个 virtio-mmio 块设备.
CHIP_DTS_WITH_BLK = CHIP_DTS.replace(
    "\t\tinterrupt-controller@c000000 {",
    "\t\tvirtio@1000 {\n"
    '\t\t\tcompatible = "virtio,mmio";\n'
    "\t\t\tinterrupts = <5>;\n"
    "\t\t\treg = <0x1000 0x200>;\n"
    "\t\t};\n"
    "\t\tinterrupt-controller@c000000 {",
)


# 在 CHIP_DTS 的 /soc 下再声明一个 CLINT 节点: 装配 Emulator 时 CLINT 的基址取自
# 该节点, 基址为 0 表示不注册.
CHIP_DTS_WITH_CLINT = CHIP_DTS.replace(
    "\t\tinterrupt-controller@c000000 {",
    "\t\tclint@2000000 {\n"
    '\t\t\tcompatible = "riscv,clint0";\n'
    "\t\t\treg = <0x2000000 0x10000>;\n"
    "\t\t};\n"
    "\t\tinterrupt-controller@c000000 {",
)


# ============================================================
#  测试装置
# ============================================================


class _FakeBus:
    """记录 write_ram_direct 调用的总线替身."""

    def __init__(self) -> None:
        self.direct_writes: list[tuple[int, bytes]] = []

    def write_ram_direct(self, addr: int, data: bytes) -> None:
        self.direct_writes.append((addr, data))


class _FakeEmu:
    """记录设备树、initramfs 与内核加载调用的 Emulator 替身."""

    def __init__(self) -> None:
        self.dtb_calls: list[int] = []
        self.dtb_file_calls: list[tuple[str, int | None]] = []
        self.dtb_blob_calls: list[tuple[int, bytes]] = []
        self.initrd_calls: list[tuple[str, int]] = []
        self.bus = _FakeBus()
        self.config = types.SimpleNamespace(
            num_harts=1,
            ram_base=0x8000_0000,
            ram_size=0x2000_0000,
            reserved_memory_ranges=[(0x8300_0000, 0x1000)],
            periph=types.SimpleNamespace(
                virtio_blk_base=0x1000_1000,
                virtio_blk_irq=1,
            ),
            disk_image="/tmp/rootfs.ext4",
        )
        self.bootargs = "console=ttySIF0"
        self.initrd = types.SimpleNamespace(start=0x8800_0000, end=0x8810_0000)

    def load_default_dtb(self, addr: int) -> None:
        self.dtb_calls.append(addr)

    def load_dtb_file(self, path: str, addr: int | None = None) -> None:
        self.dtb_file_calls.append((path, addr))

    def load_dtb_blob(self, addr: int, blob: bytes) -> None:
        self.dtb_blob_calls.append((addr, blob))

    def load_initrd(self, path: str, addr: int) -> types.SimpleNamespace:
        self.initrd_calls.append((path, addr))
        return types.SimpleNamespace(start=addr, end=addr + 0x100)


def _ns(**kwargs) -> argparse.Namespace:
    """按解析器的默认值建立命名空间, 再用 *kwargs* 覆盖."""
    ns = cli._build_arg_parser().parse_args(["fw.bin"])
    for key, val in kwargs.items():
        setattr(ns, key, val)
    return ns


def _platform(ram_size: int = RAM_SIZE) -> cli.PlatformParams:
    """按测试常量建立平台参数, 其余字段取占位值."""
    return cli.PlatformParams(
        num_harts=1,
        ram_base=RAM_BASE,
        ram_size=ram_size,
        rom_base=0x4000_0000,
        rom_size=0x2_0000,
        timebase_freq=1_000_000,
        pmp_entries=16,
        isa=configs_gen.ISA,
    )


def _raw_firmware(tmp_path: Path, data: bytes = b"\x13\x00\x00\x00") -> str:
    path = tmp_path / "fw.bin"
    path.write_bytes(data)
    return str(path)


@pytest.fixture(autouse=True)
def _restore_logger():
    """用例结束后清除本文件配置的 loguru 处理器, 避免影响其它用例."""
    yield
    logger.remove()


# ============================================================
#  参数解析
# ============================================================


class TestBuildArgParser:
    def test_defaults(self):
        ns = cli._build_arg_parser().parse_args(["fw.bin"])
        assert ns.firmware == "fw.bin"
        assert ns.base_addr == RAM_BASE and ns.prog_cnt is None
        assert ns.ram_base is None and ns.fdt == -1
        assert ns.fdt_file is None and ns.no_fdt is False
        assert ns.harts is None and ns.ram is None
        assert ns.log_level == "INFO"
        assert ns.preload is None and ns.sym_dir is None
        assert ns.kernel is None and ns.disk is None
        assert ns.hart_logs is None

    def test_numeric_options_accept_hex(self):
        ns = cli._build_arg_parser().parse_args(
            [
                "fw.bin",
                "--base-addr",
                "0x80000000",
                "--prog-cnt",
                "0x1000",
                "--ram-base",
                "0x90000000",
                "--preload-addr",
                "0x40",
                "--kernel-addr",
                "0x1000",
                "--initrd-addr",
                "0x2000",
            ]
        )
        assert ns.base_addr == 0x8000_0000
        assert ns.prog_cnt == 0x1000
        assert ns.ram_base == 0x9000_0000
        assert ns.preload_addr == 0x40
        assert ns.kernel_addr == 0x1000
        assert ns.initrd_addr == 0x2000

    def test_fdt_flag_without_value_is_minus_one(self):
        ns = cli._build_arg_parser().parse_args(["fw.bin", "--fdt"])
        assert ns.fdt == -1

    def test_fdt_flag_with_value_is_parsed(self):
        ns = cli._build_arg_parser().parse_args(["fw.bin", "--fdt", "0x1000"])
        assert ns.fdt == 0x1000

    def test_fdt_flag_with_empty_value_is_none(self):
        ns = cli._build_arg_parser().parse_args(["fw.bin", "--fdt", ""])
        assert ns.fdt is None

    def test_fdt_file_keeps_path_and_address(self):
        ns = cli._build_arg_parser().parse_args(["fw.bin", "--fdt-file", "/tmp/a.dtb:0x40"])
        assert ns.fdt_file == "/tmp/a.dtb:0x40"

    def test_boolean_and_text_options(self):
        ns = cli._build_arg_parser().parse_args(
            [
                "fw.bin",
                "--no-fdt",
                "--harts",
                "4",
                "--ram",
                "256M",
                "--preload",
                "p.bin",
                "--entry-symbol",
                "main",
                "--sym-dir",
                "/tmp/symbols",
                "--kernel",
                "Image",
                "--bootargs",
                "console=ttySIF0",
                "--initrd",
                "initrd.cpio",
                "--disk",
                "root.img",
                "--hart-logs",
                "logs",
            ]
        )
        assert ns.no_fdt is True
        assert ns.harts == 4
        assert ns.ram == "256M"
        assert ns.preload == "p.bin"
        assert ns.entry_symbol == "main"
        assert ns.sym_dir == "/tmp/symbols"
        assert ns.kernel == "Image"
        assert ns.bootargs == "console=ttySIF0"
        assert ns.initrd == "initrd.cpio"
        assert ns.disk == "root.img"
        assert ns.hart_logs == "logs"

    def test_unknown_log_level_is_rejected(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli._build_arg_parser().parse_args(["fw.bin", "--log-level", "VERBOSE"])
        assert exc_info.value.code == 2
        assert "VERBOSE" in capsys.readouterr().err


# ============================================================
#  工具函数
# ============================================================


class TestSetupLogger:
    def test_level_gates_messages(self, capsys):
        cli._setup_logger("DEBUG")
        logger.debug("调试可见")
        logger.info("信息可见")
        out = capsys.readouterr().out
        assert "调试可见" in out
        assert "信息可见" in out

    def test_higher_level_suppresses_debug(self, capsys):
        cli._setup_logger("WARNING")
        logger.info("信息不可见")
        logger.warning("告警可见")
        out = capsys.readouterr().out
        assert "信息不可见" not in out
        assert "告警可见" in out


# ============================================================
#  固件加载
# ============================================================


class TestLoadFirmwareImage:
    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            cli._load_firmware_image(str(tmp_path / "none.bin"), 0, RAM_BASE)
        assert exc_info.value.code == 1

    def test_unparsable_file_exits(self, tmp_path, monkeypatch):
        path = _raw_firmware(tmp_path)
        monkeypatch.setattr(cli, "parse_firmware", lambda *a, **k: None)
        with pytest.raises(SystemExit) as exc_info:
            cli._load_firmware_image(path, 0, RAM_BASE)
        assert exc_info.value.code == 1

    def test_raw_binary_keeps_zero_offset(self, tmp_path):
        path = _raw_firmware(tmp_path, b"\x13\x00\x00\x00")
        image, load_offset = cli._load_firmware_image(path, RAM_BASE, RAM_BASE)
        assert image.format == "raw"
        assert image.entry_point == RAM_BASE
        assert load_offset == 0

    def test_elf_above_ram_base_keeps_zero_offset(self, tmp_path, monkeypatch):
        path = _raw_firmware(tmp_path)
        image = FirmwareImage(
            entry_point=RAM_BASE + 0x1000,
            segments=[FirmwareSegment(vaddr=RAM_BASE + 0x1000, data=b"\x13", memsz=4)],
            format="elf",
        )
        monkeypatch.setattr(cli, "parse_firmware", lambda *a, **k: image)
        _, load_offset = cli._load_firmware_image(path, 0, RAM_BASE)
        assert load_offset == 0

    def test_elf_below_ram_base_shifts_by_ram_base(self, tmp_path, monkeypatch):
        """映像最小虚拟地址低于内存基址时整段搬迁到内存基址."""
        path = _raw_firmware(tmp_path)
        image = FirmwareImage(
            entry_point=0x1000,
            segments=[
                FirmwareSegment(vaddr=0x1000, data=b"\x13", memsz=4),
                FirmwareSegment(vaddr=0x2000, data=b"\x13", memsz=4),
            ],
            format="elf",
        )
        monkeypatch.setattr(cli, "parse_firmware", lambda *a, **k: image)
        _, load_offset = cli._load_firmware_image(path, 0, RAM_BASE)
        assert load_offset == RAM_BASE

    def test_pe_format_keeps_zero_offset(self, tmp_path, monkeypatch):
        path = _raw_firmware(tmp_path)
        image = FirmwareImage(
            entry_point=0x1000,
            segments=[FirmwareSegment(vaddr=0x1000, data=b"\x13", memsz=4)],
            format="pe",
        )
        monkeypatch.setattr(cli, "parse_firmware", lambda *a, **k: image)
        _, load_offset = cli._load_firmware_image(path, 0, RAM_BASE)
        assert load_offset == 0


# ============================================================
#  设备树
# ============================================================


class TestDefaultFdtAddr:
    """设备树的默认装载地址随启动路径变化."""

    ROM_BASE = 0x4000_0000

    @pytest.mark.parametrize(
        ("is_rom_boot", "expected"),
        [
            (False, RAM_BASE + RAM_SIZE - configs_gen.RAM_DTB_OFFSET),
            (True, ROM_BASE + configs_gen.ROM_DTB_OFFSET),
        ],
        ids=["no_rom", "rom"],
    )
    def test_addr_follows_boot_path(self, is_rom_boot, expected):
        addr = cli._default_fdt_addr(RAM_BASE, RAM_SIZE, self.ROM_BASE, is_rom_boot)
        assert addr == expected


class TestFdtLoadAddr:
    """--fdt 与 --fdt-file 的装载地址解析."""

    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({"no_fdt": True}, None),
            ({"fdt": 0x9000_0000}, 0x9000_0000),
            ({"fdt": -1}, DEFAULT_FDT_ADDR),
            # --fdt 取 0 按未给出处理, 与 -1 的取值判定不同
            ({"fdt": 0}, None),
            ({"fdt": None}, None),
            # 文件名后缀的 0 是合法地址, 不能被当作未给出
            ({"fdt_file": "/tmp/a.dtb:0x1000"}, 0x1000),
            ({"fdt_file": "/tmp/a.dtb:0"}, 0),
            ({"fdt_file": "/tmp/a.dtb"}, DEFAULT_FDT_ADDR),
            # 路径中的冒号按最后一个分隔, 使含冒号的路径仍可带地址
            ({"fdt_file": "/tmp/a:b.dtb:0x2000"}, 0x2000),
        ],
    )
    def test_addr_is_resolved(self, kwargs, expected):
        assert cli._fdt_load_addr(_ns(**kwargs), DEFAULT_FDT_ADDR) == expected


class TestLoadFdt:
    def test_none_address_loads_nothing(self):
        emu = _FakeEmu()
        cli._load_fdt(emu, _ns(fdt=None), None)
        assert emu.dtb_calls == []
        assert emu.dtb_file_calls == []

    def test_default_tree_is_loaded_at_address(self):
        emu = _FakeEmu()
        cli._load_fdt(emu, _ns(fdt=0x9000_0000), 0x9000_0000)
        assert emu.dtb_calls == [0x9000_0000]

    @pytest.mark.parametrize(
        ("fdt_file", "addr", "expected"),
        [
            ("/tmp/a.dtb:0x1000", 0x1000, ("/tmp/a.dtb", 0x1000)),
            ("/tmp/a:b.dtb:0x2000", 0x2000, ("/tmp/a:b.dtb", 0x2000)),
        ],
    )
    def test_prebuilt_file_is_loaded_at_address(self, fdt_file, addr, expected):
        emu = _FakeEmu()
        cli._load_fdt(emu, _ns(fdt_file=fdt_file), addr)
        assert emu.dtb_file_calls == [expected]


@pytest.fixture
def chip_dtb_calls(monkeypatch) -> list[cli.dev_tree.DeliveredTree]:
    """把 chip_dt_to_dtb 换成记录交付内容的替身."""
    calls: list[cli.dev_tree.DeliveredTree] = []

    def fake_chip_dt_to_dtb(chip, delivered=None, report=None):
        calls.append(delivered)
        return b"CHIP"

    monkeypatch.setattr(cli.dev_tree, "chip_dt_to_dtb", fake_chip_dt_to_dtb)
    return calls


def _chip(virtio_blk=None) -> types.SimpleNamespace:
    """芯片设备树替身: 交付内容只取决于树中是否声明了块设备节点."""
    return types.SimpleNamespace(periph=types.SimpleNamespace(virtio_blk=virtio_blk))


class TestLoadChipFdt:
    def test_none_address_loads_nothing(self, chip_dtb_calls):
        emu = _FakeEmu()
        cli._load_chip_fdt(emu, _chip(), None)
        assert emu.dtb_blob_calls == []
        assert chip_dtb_calls == []

    def test_blob_is_written_at_address(self, chip_dtb_calls):
        emu = _FakeEmu()
        cli._load_chip_fdt(emu, _chip(), 0x87FF_0000)
        assert emu.dtb_blob_calls == [(0x87FF_0000, b"CHIP")]

    def test_platform_facts_are_passed_to_blob(self, chip_dtb_calls):
        """平台自定的 RAM 窗口、保留区间、命令行与 initramfs 一并写入该 blob."""
        emu = _FakeEmu()
        cli._load_chip_fdt(emu, _chip(), 0x87FF_0000)
        delivered = chip_dtb_calls[0]
        assert delivered.ram == cli.dev_tree.DtRegion(0x8000_0000, 0x2000_0000)
        assert delivered.bootargs == "console=ttySIF0"
        assert delivered.initrd == (0x8800_0000, 0x8810_0000)
        assert delivered.reserved_ranges == [(0x8300_0000, 0x1000)]

    def test_absent_initrd_is_passed_as_none(self, chip_dtb_calls):
        emu = _FakeEmu()
        emu.initrd = None
        cli._load_chip_fdt(emu, _chip(), 0x87FF_0000)
        assert chip_dtb_calls[0].initrd is None

    def test_assembled_hart_count_is_passed_to_blob(self, chip_dtb_calls):
        """交付的 hart 数决定处理器编号与中断控制器的 hart 列表."""
        emu = _FakeEmu()
        emu.config.num_harts = 3

        cli._load_chip_fdt(emu, _chip(), 0x87FF_0000)

        assert chip_dtb_calls[0].num_harts == 3


class TestSupplementDevices:
    """芯片树没有块设备节点时补充 virtio-mmio 节点."""

    def test_missing_node_is_added(self):
        devices = cli._supplement_devices(_FakeEmu().config, _chip())
        assert len(devices) == 1
        assert devices[0].compatible == "virtio,mmio"
        assert devices[0].region == cli.dev_tree.DtRegion(0x1000_1000, VIRTIO_MMIO_SIZE)
        assert devices[0].irq == 1

    def test_declared_node_is_kept(self):
        chip = _chip(cli.dev_tree.DtRegion(0x1000, VIRTIO_MMIO_SIZE))
        assert cli._supplement_devices(_FakeEmu().config, chip) == ()

    def test_disabled_block_device_adds_nothing(self):
        cfg = _FakeEmu().config
        cfg.periph.virtio_blk_base = 0
        assert cli._supplement_devices(cfg, _chip()) == ()

    def test_absent_disk_image_adds_nothing(self):
        cfg = _FakeEmu().config
        cfg.disk_image = None
        assert cli._supplement_devices(cfg, _chip()) == ()


class TestResolveDiskImage:
    def test_without_chip_tree_only_disk_option_applies(self):
        assert cli._resolve_disk_image(_ns(disk="/tmp/a.img"), None) == "/tmp/a.img"
        assert cli._resolve_disk_image(_ns(disk=None), None) is None

    def test_chip_tree_without_disk_takes_default_image(self, tmp_path, monkeypatch):
        default = tmp_path / "riscv-sd.ext4"
        default.write_bytes(b"\x00")
        monkeypatch.setattr(cli, "DEFAULT_DISK_IMAGE", default)
        assert cli._resolve_disk_image(_ns(disk=None), _chip()) == str(default)

    def test_disk_path_wins_over_default_image(self, tmp_path, monkeypatch):
        default = tmp_path / "riscv-sd.ext4"
        default.write_bytes(b"\x00")
        monkeypatch.setattr(cli, "DEFAULT_DISK_IMAGE", default)
        explicit = tmp_path / "other.img"
        explicit.write_bytes(b"\x00")
        assert cli._resolve_disk_image(_ns(disk=str(explicit)), _chip()) == str(explicit)

    def test_missing_default_image_terminates(self, tmp_path, monkeypatch):
        missing = tmp_path / "absent.ext4"
        monkeypatch.setattr(cli, "DEFAULT_DISK_IMAGE", missing)
        with pytest.raises(SystemExit) as exc_info:
            cli._resolve_disk_image(_ns(disk=None), _chip())
        assert exc_info.value.code == 1


class TestEnableChipBlockDevice:
    """芯片树缺少块设备时按通用规则选定区间与中断源编号."""

    PLATFORM = cli.PlatformParams(
        num_harts=1,
        ram_base=RAM_BASE,
        ram_size=0x2000_0000,
        rom_base=0,
        rom_size=0,
        timebase_freq=1_000_000,
        pmp_entries=16,
        isa=configs_gen.ISA,
    )

    def test_free_window_and_irq_are_assigned(self):
        chip = cli.dev_tree.parse_chip_dts_text(CHIP_DTS)
        periph = cli._periph_from_chip(chip)
        assert periph.virtio_blk_base == 0
        cli._enable_chip_block_device(periph, chip, self.PLATFORM)
        # 树中串口占用中断源 1, 区间占用的最低地址段为 0x1000.
        assert periph.virtio_blk_base == 0x1000
        assert periph.virtio_blk_irq == 2

    def test_declared_node_is_not_overridden(self):
        chip = cli.dev_tree.parse_chip_dts_text(CHIP_DTS_WITH_BLK)
        periph = cli._periph_from_chip(chip)
        cli._enable_chip_block_device(periph, chip, self.PLATFORM)
        assert periph.virtio_blk_base == 0x1000
        assert periph.virtio_blk_irq == 5


class TestPeriphIrqFromChip:
    """外设配置中的中断源编号取芯片设备树声明的取值."""

    def test_declared_sources_are_used(self):
        chip = cli.dev_tree.parse_chip_dts_text(CHIP_DTS_WITH_BLK)

        periph = cli._periph_from_chip(chip)

        assert periph.uart_irq == 1
        assert periph.virtio_blk_irq == 5
        # 树中没有看门狗节点时取平台默认值.
        assert periph.watchdog_irq == WATCHDOG_IRQ

    def test_absent_interrupts_keeps_default(self):
        tree = CHIP_DTS.replace("\t\t\tinterrupts = <1>;\n", "")
        chip = cli.dev_tree.parse_chip_dts_text(tree)

        periph = cli._periph_from_chip(chip)

        assert periph.uart_irq == UART_IRQ


class TestUartIrqWiring:
    """串口与 PLIC 使用同一个中断源编号, 该编号取芯片设备树声明的取值."""

    def test_declared_source_reaches_plic(self):
        chip = cli.dev_tree.parse_chip_dts_text(CHIP_DTS_WITH_CLINT)
        cfg = PlatformConfig(num_harts=1, ram_size=0x40000, ram_base=RAM_BASE)
        cfg.periph = cli._periph_from_chip(chip)
        emu = Emulator(cfg)
        emu._termio = None

        assert emu.uart is not None
        assert emu.uart._irq == 1
        # 打开接收中断并预置一个字节: 只有树中声明的源 1 挂起.
        emu.uart.write(REG_IE, IP_RXWM.to_bytes(4, "little"))
        emu.uart.preload(b"a")
        pending = int.from_bytes(emu.plic.read(PLIC_PENDING_BASE, 4), "little")
        assert pending & (1 << 1)
        assert not pending & (1 << UART_IRQ)


class TestPmpEntryCount:
    """PMP 条目数取芯片设备树声明与 configs_gen 中的较大者.

    模拟器的 PMP 寄存器由 configs_gen 的取值定义, 设备树声明更多条目时无法装配.
    """

    def test_tree_value_below_config_yields_config(self):
        chip = cli.dev_tree.parse_chip_dts_text(_chip_dts_cpus(1, 16))
        platform = cli._resolve_platform(_ns(), chip)
        assert chip.pmp_entries == 16
        assert platform.pmp_entries == max(16, configs_gen.PMP_ENTRIES)

    def test_tree_value_above_config_terminates(self):
        """设备树声明的条目数超过模拟器实现的数目时终止模拟."""
        declared = configs_gen.PMP_ENTRIES + 8
        chip = cli.dev_tree.parse_chip_dts_text(_chip_dts_cpus(1, declared))
        with pytest.raises(SystemExit):
            cli._resolve_platform(_ns(), chip)

    def test_absent_tree_value_yields_config(self):
        chip = cli.dev_tree.parse_chip_dts_text(CHIP_DTS)
        platform = cli._resolve_platform(_ns(), chip)
        assert chip.pmp_entries is None
        assert platform.pmp_entries == configs_gen.PMP_ENTRIES


class TestPerHartDifference:
    """设备树为各 hart 声明不同取值时终止模拟.

    模拟器对全部 hart 使用同一份配置, 无法按 hart 分别实现.
    """

    def test_differing_pmp_entries_terminate(self):
        low = max(1, configs_gen.PMP_ENTRIES // 2)
        chip = cli.dev_tree.parse_chip_dts_text(
            _chip_dts_cpus(2, [low, configs_gen.PMP_ENTRIES])
        )
        assert set(chip.differing_attrs()) == {"riscv,pmpregions"}
        with pytest.raises(SystemExit):
            cli._resolve_platform(_ns(), chip)

    def test_identical_pmp_entries_are_accepted(self):
        value = configs_gen.PMP_ENTRIES
        chip = cli.dev_tree.parse_chip_dts_text(_chip_dts_cpus(2, [value, value]))
        assert chip.differing_attrs() == {}
        platform = cli._resolve_platform(_ns(), chip)
        assert platform.pmp_entries == configs_gen.PMP_ENTRIES


class TestHartCount:
    """hart 数取 min(max(1, 请求值), max(1, 设备树 CPU 节点数)).

    客机看到的 CPU 数由交给它的设备树决定, 装配多于该数的 hart 只会停在
    OpenSBI 的 _start_hang.
    """

    def test_tree_caps_requested_harts(self):
        chip = cli.dev_tree.parse_chip_dts_text(_chip_dts_cpus(1))
        assert cli._resolve_platform(_ns(harts=3), chip).num_harts == 1

    def test_requested_below_tree_is_kept(self):
        chip = cli.dev_tree.parse_chip_dts_text(_chip_dts_cpus(4))
        assert cli._resolve_platform(_ns(harts=3), chip).num_harts == 3

    def test_tree_value_used_when_cli_absent(self):
        chip = cli.dev_tree.parse_chip_dts_text(_chip_dts_cpus(4))
        assert cli._resolve_platform(_ns(), chip).num_harts == 4

    def test_tree_without_cpu_nodes_caps_at_one(self):
        chip = cli.dev_tree.parse_chip_dts_text(CHIP_DTS)
        assert cli._resolve_platform(_ns(harts=3), chip).num_harts == 1

    def test_absent_chip_tree_uses_requested(self):
        assert cli._resolve_platform(_ns(harts=3), None).num_harts == 3

    def test_zero_requested_clamped_to_one(self):
        assert cli._resolve_platform(_ns(harts=0), None).num_harts == 1


class TestPlatformIsa:
    """平台 ISA 取芯片设备树的声明, 树中未声明时取 configs_gen.ISA.

    平台 ISA 决定 hart 声明的扩展集合, 进而决定 stimecmp 与 stimecmph 是否存在.
    """

    def test_legacy_isa_string_used(self):
        chip = cli.dev_tree.parse_chip_dts_text(
            _chip_dts_isa('riscv,isa = "rv64imac_zicsr_zifencei";')
        )
        platform = cli._resolve_platform(_ns(), chip)
        assert platform.isa == "rv64imac_zicsr_zifencei"
        assert "sstc" not in isa_ext_list(platform.isa)

    def test_extension_list_used(self):
        chip = cli.dev_tree.parse_chip_dts_text(
            _chip_dts_isa('riscv,isa-extensions = "i", "m", "a", "c", "zicsr";')
        )
        platform = cli._resolve_platform(_ns(), chip)
        assert isa_ext_list(platform.isa) == ["i", "m", "a", "c", "zicsr"]

    def test_both_declarations_merged(self):
        chip = cli.dev_tree.parse_chip_dts_text(
            _chip_dts_isa(
                'riscv,isa = "rv64imac";\nriscv,isa-extensions = "zicsr", "zifencei", "sstc";'
            )
        )
        platform = cli._resolve_platform(_ns(), chip)
        assert isa_ext_list(platform.isa) == [
            "i",
            "m",
            "a",
            "c",
            "zicsr",
            "zifencei",
            "sstc",
        ]

    def test_absent_isa_falls_back_to_config(self):
        chip = cli.dev_tree.parse_chip_dts_text(CHIP_DTS)
        assert cli._resolve_platform(_ns(), chip).isa == configs_gen.ISA

    def test_differing_isa_terminates(self):
        chip = cli.dev_tree.parse_chip_dts_text(
            _chip_dts_isa(
                'riscv,isa = "rv64imac";',
                'riscv,isa = "rv64imafdc";',
            )
        )
        assert set(chip.differing_attrs()) == {"riscv,isa"}
        with pytest.raises(SystemExit):
            cli._resolve_platform(_ns(), chip)


# ============================================================
#  预加载、入口符号、initramfs 与内核
# ============================================================


class TestSetupPreload:
    def test_absent_preload_returns_none(self):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        assert cli._setup_preload(emu, _ns(preload=None)) is None

    def test_payload_is_injected_and_misa_set(self, tmp_path):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        code = b"\x13\x00\x00\x00" * 4
        src = tmp_path / "crt0.bin"
        src.write_bytes(code)
        entry, size = cli._setup_preload(emu, _ns(preload=str(src)))
        default = RAM_BASE + emu.bus.ram_size - configs_gen.RAM_PRELOAD_OFFSET
        assert entry == default & ~0xF
        assert size == len(code)
        assert emu.bus.try_read(entry, len(code)) == code
        assert emu.harts[0].csrs["misa"].val == (2 << 62) | (1 << 18) | (1 << 20)

    def test_explicit_address_is_used(self, tmp_path):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        src = tmp_path / "crt0.bin"
        src.write_bytes(b"\x13\x00\x00\x00")
        addr = RAM_BASE + 0x1000
        entry, _ = cli._setup_preload(emu, _ns(preload=str(src), preload_addr=addr))
        assert entry == addr
        assert emu.bus.try_read(addr, 4) == b"\x13\x00\x00\x00"

    def test_missing_payload_propagates(self, tmp_path):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        with pytest.raises(FileNotFoundError):
            cli._setup_preload(emu, _ns(preload=str(tmp_path / "none.bin")))

    def test_preload_leaves_dtb_and_a1_unchanged(self, tmp_path, monkeypatch):
        """预加载不写设备树副本, 也不改写 a1; 固件按 a1 自行搬迁设备树."""
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        src = tmp_path / "crt0.bin"
        src.write_bytes(b"\x13\x00\x00\x00")
        blobs: list[tuple[int, bytes]] = []
        monkeypatch.setattr(emu, "build_default_dtb", lambda: b"DTB")
        monkeypatch.setattr(
            emu, "load_dtb_blob", lambda addr, blob: blobs.append((addr, blob))
        )
        emu.harts[0].write_gpr(11, 0x87FF0000)
        cli._setup_preload(emu, _ns(preload=str(src)))
        assert blobs == []
        assert emu.harts[0].gprs[11] == 0x87FF0000


class TestSetupEntrySymbol:
    def _image(self) -> FirmwareImage:
        return FirmwareImage(
            entry_point=0x1000,
            segments=[FirmwareSegment(vaddr=0x1000, data=b"\x13", memsz=4)],
            format="elf",
            symbols={"main": 0x2000},
        )

    def test_symbol_address_is_written_to_a0(self):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        target = cli._setup_entry_symbol(emu, self._image(), "main")
        assert target == 0x2000
        assert emu.harts[0].gprs[10] == 0x2000

    def test_missing_symbol_exits(self):
        emu = make_test_emu(ram_size=RAM_SIZE, uart_base=0)
        with pytest.raises(SystemExit) as exc_info:
            cli._setup_entry_symbol(emu, self._image(), "no_such_symbol")
        assert exc_info.value.code == 1


class TestInitrdDefaultAddr:
    TOP = RAM_BASE + RAM_SIZE - configs_gen.RAM_PRELOAD_OFFSET

    def _write(self, tmp_path: Path, size: int) -> str:
        src = tmp_path / "initrd.cpio"
        src.write_bytes(b"\x00" * size)
        return str(src)

    def test_default_top_sits_below_preload_default(self, tmp_path):
        size = 0x300000
        path = self._write(tmp_path, size)
        addr = cli._initrd_default_addr(path, _platform(), None, None)
        assert addr == (self.TOP - size) & ~0x1FFFFF
        assert addr % 0x200000 == 0

    def test_lower_dtb_address_lowers_top(self, tmp_path):
        """设备树落在 RAM 内且低于默认上界时, initramfs 的上界随之下移."""
        size = 0x1000
        path = self._write(tmp_path, size)
        fdt_addr = RAM_BASE + 0x300000
        addr = cli._initrd_default_addr(path, _platform(), fdt_addr, None)
        assert addr == (fdt_addr - size) & ~0x1FFFFF

    @pytest.mark.parametrize(
        "fdt_addr",
        [
            RAM_BASE + RAM_SIZE - 0x1000,
            0x4000_5000,
        ],
        ids=["dtb_above_top", "dtb_in_rom"],
    )
    def test_higher_or_non_ram_dtb_keeps_default_top(self, tmp_path, fdt_addr):
        """设备树的装载地址高于默认上界或不在 RAM 内时, 上界不变."""
        size = 0x1000
        path = self._write(tmp_path, size)
        addr = cli._initrd_default_addr(path, _platform(), fdt_addr, None)
        assert addr == (self.TOP - size) & ~0x1FFFFF

    def test_lower_preload_address_lowers_top(self, tmp_path):
        size = 0x1000
        path = self._write(tmp_path, size)
        preload_addr = RAM_BASE + 0x400000
        addr = cli._initrd_default_addr(path, _platform(), None, preload_addr)
        assert addr == (preload_addr - size) & ~0x1FFFFF


class TestLoadKernelImage:
    def test_absent_kernel_returns_none(self):
        emu = _FakeEmu()
        assert cli._load_kernel_image(emu, None, None, 0x8100_0000) is None
        assert emu.bus.direct_writes == []

    def test_default_address_is_used(self, tmp_path):
        emu = _FakeEmu()
        src = tmp_path / "Image"
        src.write_bytes(b"KERNEL")
        result = cli._load_kernel_image(emu, str(src), None, 0x8100_0000)
        assert result == (str(src), 0x8100_0000, len(b"KERNEL"))
        assert emu.bus.direct_writes == [(0x8100_0000, b"KERNEL")]

    def test_explicit_address_overrides_default(self, tmp_path):
        emu = _FakeEmu()
        src = tmp_path / "Image"
        src.write_bytes(b"KERNEL")
        result = cli._load_kernel_image(emu, str(src), 0x8200_0000, 0x8100_0000)
        assert result == (str(src), 0x8200_0000, len(b"KERNEL"))


# ============================================================
#  入口
# ============================================================


@pytest.fixture
def repl_capture(monkeypatch):
    """把 Debugger.repl 换成记录实例的替身, 使入口用例不进入交互循环."""
    captured: dict = {}

    def fake_repl(self) -> None:
        captured["dbg"] = self

    monkeypatch.setattr(Debugger, "repl", fake_repl)
    return captured


class TestDebuggerEntry:
    def test_raw_firmware_starts_at_entry(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        cli.debugger([fw, "--ram", "4M", "--no-fdt", "--base-addr", hex(RAM_BASE)])
        dbg = repl_capture["dbg"]
        assert dbg._emu.num_harts == 1
        assert dbg.hart.pc == RAM_BASE
        assert dbg._fdt_addr is None
        assert dbg._load_offset == 0
        assert ImageKind.PRELOAD not in dbg._bins_images

    def test_prog_cnt_overrides_entry(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--prog-cnt",
                hex(RAM_BASE + 0x400),
            ]
        )
        assert repl_capture["dbg"].hart.pc == RAM_BASE + 0x400

    def test_multiple_harts_share_prog_cnt(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--harts",
                "3",
            ]
        )
        emu = repl_capture["dbg"]._emu
        assert emu.num_harts == 3
        assert [h.pc for h in emu.harts] == [RAM_BASE] * 3

    def test_default_fdt_address_is_recorded(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        cli.debugger([fw, "--ram", "4M", "--base-addr", hex(RAM_BASE), "--fdt"])
        dbg = repl_capture["dbg"]
        assert dbg._fdt_addr == RAM_BASE + RAM_SIZE - 0x10000
        assert dbg._emu.harts[0].gprs[11] == dbg._fdt_addr

    def test_preload_takes_precedence_over_entry_symbol(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        src = tmp_path / "crt0.bin"
        src.write_bytes(b"\x13\x00\x00\x00")
        addr = RAM_BASE + 0x1000
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--preload",
                str(src),
                "--preload-addr",
                hex(addr),
            ]
        )
        dbg = repl_capture["dbg"]
        assert dbg.hart.pc == addr
        assert dbg._bins_images[ImageKind.PRELOAD].path == str(src)

    def test_virtio_net_instances_off_by_default(self, tmp_path, repl_capture):
        """网卡基址取自 PeripheralConfig 的默认值 0, 未给 --chip-dts 时不注册."""
        fw = _raw_firmware(tmp_path)
        cli.debugger([fw, "--ram", "4M", "--no-fdt", "--base-addr", hex(RAM_BASE)])
        emu = repl_capture["dbg"]._emu
        assert emu.virtio_net_s is None
        assert emu.virtio_net_m is None
        assert emu.virtio_blk is None

    def test_disk_enables_block_device_and_default_bootargs(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        disk = tmp_path / "root.img"
        disk.write_bytes(b"\x00" * 512)
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--disk",
                str(disk),
            ]
        )
        emu = repl_capture["dbg"]._emu
        assert emu.virtio_blk is not None
        assert "root=/dev/vda ro" in emu._bootargs
        assert "init=/usr/lib/systemd/systemd" in emu._bootargs

    def test_explicit_bootargs_win_over_default(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        disk = tmp_path / "root.img"
        disk.write_bytes(b"\x00" * 512)
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--disk",
                str(disk),
                "--bootargs",
                "console=ttySIF0",
            ]
        )
        assert repl_capture["dbg"]._emu._bootargs == "console=ttySIF0"

    def test_hart_logs_directory_is_installed(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        log_dir = tmp_path / "logs"
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--hart-logs",
                str(log_dir),
            ]
        )
        uart = repl_capture["dbg"]._emu.uart
        assert uart._hart_log_dir == str(log_dir)
        assert log_dir.is_dir()

    def test_kernel_default_address_uses_reserved_size(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        kernel = tmp_path / "Image"
        kernel.write_bytes(b"KERNEL")
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--kernel",
                str(kernel),
            ]
        )
        dbg = repl_capture["dbg"]
        kernel_image = dbg._bins_images[ImageKind.KERNEL]
        assert kernel_image.path == str(kernel)
        assert kernel_image.start == RAM_BASE + cli.configs_gen.FW_RESERVED_MEM_SIZE

    def test_kernel_explicit_address(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        kernel = tmp_path / "Image"
        kernel.write_bytes(b"KERNEL")
        addr = RAM_BASE + 0x200000
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--kernel",
                str(kernel),
                "--kernel-addr",
                hex(addr),
            ]
        )
        dbg = repl_capture["dbg"]
        assert dbg._bins_images[ImageKind.KERNEL].start == addr

    def test_missing_entry_symbol_exits(self, tmp_path, repl_capture):
        fw = _raw_firmware(tmp_path)
        with pytest.raises(SystemExit) as exc_info:
            cli.debugger(
                [
                    fw,
                    "--ram",
                    "4M",
                    "--no-fdt",
                    "--base-addr",
                    hex(RAM_BASE),
                    "--entry-symbol",
                    "main",
                ]
            )
        assert exc_info.value.code == 1

    def test_entry_symbol_sets_pc_and_a0(self, tmp_path, monkeypatch, repl_capture):
        """给出入口符号时 hart 从该符号起跑, 并告警未设置 sp/gp."""
        fw = _raw_firmware(tmp_path)
        target = RAM_BASE + 0x40
        image = FirmwareImage(
            entry_point=RAM_BASE,
            segments=[FirmwareSegment(vaddr=RAM_BASE, data=b"\x13\x00\x00\x00", memsz=4)],
            format="raw",
            symbols={"main": target},
        )
        monkeypatch.setattr(cli, "parse_firmware", lambda *a, **k: image)
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--entry-symbol",
                "main",
            ]
        )
        dbg = repl_capture["dbg"]
        assert dbg.hart.pc == target
        assert dbg.hart.gprs[10] == target

    def test_missing_firmware_exits(self, tmp_path, repl_capture):
        with pytest.raises(SystemExit) as exc_info:
            cli.debugger([str(tmp_path / "none.bin"), "--ram", "4M", "--no-fdt"])
        assert exc_info.value.code == 1

    def test_sym_dir_sets_candidate_directory(self, tmp_path, repl_capture):
        """--sym-dir 只记录候选目录, 不访问文件系统, 也不加载符号."""
        fw = _raw_firmware(tmp_path)
        symbols = tmp_path / "not-created"
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--sym-dir",
                str(symbols),
            ]
        )
        dbg = repl_capture["dbg"]
        assert dbg._sym_mod_dir == str(symbols)
        assert dbg._sym_symbols == {}

    def test_sym_dir_relative_path_is_resolved(self, tmp_path, monkeypatch, repl_capture):
        """启动时给的相对路径按当时的工作目录换算为绝对路径."""
        fw = _raw_firmware(tmp_path)
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--no-fdt",
                "--base-addr",
                hex(RAM_BASE),
                "--sym-dir",
                "symbols",
            ]
        )
        assert repl_capture["dbg"]._sym_mod_dir == str((work / "symbols").resolve())

    def test_initrd_is_loaded_before_device_tree(self, tmp_path, repl_capture):
        """initramfs 的范围要写入设备树, 故必须先生成 DTB 之前加载."""
        fw = _raw_firmware(tmp_path)
        initrd = tmp_path / "initrd.cpio"
        initrd.write_bytes(b"\x00" * 0x1000)
        cli.debugger(
            [
                fw,
                "--ram",
                "4M",
                "--base-addr",
                hex(RAM_BASE),
                "--fdt",
                "--initrd",
                str(initrd),
            ]
        )
        emu = repl_capture["dbg"]._emu
        top = RAM_BASE + RAM_SIZE - configs_gen.RAM_PRELOAD_OFFSET
        expected = (top - 0x1000) & ~0x1FFFFF
        assert emu._initrd.start == expected
        assert emu._initrd.end == emu._initrd.start + 0x1000


# ============================================================
#  CLI 输出
# ============================================================


class TestCliConsoleOutput:
    def test_help_lists_examples(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli._build_arg_parser().parse_args(["--help"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "--entry-symbol" in out
        assert "firmware.bin --harts 4 --ram 256M" in out
