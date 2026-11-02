#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""芯片设备树回写为 DTB, 以及节点读写的公共函数.

锁定三类行为:

- 模拟器自己决定的内容写进交给受调试程序的设备树: /memory 取实际装配的 RAM
  窗口, /reserved-memory 取平台的保留区间, /chosen 取命令行与 initramfs 范围.
  芯片设备树没有这些内容时, 内核把飞地内存池当作可用内存分配, 首次陷态存档即被
  PMP 拒绝并触发 Store/AMO access fault.
- 根节点声明的单元格数不足以描述上述区间时改为 2 与 2, 直接子节点的 reg 与
  ranges 同步改写, 使各属性的含义不变.
- fdt_node 的节点读写与单元格编解码按名称与高位在前的顺序进行.
- 芯片 DTS 的读取入口接受 dtc 拒绝的两种写法: 缺少 /dts-v1/; 的源文本与不带名称的
  根节点. 由 DTB 导出的文本两者都是, 读取入口在解析前补齐.
"""

import libfdt

from pyremu.utils import dev_tree
from pyremu.utils.dev_tree import fdt_node

TREE_1_1 = """
{
	#address-cells = <1>;
	#size-cells = <1>;
	compatible = "acme,soc";
	memory@80000000 {
		device_type = "memory";
		reg = <0x80000000 0x20000000>;
	};
	rom@10000 {
		compatible = "sifive,rom0";
		reg = <0x10000 0x10000>;
	};
};
"""

TREE_PLIC = """
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
		debug-controller@0 {
			reg = <0x0 0x1000>;
		};
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

# 各设备节点各自声明中断源编号, virtio 节点按树中顺序对应块设备与两张网卡.
TREE_IRQS = """
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
		watchdog@10004000 {
			compatible = "pyremu,hart-watchdog-1.0";
			interrupts = <7>;
			reg = <0x10004000 0x10>;
		};
		virtio@1000 {
			compatible = "virtio,mmio";
			interrupts = <2 4>;
			reg = <0x1000 0x200>;
		};
		virtio@2000 {
			compatible = "virtio,mmio";
			interrupts = <3 4>;
			reg = <0x2000 0x200>;
		};
		virtio@3000 {
			compatible = "virtio,mmio";
			interrupts = <5 4>;
			reg = <0x3000 0x200>;
		};
		interrupt-controller@c000000 {
			#interrupt-cells = <1>;
			compatible = "riscv,plic0";
			interrupt-controller;
			reg = <0xc000000 0x4000000>;
			riscv,ndev = <7>;
			phandle = <6>;
		};
	};
};
"""

RAM_BASE = 0x8000_0000
RAM_6GIB = 6 * 1024 * 1024 * 1024

# 三个处理器节点, 中断控制器 phandle 依次为 1、2、3; CLINT 与 PLIC 只列出第一个 hart.
# 设备节点的 interrupts-extended 指向 PLIC, 不在补全范围.
TREE_SMP = """
{
	#address-cells = <1>;
	#size-cells = <1>;
	cpus {
		#address-cells = <1>;
		#size-cells = <0>;
		timebase-frequency = <100000>;
		cpu@0 {
			device_type = "cpu";
			reg = <0>;
			interrupt-controller {
				#interrupt-cells = <1>;
				compatible = "riscv,cpu-intc";
				interrupt-controller;
				phandle = <1>;
			};
		};
		cpu@1 {
			device_type = "cpu";
			reg = <1>;
			interrupt-controller {
				#interrupt-cells = <1>;
				compatible = "riscv,cpu-intc";
				interrupt-controller;
				phandle = <2>;
			};
		};
		cpu@2 {
			device_type = "cpu";
			reg = <2>;
			interrupt-controller {
				#interrupt-cells = <1>;
				compatible = "riscv,cpu-intc";
				interrupt-controller;
				phandle = <3>;
			};
		};
	};
	soc {
		#address-cells = <1>;
		#size-cells = <1>;
		ranges;
		clint@2000000 {
			compatible = "riscv,clint0";
			interrupts-extended = <1 3 1 7>;
			reg = <0x2000000 0x10000>;
		};
		interrupt-controller@c000000 {
			#interrupt-cells = <1>;
			compatible = "riscv,plic0";
			interrupt-controller;
			interrupts-extended = <1 11 1 9>;
			reg = <0xc000000 0x4000000>;
			riscv,ndev = <1>;
			phandle = <6>;
		};
		virtio@1000 {
			compatible = "virtio,mmio";
			interrupt-parent = <6>;
			interrupts-extended = <6 2>;
			reg = <0x1000 0x200>;
		};
	};
};
"""


def _blob(text: str = TREE_1_1, **kwargs) -> bytes:
    """按关键字给出的内容回写; 没有给出内容时原样回写."""
    delivered = dev_tree.DeliveredTree(**kwargs) if kwargs else None
    return dev_tree.chip_dt_to_dtb(dev_tree.parse_chip_dts_text(text), delivered)


def _blob_with_report(text: str = TREE_1_1, **kwargs) -> tuple[bytes, list[str]]:
    """按关键字给出的内容回写, 并收集修正项的报告文本."""
    messages: list[str] = []
    delivered = dev_tree.DeliveredTree(**kwargs) if kwargs else None
    blob = dev_tree.chip_dt_to_dtb(
        dev_tree.parse_chip_dts_text(text), delivered, messages.append
    )
    return blob, messages


def _virtio() -> dev_tree.DtDeviceRequest:
    """补充设备节点的通用参数: 节点名前缀, compatible 与 reg 的大小."""
    return dev_tree.DtDeviceRequest("virtio", "virtio,mmio", 0x200)


def _prop(blob: bytes, path: str, name: str):
    fdt = libfdt.Fdt(blob)
    return fdt.getprop(fdt.path_offset(path), name)


def _cells(blob: bytes, path: str, name: str) -> list[int]:
    return _prop(blob, path, name).as_uint32_list()


def _children(blob: bytes, path: str) -> list[str]:
    fdt = libfdt.Fdt(blob)
    node = fdt.first_subnode(fdt.path_offset(path))
    names: list[str] = []
    while node >= 0:
        names.append(fdt.get_name(node))
        try:
            node = fdt.next_subnode(node)
        except libfdt.FdtException:
            break
    return names


def _reg_of(blob: bytes, path: str, addr_cells: int, size_cells: int) -> tuple[int, int]:
    words = _cells(blob, path, "reg")
    assert len(words) == addr_cells + size_cells
    return fdt_node.decode_cells(words[:addr_cells]), fdt_node.decode_cells(words[addr_cells:])


def _has_node(blob: bytes, path: str) -> bool:
    try:
        libfdt.Fdt(blob).path_offset(path)
    except libfdt.FdtException:
        return False
    return True


# ============================================================
#  fdt_node 的节点读写与单元格编解码
# ============================================================


class TestFdtNode:
    def test_encode_decode_cells_roundtrip(self):
        assert fdt_node.encode_cells(0x1_2345_6789, 2) == [0x1, 0x2345_6789]
        assert fdt_node.encode_cells(0x7F, 1) == [0x7F]
        assert fdt_node.decode_cells([0x1, 0x2345_6789]) == 0x1_2345_6789

    def test_encode_cells_rejects_value_beyond_width(self):
        try:
            fdt_node.encode_cells(0x1_0000_0000, 1)
        except ValueError:
            return
        raise AssertionError("1 个单元格不得容纳超出 32 位的取值")

    def test_cells_for_counts_leading_cells(self):
        assert fdt_node.cells_for(0) == 1
        assert fdt_node.cells_for(0xFFFF_FFFF) == 1
        assert fdt_node.cells_for(0x1_0000_0000) == 2

    def test_set_property_replaces_and_appends(self):
        root = fdt_node.FdtNode("/")
        root.append(fdt_node.FdtPropertyWords("reg", [1, 2]))
        fdt_node.set_property(root, fdt_node.FdtPropertyWords("reg", [3]))
        fdt_node.set_property(root, fdt_node.FdtPropertyWords("other", [4]))
        assert fdt_node.node_property(root, "reg").words == [3]
        assert fdt_node.node_property(root, "other").words == [4]
        assert len(root.subdata) == 2

    def test_set_property_inserts_before_subnodes(self):
        """属性必须排在子节点之前, 否则按结构块顺序扫描的读取方看不到它."""
        root = fdt_node.FdtNode("/")
        root.append(fdt_node.FdtNode("child"))

        fdt_node.set_property(root, fdt_node.FdtPropertyWords("reg", [1]))

        assert root[0].get_name() == "reg"
        assert root[1].get_name() == "child"

    def test_cells_of_node_takes_default_without_property(self):
        root = fdt_node.FdtNode("/")
        assert fdt_node.cells_of_node(root, "#address-cells", 2) == 2
        root.append(fdt_node.FdtPropertyWords("#address-cells", [1]))
        assert fdt_node.cells_of_node(root, "#address-cells", 2) == 1

    def test_is_enabled_node_reads_status(self):
        root = fdt_node.FdtNode("/")
        assert fdt_node.is_enabled_node(root)
        root.append(fdt_node.FdtPropertyStrings("status", ["disabled"]))
        assert not fdt_node.is_enabled_node(root)
        fdt_node.set_property(root, fdt_node.FdtPropertyStrings("status", ["okay"]))
        assert fdt_node.is_enabled_node(root)


# ============================================================
#  芯片 DTS 的读取入口
# ============================================================


class TestChipDtsRead:
    def test_file_without_header_parses(self, tmp_path):
        path = tmp_path / "chip.dts"
        path.write_text(TREE_1_1, encoding="utf-8")

        chip = dev_tree.parse_chip_dts(path)

        assert chip.ram == dev_tree.DtRegion(RAM_BASE, 0x2000_0000)
        assert chip.rom == dev_tree.DtRegion(0x10000, 0x10000)

    def test_file_with_header_parses(self, tmp_path):
        path = tmp_path / "chip.dts"
        path.write_text("/dts-v1/;\n/ " + TREE_1_1.lstrip(), encoding="utf-8")

        chip = dev_tree.parse_chip_dts(path)

        assert chip.ram == dev_tree.DtRegion(RAM_BASE, 0x2000_0000)

    def test_bare_root_after_comment_parses(self):
        text = "/dts-v1/;\n/* 芯片设备树 */\n" + TREE_1_1.lstrip()

        chip = dev_tree.parse_chip_dts_text(text)

        assert chip.ram == dev_tree.DtRegion(RAM_BASE, 0x2000_0000)


class TestChipIrqSources:
    """各设备节点的中断源编号取 interrupts 属性的第一格."""

    def test_each_device_source_is_read(self):
        chip = dev_tree.parse_chip_dts_text(TREE_IRQS)

        assert chip.irq_vec.uart == 1
        assert chip.irq_vec.watchdog == 7
        # 第二格是触发类型, 不计入中断源编号.
        assert chip.irq_vec.virtio_blk == 2
        assert chip.irq_vec.virtio_net_s == 3
        assert chip.irq_vec.virtio_net_m == 5

    def test_absent_nodes_yield_none(self):
        chip = dev_tree.parse_chip_dts_text(TREE_1_1)

        assert chip.irq_vec.uart is None
        assert chip.irq_vec.watchdog is None
        assert chip.irq_vec.virtio_blk is None
        assert chip.irq_vec.virtio_net_s is None
        assert chip.irq_vec.virtio_net_m is None


def _cpus_dts(*pmp_entries: int) -> str:
    """建立每个 CPU 节点各声明一个 PMP 条目数的芯片树."""
    nodes = "".join(
        f'\tcpu@{i} {{\n\t\tdevice_type = "cpu";\n\t\treg = <{i}>;\n'
        f"\t\triscv,pmpregions = <{count}>;\n\t}};\n"
        for i, count in enumerate(pmp_entries)
    )
    header = "{\n\t#address-cells = <1>;\n\t#size-cells = <1>;\n\tcpus {\n"
    return header + nodes + "\t};\n};\n"


class TestPerHartAttrs:
    """CPU 节点逐属性声明的取值, 以及 hart 之间是否一致."""

    def test_pmp_entries_take_max(self):
        """多个 CPU 节点声明不同条目数时, 条目数取最大值."""
        chip = dev_tree.parse_chip_dts_text(_cpus_dts(16, 32))

        assert chip.pmp_entries == 32
        assert chip.per_hart["riscv,pmpregions"] == {0: 16, 1: 32}

    def test_differing_attrs_report_each_hart(self):
        chip = dev_tree.parse_chip_dts_text(_cpus_dts(16, 32))

        assert chip.differing_attrs() == {"riscv,pmpregions": {0: 16, 1: 32}}

    def test_uniform_attrs_report_empty(self):
        chip = dev_tree.parse_chip_dts_text(_cpus_dts(32, 32))

        assert chip.differing_attrs() == {}


# ============================================================
#  处理器编号与中断控制器的 hart 列表
# ============================================================


class TestCpus:
    """delivered.num_harts 给出的处理器编号与中断控制器的 hart 列表.

    OpenSBI 依 interrupts-extended 为各 hart 配置 MSIP、定时器与 PLIC 上下文. 只列出
    部分 hart 时, 其余 hart 收不到 IPI, 多 hart 启动停在等待 ALIVE 状态.
    """

    def test_matching_hart_ids_are_not_reported(self):
        _, messages = _blob_with_report(TREE_SMP, num_harts=3)

        assert not [item for item in messages if "CPU 节点" in item]

    def test_mismatched_hart_id_is_reported_and_rewritten(self):
        text = TREE_SMP.replace("reg = <1>;", "reg = <7>;")

        blob, messages = _blob_with_report(text, num_harts=3)

        assert _cells(blob, "/cpus/cpu@1", "reg") == [1]
        assert [item for item in messages if "CPU 节点 cpu@1" in item]

    def test_extra_cpu_node_is_disabled(self):
        blob, messages = _blob_with_report(TREE_SMP, num_harts=2)

        assert _prop(blob, "/cpus/cpu@2", "status").as_str() == "disabled"
        assert [item for item in messages if "超出装配的 hart 数 2" in item]

    def test_clint_lists_every_assembled_hart(self):
        """只列出 hart 0 的 CLINT 补全为全部 hart, 各 hart 的中断号序列不变."""
        blob, messages = _blob_with_report(TREE_SMP, num_harts=3)

        assert _cells(blob, "/soc/clint@2000000", "interrupts-extended") == [
            1,
            3,
            1,
            7,
            2,
            3,
            2,
            7,
            3,
            3,
            3,
            7,
        ]
        assert [item for item in messages if "clint@2000000" in item]

    def test_plic_lists_every_assembled_hart(self):
        blob, messages = _blob_with_report(TREE_SMP, num_harts=3)

        assert _cells(blob, "/soc/interrupt-controller@c000000", "interrupts-extended") == [
            1,
            11,
            1,
            9,
            2,
            11,
            2,
            9,
            3,
            11,
            3,
            9,
        ]
        assert [item for item in messages if "interrupt-controller@c000000" in item]

    def test_hart_list_follows_assembled_count(self):
        blob, _ = _blob_with_report(TREE_SMP, num_harts=2)

        assert _cells(blob, "/soc/clint@2000000", "interrupts-extended") == [
            1,
            3,
            1,
            7,
            2,
            3,
            2,
            7,
        ]

    def test_device_interrupts_extended_is_kept(self):
        """设备节点指向 PLIC 的 interrupts-extended 不属于 hart 列表."""
        blob, messages = _blob_with_report(TREE_SMP, num_harts=3)

        assert _cells(blob, "/soc/virtio@1000", "interrupts-extended") == [6, 2]
        assert not [item for item in messages if "virtio@1000" in item]

    def test_complete_hart_list_is_not_reported(self):
        clint = "interrupts-extended = <1 3 1 7 2 3 2 7 3 3 3 7>;"
        text = TREE_SMP.replace("interrupts-extended = <1 3 1 7>;", clint)

        blob, messages = _blob_with_report(text, num_harts=3)

        assert _cells(blob, "/soc/clint@2000000", "interrupts-extended") == [
            1,
            3,
            1,
            7,
            2,
            3,
            2,
            7,
            3,
            3,
            3,
            7,
        ]
        assert not [item for item in messages if "clint@2000000" in item]

    def test_cpu_node_without_interrupt_controller_raises(self):
        text = TREE_SMP.replace(
            "\t\t\tinterrupt-controller {\n"
            "\t\t\t\t#interrupt-cells = <1>;\n"
            '\t\t\t\tcompatible = "riscv,cpu-intc";\n'
            "\t\t\t\tinterrupt-controller;\n"
            "\t\t\t\tphandle = <3>;\n"
            "\t\t\t};\n",
            "",
        )

        try:
            _blob_with_report(text, num_harts=3)
        except ValueError:
            return
        raise AssertionError("处理器节点没有中断控制器时必须报告原因")

    def test_disabled_cpu_node_raises(self):
        text = TREE_SMP.replace(
            'device_type = "cpu";\n\t\t\treg = <1>;',
            'device_type = "cpu";\n\t\t\treg = <1>;\n\t\t\tstatus = "disabled";',
        )

        try:
            _blob_with_report(text, num_harts=3)
        except ValueError:
            return
        raise AssertionError("装配范围内的处理器节点未启用时必须报告原因")

    def test_fewer_cpu_nodes_than_harts_raises(self):
        try:
            _blob_with_report(TREE_SMP, num_harts=4)
        except ValueError:
            return
        raise AssertionError("处理器节点少于装配的 hart 数时必须报告原因")


# ============================================================
#  /memory 与根节点的单元格数
# ============================================================


class TestMemory:
    def test_memory_window_replaces_tree_reg(self):
        blob = _blob(ram=dev_tree.DtRegion(RAM_BASE, RAM_6GIB))

        assert _reg_of(blob, "/memory@80000000", 1, 2) == (RAM_BASE, RAM_6GIB)
        assert _cells(blob, "/", "#size-cells") == [2]

    def test_root_cells_stay_when_window_fits(self):
        blob = _blob(ram=dev_tree.DtRegion(RAM_BASE, 0x2000_0000))

        assert _cells(blob, "/", "#address-cells") == [1]
        assert _cells(blob, "/", "#size-cells") == [1]
        assert _cells(blob, "/rom@10000", "reg") == [0x10000, 0x10000]

    def test_child_reg_rewritten_when_cells_grow(self):
        blob = _blob(ram=dev_tree.DtRegion(0x1_0000_0000, 0x1_0000_0000))

        assert _cells(blob, "/", "#address-cells") == [2]
        assert _cells(blob, "/", "#size-cells") == [2]
        assert _cells(blob, "/rom@10000", "reg") == [0, 0x10000, 0, 0x10000]

    def test_child_ranges_rewritten_when_cells_grow(self):
        text = """
        {
            #address-cells = <1>;
            #size-cells = <1>;
            soc {
                #address-cells = <1>;
                #size-cells = <1>;
                ranges = <0x0 0x0 0x1000>;
            };
        };
        """
        blob = _blob(text, ram=dev_tree.DtRegion(0x1_0000_0000, 0x1_0000_0000))

        assert _cells(blob, "/soc", "ranges") == [0, 0, 0, 0x1000]

    def test_memory_node_created_when_absent(self):
        text = """
        {
            #address-cells = <1>;
            #size-cells = <1>;
            rom@10000 {
                reg = <0x10000 0x10000>;
            };
        };
        """
        blob = _blob(text, ram=dev_tree.DtRegion(RAM_BASE, RAM_6GIB))

        assert _has_node(blob, "/memory")
        assert _reg_of(blob, "/memory", 1, 2) == (RAM_BASE, RAM_6GIB)

    def test_disabled_memory_node_keeps_its_reg(self):
        text = """
        {
            #address-cells = <1>;
            #size-cells = <1>;
            memory@8000000 {
                device_type = "memory";
                reg = <0x8000000 0x10000>;
                status = "disabled";
            };
            memory@80000000 {
                device_type = "memory";
                reg = <0x80000000 0x20000000>;
            };
        };
        """
        blob = _blob(text, ram=dev_tree.DtRegion(RAM_BASE, RAM_6GIB))

        assert _reg_of(blob, "/memory@8000000", 1, 2) == (0x800_0000, 0x1_0000)
        assert _reg_of(blob, "/memory@80000000", 1, 2) == (RAM_BASE, RAM_6GIB)


# ============================================================
#  /reserved-memory 与 /chosen
# ============================================================


class TestReservedAndChosen:
    def test_reserved_ranges_become_no_map_children(self):
        ranges = [(0x8000_0000, 0x0400_0000), (0x8300_0000, 0x9000_0000)]
        blob = _blob(ram=dev_tree.DtRegion(RAM_BASE, RAM_6GIB), reserved_ranges=ranges)

        children = _children(blob, "/reserved-memory")
        assert children == ["reserved-0@80000000", "reserved-1@83000000"]
        for (base, size), child in zip(ranges, children, strict=True):
            path = f"/reserved-memory/{child}"
            assert bytes(_prop(blob, path, "no-map")) == b""
            assert _reg_of(blob, path, 1, 2) == (base, size)

    def test_reserved_memory_appended_to_existing_node(self):
        text = """
        {
            #address-cells = <1>;
            #size-cells = <1>;
            reserved-memory {
                #address-cells = <1>;
                #size-cells = <1>;
                ranges;
                region@90000000 {
                    reg = <0x90000000 0x1000>;
                };
            };
        };
        """
        blob = _blob(text, reserved_ranges=[(0x8300_0000, 0x1000)])

        children = _children(blob, "/reserved-memory")
        assert children == ["region@90000000", "reserved-1@83000000"]
        assert bytes(_prop(blob, "/reserved-memory/reserved-1@83000000", "no-map")) == b""

    def test_reserved_memory_cells_mismatch_raises(self):
        text = """
        {
            #address-cells = <1>;
            #size-cells = <1>;
            reserved-memory {
                #address-cells = <2>;
                #size-cells = <2>;
                ranges;
            };
        };
        """
        try:
            _blob(text, reserved_ranges=[(0x8300_0000, 0x1000)])
        except ValueError:
            return
        raise AssertionError("/reserved-memory 的单元格数与根节点不一致时必须报告原因")

    def test_chosen_carries_bootargs_seed_and_initrd(self):
        blob = _blob(
            bootargs="console=ttySIF0 root=/dev/vda",
            initrd=(0x1_0000_0000, 0x1_0100_0000),
        )

        assert _prop(blob, "/chosen", "bootargs").as_str() == "console=ttySIF0 root=/dev/vda"
        assert len(bytes(_prop(blob, "/chosen", "rng-seed"))) == 64
        assert _prop(blob, "/chosen", "linux,initrd-start").as_uint64() == 0x1_0000_0000
        assert _prop(blob, "/chosen", "linux,initrd-end").as_uint64() == 0x1_0100_0000


# ============================================================
#  补充设备节点的位置
# ============================================================


class TestPlaceDevice:
    def test_irq_source_takes_smallest_unused(self):
        """串口声明了 1, 块设备取 2."""
        chip = dev_tree.parse_chip_dts_text(TREE_PLIC)

        assert chip.first_free_irq_source() == 2

    def test_irq_source_counts_each_interrupt_cell(self):
        """两格中断描述里的触发类型只使该编号被跳过, 不占住 1."""
        text = TREE_PLIC.replace("interrupts = <1>;", "interrupts = <1 4>;")
        chip = dev_tree.parse_chip_dts_text(text)

        assert chip.first_free_irq_source() == 2

    def test_mmio_region_skips_declared_ranges(self):
        chip = dev_tree.parse_chip_dts_text(TREE_PLIC)

        region = chip.first_avail_mmio_region(0x200)

        assert region == dev_tree.DtRegion(0x1000, 0x200)

    def test_mmio_region_never_starts_at_zero(self):
        """基址 0 表示该设备不注册, 故自第一页起分配."""
        chip = dev_tree.parse_chip_dts_text(TREE_1_1)

        region = chip.first_avail_mmio_region(0x200)

        assert region == dev_tree.DtRegion(0x1000, 0x200)

    def test_mmio_region_skips_reserved_ranges(self):
        chip = dev_tree.parse_chip_dts_text(TREE_PLIC)

        region = chip.first_avail_mmio_region(0x200, reserved=[(0x1000, 0x3000)])

        assert region == dev_tree.DtRegion(0x3000, 0x200)

    def test_mmio_region_needs_a_gap_that_fits(self):
        """0x1000 至 0x1100 的空隙装不下 0x200 字节, 越过它另取一段."""
        text = """
        {
            #address-cells = <1>;
            #size-cells = <1>;
            block-a {
                reg = <0x0 0x1000>;
            };
            block-b {
                reg = <0x1100 0x100>;
            };
        };
        """
        chip = dev_tree.parse_chip_dts_text(text)

        region = chip.first_avail_mmio_region(0x200)

        assert region == dev_tree.DtRegion(0x2000, 0x200)

    def test_place_device_gives_region_and_irq(self):
        chip = dev_tree.parse_chip_dts_text(TREE_PLIC)

        device = chip.place_device(_virtio())

        assert device.region == dev_tree.DtRegion(0x1000, 0x200)
        assert device.irq == 2

    def test_place_device_without_plic_raises(self):
        chip = dev_tree.parse_chip_dts_text(TREE_1_1)

        try:
            chip.place_device(_virtio())
        except ValueError:
            return
        raise AssertionError("树中没有 PLIC 节点时无法为设备声明中断")


class TestSupplementDeviceNode:
    def test_node_is_appended_under_interrupt_controller_parent(self):
        chip = dev_tree.parse_chip_dts_text(TREE_PLIC)
        device = chip.place_device(_virtio())

        blob = _blob(TREE_PLIC, devices=(device,))

        path = "/soc/virtio@1000"
        assert _has_node(blob, path)
        assert _prop(blob, path, "compatible").as_str() == "virtio,mmio"
        assert _reg_of(blob, path, 1, 1) == (0x1000, 0x200)
        assert _cells(blob, path, "interrupt-parent") == [6]
        assert _cells(blob, path, "interrupts") == [2]

    def test_ndev_is_raised_to_cover_the_irq(self):
        chip = dev_tree.parse_chip_dts_text(TREE_PLIC)
        device = chip.place_device(_virtio())

        blob = _blob(TREE_PLIC, devices=(device,))

        assert _cells(blob, "/soc/interrupt-controller@c000000", "riscv,ndev") == [2]

    def test_ndev_is_kept_when_it_already_covers_the_irq(self):
        text = TREE_PLIC.replace("riscv,ndev = <1>;", "riscv,ndev = <8>;")
        chip = dev_tree.parse_chip_dts_text(text)
        device = chip.place_device(_virtio())

        blob = _blob(text, devices=(device,))

        assert _cells(blob, "/soc/interrupt-controller@c000000", "riscv,ndev") == [8]

    def test_absent_devices_leave_the_tree_unchanged(self):
        blob = _blob(TREE_PLIC)

        assert not _has_node(blob, "/soc/virtio@1000")
        assert _children(blob, "/soc") == [
            "debug-controller@0",
            "serial@64000000",
            "interrupt-controller@c000000",
        ]

    def test_missing_plic_raises(self):
        region = dev_tree.DtRegion(0x1000, 0x200)
        device = dev_tree.DtDeviceNode("virtio", "virtio,mmio", region, 2)

        try:
            _blob(devices=(device,))
        except ValueError:
            return
        raise AssertionError("树中没有 PLIC 节点时必须报告原因")
