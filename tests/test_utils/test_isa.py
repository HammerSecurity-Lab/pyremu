#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""ISA 字符串的归一化.

覆盖旧式 ``riscv,isa`` 字符串与 ``riscv,isa-extensions`` 扩展名列表两种输入:
单字母扩展、``g`` 的展开、末尾版本号、下划线分段、大小写与空值.
"""

from pyremu.utils.isa import (
    encode_isa_exts,
    encode_misa,
    ISA_EXT_FIELDS,
    isa_ext_list,
)


class TestIsaString:
    def test_single_letters_before_underscore(self):
        """第一个下划线之前的字母逐个作为扩展名."""
        assert isa_ext_list("rv64imafdc") == list("imafdc")

    def test_g_expands_to_imafd_zicsr_zifencei(self):
        """单字母 g 展开为 imafd 与 zicsr、zifencei."""
        assert isa_ext_list("rv64g") == [
            "i",
            "m",
            "a",
            "f",
            "d",
            "zicsr",
            "zifencei",
        ]

    def test_multi_letter_names_after_underscore(self):
        assert isa_ext_list("rv64imac_zicsr_zifencei_sstc") == [
            "i",
            "m",
            "a",
            "c",
            "zicsr",
            "zifencei",
            "sstc",
        ]

    def test_version_suffix_stripped(self):
        """扩展名末尾的版本号去掉, 形如 2p0 与 1p11."""
        assert isa_ext_list("rv64i2p1_m2p0_zicsr2p0_sstc1p0") == [
            "i",
            "m",
            "zicsr",
            "sstc",
        ]

    def test_uppercase_normalized(self):
        assert isa_ext_list("RV64IMAC_ZIFENCEI") == [
            "i",
            "m",
            "a",
            "c",
            "zifencei",
        ]

    def test_rv32_prefix_stripped(self):
        assert isa_ext_list("rv32im_zbb") == ["i", "m", "zbb"]

    def test_missing_sstc_not_in_result(self):
        """树中给出的 ISA 未声明 sstc 时结果不含该扩展."""
        assert "sstc" not in isa_ext_list("rv64imafdc_zicsr_zifencei_zbb")

    def test_multi_letter_without_underscore(self):
        """首段末尾漏写下划线时, z 起至段末仍为一个多字母扩展名.

        chip.dts 声明 "rv64imafdcbzicsr", 按单个字母切分会得到 z、i、c、s、r
        五个并不存在的扩展, 并丢掉 zicsr.
        """
        got = isa_ext_list(
            "rv64imafdcbzicsr_zifencei_zihpm_zfh_zba_zbb_zbs_xrocket"
        )
        assert got == [
            "i",
            "m",
            "a",
            "f",
            "d",
            "c",
            "b",
            "zicsr",
            "zifencei",
            "zihpm",
            "zfh",
            "zba",
            "zbb",
            "zbs",
            "xrocket",
        ]
        for bogus in ("z", "s", "r"):
            assert bogus not in got

    def test_supervisor_multi_letter_without_underscore(self):
        """首段末尾粘连的 sstc 同样作为一个多字母扩展名."""
        assert isa_ext_list("rv64imacsstc") == ["i", "m", "a", "c", "sstc"]

    def test_multi_letter_ending_with_p_kept(self):
        """以字母开头的名称不被当作版本号截断, 如 zcmp 与 zcmp1p0."""
        assert isa_ext_list("rv64imac_zcmp") == ["i", "m", "a", "c", "zcmp"]
        assert isa_ext_list("rv64imac_zcmp1p0") == ["i", "m", "a", "c", "zcmp"]


class TestIsaExtListInput:
    def test_extension_list_normalized(self):
        """扩展名列表逐项转为小写并去掉版本号."""
        assert isa_ext_list(["I", "M", "Zicsr2p0", "sstc"]) == [
            "i",
            "m",
            "zicsr",
            "sstc",
        ]

    def test_none_gives_empty_list(self):
        assert isa_ext_list(None) == []

    def test_empty_string_gives_empty_list(self):
        assert isa_ext_list("") == []


class TestIsaExtSwitches:
    """扩展名集合到加速执行引擎扩展开关的编码."""

    def test_declared_extensions_set(self):
        """声明的扩展对应字段取 True, 其余取 False."""
        switches = encode_isa_exts(isa_ext_list("rv64imafdc_zicsr_zifencei"))
        assert switches["is_i"] is True
        assert switches["is_c"] is True
        assert switches["is_zifencei"] is True
        assert switches["is_sstc"] is False
        assert switches["is_smaia"] is False

    def test_sstc_declared(self):
        """声明 sstc 时只有 is_sstc 随之为真."""
        switches = encode_isa_exts(isa_ext_list("rv64imac_zicsr_sstc"))
        assert switches["is_sstc"] is True

    def test_unknown_name_ignored(self):
        """未登记的扩展名不影响任何字段, 例如厂商扩展 xrocket."""
        base = encode_isa_exts(["i", "m"])
        assert encode_isa_exts(["i", "m", "xrocket"]) == base

    def test_keys_cover_every_field(self):
        """取值表恰好覆盖登记的全部字段, 且取值均为布尔."""
        switches = encode_isa_exts(["i"])
        assert set(switches) == set(ISA_EXT_FIELDS.values())
        assert all(isinstance(v, bool) for v in switches.values())


class TestEncodeMisa:
    """扩展名集合到 misa 取值的编码."""

    BASE = (2 << 62) | (1 << 18) | (1 << 20)

    def test_empty_set_keeps_mxl_and_privilege_bits(self):
        """空集合给出 RV64 的 MXL 与 S、U 两个特权级位."""
        assert encode_misa([]) == self.BASE

    def test_single_letters_map_to_bits(self):
        """每个单字母扩展按该字母在字母表中的序号占一个位."""
        assert encode_misa(["i", "m", "a"]) == self.BASE | 0x100 | 0x1000 | 0x1
        assert encode_misa(["b"]) == self.BASE | 0b10
        assert encode_misa(["v"]) == self.BASE | (1 << 21)

    def test_imafdc_equals_legacy_literal(self):
        """i/m/a/f/d/c 六位与 S、U 两位合起来为原实现写死的取值."""
        assert encode_misa(isa_ext_list("rv64imafdc")) == 0x8000_0000_0014_112D

    def test_multi_letter_extensions_add_nothing(self):
        """多字母扩展不在 misa 中表达."""
        value = encode_misa(
            isa_ext_list("rv64imac_zba_zbb_zbs_zicsr_zifencei_sstc")
        )
        assert value == encode_misa(["i", "m", "a", "c"])

    def test_versioned_and_uppercase_input(self):
        """带版本号与大小写混写的字符串经归一化后取值不变."""
        assert encode_misa(isa_ext_list("RV64I2P1_M2P0_ZBB")) == encode_misa(
            ["i", "m"]
        )
