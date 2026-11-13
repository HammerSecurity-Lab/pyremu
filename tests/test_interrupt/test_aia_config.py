#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""AIA 配置层测试 — PlatformConfig 序列化 + 向后兼容."""

import json
from pathlib import Path
import tempfile

import pytest

from pyremu import configs_gen
from pyremu.emulator import Emulator
from pyremu.platform import InterruptMode, PeripheralConfig, PlatformConfig


@pytest.fixture(autouse=True)
def _disable_aia_compile_override(monkeypatch):
    """Disable PYREMU_AIA compile-time override.

    Tests use explicit configs: basic_machine() for legacy,
    basic_aia_machine() for AIA.
    """
    monkeypatch.setattr(configs_gen, "PYREMU_AIA", False)


class TestInterruptModeEnum:
    """InterruptMode 枚举."""

    def test_legacy_aia_values(self):
        assert InterruptMode.LEGACY.value == "legacy"
        assert InterruptMode.AIA.value == "aia"

    def test_from_string(self):
        assert InterruptMode("legacy") == InterruptMode.LEGACY
        assert InterruptMode("aia") == InterruptMode.AIA

    def test_default_is_legacy(self):
        cfg = PlatformConfig()
        assert cfg.interrupt_mode == InterruptMode.LEGACY


class TestQemuVirtAiaPreset:
    """basic_aia_machine 工厂方法."""

    def test_creates_correct_mode(self):
        cfg = PlatformConfig.basic_aia_machine()
        assert cfg.interrupt_mode == InterruptMode.AIA
        assert cfg.periph.imsic_m_base == configs_gen.IMSIC_M_BASE
        assert cfg.periph.aplic_s_base == configs_gen.APLIC_S_BASE

    def test_emulator_creates_imsic(self, make_aia_config):
        emu = Emulator(make_aia_config())
        assert emu.imsic is not None
        assert emu.harts[0]._imsic is not None

    def test_legacy_basic_machine_has_no_imsic(self):
        emu = Emulator(PlatformConfig.basic_machine())
        assert emu.imsic is None
        assert emu.harts[0]._imsic is None


class TestConfigSerialization:
    """JSON/TOML 序列化与枚举互转."""

    def test_json_roundtrip_legacy(self):
        cfg = PlatformConfig.basic_machine()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(
                {
                    "num_harts": cfg.num_harts,
                    "ram_size": cfg.ram_size,
                    "ram_base": cfg.ram_base,
                    "interrupt_mode": cfg.interrupt_mode.value,
                    "periph": {
                        "imsic_m_base": 0,
                        "imsic_s_base": 0,
                        "aplic_s_base": 0,
                        "plic_base": cfg.periph.plic_base,
                    },
                },
                f,
            )
            path = f.name

        loaded = PlatformConfig.from_json(path)
        assert loaded.interrupt_mode == InterruptMode.LEGACY
        assert loaded.periph.imsic_m_base == 0
        Path(path).unlink()

    def test_json_roundtrip_aia(self):
        cfg = PlatformConfig.basic_aia_machine()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(
                {
                    "num_harts": cfg.num_harts,
                    "interrupt_mode": cfg.interrupt_mode.value,
                    "periph": {
                        "imsic_m_base": cfg.periph.imsic_m_base,
                        "imsic_s_base": cfg.periph.imsic_s_base,
                        "aplic_s_base": cfg.periph.aplic_s_base,
                        "plic_base": cfg.periph.plic_base,
                    },
                },
                f,
            )
            path = f.name

        loaded = PlatformConfig.from_json(path)
        assert loaded.interrupt_mode == InterruptMode.AIA
        assert loaded.periph.imsic_m_base == cfg.periph.imsic_m_base
        Path(path).unlink()


class TestPeripheralConfigDefault:
    """PeripheralConfig 默认值向后兼容."""

    def test_default_imsic_base_follows_build_config(self):
        """默认 IMSIC 与 APLIC 基址取自根据项目编译选项自动生成的AIA
        中断控制器基地址常量."""
        p = PeripheralConfig()
        assert p.imsic_m_base == configs_gen.IMSIC_M_BASE
        assert p.aplic_s_base == configs_gen.APLIC_S_BASE

    def test_minimal_preset_rejected_by_window_overlap(self):
        """minimal 预设的 RAM 窗口覆盖 CLINT,
        装配模拟器时被地址窗口重叠断言拒绝."""
        cfg = PlatformConfig.minimal()
        with pytest.raises(AssertionError, match="与 RAM"):
            Emulator(cfg)
