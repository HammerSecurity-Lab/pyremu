#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""多 hart 集成测试: 验证多核启动 + 定时器中断."""

import struct

import pytest

from pyremu.configs_aux import examed_elf_dir, path_join
from pyremu.emulator import Emulator
from pyremu.platform import PlatformConfig
from pyremu.utils.parse_bin import parse_firmware


@pytest.fixture
def multi_hart_emu():
    """2-hart emulator with kernel loaded."""
    cfg = PlatformConfig.basic_machine()
    cfg.num_harts = 2
    # 时钟源取固定值, 使 mtime 的推进量与项目的编译选项无关.
    cfg.timebase_freq = 10_000_000
    emu = Emulator(cfg)
    kernel = parse_firmware(path_join(examed_elf_dir(), "kernel.elf"))
    assert kernel is not None, "kernel.elf 解析失败"
    emu.load_firmware(kernel)
    return emu


class TestMultiHartBoot:
    """验证多 hart 基本启动: 仅启动 hart 进入 S 模式, 其余 hart 驻留等待."""

    def test_boot_hart_boots_to_smode(self, multi_hart_emu):
        """启动 hart 从 M 模式进入 S 模式."""
        emu = multi_hart_emu
        for _ in range(500):
            emu.step()
            if emu.harts[0].mode.name == "S":
                break

        assert emu.harts[0].mode.name == "S", f"Hart 0 仍是 {emu.harts[0].mode.name}"

    def test_non_boot_harts_park(self, multi_hart_emu):
        """非启动 hart 保持 M 模式, 停在 park_hart 的 WFI 循环内."""
        emu = multi_hart_emu
        for _ in range(500):
            emu.step()

        kernel = parse_firmware(path_join(examed_elf_dir(), "kernel.elf"))
        assert kernel is not None
        park_pc = kernel.symbols["park_hart"]
        for h in emu.harts[1:]:
            assert h.mode.name == "M", f"Hart {h.id} 应为 M 模式, 实际 {h.mode.name}"
            assert park_pc <= h.pc < park_pc + 8, f"Hart {h.id} PC=0x{h.pc:08x}"

    def test_harts_have_separate_csrs(self, multi_hart_emu):
        """每个 hart 的 CSR 状态独立: 写入一个 hart 的 mscratch 不影响另一个."""
        emu = multi_hart_emu
        for _ in range(500):
            emu.step()

        emu.harts[1].csrs["mscratch"].val = 0x5A5A
        assert emu.harts[1].csrs["mscratch"].val == 0x5A5A
        assert emu.harts[0].csrs["mscratch"].val != 0x5A5A, "CSR 状态不应跨 hart 共享"


class TestMultiHartTimer:
    """验证定时器中断."""

    def test_clint_mtime_advances(self, multi_hart_emu):
        """CLINT mtime 应随 step() 推进 (按指令计数)."""
        emu = multi_hart_emu
        mtime_before = emu.clint.get_mtime()
        for _ in range(100):
            emu.step()
        mtime_after = emu.clint.get_mtime()
        assert mtime_after > mtime_before, f"mtime 应推进，但 {mtime_before} >= {mtime_after}"

    def test_mtimecmp_writable(self, multi_hart_emu):
        """mtimecmp 可通过总线写入."""
        emu = multi_hart_emu
        # 写入 hart 0 的 mtimecmp (CLINT_BASE + 0x4000)
        val = 50000
        emu.bus.write(0x02004000, struct.pack("<Q", val))
        raw = emu.bus.try_read(0x02004000, 8)
        assert raw is not None, "无法读取 mtimecmp"
        assert int.from_bytes(raw, "little") == val, "mtimecmp 回读不匹配"

    def test_timer_interrupt_signaled(self, multi_hart_emu):
        """当 mtime >= mtimecmp > 0 时 MTIP 应置位."""
        emu = multi_hart_emu
        # 等待内核完成 mtimecmp 初始化 (boot 期间设为 -1)
        for _ in range(300):
            emu.step()
        # 获取当前 mtime, 设置 mtimecmp = mtime + 50
        mtime = emu.clint.get_mtime()
        emu.bus.write(0x02004000, struct.pack("<Q", mtime + 50))
        # mtime 按指令计数推进, 直接 tick 越过 mtimecmp 而非依赖大量 step
        emu.clint.tick(60)
        # 再 step 一次, 指令边界 check_pending_interrupts 将 MTIP 同步到 mip CSR
        emu.step()
        mip = emu.harts[0].csrs["mip"].val
        assert mip & (1 << 7), f"MTIP 未置位, mip=0x{mip:x}"
