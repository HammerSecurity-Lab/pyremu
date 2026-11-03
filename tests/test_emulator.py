#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""模拟器集成测试: 执行循环、状态导出、固件装载与空闲等待."""

import ctypes
import threading
import time

import pytest

from pyremu.emu import run
from pyremu.emulator import Emulator, TimeoutError
from pyremu.peripheral.termio import TerminalIO
from pyremu.peripheral.uart import UART, UART_IRQ
from pyremu.platform import PeripheralConfig, PlatformConfig


class TestEmulatorInit:
    """模拟器初始化."""

    @pytest.mark.parametrize("hart_num", [1, 2, 3, 4, 8, 9, 10, 12, 16])
    def test_hart(self, hart_num: int):
        """单 hart 初始化."""
        emu = Emulator(num_harts=hart_num)
        assert emu.num_harts == hart_num and len(emu.harts) == hart_num
        for i, h in enumerate(emu.harts):
            assert h.id == i and h.pc == emu.prog_cnt
            assert h.gprs[0] == 0, "x0应始终为 0"
            assert h.mode.name == "M", "复位后应为 M 模式"
            assert h.bus is emu.bus

    def test_hart_ids_unique(self):
        """每个 hart 的 mhartid CSR 应唯一."""
        emu = Emulator(num_harts=4)
        ids = {h.csrs["mhartid"].val for h in emu.harts}
        assert ids == {0, 1, 2, 3}

    def test_clint_registered(self):
        """CLINT 已注册为 Bus 设备."""
        emu = Emulator(num_harts=4)
        assert emu.bus.is_device_addr(emu.clint.base_addr)

    def test_misa_initialized(self):
        """misa CSR 复位后非零, 包含 MXL=2 (RV64) 及 I/M/A/C 扩展位."""
        emu = Emulator(num_harts=1)
        misa = emu.harts[0].csrs["misa"].val
        assert misa != 0, "misa 应为非零, 告知 OS 可用扩展"
        mxl = (misa >> 62) & 0x3
        assert mxl == 2, f"MXL 应为 2 (RV64), 实际 {mxl}"
        # I (bit 8), M (bit 12), A (bit 0), C (bit 2) 应置位
        assert misa & (1 << 8), "I (base integer) 扩展位应置位"
        assert misa & (1 << 12), "M (mul/div) 扩展位应置位"
        assert misa & (1 << 0), "A (atomic) 扩展位应置位"
        assert misa & (1 << 2), "C (compressed) 扩展位应置位"


class TestEmulatorExecution:
    """执行循环."""

    def test_step_executes_all_harts(self):
        """step() 每个 hart 执行一条指令."""
        emu = Emulator(num_harts=4, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        # 载入 NOP 指令 (ADDI x0, x0, 0 = 0x00000013)
        emu.load_code(0x1000, b"\x13\x00\x00\x00")
        initial_pc = emu.harts[0].pc
        executed = emu.step()
        assert executed == 4
        # 每条指令后 PC 应 +4
        for h in emu.harts:
            assert h.pc == initial_pc + 4

    def test_pc_advances_per_step(self):
        """每条 ADDI x0,x0,0 后 PC 推进 4 字节."""
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        # 载入多条 NOP 保证有足够的指令
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 10)
        assert emu.harts[0].pc == 0x1000
        emu.step()
        assert emu.harts[0].pc == 0x1004
        emu.step()
        assert emu.harts[0].pc == 0x1008

    def test_hart_gpr_write_independent(self):
        """hart 间寄存器独立: hart 0 写 x5, 不影响 hart 1 的 x5."""
        emu = Emulator(num_harts=4, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        # ADDI x5, x10, 0 -> x5 = x10 (每条 hart 的 x10 不同)
        # Instr: imm[11:0]=0, rs1=x10, funct3=000, rd=x5, op=0010011
        instr = (0 << 20) | (10 << 15) | (5 << 7) | 0b0010011
        emu.load_code(0x1000, instr.to_bytes(4, "little"))
        # 各 hart 的 x10 不同
        emu.harts[0].gprs[10] = 0
        emu.harts[1].gprs[10] = 100
        emu.harts[2].gprs[10] = 200
        emu.harts[3].gprs[10] = 300
        emu.step()
        assert emu.harts[0].gprs[5] == 0
        assert emu.harts[1].gprs[5] == 100
        assert emu.harts[2].gprs[5] == 200
        assert emu.harts[3].gprs[5] == 300

    def test_read_gpr_by_name(self):
        """Hart.read_gpr_by_name 按名称/别名查找 GPR."""
        emu = Emulator()
        h = emu.harts[0]
        h.write_gpr(10, 0x1234_5678_9ABC)
        # 按 x 编号
        assert h.read_gpr_by_name("x10") == 0x1234_5678_9ABC
        # 按 ABI 别名
        assert h.read_gpr_by_name("a0") == 0x1234_5678_9ABC
        # zero 永远为 0
        assert h.read_gpr_by_name("zero") == 0
        assert h.read_gpr_by_name("x0") == 0
        # 不存在 -> 0
        assert h.read_gpr_by_name("nonexistent") == 0

    def test_read_csr_by_name(self):
        """Hart.read_csr_by_name 按名称查找 CSR."""
        emu = Emulator()
        h = emu.harts[0]
        # mtvec 默认值 0
        assert h.read_csr_by_name("mtvec") == 0
        # 写 CSR 后读取
        h.csrs["mtvec"].val = 0x378
        assert h.read_csr_by_name("mtvec") == 0x378
        # mstatus
        h.csrs["mstatus"].val = 0x1800
        assert h.read_csr_by_name("mstatus") == 0x1800
        # 不存在 -> 0
        assert h.read_csr_by_name("nonexistent") == 0


class TestEmulatorState:
    """状态导出."""

    def test_dump_hart_regs(self):
        """dump_hart_regs 导出关键状态."""
        emu = Emulator(num_harts=2, prog_cnt=0x80000000)
        regs = emu.dump_hart_regs(0)
        assert regs["hart_id"] == 0 and regs["pc"] == 0x80000000
        assert "x0" in regs["gprs"] and "x31" in regs["gprs"]

    def test_mem_hexdump(self):
        """mem_hexdump 输出格式化 hex 字符串."""
        emu = Emulator(num_harts=1)
        emu.bus.write(0x1000, b"Hello, RISC-V!")
        dump = emu.mem_hexdump(0x1000, 14)
        assert "Hello, RISC-V!" in dump
        assert "1000" in dump


class TestEmulatorStoreMemory:
    """通过 hart 执行 store 指令写入物理内存.

    验证完整的 store 路径: exec_instr -> handle_st -> _mem_write ->
    _translate_full -> mem_write_phy -> Bus.write -> RAM/L2。
    这是对 #sw-not-writing-to-ram 的回归测试。
    """

    RAM_BASE = 0x8000_0000  # 默认 DRAM 基址

    @pytest.fixture
    def emu(self) -> Emulator:
        return Emulator(num_harts=1)

    def test_sw_in_ram_range(self, emu):
        """SW 写入 RAM 范围内的地址, 应能通过 Bus 读回."""
        h = emu.harts[0]
        # sp 指向 RAM 内
        h.gprs[2] = self.RAM_BASE + 0x1000  # sp
        h.gprs[1] = 0xCAFE_BABE  # ra (x1)

        # sw x1, 0(x2):  opcode=0100011 funct3=010 rs2=1 rs1=2 imm=0
        instr = (0 << 25) | (1 << 20) | (2 << 15) | (2 << 12) | (0x23)
        h.exec_instr(instr)

        data = emu.bus.read(self.RAM_BASE + 0x1000, 4)
        assert data == b"\xbe\xba\xfe\xca", (
            f"SW 写入失败: 期望 b'\\xbe\\xba\\xfe\\xca', 实际 {data.hex()}"
        )

    def test_sw_multiple_stores(self, emu):
        """连续 SW 写入不同偏移, 数据不互相覆盖."""
        h = emu.harts[0]
        base = self.RAM_BASE + 0x2000
        h.gprs[2] = base  # sp
        h.gprs[8] = 0xAAAA_BBBB  # s0
        h.gprs[9] = 0xCCCC_DDDD  # s1

        # sw s0, 0(sp)
        instr0 = (0 << 25) | (8 << 20) | (2 << 15) | (2 << 12) | (0x23)
        h.exec_instr(instr0)
        # sw s1, 4(sp)
        instr1 = (0 << 25) | (9 << 20) | (2 << 15) | (2 << 12) | (0x23)
        # 手动构造 imm=4: bit 7=1, bits 8-11=0, bits 25-31=0
        instr1 = (0 << 25) | (9 << 20) | (2 << 15) | (2 << 12) | (4 << 7) | (0x23)
        h.exec_instr(instr1)

        data = emu.bus.read(base, 8)
        assert data[:4] == b"\xbb\xbb\xaa\xaa", f"偏移 0: {data[:4].hex()}"
        assert data[4:8] == b"\xdd\xdd\xcc\xcc", f"偏移 4: {data[4:8].hex()}"

    def test_sd_doubleword_store(self, emu):
        """SD 写入 8 字节, 验证双字 store 的 PMA."""
        h = emu.harts[0]
        addr = self.RAM_BASE + 0x3000
        h.gprs[2] = addr  # sp
        h.gprs[1] = 0xDEAD_BEEF_CAFE_BABE  # ra

        # sd x1, 0(x2): opcode=0100011 funct3=011 rs2=1 rs1=2 imm=0
        instr = (0 << 25) | (1 << 20) | (2 << 15) | (3 << 12) | (0x23)
        h.exec_instr(instr)

        data = emu.bus.read(addr, 8)
        expected = (0xDEAD_BEEF_CAFE_BABE).to_bytes(8, "little")
        assert data == expected, f"SD 写入失败: 期望 {expected.hex()}, 实际 {data.hex()}"

    def test_store_at_ram_base_edge(self, emu):
        """SW 写入 RAM 基址 (ram_base) 边界, 确保不越界."""
        h = emu.harts[0]
        # 恰好从 ram_base 开始
        h.gprs[2] = self.RAM_BASE
        h.gprs[1] = 0x1234_5678
        instr = (0 << 25) | (1 << 20) | (2 << 15) | (2 << 12) | (0x23)
        h.exec_instr(instr)
        assert emu.bus.read(self.RAM_BASE, 4) == b"\x78\x56\x34\x12"


# ============================================================
#  step() 边界用例: 已停止 hart, 连续 trap, 非法指令
# ============================================================


class TestStepEdgeCases:
    """step() 的边界行为."""

    def test_halted_hart_is_skipped(self):
        """已停止的 hart 在 step() 中被跳过."""
        emu = Emulator(num_harts=2, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 10)
        emu.harts[0]._halted = True
        executed = emu.step()
        # 仅 hart 1 执行了
        assert executed == 1
        assert emu.harts[0].pc == 0x1000  # 跳过的 hart PC 未变
        assert emu.harts[1].pc == 0x1004  # 正常执行的 hart PC+4

    def test_not_implemented_error_delivers_ill_instr(self):
        """未实现的操作码触发 IllInstr 陷态, hart 不崩溃."""
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        # 构造一个未实现的自定义 opcode (bits[1:0]=11 保证 32-bit 编码)
        bad_instr = 0x7F | (10 << 7) | (10 << 15) | (10 << 20)
        emu.load_code(0x1000, bad_instr.to_bytes(4, "little"))
        h = emu.harts[0]
        h.csrs["mtvec"].val = 0x80000000  # 设置 trap handler
        emu.step()
        # 应投递 IllInstr 后跳转到 mtvec
        assert h.pc == 0x80000000
        assert (h.mcause_val & 0x7FFF_FFFF_FFFF_FFFF) == 2  # IllInstr


# ============================================================
#  load_firmware 边界
# ============================================================


class TestLoadFirmware:
    """load_firmware 边界用例."""

    def test_none_image_raises_valueerror(self):
        """image=None 时抛出 ValueError."""
        emu = Emulator()
        with pytest.raises(ValueError, match="无效"):
            emu.load_firmware(None)


# ============================================================
#  run() 超时
# ============================================================


class TestRunTimeout:
    """run() 的超时."""

    def test_timeout_raises_timeouterror(self):
        """非零 timeout 超时时抛出 TimeoutError."""
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=64 * 1024)
        # nop @0x1000 + jal x0,-4 @0x1004 — 死循环 (跳回 0x1000), 依赖时钟源超时兜底.
        # 不能用 jal x0,0 (跳自身): 停滞检测会将其误判为 trap 循环而提前 halt.
        emu.load_code(0x1000, b"\x13\x00\x00\x00\x6f\xf0\xdf\xff")
        with pytest.raises(TimeoutError) as exc_info:
            emu.run(timeout=0.01, yield_every=1000)
        err = exc_info.value
        assert "超时" in str(err)

    def test_timeout_zero_disables(self):
        """timeout 取 0 表示禁用超时, 执行到断点而不抛 TimeoutError.

        回归: 判定写成 ``time.monotonic() < _timeout_deadline`` 时, 禁用超时的
        截止时刻 0 会让第一次检查即判定超时.
        """
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=64 * 1024)
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 5)
        emu._bp_addrs = [0x1000 + 4 * 5]
        emu.run(timeout=0)
        assert emu.harts[0].pc == 0x1000 + 4 * 5

    def test_run_returns_int(self):
        """run() 返回执行的周期数 (int)."""
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=64 * 1024)
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 5)
        # 断点终止连续执行 (max_cycles 已移除), 使 run() 确定性返回.
        emu._bp_addrs = [0x1000 + 4 * 5]
        cycles = emu.run(timeout=0)
        assert isinstance(cycles, int)

    def test_yield_every_zero_runs_full(self):
        """yield_every=0 时 run() 不限速执行到断点."""
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 5)
        emu._bp_addrs = [0x1000 + 4 * 5]
        cycles = emu.run(timeout=0, yield_every=0)
        assert isinstance(cycles, int)


# ============================================================
#  属性与状态
# ============================================================


class TestEmulatorProperties:
    """Emulator 的属性和状态."""

    def test_peripherals_dict(self):
        """peripherals 属性返回外设字典 (CLINT 为独立设备不在 dict 中)."""
        cfg = PlatformConfig(
            periph=PeripheralConfig(
                uart_base=0x1000_0000,
                spi_base=0x1000_1000,
                i2c_base=0x1000_2000,
                gpio_base=0x1000_3000,
            ),
        )
        emu = Emulator(cfg)
        periph = emu.peripherals
        assert "uart" in periph
        assert "spi" in periph
        assert "i2c" in periph
        assert "gpio" in periph

    def test_cycle_and_total_instructions(self):
        """cycle 和 total_instructions 初始为 0, step() 后增长."""
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 10)
        assert emu.cycle == 0
        assert emu.total_instructions == 0
        emu.step()
        assert emu.cycle >= 1
        assert emu.total_instructions == 1
        emu.step()
        assert emu.total_instructions == 2

    def test_counter_csr_sync_per_step(self):
        """mcycle/cycle/minstret/instret/time CSR 每条指令后同步更新."""
        emu = Emulator(num_harts=1, prog_cnt=0x1000, ram_base=0, ram_size=0x2000)
        emu.load_code(0x1000, b"\x13\x00\x00\x00" * 10)
        h = emu.harts[0]

        # 初始值取决于复位, 允许从 0 开始
        c0 = h.csrs["mcycle"].val
        i0 = h.csrs["minstret"].val
        emu.step()
        c1 = h.csrs["mcycle"].val
        i1 = h.csrs["minstret"].val
        t1 = h.csrs["time"].val
        assert c1 > c0, f"mcycle 应递增: {c0} -> {c1}"
        assert i1 > i0, f"minstret 应递增: {i0} -> {i1}"
        # mtime 按指令计数推进, 单条指令不足 1 tick, time 可不递增但须与 mtime 同步
        assert t1 == emu.clint.get_mtime(), (
            f"time CSR 应与 CLINT mtime 同步: {t1} vs {emu.clint.get_mtime()}"
        )

        # cycle / instret 为只读影子, 应与 mcycle / minstret 同步
        assert h.csrs["cycle"].val == c1, "cycle 应与 mcycle 同步"
        assert h.csrs["instret"].val == i1, "instret 应与 minstret 同步"

        # 执行更多指令, 验证差值
        emu.step()
        emu.step()
        delta_c = h.csrs["mcycle"].val - c1
        delta_i = h.csrs["minstret"].val - i1
        delta_t = h.csrs["time"].val - t1
        # mcycle 按时钟源推进, 差值由流逝时间决定, 不固定为 2.
        assert delta_c >= 0, f"mcycle 差值不应为负, 实际 {delta_c}"
        assert delta_i == 2, f"3 步后 minstret 差值应为 2, 实际 {delta_i}"
        # mtime 按指令计数推进, 2 条指令不足 1 tick, time 不递增.
        assert delta_t >= 0, f"time 差值不应为负: delta={delta_t}"
        assert h.csrs["time"].val == emu.clint.get_mtime(), "time CSR 应与 CLINT mtime 同步"


class TestPlatformConfigTimebase:
    """平台配置的时钟源频率下限: 低于 1000 Hz 时 1 ms 内不足一个计数."""

    def test_below_one_khz_rejected(self):
        with pytest.raises(AssertionError):
            PlatformConfig(timebase_freq=999)

    def test_one_khz_accepted(self):
        assert PlatformConfig(timebase_freq=1_000).timebase_freq == 1_000


class _FakeTime:
    """以固定步长推进的单调时钟, 供 WFI 睡眠用例确定性地推进时间."""

    def __init__(self, step_sec: float) -> None:
        self.now = 0.0
        self.step_sec = step_sec

    def monotonic(self) -> float:
        return self.now


class _FakeWakeEvent:
    """等待时把假时钟推进固定时长的事件替身."""

    def __init__(self, fake_time: _FakeTime) -> None:
        self._fake_time = fake_time

    def clear(self) -> None:
        pass

    def wait(self, timeout: float | None) -> bool:
        self._fake_time.now += self._fake_time.step_sec
        return False


class TestWfiIdleSleep:
    """WFI 全 hart 空闲睡眠 — 事件驱动唤醒, 上限取定时器截止时刻与运行超时."""

    def test_wfi_sleep_stale_event_does_not_spin(self):
        """回归: 已置位的 _wake_event 电平残留不得阻止睡眠 (忙转).

        修复前 drain_rx 无条件 set(_wake_event), 首次外设活动 (UART RX /
        ext_irq / 看门狗 MSIP) 后事件永久置位, 且 _wfi_sleep_if_idle 等待前
        不 clear — wait(timeout) 每次立即返回, 全 hart WFI 空闲退化为 ~100%
        CPU 忙转, 宿主被拖满, 键盘输入看似"无响应"。

        修复后等待前先 clear() 事件; 陈旧事件仅表示先前循环已处理过的工作,
        本轮回合应正常睡眠, 不得因残留置位空转。
        """
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x10000)
        hart = emu.harts[0]
        hart._waiting = True
        # 截止时刻取 0.2 秒后, 等待上限即为该截止时刻
        emu.clint.set_mtimecmp(0, emu._cfg.timebase_freq // 5)

        # 模拟 boot 期间外设活动遗留的电平: 事件已 set
        emu._wake_event.set()
        start = time.monotonic()
        emu._wfi_sleep_if_idle([hart], 1)
        elapsed = time.monotonic() - start
        assert elapsed >= 0.15, f"陈旧事件不得阻止睡眠 (忙转), 实际 {elapsed:.3f}s"

    def test_wfi_sleep_wakes_on_event_during_wait(self):
        """无定时器且无运行超时时等待不设上限, 睡眠期间的输入事件应即时唤醒.

        clear-then-wait 之后由守护线程在睡眠中途 set 事件, 主线程立即返回,
        使键盘输入能被下一轮加速执行及时转发.
        """
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x10000)
        hart = emu.harts[0]
        hart._waiting = True
        emu.clint.set_mtimecmp(0, 0)

        def _late_set():
            time.sleep(0.05)
            emu._wake_event.set()

        th = threading.Thread(target=_late_set, daemon=True)
        th.start()
        start = time.monotonic()
        emu._wfi_sleep_if_idle([hart], 1)
        elapsed = time.monotonic() - start
        th.join()
        assert elapsed < 0.15, f"睡眠中到达的事件应即时唤醒, 实际 {elapsed:.3f}s"

    def test_wfi_idle_advances_mtime_without_timer(self, monkeypatch):
        """回归: 无定时器时全 hart 等待, mtime 仍按真实流逝时间推进.

        mtime 是自由运行的计数器. 修复前无定时器走固定轮询分支且不调用
        clint.tick, 客机在空闲等待期间读到的 time 停滞.
        """
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x10000)
        hart = emu.harts[0]
        hart._waiting = True
        emu.clint.set_mtimecmp(0, 0)
        fake_time = _FakeTime(step_sec=0.01)
        emu._wake_event = _FakeWakeEvent(fake_time)
        monkeypatch.setattr(run, "time", fake_time)

        emu._wfi_sleep_if_idle([hart], 1)

        assert emu.clint.get_mtime() == int(0.01 * emu._cfg.timebase_freq)

    def test_wfi_wait_bound_is_deadline_not_fixed_cap(self):
        """等待上限取最早到期的定时器, 不截断为固定值."""
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x20000)
        emu.clint.set_mtimecmp(0, 5_000_000)

        assert emu._wfi_wait_bound_sec([emu.harts[0]]) == pytest.approx(50.0)

    def test_wfi_wait_bound_includes_run_timeout(self):
        """无定时器时等待上限取运行超时的剩余时间."""
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x20000)
        emu.clint.set_mtimecmp(0, 0)
        emu._timeout_deadline = time.monotonic() + 2.0

        bound = emu._wfi_wait_bound_sec([emu.harts[0]])

        assert 1.5 < bound <= 2.0

    def test_wfi_wait_bound_is_none_without_deadline(self):
        """既无定时器也无运行超时时不设等待上限."""
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x20000)
        emu.clint.set_mtimecmp(0, 0)
        emu._timeout_deadline = 0.0

        assert emu._wfi_wait_bound_sec([emu.harts[0]]) is None

    def test_native_finalize_idle_wait_skips_halted_harts(self, monkeypatch):
        """回归: 存在停机 hart 时, 存活 hart 全部等待仍须进入空闲睡眠.

        修复前 _native_finalize 把全部 hart 传给 _wfi_sleep_if_idle, 而等待
        计数只统计存活 hart, 两者在存在停机 hart 时永不相等, 空闲时不进入睡眠.
        """
        emu = Emulator(num_harts=2, ram_base=0x80000000, ram_size=0x20000)
        harts = emu.harts
        harts[0]._waiting = True
        harts[1]._halted = True
        seen: list[list] = []

        def fake_sleep(active, waiting_count):
            seen.append(list(active))

        monkeypatch.setattr(emu, "_wfi_sleep_if_idle", fake_sleep)
        emu._native_finalize(0)

        assert seen == [[harts[0]]]

    def test_step_does_not_block_when_all_harts_wait(self):
        """回归: 全部 hart 处于 WFI 等待时 step() 不得进入空闲等待.

        修复前 step() 末尾对等待中的 hart 调用 _wfi_sleep_if_idle; 既无定时器
        也无运行超时时该等待的上限为 None, 逐周期驱动固件的用例与调试器的 step
        命令因此永久挂起.
        """
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x10000)
        emu.harts[0]._waiting = True
        waits: list[float | None] = []

        class _Recorder:
            def clear(self) -> None:
                pass

            def wait(self, timeout: float | None) -> bool:
                waits.append(timeout)
                return False

        emu._wake_event = _Recorder()

        assert emu.step() == 0
        assert waits == [], f"step() 不应进入空闲等待, 实际 wait 超时 {waits}"

    def test_pure_python_round_sleeps_when_all_harts_wait(self, monkeypatch):
        """纯 Python 连续执行的一轮在全 hart 等待时仍进入空闲睡眠."""
        emu = Emulator(num_harts=1, ram_base=0x80000000, ram_size=0x10000)
        emu.harts[0]._waiting = True
        calls: list[tuple[int, int]] = []

        def fake_sleep(active, waiting_count):
            calls.append((len(active), waiting_count))

        monkeypatch.setattr(emu, "_wfi_sleep_if_idle", fake_sleep)

        assert emu._run_one_round(emu.harts, 1.0, 0) is False
        assert calls == [(1, 1)]

    def test_drain_rx_only_wakes_on_input(self):
        """回归: 空 drain (无输入) 不得 set _wake_event.

        修复前 drain_rx 无条件 set(_wake_event), RX daemon 每 0.5s 周期
        drain 一次, 事件被无限重新置位 -> _wfi_sleep_if_idle 的 wait 永不
        阻塞 (忙转)。修复后仅在有实际输入搬运到 UART FIFO 时才唤醒。
        """
        uart = UART()
        ev = threading.Event()
        termio = TerminalIO(uart, ev)

        # 空 ring: drain_rx 返回 False, 不 set 事件
        termio._rx_wr.value = 0
        termio._rx_rd.value = 0
        ev.clear()
        ok = termio.drain_rx()
        assert ok is False
        assert not ev.is_set(), "空 drain 不得 set _wake_event"

        # ring 中有字节: drain_rx 返回 True, set 事件
        termio._rx_buf[0] = ord("a")
        termio._rx_wr.value = 1
        termio._rx_rd.value = 0
        ev.clear()
        ok = termio.drain_rx()
        assert ok is True
        assert ev.is_set(), "有输入时应 set _wake_event"

    @pytest.mark.usefixtures("legacy_plic")
    def test_drain_rx_write_through_plic(self):
        """回归: RX 排空必须经 irq_sink write-through 持久 PLIC 数组.

        修复前 drain_rx 仅置 _ext_irq.pending, 不写 FFI 持久数组 (源挂起)。
        batch 运行期间 Rust 内联 plic_recompute_mip 用 batch 起始的旧数组
        (源挂起=0) 覆盖 SEIP -> UART 中断永远投递不出去, 受调试程序在 nohz 空闲
        路径自旋冻结 (make emu-linux-sh 间歇性卡死)。修复后 drain 经
        on_irq (= irq_sink) -> plic.set_irq 内联写穿 pending/
        level, 使 batch 内 Rust 仲裁立即看到 UART 源挂起。
        """
        emu = Emulator(num_harts=1)
        uart = emu.uart
        assert uart is not None and uart._irq == UART_IRQ
        # 模拟受调试程序已使能 rxwm 中断, 即 IE 的 bit1
        uart._ie = 1 << 1
        ev = threading.Event()
        termio = TerminalIO(
            uart,
            ev,
            ext_irq=emu._native_ext_irq,
            on_irq=emu.irq_sink,
        )
        # Rust termio 线程写入 stdin -> ring buffer, daemon drain
        termio._rx_buf[0] = ord("H")
        termio._rx_wr.value = 1
        termio._rx_rd.value = 0
        assert termio.drain_rx() is True
        # write-through: PLIC 持有的共享数组与 ext_irq 通知位同步置位
        assert emu.plic.pending[UART_IRQ] == 1
        assert emu.plic.level[UART_IRQ] == 1
        assert emu._native_ext_irq.pending == 1
        assert ev.is_set()

        # 反向: 受调试程序关闭 RX 中断 (IE=0) 后 drain 不得强制拉高挂起位 —
        # 电平语义, irq_sink 收到真实电平 False 时共享数组清零.
        uart._ie = 0
        uart.clear_rx()
        termio._rx_buf[1] = ord("B")
        termio._rx_wr.value = 2
        termio._rx_rd.value = 1
        emu._native_ext_irq.pending = 0
        assert termio.drain_rx() is True
        assert emu.plic.pending[UART_IRQ] == 0, "IE 关闭时不得虚假挂起"

    @pytest.mark.usefixtures("legacy_plic")
    def test_uart_read_empty_deasserts_level(self):
        """回归: 受调试程序读空 RX FIFO 必须写穿 level=0, 防 Rust complete 重挂起风暴.

        修复前 UART._publish_state 仅更新 Python PLIC 对象, 不写引擎读取的数组。
        batch 运行期间受调试程序读空 FIFO 后, Rust 内联 plic_do_complete 读到陈旧
        level=1 -> 重挂起 pending -> SEIP 再次置位 -> spurious 中断无限循环
        (batch 永不结束, 等价冻结)。修复后 set_irq 写穿 pending/
        level, complete 读到 level=0 不再重挂。
        """
        emu = Emulator(num_harts=1)
        uart = emu.uart
        assert uart is not None and uart._irq == UART_IRQ
        uart._ie = 1 << 1  # 使能 rxwm 中断, 即 IE 的 bit1
        # 数据入队 -> set_irq 写穿: 引擎读取的数组同步置位
        uart.preload(b"AB")
        assert emu.plic.pending[UART_IRQ] == 1
        assert emu.plic.level[UART_IRQ] == 1
        # 模拟受调试程序的中断服务程序逐个读出 FIFO 中的字节; 读空后电平写穿为 0
        uart.read(0x04, 1)
        assert emu.plic.pending[UART_IRQ] == 1, "还有数据时不得 deassert"
        uart.read(0x04, 1)
        assert emu.plic.pending[UART_IRQ] == 0, "读空后不得残留挂起"
        assert emu.plic.level[UART_IRQ] == 0, "读空后陈旧电平不得残留"

    @pytest.mark.usefixtures("legacy_plic")
    def test_uart_ffi_regs_track_device_state_live(self):
        """回归: 寄存器字段随设备状态变化同步到持久 FFI 上下文.

        修复前 _native_marshal_uart 每轮重建 FfiUartCtx 快照, 设备侧的 RX
        daemon 线程在 batch 运行期间填入的新字节对 Rust 不可见, 于是受调试程序
        的中断服务程序读 IP 时得到内联应答 rxwm=0, 判定无接收数据而不读 RXDATA,
        PLIC RX 电平永不清除而引发中断风暴, 表现为 CPU 空转与输入无响应。
        """
        emu = Emulator(num_harts=1)
        uart = emu.uart
        assert uart is not None
        ev = threading.Event()
        emu._termio = TerminalIO(
            uart,
            ev,
            ext_irq=emu._native_ext_irq,
            on_irq=emu.irq_sink,
        )
        emu._init_for_speedup_lib()
        ctx = emu._native_uart_ffi
        assert ctx is not None and ctx is uart._ffi_ctx

        # 数据到达 -> 无需重新 marshal 即可被 native 侧看到
        uart._ie = 1 << 1
        uart.preload(b"AB")
        assert ctx.rx_fifo_len == 2
        assert ctx.ie == 1 << 1
        # 受调试程序逐个从 RXDATA 读出字节后, rx_fifo_len 同步减一
        uart.read(0x04, 1)
        assert ctx.rx_fifo_len == 1
        uart.clear_rx()
        assert ctx.rx_fifo_len == 0
        # marshal 复用同一持久对象, 不重建快照
        assert emu._native_marshal_uart().ffi is ctx
        # 第二轮防线: 绕过 _publish_state 直接改状态 (模拟未来新增的遗漏路径),
        # 每轮 marshal 必须重新同步 — 遗漏至多影响一轮, 不会永久失配.
        uart._ie = 0
        uart._rx_fifo.append(0x5A)
        assert ctx.ie == 1 << 1
        assert emu._native_marshal_uart().ffi is ctx
        assert ctx.ie == 0
        assert ctx.rx_fifo_len == 1


class TestSpeedupPmpBuffers:
    """加速执行期间 PMP 条目数组与各 hart 共享缓冲区的绑定."""

    @staticmethod
    def _make_speedup_emu(num_harts: int = 2) -> Emulator:
        emu = Emulator(num_harts=num_harts)
        assert emu.uart is not None
        emu._termio = TerminalIO(
            emu.uart,
            threading.Event(),
            ext_irq=emu._native_ext_irq,
            on_irq=emu.irq_sink,
        )
        emu._init_for_speedup_lib()
        return emu

    def test_hart_slices_share_buffer(self):
        """每个 hart 的条目数组是共享缓冲区中从 hid*n 开始的切片."""
        emu = self._make_speedup_emu(2)
        n = emu._pmp_num
        assert n > 0
        base_cfg = ctypes.addressof(emu._pmp_cfg_buf)
        base_addr = ctypes.addressof(emu._pmp_addr_buf)
        for hid, hart in enumerate(emu.harts):
            assert len(hart.pmp.flat_cfg) == n
            assert ctypes.addressof(hart.pmp.flat_cfg) == base_cfg + hid * n
            assert ctypes.addressof(hart.pmp.flat_addr) == base_addr + hid * n * 8

    def test_engine_write_syncs_only_changed_hart(self):
        """引擎写入某个 hart 的切片之后只同步该 hart 的 CSR."""
        emu = self._make_speedup_emu(2)
        emu._native_marshal_pmp([])
        emu.harts[1].pmp.flat_cfg[0] = 0x9F
        emu.harts[1].pmp.flat_addr[0] = 0x8000_0000
        emu._native_unmarshal_pmp()
        assert emu.harts[1].csrs["pmpcfg0"].val == 0x9F
        assert emu.harts[1].csrs["pmpaddr0"].val == 0x8000_0000
        assert emu.harts[0].csrs["pmpcfg0"].val == 0
        assert emu.harts[0].csrs["pmpaddr0"].val == 0

    def test_unchanged_buffers_skip_sync(self):
        """数组内容与快照相同时不写 CSR, 切片变化之后才写回."""
        emu = self._make_speedup_emu(1)
        hart = emu.harts[0]
        emu._native_marshal_pmp([])
        hart.csrs["pmpcfg0"].val = 0xAB
        emu._native_unmarshal_pmp()
        assert hart.csrs["pmpcfg0"].val == 0xAB
        hart.pmp.flat_cfg[0] = 0x1F
        emu._native_unmarshal_pmp()
        assert hart.csrs["pmpcfg0"].val == 0x1F
