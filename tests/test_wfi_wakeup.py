"""WFI 被跨核 MSIP 唤醒的正确性测试 — 最小多核场景."""

import struct
import threading

import pytest

from pyremu.core.hart import RiscvMode
from pyremu.core.priv_defs import MSTATUS_MIE
from pyremu.emulator import Emulator
from pyremu.interrupt.clint import CLINT
from pyremu.memory.bus import Bus
from pyremu.platform import PlatformConfig
from tests.conftest import make_test_emu
from tests.hart_helpers import (
    make_hart,
    make_pmp,
    set_mie,
    set_msip,
)

CLINT_BASE = 0x02000000


class TestWFIMsipWakeup:
    """H0 写 MSIP 使 H1 从 WFI 唤醒."""

    @pytest.fixture
    def emu_two_harts(self):
        cfg = PlatformConfig(
            num_harts=2,
            ram_base=0x80000000,
            ram_size=64 * 1024 * 1024,
        )
        emu = Emulator(cfg, bootargs="")
        return emu

    @staticmethod
    def _setup_harts(emu):
        for h in emu.harts:
            h.mode = RiscvMode.M
            h.satp_val = 0
            mtvec = 0x80000000 + h.id * 0x100
            h.csrs["mtvec"].val = mtvec
            emu.bus.write(mtvec, struct.pack("<I", 0x30200073))  # mret
            h.csrs["mie"].val = 1 << 3  # MSIE
            h.csrs["mstatus"].val = 1 << 3  # MIE=1

    def test_msip_wakes_wfi_hart_native(self, emu_two_harts):
        """原生 batch 路径: MSIP 唤醒 WFI hart.

        验证:
        1. H1 进入 WFI ->state.waiting = 1
        2. H0 写 CLINT MSIP[1] = 1
        3. 下一个 step() 后 H1 不再 waiting, 且已处理中断
        """
        emu = emu_two_harts
        self._setup_harts(emu)
        _, h1 = emu.harts[0], emu.harts[1]

        # 在 H1 的 PC 位置写入 WFI 指令 + 自旋
        wfi_loop = struct.pack("<I", 0x10500073)  # wfi
        emu.bus.write(0x80000100, wfi_loop)  # H1 PC
        h1.pc = 0x80000100

        # H0 先运行几步, 让 H1 有机会执行 WFI
        # step() 会让两个 hart 各执行一条指令
        for _ in range(5):
            emu.step()

        # H1 应该已经执行了 WFI 进入 waiting
        assert h1._waiting, (
            f"H1 should be in WFI state, got waiting={h1._waiting}"
        )

        # H0 写 CLINT MSIP[1] = 1
        msip1_pa = CLINT_BASE + 4
        emu.bus.write(msip1_pa, struct.pack("<I", 1))

        # 再 step
        emu.step()

        # H1 应该已被唤醒 (waiting=False)
        assert not h1._waiting, (
            f"H1 should have woken up from WFI after MSIP, "
            f"but waiting={h1._waiting}, mode={h1.mode.name}, "
            f"pc={h1.pc:#010x}, mip={h1.mip_val:#x}, mie={h1.mie_val:#x}"
        )

    def test_msip_wakes_wfi_hart_pure_python(self, emu_two_harts):
        """纯 Python 路径: MSIP 唤醒 WFI hart."""
        self.test_msip_wakes_wfi_hart_native(emu_two_harts)

    def test_no_msip_wfi_stays_waiting(self, emu_two_harts):
        """无 MSIP 时 WFI 保持等待."""
        emu = emu_two_harts
        self._setup_harts(emu)
        h0, h1 = emu.harts[0], emu.harts[1]
        # H0 做 NOP 循环 (避免在 PC=0 触发非法指令 trap)
        emu.bus.write(0x80000200, struct.pack("<I", 0x00000013))  # nop
        h0.pc = 0x80000200
        # H1 执行 WFI
        emu.bus.write(0x80000100, struct.pack("<I", 0x10500073))  # wfi
        h1.pc = 0x80000100
        for _ in range(5):
            emu.step()
        assert h1._waiting, (
            f"H1 should still be in WFI (no MSIP sent), "
            f"got waiting={h1._waiting}"
        )
        assert h1.pc == 0x80000104, (
            f"H1 PC should advance past WFI, got {h1.pc:#010x}"
        )


# 指令编码
LUI_X5_CLINT = 0x020002B7  # lui x5, 0x2000
ADDI_X5_X5_4 = 0x00428293  # addi x5, x5, 4
ADDI_X6_X0_1 = 0x00100313  # addi x6, x0, 1
SW_X6_0_X5 = 0x0062A023  # sw x6, 0(x5)
SW_X0_0_X5 = 0x0002A023  # sw x0, 0(x5)
LUI_X7_RAM = 0x800003B7  # lui x7, 0x80000, 结果为符号扩展的 0xffffffff80000000
SLLI_X7_X7_32 = 0x02039393  # slli x7, x7, 32
SRLI_X7_X7_32 = 0x0203D393  # srli x7, x7, 32
ADDI_X8_X0_MARK = 0x05500413  # addi x8, x0, 0x55
SW_X8_0X40_X7 = 0x0483A023  # sw x8, 0x40(x7)
WFI_INSTR = 0x10500073  # wfi
MRET_INSTR = 0x30200073  # mret
J_SELF = 0x0000006F  # jal x0, 0

# hart1 唤醒后写入的标记地址
MARK_ADDR = 0x8000_0040
MARK_VALUE = 0x55


class TestMsipStoreInNativeBatch:
    """hart0 经指令写 CLINT 的 MSIP 寄存器, 唤醒在 WFI 中等待的 hart1.

    ``Emulator.step`` 只走纯 Python 执行路径, 写 CLINT 落在 Python 侧的
    设备实现上; 连续执行由加速执行引擎并发运行各 hart, 该写入落在 Rust 侧的
    ``try_handle_clint_concurrent``. 本组用例进入 ``run()``, 覆盖后一条路径.
    """

    @pytest.fixture
    def emu_two_harts(self):
        cfg = PlatformConfig(
            num_harts=2,
            ram_base=0x80000000,
            ram_size=64 * 1024 * 1024,
        )
        return Emulator(cfg, bootargs="")

    @staticmethod
    def _setup_harts(emu: Emulator) -> None:
        for h in emu.harts:
            h.mode = RiscvMode.M
            h.satp_val = 0
            mtvec = 0x8000_1000 + h.id * 0x100
            h.csrs["mtvec"].val = mtvec
            # 陷态处理函数向本 hart 的 MSIP 写入 0 再返回: 进入陷态不清除挂起位,
            # 中断源须由软件撤销, 否则 mret 后立即再次进入陷态
            msip_addr = 4 * h.id
            msip_imm = (msip_addr << 20) | (5 << 15) | (5 << 7) | 0x13
            for index, instr in enumerate(
                (LUI_X5_CLINT, msip_imm, SW_X0_0_X5, MRET_INSTR)
            ):
                emu.bus.write(mtvec + index * 4, struct.pack("<I", instr))
            h.csrs["mie"].val = 1 << 3  # MSIE
            h.csrs["mstatus"].val = 1 << 3  # MIE

    @staticmethod
    def _run_until_pause(emu: Emulator) -> None:
        """运行连续执行, 经设备暂停事件使 run() 返回.

        hart0 以自跳转结束, 不会自行停机, 故以定时器调用 notify_processor.
        """
        timer = threading.Timer(0.05, emu.notify_processor)
        timer.start()
        try:
            emu.run()
        finally:
            timer.cancel()

    def test_hart_store_to_msip_wakes_waiting_hart(self, emu_two_harts):
        """hart0 写 MSIP[1] 后, hart1 离开 WFI 并执行后继指令.

        先经单步让 hart1 进入 WFI 再启动连续执行: 两个 hart 同时开始执行时,
        写 MSIP 的时序可能早于 hart1 执行 WFI, 此时中断在 WFI 之前投递, 不经过
        唤醒路径.
        """
        emu = emu_two_harts
        self._setup_harts(emu)
        h0, h1 = emu.harts[0], emu.harts[1]
        # hart1: WFI 唤醒后向 MARK_ADDR 写入标记, 再自跳转
        h1_code = [
            WFI_INSTR,
            LUI_X7_RAM,
            SLLI_X7_X7_32,
            SRLI_X7_X7_32,
            ADDI_X8_X0_MARK,
            SW_X8_0X40_X7,
            J_SELF,
        ]
        for index, instr in enumerate(h1_code):
            emu.bus.write(0x8000_0100 + index * 4, struct.pack("<I", instr))
        h1.pc = 0x8000_0100
        # hart0 先执行自跳转, 使 hart1 有机会进入 WFI
        emu.bus.write(0x8000_0300, struct.pack("<I", J_SELF))
        h0.pc = 0x8000_0300
        for _ in range(8):
            emu.step()
            if h1._waiting:
                break
        assert h1._waiting, "hart1 未进入 WFI 等待"
        # hart0: 向 0x20000004 写入 1, 再自跳转
        h0_code = [
            LUI_X5_CLINT,
            ADDI_X5_X5_4,
            ADDI_X6_X0_1,
            SW_X6_0_X5,
            J_SELF,
        ]
        for index, instr in enumerate(h0_code):
            emu.bus.write(0x8000_0200 + index * 4, struct.pack("<I", instr))
        h0.pc = 0x8000_0200

        self._run_until_pause(emu)

        raw = emu.bus.read(MARK_ADDR, 4)
        assert struct.unpack("<I", raw)[0] == MARK_VALUE, (
            f"hart1 未在唤醒后写入标记: waiting={h1._waiting}, pc={h1.pc:#x}, "
            f"mip={h1.mip_val:#x}, mie={h1.mie_val:#x}, msip={emu.clint._msip}"
        )


class TestWfiCrossHartWake:
    """WFI 等待的 hart 应能被另一 hart 的 MSIP 唤醒."""

    def test_wfi_wake_by_msip_python(self):
        bus = Bus(ram_base=0x80000000, ram_size=128 * 1024 * 1024)
        clint = CLINT(num_harts=2)
        h1 = make_hart(1, bus, clint, make_pmp())

        h1._waiting = True
        set_mie(h1, 1 << 3)
        set_msip(clint, 1, 1)

        h1.sync_pending_interrupts()
        awakened = h1.wake_hart_from_wfi()
        assert awakened, "MSIP=1 时应唤醒 WFI"
        assert not h1._waiting, "唤醒后 _waiting 应为 False"

    def test_wfi_native_batch_wake(self):
        """Rust batch 中 WFI hart 应被 CLINT MSIP 唤醒."""
        cfg = PlatformConfig(
            num_harts=2,
            ram_base=0x80000000,
            ram_size=128 * 1024 * 1024,
        )
        emu = Emulator(cfg)
        h0, h1 = emu.harts

        h1._waiting = True
        set_mie(h1, 1 << 3)
        h1.mode = RiscvMode.M
        emu.clint._msip[1] = 1

        emu.step()
        assert not h1._waiting, f"native batch 后 H1 _waiting={h1._waiting}"


class TestWfiWakeupMsipNeedsMsie:
    """WFI 唤醒: 挂起的中断还须在 mie 中使能.

    RISC-V 特权规范 §3.6.1: 任一挂起且已使能的中断使 WFI 恢复执行, 与
    mstatus.MIE 无关; mie 中未使能的挂起中断不构成唤醒来源. MSIP 挂起而
    mie.MSIE 为 0 时 hart 继续等待, 由受调试程序置位 MSIE 后才被唤醒.
    """

    @staticmethod
    def _setup_msip_handler(emu: Emulator):
        """MSIP 陷态处理函数 @ 0x80000000: 写 0 到 CLINT MSIP 后 mret.

        hart 处于 M 模式且 mstatus.MIE=1, mie 由调用方设置.
        """
        h = emu.harts[0]
        # lui  t0, 0x02000  -> t0 = 0x02000000 (CLINT 基址)
        # sw   x0, 0(t0)    -> CLINT MSIP[hart0] = 0
        # mret
        emu.bus.write_ram_direct(0x80000000, (0x020002B7).to_bytes(4, "little"))
        emu.bus.write_ram_direct(0x80000004, (0x0002A023).to_bytes(4, "little"))
        emu.bus.write_ram_direct(0x80000008, (0x30200073).to_bytes(4, "little"))
        h.csrs["mtvec"].val = 0x80000000
        h.mode = RiscvMode.M
        h.mstatus_val |= MSTATUS_MIE
        h.pc = 0x8000000C  # 用户代码起点 (处理函数占 12 字节)

    @pytest.mark.parametrize("use_native", [False, True])
    def test_wfi_keeps_waiting_with_msie_zero(self, use_native):
        """CLINT MSIP=1 且 mie.MSIE=0 时 wake_hart_from_wfi 返回 False."""
        emu = make_test_emu(ram_size=1024 * 1024)
        h = emu.harts[0]
        h.mode = RiscvMode.M
        h.mstatus_val |= MSTATUS_MIE
        set_mie(h, 0)  # MSIE=0
        set_msip(emu.clint, 0, 1)

        # 手工置 WFI 等待
        h._waiting = True

        h.sync_pending_interrupts()
        result = h.wake_hart_from_wfi()
        assert not result, (
            f"[{'native' if use_native else 'python'}] "
            "CLINT MSIP=1 但 MSIE=0: wake_hart_from_wfi 应返回 False"
        )
        assert h._waiting, "WFI 等待标志应保持"
        assert not h._wfi_woken, "未唤醒时 wfi_woken 不应置位"

    @pytest.mark.parametrize("use_native", [False, True])
    def test_sync_writes_mip_without_changing_mie(self, use_native):
        """同步硬件中断源只写 mip, 不改变 mie.MSIE."""
        emu = make_test_emu(ram_size=1024 * 1024)
        h = emu.harts[0]
        h.mode = RiscvMode.M
        h.mstatus_val |= MSTATUS_MIE
        set_mie(h, 0)  # MSIE=0
        set_msip(emu.clint, 0, 1)
        h._waiting = True

        h.sync_pending_interrupts()

        assert (h._csr_read_raw("mie") & (1 << 3)) == 0, (
            f"[{'native' if use_native else 'python'}] 同步之后 MSIE 应仍为 0"
        )
        assert (h.mip_val & (1 << 3)) != 0, "MSIP 挂起应写入 mip"

    @pytest.mark.parametrize("use_native", [False, True])
    def test_msip_wakes_and_traps_after_msie_set(self, use_native):
        """置位 MSIE 之后 MSIP 唤醒 hart 并投递到 M 模式陷态处理函数."""
        emu = make_test_emu(ram_size=1024 * 1024)
        self._setup_msip_handler(emu)
        h = emu.harts[0]
        set_mie(h, 0)
        set_msip(emu.clint, 0, 1)
        h._waiting = True

        h.sync_pending_interrupts()
        assert not h.wake_hart_from_wfi(), "MSIE=0 时不应唤醒"

        h._csr_write_raw("mie", 1 << 3)
        h.sync_pending_interrupts()
        assert h.wake_hart_from_wfi(), "MSIE=1 时 MSIP 应唤醒"
        assert not h._waiting

        assert h.check_pending_interrupts(), "MSIP 应投递到 M 模式"
        assert h.pc == 0x80000000, "pc 应跳到 mtvec"
        mcause = h.mcause_val
        assert mcause >> 63 == 1, "mcause 的中断位应为 1"
        assert (mcause & 0x7FFF_FFFF) == 3, "mcause 的中断码应为 MSIP"
        assert emu.clint._msip[0] == 1, "投递不改变 CLINT 的 MSIP"

    @pytest.mark.parametrize("use_native", [False, True])
    def test_wfi_wakeup_msie_enabled_no_spurious_halt(self, use_native):
        """MSIE=1 时 MSIP 唤醒并投递, 处理函数清除中断源, 不应 halted."""
        emu = make_test_emu(ram_size=1024 * 1024)
        self._setup_msip_handler(emu)
        h = emu.harts[0]

        # WFI @ 0x8000000C — 处理函数 mret 之后执行, 进入等待并退出批次
        emu.bus.write_ram_direct(0x8000000C, (0x10500073).to_bytes(4, "little"))

        set_mie(h, 1 << 3)  # MSIE=1
        set_msip(emu.clint, 0, 1)

        emu.step()

        assert not h._halted, (
            f"[{'native' if use_native else 'python'}] MSIP 唤醒不应 halted"
        )

    def test_wfi_wakeup_with_mie_msie_also_works(self):
        """mie.MSIE=1 的正常路径不受影响."""
        emu = make_test_emu(ram_size=1024 * 1024)
        h = emu.harts[0]
        h.mode = RiscvMode.M
        h.mstatus_val |= MSTATUS_MIE
        set_mie(h, 1 << 3)  # MSIE=1
        set_msip(emu.clint, 0, 1)
        h._waiting = True

        h.sync_pending_interrupts()
        assert h.wake_hart_from_wfi(), "MSIE=1 时 MSIP 应正常唤醒"
        assert not h._waiting

    def test_wfi_wakeup_no_interrupt_no_wake(self):
        """无待处理中断时 WFI 不应被唤醒."""
        emu = make_test_emu(ram_size=1024 * 1024)
        h = emu.harts[0]
        h.mode = RiscvMode.M
        h.mstatus_val |= MSTATUS_MIE
        set_mie(h, 1 << 3)  # MSIE=1
        set_msip(emu.clint, 0, 0)  # MSIP=0
        h._waiting = True

        h.sync_pending_interrupts()
        assert not h.wake_hart_from_wfi(), "无待处理中断时不应唤醒"
        assert h._waiting, "WFI 等待标志应保持"
