from collections.abc import Callable
import io
import sys

import pytest
from rich.console import Console

from pyremu.configs_aux import force_config
from pyremu.core.decoder import Hart
from pyremu.debug import Debugger
from pyremu.emulator import Emulator
from pyremu.platform import PeripheralConfig, PlatformConfig
from pyremu.utils.parse_bin import FirmwareImage

AIA_IMSIC_M_BASE = 0x2400_0000
AIA_IMSIC_S_BASE = 0x2800_0000
AIA_APLIC_S_BASE = 0x0C00_0000
AIA_APLIC_M_BASE = 0x0C00_8000

TEST_RAM_BASE = 0x8000_0000


def make_test_config(
    *,
    num_harts: int = 1,
    ram_base: int = TEST_RAM_BASE,
    ram_size: int | None = None,
    prog_cnt: int | None = None,
    pmp_entries: int | None = None,
    **periph_fields: int,
) -> PlatformConfig:
    """构造测试用的平台配置.

    RAM 基址与程序装载地址固定为 0x8000_0000, 不随 mk/ 下的编译选项变化.
    prog_cnt 缺省时与 ram_base 相同, ram_size 缺省时取 PlatformConfig 的默认值.
    其余字段取默认值, periph_fields 按 PeripheralConfig 的字段名传入.
    """
    config = PlatformConfig(
        num_harts=num_harts,
        ram_base=ram_base,
        prog_cnt=ram_base if prog_cnt is None else prog_cnt,
        periph=PeripheralConfig(**periph_fields),
    )
    if ram_size is not None:
        config.ram_size = ram_size
    if pmp_entries is not None:
        config.pmp_entries = pmp_entries
    return config


def make_test_emu(
    *,
    num_harts: int = 1,
    ram_size: int | None = None,
    ram_base: int = TEST_RAM_BASE,
    prog_cnt: int | None = None,
    pmp_entries: int | None = None,
    **periph_fields: int,
) -> Emulator:
    """按测试平台配置构造 Emulator, 参数含义同 make_test_config."""
    return Emulator(
        make_test_config(
            num_harts=num_harts,
            ram_size=ram_size,
            ram_base=ram_base,
            prog_cnt=prog_cnt,
            pmp_entries=pmp_entries,
            **periph_fields,
        )
    )


def make_test_ram(
    size: int = 2 * 1024 * 1024,
    *,
    has_bounds_check: bool = False,
) -> tuple[bytearray, Callable[[int, int], bytes], Callable[[int, bytes], None]]:
    """构造模拟物理内存, 返回 (内存, 读函数, 写函数).

    读写函数以内存数组内的偏移为地址. has_bounds_check 为真时越界读返回同样长度的
    零字节, 越界写被丢弃; 为假时读按切片截短, 越界写抛出 IndexError.
    """
    ram = bytearray(size)

    def read_fn(addr: int, length: int) -> bytes:
        if has_bounds_check and (addr < 0 or addr + length > len(ram)):
            return b"\x00" * length
        return bytes(ram[addr : addr + length])

    def write_fn(addr: int, data: bytes) -> None:
        if has_bounds_check and (addr < 0 or addr + len(data) > len(ram)):
            return
        for i, b in enumerate(data):
            ram[addr + i] = b

    return ram, read_fn, write_fn


class DbgTestBase:
    """调试器操作类单元测试的通用基类.

    提供 _emu、_hart_id、_console 与 hart 属性; 子类把被测操作类放在本类之后.
    """

    def __init__(self, emu: Emulator, hart_id: int = 0) -> None:
        self._emu = emu
        self._hart_id = hart_id
        self._console = Console(highlight=False)

    @property
    def hart(self) -> Hart:
        return self._emu.harts[self._hart_id]

    def _warn(self, _msg: str) -> None:
        pass

    def _err(self, _msg: str) -> None:
        pass


def make_test_dbg(
    *,
    num_harts: int = 1,
    ram_size: int = 0x10000,
    prog_cnt: int = 0x1000,
    image: FirmwareImage | None = None,
    is_code_loaded: bool = True,
    **periph_fields: int,
) -> Debugger:
    """按测试平台配置构造 Emulator 与 Debugger.

    is_code_loaded 为真时在 prog_cnt 处写入一条 NOP 指令.
    periph_fields 按 PeripheralConfig 的字段名传入, 用于启用默认配置未注册的外设.
    """
    emu = make_test_emu(
        num_harts=num_harts,
        ram_size=ram_size,
        prog_cnt=prog_cnt,
        **periph_fields,
    )
    if is_code_loaded:
        emu.load_code(prog_cnt, b"\x13\x00\x00\x00")
    return Debugger(emulator=emu, hart_id=0, image=image)


def make_test_dbg_buffered(**kwargs) -> tuple[Debugger, Emulator, io.StringIO]:
    """构造 Debugger 并把输出重定向到内存缓冲区, 参数含义同 make_test_dbg.

    终端 I/O 管理器置空, 使用例不经宿主标准输入输出.
    """
    dbg = make_test_dbg(**kwargs)
    emu = dbg._emu
    emu._termio = None
    buf = io.StringIO()
    dbg._console = Console(file=buf, highlight=False, width=200)
    return dbg, emu, buf


@pytest.fixture
def hart() -> Hart:
    """带模拟物理内存后端的 hart."""
    h = Hart(id=0)
    _, read_fn, write_fn = make_test_ram()
    h.mem_read_phy = read_fn
    h.mem_write_phy = write_fn
    return h


@pytest.fixture(autouse=True)
def _mock_stdin_fileno(monkeypatch):
    """
    因为 pytest 的 DontReadFromInput
    的 fileno() 抛 UnsupportedOperation, 而 Debugger.__init__ 需要它来捕获 stdin fd.
    """
    monkeypatch.setattr(sys.stdin, "fileno", lambda: 0)


@pytest.fixture
def legacy_plic():
    """强制 legacy PLIC 模式 (PYREMU_AIA=0), 供测试 PLIC 内联/直写契约的用例.

    编译期开关 PYREMU_AIA=1 时 Emulator 默认走 AIA (IMSIC+APLIC), 不再创建
    PLIC; 本 fixture 局部覆盖回 legacy, 用例结束自动恢复, 不污染后续测试.
    """
    with force_config("PYREMU_AIA", 0):
        yield


@pytest.fixture
def make_aia_config():
    """返回 AIA 平台配置构造器, 按 hart 数构造."""

    def _make(num_harts: int = 1) -> PlatformConfig:
        cfg = PlatformConfig.basic_aia_machine()
        cfg.num_harts = num_harts
        cfg.periph.imsic_m_base = AIA_IMSIC_M_BASE
        cfg.periph.imsic_s_base = AIA_IMSIC_S_BASE
        cfg.periph.aplic_s_base = AIA_APLIC_S_BASE
        cfg.periph.aplic_m_base = AIA_APLIC_M_BASE
        return cfg

    return _make


@pytest.fixture
def make_aia_emu(make_aia_config):
    """返回按 hart 数创建 AIA 模式 Emulator的构造器."""

    def _make(num_harts: int = 1) -> Emulator:
        return Emulator(make_aia_config(num_harts))

    return _make
