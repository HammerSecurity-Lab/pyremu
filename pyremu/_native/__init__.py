#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import atexit
from contextlib import suppress
import ctypes
import os
from pathlib import Path
import shutil
import sys
import tempfile

from loguru import logger

try:
    from pyremu._native import defs_gen
except ImportError as exc:
    raise ImportError(
        "缺少 FFI 定义生成物 pyremu/_native/defs_gen.py, 请先执行 make ffi-defs"
    ) from exc

from pyremu._native.export_lib_syms import bind_functions
from pyremu.utils.file_ops import abs_dir

_EXT = {"linux": ".so", "darwin": ".dylib", "win32": ".dll"}.get(
    sys.platform, ".so"
)
# 结构体与导出函数签名由 defs_aux.py 从 Rust 侧 LLVM IR 的 DI 元数据生成,
# 生成物与 Rust 定义不一致时须重新生成.
_STRUCTS = defs_gen.STRUCTS
_NATIVE_DIR = abs_dir(__file__)
_LIB_PATH = _NATIVE_DIR / f"libdecode{_EXT}"
_lib: ctypes.CDLL | None = None
_tmp_so_path: str | None = None


def _newest_rust_source() -> float:
    """返回 Rust 源码中最新的修改时间; 找不到源码时返回 0."""
    roots = [
        abs_dir(__file__) / "cpu" / "src",
        abs_dir(__file__) / "termio" / "src",
    ]
    newest = 0.0
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*.rs"):
            newest = max(newest, path.stat().st_mtime)
    return newest


def _warn_if_stale(lib_path: Path) -> None:
    """加速库比 Rust 源码旧时给出提示.

    直接以 python -m pyremu.debugger 启动不经过 make, 不会重编加速库; 此时运行
    的是旧实现, 排查源码改动时极易误判. 经 make emu-linux-sh 启动无此问题.
    """
    with suppress(OSError):
        if _newest_rust_source() <= lib_path.stat().st_mtime:
            return
        logger.warning(
            "{} 比 Rust 源码旧, 当前运行的是旧实现; "
            "请先执行 make build-native 重新编译",
            lib_path.name,
        )


def _load_lib_safe(lib_path: Path) -> ctypes.CDLL | None:
    global _tmp_so_path  # noqa: PLW0603 — intentional module-level tracking
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".so", prefix="libdecode_")
        os.close(fd)
        shutil.copy2(str(lib_path), tmp_path)
        _tmp_so_path = tmp_path
        atexit.register(_cleanup_tmp_so)
        return ctypes.CDLL(tmp_path)
    except (OSError, IOError) as exc:
        logger.warning("Failed to create temp copy of {}: {}", lib_path, exc)
        try:
            return ctypes.CDLL(str(lib_path))
        except OSError:
            return None


def _cleanup_tmp_so() -> None:
    if _tmp_so_path is None:
        return
    with suppress(OSError):
        os.unlink(_tmp_so_path)


try:
    _warn_if_stale(_LIB_PATH)
    _lib = _load_lib_safe(_LIB_PATH)
    if _lib is None:
        raise OSError(f"无法加载 {_LIB_PATH.name}")
    bind_functions(_lib, defs_gen.FUNCTIONS["cpu"])

except OSError as exc:
    logger.warning(
        "无法加载 native 加速库 ({}): {} — 降级为性能较低的纯 Python 实现",
        _LIB_PATH.name,
        exc,
    )
    _lib = None


def __getattr__(name: str):
    """生成的结构体类由 defs_gen 转出, 本模块不逐名登记."""
    try:
        return getattr(defs_gen, name)
    except AttributeError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from None


def native_available() -> bool:
    return _lib is not None


def loaded_lib() -> ctypes.CDLL | None:
    """返回已装载的动态库句柄; 未装载时为 None.

    ``ops`` 层据此选择后端. 每次调用都读模块级 ``_lib``, 使替换该全局变量的
    用例与运行期卸载同样生效.
    """
    return _lib


_TERMIO_LIB_PATH = _NATIVE_DIR / f"libtermio{_EXT}"
_termio_lib: ctypes.CDLL | None = None


try:
    _termio_lib = _load_lib_safe(_TERMIO_LIB_PATH)
    if _termio_lib is None:
        raise OSError(f"无法加载 {_TERMIO_LIB_PATH.name}")

    bind_functions(_termio_lib, defs_gen.FUNCTIONS["termio"])

except OSError as exc:
    logger.warning(
        "无法加载 terminal I/O 加速库 ({}): {} — 降级为 Python 轮询 stdin",
        _TERMIO_LIB_PATH.name,
        exc,
    )


def termio_available() -> bool:
    """Return ``True`` if the terminal I/O library (libtermio.so) is loaded."""
    return _termio_lib is not None


def termio_start(handle: defs_gen.TermIoHandle) -> int:
    """Start the terminal I/O background thread in Rust (raw mode).

    *handle* 由调用方 (TerminalIO) 构建; 其指针字段指向的缓冲区必须
    存活至线程退出。

    Returns 0 on success, -1 on error (thread already running or stdin
    is not a TTY), -2 if libtermio.so is not available.
    """
    if not termio_available():
        return -2  # not available
    return _termio_lib.terminal_io_start(ctypes.byref(handle))


def termio_stop() -> None:
    """Signal the I/O thread to stop and wait for it to exit."""
    if not termio_available():
        return
    _termio_lib.terminal_io_stop()


def termio_attach(handle: defs_gen.TermIoHandle) -> int:
    """Attach I/O thread to already-configured fds (no termios changes)."""
    if not termio_available():
        return -2
    return _termio_lib.terminal_io_attach(ctypes.byref(handle))


def termio_is_running() -> bool:
    """Return True if the terminal I/O thread is currently running."""
    if not termio_available():
        return False
    return _termio_lib.terminal_io_is_running() != 0


def termio_set_emu_stop_flag(ptr: int) -> None:
    """把 CPU 引擎停止标志地址注入 termio 线程, 供 Ctrl+Q 直连置位.

    *ptr* 为 ``ctypes.addressof(emu._native_stop_flag)``. termio 线程检测到
    Ctrl+Q 时直接写该标志, 绕过 SIGINT -> Python handler 往返 (主线程阻塞在
    run_parallel 时信号处理器不执行, 直连路径保证 Rust 引擎仍能即时停止).
    """
    if not termio_available():
        return
    _termio_lib.terminal_io_set_emu_stop_flag(ptr)
