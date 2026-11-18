#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT

"""给动态库函数赋 ctypes 签名.

签名条目由 ``defs_gen.py`` 给出, 该生成物取自 Rust 侧 LLVM IR 的 DI 元数据;
本模块只负责把条目逐条设置到 ``ctypes.CDLL`` 的函数对象上.
"""

from __future__ import annotations

from collections.abc import Iterable
import ctypes


def bind_functions(
    lib: ctypes.CDLL,
    entries: Iterable[tuple[str, object, list]],
) -> None:
    """按 *entries* 逐条给 *lib* 中的函数赋值签名.

    每条为 ``(函数名, 返回类型, 参数类型列表)``, 类型已是 ctypes 对象.
    """
    for name, restype, argtypes in entries:
        fn = getattr(lib, name)
        fn.argtypes = list(argtypes)
        fn.restype = restype
