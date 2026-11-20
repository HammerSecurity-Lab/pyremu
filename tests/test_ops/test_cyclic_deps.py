#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
"""
循环依赖检查。
预期上理应只有下列包导入generic_ops定义
且不得提供导出定义到generic_ops。
    emu
    debug
    memory
    termio
"""

from __future__ import annotations

import ast
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_GENERIC_OPS_DIR = _PROJECT_ROOT / "pyremu" / "generic_ops"
_LOWER_LAYER_DIRS = (
    _PROJECT_ROOT / "pyremu" / "_native",
    _PROJECT_ROOT / "pyremu" / "core",
    _PROJECT_ROOT / "pyremu" / "decoder",
    _PROJECT_ROOT / "pyremu" / "utils",
)
_ALLOWED_PREFIXES = (
    "pyremu._native",
    "pyremu.core.priv_defs",
    "pyremu.decoder",
    "pyremu.generic_ops",
    "pyremu.utils",
)


def _imports(path: Path) -> list[tuple[int, str]]:
    """返回文件内全部 pyremu 导入的 (行号, 模块全名)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(
                (node.lineno, alias.name)
                for alias in node.names
                if alias.name == "pyremu" or alias.name.startswith("pyremu.")
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "pyremu":
                found.extend(
                    (node.lineno, f"pyremu.{alias.name}")
                    for alias in node.names
                )
            elif module.startswith("pyremu."):
                found.append((node.lineno, module))
    return found


def _violations(path: Path, is_allowed) -> list[str]:
    return [
        f"{path.relative_to(_PROJECT_ROOT)}:{lineno}: {module}"
        for lineno, module in _imports(path)
        if not is_allowed(module)
    ]


def test_generic_ops_imports_only_backends_and_helpers():
    """generic_ops 只导入实现后端与公共工具."""
    bad: list[str] = []
    for path in sorted(_GENERIC_OPS_DIR.rglob("*.py")):
        bad += _violations(path, lambda m: m.startswith(_ALLOWED_PREFIXES))
    assert not bad, "\n".join(bad)


def test_lower_layers_do_not_import_generic_ops():
    """不应出现循环依赖."""
    bad: list[str] = []
    for root in _LOWER_LAYER_DIRS:
        for path in sorted(root.rglob("*.py")):
            bad += _violations(
                path,
                lambda m: not m.startswith("pyremu.generic_ops"),
            )
    assert not bad, "generic_ops导入了自身的导出:\n" + "\n".join(bad)
