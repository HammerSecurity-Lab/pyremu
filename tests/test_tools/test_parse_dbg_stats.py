#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026

"""解析工具对带控制字符的日志的处理.

日志文件可能带有 NUL 等控制字符. 名称解析须把控制字符按空白处理, 写表前须把它们
替换为空格, 否则 openpyxl 拒绝写出该单元格.
"""

from __future__ import annotations

from pathlib import Path

from openpyxl import load_workbook

from tools import parse_dbg_stats

CORRUPTED_LOG = (
    "encl_stat<pmp-data-1>(evic,load,flt): 10,11,0\n"
    ">> regress-check load malloc_chur\x00\x00\x00\x00\x00\x00(exited): PASS\n"
)


def write_log(tmp_path: Path) -> Path:
    path = tmp_path / "rec.log"
    path.write_text(CORRUPTED_LOG, encoding="utf-8")
    return path


def test_control_chars_in_name_are_matched_as_space(tmp_path):
    """名称后的控制字符按空白处理, 名称取控制字符之前的部分."""
    patterns = parse_dbg_stats.compile_patterns(None)
    parsed = parse_dbg_stats.parse_log(write_log(tmp_path), patterns, "after")
    assert [item.name for item in parsed.items] == ["malloc_chur"]


def test_xlsx_written_when_log_line_has_control_chars(tmp_path):
    """带控制字符的日志行写表时不触发 IllegalCharacterError."""
    patterns = parse_dbg_stats.compile_patterns(None)
    parsed = parse_dbg_stats.parse_log(write_log(tmp_path), patterns, "after")
    columns = parse_dbg_stats.build_columns({"pmp"})
    rows = parse_dbg_stats.build_rows(parsed, {"pmp"}, set())

    output = tmp_path / "stats.xlsx"
    parse_dbg_stats.write_xlsx(output, rows, columns)

    sheet = load_workbook(output).active
    for row in sheet.iter_rows(values_only=True):
        for value in row:
            if isinstance(value, str):
                assert not parse_dbg_stats.CONTROL_CHARS.search(value)
    assert sheet.cell(row=2, column=1).value == "malloc_chur"


def test_write_xlsx_replaces_control_chars(tmp_path):
    """写出时把单元格中的控制字符替换为空格, 与名称解析路径无关."""
    output = tmp_path / "stats.xlsx"
    rows = [{"test": "a\x00b\x07c", "status": "PASS"}]
    parse_dbg_stats.write_xlsx(output, rows, ["test", "status"])

    sheet = load_workbook(output).active
    assert sheet.cell(row=2, column=1).value == "a b c"
