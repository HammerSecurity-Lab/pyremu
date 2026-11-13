# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""RISC-V ISA 字符串的解析与编码.

旧式 ``riscv,isa`` 字符串与 ``riscv,isa-extensions`` 扩展名列表都归一为
小写扩展名列表, 再由该列表给出引擎侧的扩展开关与 misa 的取值.
"""

from __future__ import annotations

from collections.abc import Iterable

# 单字母缩写 "g" 展开为的扩展.
_G_EXPANSION = ("i", "m", "a", "f", "d", "zicsr", "zifencei")

# 单字母段中开始一个多字母扩展名的字符: z 为已批准的扩展, x 为厂商自定义扩展,
# s 为监督级扩展. 字母表本身不把这三个字符用作单字母扩展.
_MULTI_LETTER_START = frozenset("zxs")

# 加速执行引擎侧 IsaExts 结构登记的全部扩展开关: 扩展名到结构字段名.
# 字段名与顺序必须与 Rust ``state::IsaExts`` 和 ctypes ``IsaExtsC`` 一致.
# 只登记引擎可能据以判定行为的扩展; 模拟器不解析的其余名称在编码时忽略.
ISA_EXT_FIELDS: dict[str, str] = {
    "i": "is_i",
    "m": "is_m",
    "a": "is_a",
    "f": "is_f",
    "d": "is_d",
    "c": "is_c",
    "b": "is_b",
    "h": "is_h",
    "v": "is_v",
    "zicsr": "is_zicsr",
    "zifencei": "is_zifencei",
    "zbb": "is_zbb",
    "zba": "is_zba",
    "zbs": "is_zbs",
    "zfh": "is_zfh",
    "zihpm": "is_zihpm",
    "zicntr": "is_zicntr",
    "sstc": "is_sstc",
    "smaia": "is_smaia",
    "ssaia": "is_ssaia",
    "smepmp": "is_smepmp",
}


def encode_isa_exts(names: Iterable[str]) -> dict[str, bool]:
    """把扩展名集合整理为引擎侧 ``IsaExts`` 各字段的取值.

    表中未登记的扩展名 (如厂商扩展) 不影响任何字段.
    """
    present = frozenset(names)
    return {field: ext in present for ext, field in ISA_EXT_FIELDS.items()}


# misa 的 MXL 字段, 取自 bits[63:62]; 取 2 表示 RV64
MISA_MXL_RV64 = 2 << 62

# misa 中 S 模式与 U 模式对应的位. 模拟器无条件实现这两个特权级, 其取值
# 不来自扩展名列表.
MISA_PRIV_BITS = (1 << 18) | (1 << 20)


def encode_misa(names: Iterable[str]) -> int:
    """由扩展名集合给出 misa 的取值.

    每个单字母扩展按该字母在字母表中的序号占一个位. 多字母扩展不在 misa 中
    表达, 由设备树的扩展名列表给出.
    """
    value = MISA_MXL_RV64 | MISA_PRIV_BITS
    for name in frozenset(names):
        if len(name) == 1 and "a" <= name <= "z":
            value |= 1 << (ord(name) - ord("a"))
    return value


def _strip_version(name: str) -> str:
    """去掉扩展名末尾的版本号, 例 "zicsr2p0" 变为 "zicsr".

    版本号由一段数字与可选的 "p" 加数字构成, 故只有末尾数字段之前紧跟 "p" 且
    "p" 之前还有数字时, 才把该 "p" 一并去掉. 以字母开头的名称 (如 "zcmp")
    保持原样.
    """
    end = len(name)
    while end > 0 and name[end - 1].isdigit():
        end -= 1
    if end == len(name):
        return name
    if end >= 2 and name[end - 1] == "p" and name[end - 2].isdigit():
        end -= 2
    return name[:end] if end > 0 else name


def _skip_version(text: str, start: int) -> int:
    """返回单字母扩展之后第一个不属于版本号的字符索引.

    版本号形如 "2p0"; 数字之后紧跟 "p" 与数字时, 该 "p" 才属于版本号,
    否则它本身是一个扩展字母.
    """
    i = start
    while i < len(text) and text[i].isdigit():
        i += 1
    if i + 1 < len(text) and text[i] == "p" and text[i + 1].isdigit():
        i += 1
        while i < len(text) and text[i].isdigit():
            i += 1
    return i


def _parse_isa_string(isa: str) -> list[str]:
    """把旧式 ISA 字符串解析为小写扩展名列表."""
    s = isa.strip().lower()
    if s.startswith("rv64") or s.startswith("rv32"):
        s = s[4:]

    single_part, _, multi_part = s.partition("_")
    exts: list[str] = []
    i = 0
    while i < len(single_part):
        ch = single_part[i]
        if ch in _MULTI_LETTER_START:
            # 单字母段中出现 z 或 x 或 s 时, 该字符起至本段末尾
            # 为一个多字母扩展名; 首段与其余段之间漏写下划线时
            # (如 "rv64imafdcbzicsr") 由此纠正
            exts.append(_strip_version(single_part[i:]))
            break
        i += 1
        if ch == "g":
            exts.extend(_G_EXPANSION)
        elif ch.isalpha():
            exts.append(ch)
        else:
            continue
        i = _skip_version(single_part, i)
    if multi_part:
        exts.extend(
            _strip_version(part) for part in multi_part.split("_") if part
        )
    return [ext for ext in exts if ext]


def isa_ext_list(
    isa: str | Iterable[str] | None,
) -> list[str]:
    """把旧式 ISA 字符串或扩展名列表归一为小写扩展名列表; 空值给出空列表.

    字符串先去掉 "rv64" 或 "rv32" 前缀, 第一个 "_" 之前按单个字母取扩展,
    其中 "g" 展开为 imafd 与 zicsr、zifencei; 该段中一旦出现 z 或 x 或 s,
    自该字符起至本段末尾为一个多字母扩展名; 其后各段为多字母扩展名.
    末尾版本号一并去掉.
    """
    if isa is None:
        return []
    if isinstance(isa, str):
        return _parse_isa_string(isa)
    return [_strip_version(ext.strip().lower()) for ext in isa if ext.strip()]
