# SPDX-LICENSE-IDENTIFIER: MIT
"""反汇编文本的着色与控制流分类."""

from __future__ import annotations

import re

# 反汇编着色常量
_BRANCH_JUMP_MNEMONICS = frozenset(
    {
        "beq",
        "bne",
        "blt",
        "bge",
        "bltu",
        "bgeu",
        "jal",
        "jalr",
        "j",
        "jr",
        "ret",
        # Compressed jump/branch mnemonics
        "c.j",
        "c.jr",
        "c.jalr",
        "c.beqz",
        "c.bnez",
    }
)
_LOAD_STORE_MNEMONICS = frozenset(
    {
        "ld",
        "lw",
        "lh",
        "lb",
        "lwu",
        "lhu",
        "lbu",
        "sd",
        "sw",
        "sh",
        "sb",
        # Compressed load/store mnemonics
        "c.ld",
        "c.ldsp",
        "c.lw",
        "c.lwsp",
        "c.sd",
        "c.sdsp",
        "c.sw",
        "c.swsp",
    }
)
_PRIVILEGED_MNEMONICS = frozenset(
    {"ecall", "ebreak", "mret", "sret", "wfi", "c.ebreak"}
)
_FENCE_AMO_MNEMONICS = frozenset(
    {
        "fence",
        "fence.i",
        "sfence.vma",
        "lr.w",
        "lr.d",
        "sc.w",
        "sc.d",
        "amoswap.w",
        "amoswap.d",
        "amoadd.w",
        "amoadd.d",
        "amoxor.w",
        "amoxor.d",
        "amoand.w",
        "amoand.d",
        "amoor.w",
        "amoor.d",
        "amomin.w",
        "amomin.d",
        "amomax.w",
        "amomax.d",
        "amominu.w",
        "amominu.d",
        "amomaxu.w",
        "amomaxu.d",
    }
)

# 助记符类别与对应的颜色名, 按该顺序判定
_MNEMONIC_COLORS = (
    (_BRANCH_JUMP_MNEMONICS, "green"),
    (_FENCE_AMO_MNEMONICS, "yellow"),
    (_PRIVILEGED_MNEMONICS, "red"),
    (_LOAD_STORE_MNEMONICS, "cyan"),
)

# 32 位指令的 opcode 到控制流分类
_OPCODE_FLOW_KINDS = {
    0x6F: "jal",
    0x67: "jalr",
    0x63: "branch",
    0x0F: "fence",
    0x2F: "fence",
}


# SYSTEM 指令的 funct12 到控制流分类
_SYSTEM_FLOW_KINDS = {
    0x000: "ecall",
    0x001: "ebreak",
    0x302: "mret",
    0x102: "sret",
    0x105: "wfi",
}


def mnemonic_color(mnemonic: str) -> str | None:
    """返回反汇编助记符对应的颜色名; 无对应颜色时返回 None."""
    for group, color in _MNEMONIC_COLORS:
        if mnemonic in group:
            return color
    return None


def colorize_asm(asm_text: str) -> str:
    """为反汇编文本添加 Rich 颜色标记."""
    if not asm_text or asm_text.startswith("[") or asm_text == "(unknown)":
        return asm_text
    parts = asm_text.split(maxsplit=1)
    mnemonic = parts[0]
    operands = parts[1] if len(parts) > 1 else ""
    color = mnemonic_color(mnemonic)
    if not operands:
        return asm_text if color is None else f"[{color}]{mnemonic}[/]"
    # 十六进制与纯数字立即数显示为品红
    operands = re.sub(r"\b(0x[0-9a-fA-F]+|\d+)\b", r"[magenta]\1[/]", operands)
    if color is None:
        return f"{mnemonic} {operands}"
    return f"[{color}]{mnemonic}[/] {operands}"


def ctrl_flow_kind(instr: int) -> str:
    """32-bit 指令的控制流分类."""
    opcode = instr & 0x7F
    if opcode == 0x73:
        return _SYSTEM_FLOW_KINDS.get((instr >> 20) & 0xFFF, "csr")
    return _OPCODE_FLOW_KINDS.get(opcode, "normal")


def ctrl_flow_kind_compressed(instr16: int) -> str:
    """16-bit 压缩指令的控制流分类."""
    op = instr16 & 0x3
    funct3 = (instr16 >> 13) & 0x7
    if op == 0x1 and funct3 in (0x1, 0x5):
        return "jal"
    if op == 0x2 and funct3 == 0x4:
        # C2 funct3=100: C.JR/C.JALR (rs2=0) vs C.MV/C.ADD (rs2≠0)
        rs2 = (instr16 >> 2) & 0x1F
        if rs2 == 0:
            return "jalr"
    elif op == 0x2 and funct3 == 0x6:
        # C.JALR (rs2=0 only)
        rs2 = (instr16 >> 2) & 0x1F
        if rs2 == 0:
            return "jalr"
    if op == 0x1 and funct3 in (0x6, 0x7):
        return "branch"
    if op == 0x2 and funct3 == 0x0:
        return "ebreak"
    return "normal"
