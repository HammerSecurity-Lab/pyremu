"""反汇编器公共定义: 指令字段枚举、字段提取与格式化辅助."""

from enum import Enum

from pyremu.disasm.regname import gpr_name
from pyremu.utils.mask import sext, sext12

UNKNOWN = "<unk-op>"


class Opc(Enum):
    """
    如果是压缩指令，低两位不是11,而可能是00,01,10
    然后长度按照16位来解析
    """

    ld = 0b00000_11  # 载入
    ld_fp = 0b00001_11  # 浮点载入 (FLW/FLD) — LOAD-FP
    fence = 0b00011_11  # 内存/执行流屏障
    op_imm = 0b00100_11  # 立即数 ALU (32-bit)
    op_imm32 = 0b00110_11  # RV64 32-bit 立即数 ALU
    auipc = 0b00101_11  # 累加 pc
    st = 0b01000_11  # 写入
    stfp = 0b01001_11  # 浮点存储 (FSW/FSD) — STORE-FP
    amo = 0b01011_11  # 原子
    fmadd = 0b10000_11  # 合并乘加 FMADD
    fmsub = 0b10001_11  # 合并乘减 FMSUB
    fnmsub = 0b10010_11  # 负合并乘减 FNMSUB
    fnmadd = 0b10011_11  # 负合并乘加 FNMADD
    fp_op = 0b10100_11  # 浮点算术/转换/比较 OP-FP
    op = 0b01100_11  # ALU (R-type)
    lui = 0b01101_11  # 立即数载入
    op32 = 0b01110_11  # RV64 32-bit 操作
    br = 0b11000_11  # 有条件跳转
    jalr = 0b11001_11  # 无条件跳转 (寄存器)
    jal = 0b11011_11  # 无条件跳转
    sys = 0b11100_11  # ecall/ebreak/sfence.vma / CSR


AluOp = Enum(
    "AluOp",
    (
        "add",
        "sub",
        "mul",
        "mulh",
        "mulhu",
        "mulhsu",
        "div",
        "divu",
        "rem",
        "remu",
        "andi",
        "ori",
        "xor",
        "sll",
        "srl",
        "sra",
        "slti",
        "sltiu",
        "slt",
        "sltu",
    ),
)

SysOp = Enum(
    "SysOp",
    (
        "ecall",
        "ebreak",
        "csrrc",
        "csrrci",
        "csrrw",
        "csrrwi",
        "csrrs",
        "csrrsi",
        "mret",
        "sret",
        "wfi",
        "sfence_vma",
    ),
)


class BrFn3(Enum):
    beq = 0b000
    bne = 0b001
    blt = 0b100
    bge = 0b101
    bltu = 0b110
    bgeu = 0b111


class LdFn3(Enum):
    lb = 0b000
    lh = 0b001
    lw = 0b010
    ld = 0b011
    lbu = 0b100
    lhu = 0b101
    lwu = 0b110


class StFn3(Enum):
    sb = 0b000
    sh = 0b001
    sw = 0b010
    sd = 0b011


class SysFn12(Enum):
    ecall = 0
    ebreak = 1


# AMO funct5 编码 (bits 31:27), funct3 区分 32/64-bit
class AmoFunct5(Enum):
    LR = 0b00010
    SC = 0b00011
    SWAP = 0b00001
    ADD = 0b00000
    XOR = 0b00100
    AND = 0b01100
    OR = 0b01000
    MIN = 0b10000
    MAX = 0b10100
    MINU = 0b11000
    MAXU = 0b11100


class AmoWidth(Enum):
    W = 0b010  # 32-bit
    D = 0b011  # 64-bit


# 热路径优化: 预建 dict 查找表替代 Enum() 构造调用 (~0.10s 节省)
# Enum.__call__ 内部做线性搜索, dict.get 是 O(1) 哈希查找
BrFn3_MAP: dict[int, BrFn3] = {
    v.value: v
    for v in BrFn3  # type: ignore[var-annotated]
}
LdFn3_MAP: dict[int, LdFn3] = {
    v.value: v
    for v in LdFn3  # type: ignore[var-annotated]
}
StFn3_MAP: dict[int, StFn3] = {
    v.value: v
    for v in StFn3  # type: ignore[var-annotated]
}
AMOF5_MAP: dict[int, AmoFunct5] = {
    v.value: v
    for v in AmoFunct5  # type: ignore[var-annotated]
}
AMOW_MAP: dict[int, AmoWidth] = {
    v.value: v
    for v in AmoWidth  # type: ignore[var-annotated]
}


def parse_opcode(x: int) -> int:
    return x & 0b111_1111


def parse_rd(x: int) -> int:
    return (x >> 7) & 0b1_1111


def parse_func3(x: int) -> int:
    return (x >> 12) & 0b0111


def parse_rs1(x: int) -> int:
    return (x >> 15) & 0b1_1111


def parse_rs2(x: int) -> int:
    return (x >> 20) & 0b1_1111


def parse_func7(x: int) -> int:
    return (x >> 25) & 0b111_1111


def parse_func6(x: int) -> int:
    """for SLLI/SRLI/SRAI (I-type shifts)"""
    return (x >> 26) & 0x3F


def parse_func12(x: int) -> int:
    """I-type funct12 (bits[31:20]) — CSR / ECALL / EBREAK / etc."""
    return (x >> 20) & 0xFFF


# 立即数解析
def parse_imm12_raw(x: int) -> int:
    """I-type"""
    return (x >> 20) & 0xFFF


def parse_imm12_se(x: int) -> int:
    return sext12((x >> 20) & 0xFFF)


def parse_imm20_raw(x: int) -> int:
    """U-type"""
    return (x >> 12) & 0xF_FFFF


def parse_imm_s(instr: int) -> int:
    """S-type 12-bit immediate, sign-extended."""
    imm = ((instr >> 25) & 0x7F) << 5  # imm[11:5]
    imm |= (instr >> 7) & 0x1F  # imm[4:0]  -- from rd field
    return sext12(imm)


def parse_imm_b(instr: int) -> int:
    """B-type 13-bit immediate, sign-extended (byte-address diff)."""
    imm = ((instr >> 31) & 1) << 12  # imm[12]
    imm |= ((instr >> 25) & 0x3F) << 5  # imm[10:5]
    imm |= ((instr >> 8) & 0xF) << 1  # imm[4:1]
    imm |= ((instr >> 7) & 1) << 11  # imm[11]
    return sext(imm, 13)


def parse_imm_j(instr: int) -> int:
    """J-type 21-bit immediate, sign-extended (byte-address diff)."""
    imm = ((instr >> 31) & 1) << 20  # imm[20]
    imm |= ((instr >> 21) & 0x3FF) << 1  # imm[10:1]
    imm |= ((instr >> 20) & 1) << 11  # imm[11]
    imm |= ((instr >> 12) & 0xFF) << 12  # imm[19:12]
    return sext(imm, 21)


def parse_compressed(instr: int) -> bool:
    return (instr & 0x3) != 3


def decode_c_sdsp(half: int) -> tuple[int, int] | None:
    """If *half* is ``c.sdsp rs2, uimm(sp)``, return ``(rs2, uimm)``; else None.

    C.SDSP encoding (C2 quadrant, RV64 only):
        bits[1:0]   = 10
        bits[4:2]   = rs2 (x8--x15 in standard, but we also accept x1)
        bits[6:5]   = uimm[5:3] lower bits
        bits[12:10] = uimm[5:3]
        bits[9:7]   = uimm[8:6]
        bits[15:13] = 111 (funct3)
    The uimm is assembled from {bits[9:7], bits[12:10]} << 3,
    i.e. 8-byte aligned.
    """
    if (half & 0xE003) != 0xE002:  # bits[15:13]=111, bits[1:0]=10
        return None
    rs2 = (half >> 2) & 0x1F
    uimm = ((half >> 7) & 0x7) << 6  # bits[9:7]  -> uimm[8:6]
    uimm |= ((half >> 10) & 0x7) << 3  # bits[12:10] -> uimm[5:3]
    return rs2, uimm


def decode_sd_sp(instr: int) -> tuple[int, int] | None:
    """If *instr* is ``sd rs2, imm(sp)``, return ``(rs2, imm)``; else None.

    S-type encoding:
        opcode (bits[6:0])   = 0b0100011 (STORE)
        funct3 (bits[14:12]) = 0b011     (SD / doubleword store)
        rs1    (bits[19:15]) = 2         (sp)
        rs2    (bits[24:20]) = source register
        imm[4:0]  at bits[11:7], imm[11:5] at bits[31:25]
    """
    if (instr & 0x7F) != 0b0100011:
        return None
    if ((instr >> 12) & 0x7) != 0b011:  # funct3 = SD
        return None
    if ((instr >> 15) & 0x1F) != 2:  # rs1 = sp
        return None
    rs2 = (instr >> 20) & 0x1F
    imm = ((instr >> 25) << 5) | ((instr >> 7) & 0x1F)
    if imm & 0x800:  # 按有符号立即数返回, 供调用方与 sp 相加
        imm -= 0x1000
    return rs2, imm


def fmt_imm(val: int) -> str:
    """格式化指令立即数: 有符号十进制 (处理 64-bit 规范化值)."""
    # sext 规范化后, 负立即数以 64-bit 无符号形式传入.
    # 若 bit 63 置位则还原为有符号显示 (例如 0xFF…F0 -> -16).
    if val >= (1 << 63):
        val = val - (1 << 64)
    return str(val)


def rd_name(instr: int) -> str:
    return gpr_name(parse_rd(instr))


def rs1_name(instr: int) -> str:
    return gpr_name(parse_rs1(instr))


def rs2_name(instr: int) -> str:
    return gpr_name(parse_rs2(instr))
