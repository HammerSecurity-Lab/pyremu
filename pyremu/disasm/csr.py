"""CSR 指令、特权指令与 FENCE 指令."""

from pyremu.disasm.common import (
    parse_func3,
    parse_rs1,
    rd_name,
    rs1_name,
    UNKNOWN,
)
from pyremu.disasm.regname import check_csr

_CSR_MNEMONIC: dict[int, str] = {
    0b001: "csrrw",
    0b010: "csrrs",
    0b011: "csrrc",
    0b101: "csrrwi",
    0b110: "csrrsi",
    0b111: "csrrci",
}


def _csr_name(addr: int) -> str:
    """由 CSR 地址得到名称, 未找到则返回地址的十六进制形式."""
    ok, name = check_csr(addr)
    return name if ok else f"0x{addr:03x}"


def dis_csr(instr: int) -> str:
    """CSR 指令: mnemonic rd, csr, rs1/uimm."""
    f3 = parse_func3(instr)
    mnemonic = _CSR_MNEMONIC.get(f3)
    if mnemonic is None:
        return UNKNOWN
    csr_addr = (instr >> 20) & 0xFFF
    csr = _csr_name(csr_addr)
    rd = rd_name(instr)
    if f3 & 0b100:  # immediate 形式
        uimm = parse_rs1(instr)
        return f"{mnemonic:<12} {rd}, {csr}, {uimm}"
    return f"{mnemonic:<12} {rd}, {csr}, {rs1_name(instr)}"


_PRIV_MNEMONIC: dict[int, str] = {
    0x000: "ecall",
    0x001: "ebreak",
    0x302: "mret",
    0x102: "sret",
    0x105: "wfi",
    0x120: "sfence.vma",
    0x5A0: "mfence.did",
}


def dis_priv(instr: int) -> str:
    """特权指令 (funct3=000)."""
    funct12 = (instr >> 20) & 0xFFF
    mnemonic = _PRIV_MNEMONIC.get(funct12)
    if mnemonic is None:
        return UNKNOWN
    return mnemonic


def dis_fence(instr: int) -> str:
    f3 = parse_func3(instr)
    if f3 == 0b000:
        return "fence"
    if f3 == 0b001:
        return "fence.i"
    return UNKNOWN
