# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""16 位压缩指令的 C0 / C1 / C2 三个象限.

CompressedInstrOps 由 decoder/hart.py 的 Hart 组合, 方法以 hart 自身为接收者.
对外入口为 exec_compressed, 由它解码一条压缩指令的全部字段并把字段对象向下传递,
各象限按 funct3 查表分发.
"""

from pyremu._native import decode_compressed
from pyremu.core.trap_def import TrapType
from pyremu.utils.mask import mask32, mask64, sext, sext32, sint64

# C1 ALU 的寄存器运算, 索引为 bits[6:5]
_C1_ALU_REGS = {
    0b00: lambda a, b: mask64(a - b),  # C.SUB
    0b01: lambda a, b: a ^ b,  # C.XOR
    0b10: lambda a, b: a | b,  # C.OR
    0b11: lambda a, b: a & b,  # C.AND
}


def _c1_shamt(cf) -> int:
    """C.SRLI/C.SRAI/C.ANDI 的 6 位立即数, 由 bit12 与 bits[6:2] 组成."""
    return (cf.bit12 << 5) | (cf.rs2 & 0x1F)


class CompressedInstrOps:
    """压缩指令的处理方法与象限分发."""

    # ---------------------------------------------------------------
    #  C0 象限
    #  ---------------------------------------------------------------

    def _c0_addi4spn(self, cf, instr: int) -> int:
        """C.ADDI4SPN: rd' = sp + nzuimm, nzuimm 为 0 属保留编码."""
        if cf.imm == 0:
            self.deliver_trap(TrapType.IllInstr, tval=instr, is_interrupt=False)
            return 0
        self.gprs[cf.rd] = mask64(self.gprs[2] + cf.imm)
        return 2

    def _c0_mem_addr(self, cf) -> int:
        """C0 访存地址: rs1' + uimm."""
        return mask64(self.gprs[cf.rs1p] + cf.imm)

    def _c0_fld(self, cf) -> int:
        """C.FLD: fpr[rd'] = mem[rs1' + uimm]."""
        if not self._fp_enabled():
            raise ValueError("C.FLD: FP disabled (mstatus.FS=Off)")
        addr = self._c0_mem_addr(cf)
        saved_pc = self.pc
        mem = self.mem_read(addr, 8)
        if self.pc != saved_pc:
            return 0
        self._fpr_bits[cf.rd] = int.from_bytes(mem, "little")
        self._fp_mark_dirty()
        return 2

    def _c0_lw(self, cf) -> int:
        """C.LW: rd' = sext32(mem[rs1' + uimm])."""
        addr = self._c0_mem_addr(cf)
        saved_pc = self.pc
        mem = self.mem_read(addr, 4)
        if self.pc != saved_pc:
            return 0
        self.gprs[cf.rd] = sext32(int.from_bytes(mem, "little"))
        return 2

    def _c0_ld(self, cf) -> int:
        """C.LD: rd' = mem[rs1' + uimm]."""
        addr = self._c0_mem_addr(cf)
        saved_pc = self.pc
        mem = self.mem_read(addr, 8)
        if self.pc != saved_pc:
            return 0
        self.gprs[cf.rd] = int.from_bytes(mem, "little")
        return 2

    def _c0_sw(self, cf) -> int:
        """C.SW: mem[rs1' + uimm] = rs2'[31:0]."""
        addr = self._c0_mem_addr(cf)
        data = mask32(self.gprs[cf.rdp]).to_bytes(4, "little")
        saved_pc = self.pc
        self.mem_write(addr, data)
        return 0 if self.pc != saved_pc else 2

    def _c0_sd(self, cf) -> int:
        """C.SD: mem[rs1' + uimm] = rs2'."""
        addr = self._c0_mem_addr(cf)
        data = self.gprs[cf.rdp].to_bytes(8, "little")
        saved_pc = self.pc
        self.mem_write(addr, data)
        return 0 if self.pc != saved_pc else 2

    def _c0_fsd(self, cf) -> int:
        """C.FSD: mem[rs1' + uimm] = fpr[rd']."""
        if not self._fp_enabled():
            raise ValueError("C.FSD: FP disabled (mstatus.FS=Off)")
        addr = self._c0_mem_addr(cf)
        data = self._fpr_bits[cf.rd].to_bytes(8, "little")
        saved_pc = self.pc
        self.mem_write(addr, data)
        if self.pc != saved_pc:
            return 0
        self._fp_mark_dirty()
        return 2

    # C0 象限分发表: funct3 映射到方法名, C.ADDI4SPN 单独处理
    _C0_OPS: dict[int, str] = {
        0b001: "_c0_fld",
        0b010: "_c0_lw",
        0b011: "_c0_ld",
        0b101: "_c0_fsd",
        0b110: "_c0_sw",
        0b111: "_c0_sd",
    }

    # ---------------------------------------------------------------
    #  C1 象限
    #  ---------------------------------------------------------------

    def _c1_addi(self, cf) -> int:
        """C.ADDI: rd += imm."""
        self.gprs[cf.rd] = mask64(self.gprs[cf.rd] + cf.imm)
        return 2

    def _c1_addiw(self, cf) -> int:
        """C.ADDIW: rd = sext32(rd + imm)."""
        self.gprs[cf.rd] = sext32(mask32(self.gprs[cf.rd] + cf.imm))
        return 2

    def _c1_li(self, cf) -> int:
        """C.LI: rd = imm."""
        self.gprs[cf.rd] = mask64(cf.imm)
        return 2

    def _c1_lui_or_addi16sp(self, cf) -> int:
        """C.LUI (rd≠2) 或 C.ADDI16SP (rd=2), nzuimm 为 0 属保留编码."""
        if cf.rd == 2:
            if cf.imm == 0:
                raise ValueError("C.ADDI16SP: nzuimm must be non-zero")
            self.gprs[2] = mask64(self.gprs[2] + cf.imm)
        else:
            if cf.imm == 0:
                raise ValueError("C.LUI: nzuimm must be non-zero")
            self.gprs[cf.rd] = mask64(cf.imm << 12)
        return 2

    def _c1_j(self, cf) -> int:
        """C.J: pc += offset."""
        self.pc = mask64(self.pc + cf.imm)
        return 0

    def _c1_branch(self, cf, is_eqz: bool) -> int:
        """C.BEQZ 与 C.BNEZ 的公共部分, is_eqz 为真时按 rs1' == 0 取跳转条件."""
        if (self.gprs[cf.rs1p] == 0) == is_eqz:
            self.pc = mask64(self.pc + cf.imm)
            return 0
        return 2

    def _c1_beqz(self, cf) -> int:
        """C.BEQZ: rs1' == 0 时跳转."""
        return self._c1_branch(cf, True)

    def _c1_bnez(self, cf) -> int:
        """C.BNEZ: rs1' != 0 时跳转."""
        return self._c1_branch(cf, False)

    # C1 象限分发表: funct3 映射到方法名, funct3=100 为 ALU 运算
    _C1_OPS: dict[int, str] = {
        0b000: "_c1_addi",
        0b001: "_c1_addiw",
        0b010: "_c1_li",
        0b011: "_c1_lui_or_addi16sp",
        0b101: "_c1_j",
        0b110: "_c1_beqz",
        0b111: "_c1_bnez",
    }

    # ---------------------------------------------------------------
    #  C2 象限
    #  ---------------------------------------------------------------

    def _sp_addr(self, uimm: int) -> int:
        """栈指针相对的访存地址."""
        return mask64(self.gprs[2] + uimm)

    def _c2_slli(self, cf) -> int:
        """C.SLLI: rd <<= shamt."""
        self.gprs[cf.rd] = mask64(self.gprs[cf.rd] << cf.imm)
        return 2

    def _c2_fldsp(self, cf) -> int:
        """C.FLDSP: fpr[rd] = mem[sp + uimm]."""
        if not self._fp_enabled():
            raise ValueError("C.FLDSP: FP disabled (mstatus.FS=Off)")
        addr = self._sp_addr(cf.imm)
        saved_pc = self.pc
        mem = self.mem_read(addr, 8)
        if self.pc != saved_pc:
            return 0
        self._fpr_bits[cf.rd] = int.from_bytes(mem, "little")
        self._fp_mark_dirty()
        return 2

    def _c2_lwsp(self, cf) -> int:
        """C.LWSP: rd = sext32(mem[sp + uimm])."""
        if cf.rd == 0:
            raise ValueError("C.LWSP rd=0 (reserved)")
        addr = self._sp_addr(cf.imm)
        saved_pc = self.pc
        mem = self.mem_read(addr, 4)
        if self.pc != saved_pc:
            return 0
        self.gprs[cf.rd] = sext32(int.from_bytes(mem, "little"))
        return 2

    def _c2_ldsp(self, cf) -> int:
        """C.LDSP: rd = mem[sp + uimm]."""
        if cf.rd == 0:
            raise ValueError("C.LDSP rd=0 (reserved)")
        addr = self._sp_addr(cf.imm)
        saved_pc = self.pc
        mem = self.mem_read(addr, 8)
        if self.pc != saved_pc:
            return 0
        self.gprs[cf.rd] = int.from_bytes(mem, "little")
        return 2

    def _c2_jump_or_mv(self, cf) -> int:
        """funct3=100: C.JR / C.JALR / C.MV / C.ADD / C.EBREAK, 由 bit12 与 rs2 区分."""
        rd_rs1 = cf.rd  # C.JR/C.JALR 的 rs1, C.MV/C.ADD 的 rd
        rs2 = cf.rs2
        if rd_rs1 == 0 and rs2 == 0:
            self.trap_ebreak()
            return 0
        if rs2 == 0:
            # 先读跳转目标, rd_rs1 可能为 x1 并在随后被写入
            target = self.gprs[rd_rs1]
            if cf.bit12:
                self.gprs[1] = mask64(self.pc + 2)
            self.pc = mask64(target & ~1)
            return 0
        if cf.bit12:
            self.gprs[rd_rs1] = mask64(self.gprs[rd_rs1] + self.gprs[rs2])
        else:
            self.gprs[rd_rs1] = self.gprs[rs2]
        return 2

    def _c2_fsdsp(self, cf) -> int:
        """C.FSDSP: mem[sp + uimm] = fpr[rs2]."""
        if not self._fp_enabled():
            raise ValueError("C.FSDSP: FP disabled (mstatus.FS=Off)")
        addr = self._sp_addr(cf.imm2)
        data = self._fpr_bits[cf.rs2].to_bytes(8, "little")
        saved_pc = self.pc
        self.mem_write(addr, data)
        if self.pc != saved_pc:
            return 0
        self._fp_mark_dirty()
        return 2

    def _c2_swsp(self, cf) -> int:
        """C.SWSP: mem[sp + uimm] = rs2[31:0]."""
        addr = self._sp_addr(cf.imm2)
        data = mask32(self.gprs[cf.rs2]).to_bytes(4, "little")
        saved_pc = self.pc
        self.mem_write(addr, data)
        return 0 if self.pc != saved_pc else 2

    def _c2_sdsp(self, cf) -> int:
        """C.SDSP: mem[sp + uimm] = rs2."""
        addr = self._sp_addr(cf.imm2)
        data = self.gprs[cf.rs2].to_bytes(8, "little")
        saved_pc = self.pc
        self.mem_write(addr, data)
        return 0 if self.pc != saved_pc else 2

    # C2 象限分发表: funct3 映射到方法名
    _C2_OPS: dict[int, str] = {
        0b000: "_c2_slli",
        0b001: "_c2_fldsp",
        0b010: "_c2_lwsp",
        0b011: "_c2_ldsp",
        0b100: "_c2_jump_or_mv",
        0b101: "_c2_fsdsp",
        0b110: "_c2_swsp",
        0b111: "_c2_sdsp",
    }

    # ---------------------------------------------------------------
    #  象限分发与 C1 ALU 运算
    #  ---------------------------------------------------------------

    def exec_compressed(self, instr: int) -> int:
        """执行一条 16-bit 压缩指令, 按低 2 位分派到对应象限的处理函数.

        Returns:
            2: 正常完成, 调用方做 PC += 2
            0: PC 已被该指令修改 (跳转/trap 等), 调用方不追加 PC
        """
        cf = decode_compressed(instr)
        if cf.quadrant == 0:
            return self._exec_c0(cf, instr)
        if cf.quadrant == 1:
            return self._exec_c1(cf)
        if cf.quadrant == 2:
            return self._exec_c2(cf)
        raise ValueError(f"handle_compressed: not compressed {instr:#06x}")

    def _exec_c0(self, cf, instr: int) -> int:
        """C0 象限分发: C.ADDI4SPN 之外按 funct3 查表."""
        if cf.funct3 == 0b000:
            return self._c0_addi4spn(cf, instr)
        handler = self._C0_OPS.get(cf.funct3)
        if handler is None:
            raise NotImplementedError(f"C0 funct3={cf.funct3:#05b} (reserved)")
        return getattr(self, handler)(cf)

    def _exec_c1(self, cf) -> int:
        """C1 象限分发: funct3=100 为 ALU 运算, 其余按 funct3 查表."""
        if cf.funct3 == 0b100:
            return self._c1_alu(cf)
        handler = self._C1_OPS.get(cf.funct3)
        if handler is None:
            raise NotImplementedError(f"C1 funct3={cf.funct3:#05b}")
        return getattr(self, handler)(cf)

    def _exec_c2(self, cf) -> int:
        """C2 象限分发."""
        handler = self._C2_OPS.get(cf.funct3)
        if handler is None:
            raise NotImplementedError(f"C2 funct3={cf.funct3:#05b} (reserved)")
        return getattr(self, handler)(cf)

    def _c1_alu(self, cf) -> int:
        """C1 ALU 运算 (funct3=100), 由 sf 选择移位、与运算或寄存器运算.

        sf=00 -> C.SRLI  (shamt = {bit12, bits[6:2]}, 1-63 for RV64C)
        sf=01 -> C.SRAI  (shamt = {bit12, bits[6:2]}, 1-63 for RV64C)
        sf=10 -> C.ANDI (imm[5]=bit12, imm[4:0]=bits[6:2])
        sf=11 bit12=0 -> C.SUB/C.XOR/C.OR/C.AND (bits[6:5]: 00=SUB,01=XOR,10=OR,11=AND)
        sf=11 bit12=1 -> C.SUBW/C.ADDW (bits[6:5]: 00=SUBW, 01=ADDW)
        """
        sf = cf.sf
        rd_rs1 = cf.rs1p  # creg-mapped from bits[9:7]
        v1 = self.gprs[rd_rs1]
        if sf == 0b00:
            self.gprs[rd_rs1] = mask64(mask64(v1) >> _c1_shamt(cf))
        elif sf == 0b01:
            self.gprs[rd_rs1] = mask64(sint64(v1) >> _c1_shamt(cf))
        elif sf == 0b10:
            self.gprs[rd_rs1] = mask64(v1 & sext(_c1_shamt(cf), 6))
        elif sf == 0b11:
            self._c1_alu_register(cf, v1)
        else:
            raise NotImplementedError(f"C1 ALU sub_fn={sf:#03b}")
        return 2

    def _c1_alu_register(self, cf, v1: int) -> None:
        """sf=11: bit12=0 为 64 位运算, bit12=1 为 32 位运算."""
        rd_rs1 = cf.rs1p
        v2 = self.gprs[cf.rdp]
        k = cf.bit65
        if cf.bit12 == 0:
            self.gprs[rd_rs1] = _C1_ALU_REGS[k](v1, v2)
        elif k == 0b00:
            self.gprs[rd_rs1] = sext32(mask32(v1 - v2))
        elif k == 0b01:
            self.gprs[rd_rs1] = sext32(mask32(v1 + v2))
        else:
            raise NotImplementedError(f"C.SUBW/C.ADDW reserved bit[6:5]={k:#03b}")
