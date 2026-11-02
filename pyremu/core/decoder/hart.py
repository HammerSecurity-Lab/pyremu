# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""RISC-V hart 的指令执行入口与 32 位指令处理器.

exec_instr 解码字段并按 opcode 查表分发到各处理器. 压缩指令与特权指令的方法由同包的
compressed.CompressedInstrOps 与 sys_ops.SysInstrOps 组合进来; 算术运算与访存取值
委托给同包的 alu / mem_ops 模块.
"""

from pyremu._native import decode_fields, fp_exec_fma, fp_exec_op
from pyremu.core.decoder.alu import exec_alu, exec_op32, exec_op_imm, exec_op_imm32
from pyremu.core.decoder.check_ext_isa import check_ext_isa
from pyremu.core.decoder.compressed import CompressedInstrOps
from pyremu.core.decoder.mem_ops import amo_result, amo_width, LD_READ_SIZE, load_value
from pyremu.core.decoder.sys_ops import SysInstrOps
from pyremu.core.hart import HartWithRegs
from pyremu.core.mem_check_aux import MemoryAccessError
from pyremu.core.registers import CsrAccessError
from pyremu.core.trap_def import TrapType
from pyremu.utils.disassem import (
    AMOF5_MAP,
    AmoFunct5,
    AMOW_MAP,
    AmoWidth,
    BrFn3,
    BrFn3_MAP,
    LdFn3_MAP,
    StFn3,
    StFn3_MAP,
)
from pyremu.utils.mask import mask16, mask64, sext, sext32, sint64


class Hart(CompressedInstrOps, SysInstrOps, HartWithRegs):
    # 32-bit 指令分发表: opcode 映射到处理方法名, 索引取值为整数 0 到 127, 分发复杂度为 O(1)
    _DISPATCH: dict[int, str] = {
        0b01100_11: "handle_alu",  # Opc.op
        0b00100_11: "handle_op_imm",  # Opc.op_imm
        0b00110_11: "handle_op_imm32",  # Opc.op_imm32
        0b01110_11: "handle_op32",  # Opc.op32
        0b00000_11: "handle_ld",  # Opc.ld
        0b01000_11: "handle_st",  # Opc.st
        0b11000_11: "handle_br",  # Opc.br
        0b11001_11: "handle_jalr",  # Opc.jalr
        0b11011_11: "_handle_jal",  # Opc.jal
        0b01101_11: "_handle_lui",  # Opc.lui
        0b00101_11: "_handle_auipc",  # Opc.auipc
        0b11100_11: "handle_sys",  # Opc.sys
        0b00011_11: "handle_fence",  # Opc.fence
        0b01011_11: "handle_amo",  # Opc.amo
        0b00001_11: "handle_fp_load",  # Opc.ld_fp (FLW/FLD)
        0b01001_11: "handle_fp_store",  # Opc.stfp (FSW/FSD)
        0b10100_11: "handle_fp_op",  # Opc.fp_op (OP-FP)
        0b10000_11: "handle_fp_fma",  # Opc.fmadd
        0b10001_11: "handle_fp_fma",  # Opc.fmsub
        0b10010_11: "handle_fp_fma",  # Opc.fnmsub
        0b10011_11: "handle_fp_fma",  # Opc.fnmadd
    }

    # ----------------------------------------------------------
    #  R-type ALU (opcode = Opc.op)
    # ----------------------------------------------------------
    def handle_alu(self, instr: int) -> int:
        """执行 R 型 ALU 指令."""
        f = self._f
        result = exec_alu(f, self.gprs[f.rs1], self.gprs[f.rs2])
        if f.rd != 0:
            self.gprs[f.rd] = result
        return 4

    # ----------------------------------------------------------
    #  I-type ALU (opcode = Opc.op_imm)
    # ----------------------------------------------------------
    def handle_op_imm(self, instr: int) -> int:
        """执行 I 型立即数 ALU 指令."""
        f = self._f
        result = exec_op_imm(f, self.gprs[f.rs1])
        if f.rd != 0:
            self.gprs[f.rd] = result
        return 4

    # ----------------------------------------------------------
    #  RV64 32-bit word operations (opcode = Opc.op32)
    # ----------------------------------------------------------
    def handle_op32(self, instr: int):
        """执行 RV64 的 32 位字运算指令, 如 ADDW、SUBW、SLLW 等."""
        f = self._f
        result = exec_op32(f, self.gprs[f.rs1], self.gprs[f.rs2])
        if f.rd != 0:
            self.gprs[f.rd] = result
        return 4

    # ----------------------------------------------------------
    #  I-type immediate word operations (opcode = Opc.op_imm32)
    # ----------------------------------------------------------
    def handle_op_imm32(self, instr: int):
        """执行 I 型 32 位字立即数 ALU 指令, 如 ADDIW、SLLIW 等."""
        f = self._f
        result = exec_op_imm32(f, self.gprs[f.rs1])
        if f.rd != 0:
            self.gprs[f.rd] = result
        return 4

    def handle_br(self, instr: int) -> int:
        """Execute a conditional branch.  Returns 0 if taken (pc updated),
        4 if not taken (pc advances normally)."""
        f = self._f
        fn3 = f.func3
        rs1 = f.rs1
        rs2 = f.rs2
        offset = f.imm_b

        v1 = self.gprs[rs1]
        v2 = self.gprs[rs2]

        taken = False
        f = BrFn3_MAP.get(fn3)
        if f is None:
            return 4

        if f == BrFn3.beq:
            taken = v1 == v2
        elif f == BrFn3.bne:
            taken = v1 != v2
        elif f == BrFn3.blt:
            taken = sint64(v1) < sint64(v2)
        elif f == BrFn3.bge:
            taken = sint64(v1) >= sint64(v2)
        elif f == BrFn3.bltu:
            taken = mask64(v1) < mask64(v2)
        elif f == BrFn3.bgeu:
            taken = mask64(v1) >= mask64(v2)

        if taken:
            self.pc = mask64((self.pc + offset))
            return 0
        return 4

    def handle_ld(self, instr: int):
        """执行加载指令, 按 funct3 决定读取宽度与符号扩展方式."""
        fields = self._f
        kind = LdFn3_MAP.get(fields.func3)
        if kind is None:
            raise ValueError(f"invalid funct3={fields.func3:#x} for load")
        addr = mask64((self.gprs[fields.rs1] + fields.imm12_se))
        saved_pc = self.pc
        # 按实际操作宽度读取, 避免对 lb/lbu/lh/lhu/lw/lwu 产生虚假对齐故障
        mem = self.mem_read(addr, LD_READ_SIZE[kind])
        # 访存故障已经投递并把 PC 改写为陷态入口时, 不覆盖 rd, 使陷态处理
        # 函数看到故障前的寄存器状态
        if self.pc != saved_pc:
            return 0
        if fields.rd != 0:
            self.gprs[fields.rd] = load_value(kind, mem)
        return 4

    def handle_st(self, instr: int):
        """Execute a store instruction."""
        f = self._f
        fn3 = f.func3
        rs1 = f.rs1
        rs2 = f.rs2
        offset = f.imm_s

        addr = mask64((self.gprs[rs1] + offset))
        val = self.gprs[rs2]

        f = StFn3_MAP.get(fn3)
        if f is None:
            raise ValueError(f"invalid funct3={fn3:#x} for store")

        if f == StFn3.sb:
            data = bytes([val & 0xFF])
        elif f == StFn3.sh:
            data = bytes([val & 0xFF, (val >> 8) & 0xFF])
        elif f == StFn3.sw:
            data = bytes(
                [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF]
            )
        elif f == StFn3.sd:
            data = bytes([(val >> (8 * i)) & 0xFF for i in range(8)])
        else:
            raise ValueError(f"unhandled store funct3={fn3:#x}")

        saved_pc = self.pc
        self.mem_write(addr, data)
        # mem_write may have delivered a trap (StPageFault / StAccessFault) and
        # redirected PC to stvec.  If so, return 0 so the caller doesn't advance PC.
        if self.pc != saved_pc:
            return 0
        return 4

    # ----------------------------------------------------------
    #  F/D 浮点指令
    #
    #  计算委托给加速执行引擎的 softfloat, 入口为 fp_exec_op 与 fp_exec_fma,
    #  单精度结果的高 32 位由该引擎填为全 1 以设置为 NaN; Python 侧仅负责寄存器与内存的路由,
    #  并在 FLW 载入 32 位浮点数时做同样的填充.
    # ----------------------------------------------------------

    _NANBOX_S = 0xFFFF_FFFF_0000_0000
    _MSTATUS_FS = 0b11 << 13
    _MSTATUS_SD = 1 << 63

    def _fp_enabled(self) -> bool:
        """mstatus.FS != Off。"""
        return (self.mstatus_val & self._MSTATUS_FS) != 0

    def _fp_mark_dirty(self) -> None:
        """执行浮点指令后置 FS=Dirty 与 SD。"""
        self.mstatus_val = self.mstatus_val | self._MSTATUS_FS | self._MSTATUS_SD

    def _fp_frm(self) -> int:
        """当前动态舍入模式 fcsr.frm。"""
        return (self.csrs["fcsr"].val >> 5) & 0x7

    def _fp_accumulate_flags(self, fflags: int) -> None:
        """将异常标志累积进 fcsr.fflags 并同步 fflags CSR。"""
        fcsr = (self.csrs["fcsr"].val | (fflags & 0x1F)) & 0xFF
        self.csrs["fcsr"].val = fcsr
        self.csrs["fflags"].val = fcsr & 0x1F

    def handle_fp_load(self, instr: int) -> int:
        """FLW / FLD — 从内存加载到 FPR。FLW 结果 NaN-boxed。"""
        if not self._fp_enabled():
            raise ValueError("FP disabled (mstatus.FS=Off)")
        f = self._f
        fn3 = f.func3
        if fn3 == 0b010:
            size = 4
        elif fn3 == 0b011:
            size = 8
        else:
            raise ValueError(f"invalid funct3={fn3:#x} for FP load")
        addr = mask64((self.gprs[f.rs1] + f.imm12_se))
        saved_pc = self.pc
        mem = self.mem_read(addr, size)
        if self.pc != saved_pc:
            return 0
        val = 0
        for i in range(size):
            val |= mem[i] << (8 * i)
        self._fpr_bits[f.rd] = (self._NANBOX_S | val) if size == 4 else val
        self._fp_mark_dirty()
        return 4

    def handle_fp_store(self, instr: int) -> int:
        """FSW / FSD — 将 FPR 存入内存。FSW 存低 32 位。"""
        if not self._fp_enabled():
            raise ValueError("FP disabled (mstatus.FS=Off)")
        f = self._f
        fn3 = f.func3
        if fn3 == 0b010:
            size = 4
        elif fn3 == 0b011:
            size = 8
        else:
            raise ValueError(f"invalid funct3={fn3:#x} for FP store")
        addr = mask64((self.gprs[f.rs1] + f.imm_s))
        val = self._fpr_bits[f.rs2]
        data = bytes([(val >> (8 * i)) & 0xFF for i in range(size)])
        saved_pc = self.pc
        self.mem_write(addr, data)
        if self.pc != saved_pc:
            return 0
        return 4

    def handle_fp_op(self, instr: int) -> int:
        """OP-FP — 算术、转换、比较、符号、分类、移动指令, 计算委托给加速执行引擎."""
        if not self._fp_enabled():
            raise ValueError("FP disabled (mstatus.FS=Off)")
        f = self._f
        op5 = f.func7 >> 2
        # int->float (0x1A) 与 FMV.*.X (0x1E) 的 rs1 源为 GPR。
        rs1_bits = self.gprs[f.rs1] if op5 in (0x1A, 0x1E) else self._fpr_bits[f.rs1]
        rs2_bits = self._fpr_bits[f.rs2]
        out = fp_exec_op(f.func7, f.func3, f.rs2, (rs1_bits, rs2_bits), self._fp_frm())
        if out.trap:
            raise ValueError(f"invalid OP-FP funct7={f.func7:#x} funct3={f.func3:#x}")
        if out.to_gpr:
            if f.rd != 0:
                self.gprs[f.rd] = out.value
        else:
            self._fpr_bits[f.rd] = out.value
        self._fp_accumulate_flags(out.fflags)
        self._fp_mark_dirty()
        return 4

    def handle_fp_fma(self, instr: int) -> int:
        """FMADD/FMSUB/FNMSUB/FNMADD — 合并乘加指令, 计算委托给加速执行引擎."""
        if not self._fp_enabled():
            raise ValueError("FP disabled (mstatus.FS=Off)")
        f = self._f
        out = fp_exec_fma(
            f.opcode,
            f.func3,
            f.fmt,
            (self._fpr_bits[f.rs1], self._fpr_bits[f.rs2], self._fpr_bits[f.rs3]),
            self._fp_frm(),
        )
        if out.trap:
            raise ValueError(f"invalid FMA opcode={f.opcode:#x} fmt={f.fmt}")
        self._fpr_bits[f.rd] = out.value
        self._fp_accumulate_flags(out.fflags)
        self._fp_mark_dirty()
        return 4

    # ----------------------------------------------------------
    #  Atomic Memory Operations (opcode = Opc.amo)
    # ----------------------------------------------------------
    # AMO 编码: funct5[31:27] | aq[26] | rl[25] | rs2[24:20] |
    #           rs1[19:15] | funct3[14:12] | rd[11:7] | opcode=0101111
    # aq/rl 为内存排序提示, 顺序执行模型中可忽略.

    def handle_amo(
        self,
        instr: int,
    ) -> int:
        """执行原子内存操作 (LR/SC/AMOxxx)."""
        f = self._f
        funct5_val = f.func7 >> 2  # bits[31:27] = func7[6:2]
        op = AMOF5_MAP.get(funct5_val)
        width = AMOW_MAP.get(f.func3)
        if op is None or width is None:
            raise ValueError(
                f"invalid AMO encoding: funct5={funct5_val:#07b}, funct3={f.func3:#05b}"
            )
        addr = mask64(self.gprs[f.rs1])
        if op == AmoFunct5.LR:
            return self._amo_lr(f, addr, width)
        if op == AmoFunct5.SC:
            return self._amo_sc(f, addr, width)
        return self._amo_rmw(f, addr, width, op)

    def _amo_lr(self, f, addr: int, width: AmoWidth) -> int:
        """Load-Reserved: 读取内存并设置预留."""
        byte_len, mask = amo_width(width)
        saved_pc = self.pc
        data_bytes = self.mem_read(addr, byte_len)
        if self.pc != saved_pc:
            return 0
        val = int.from_bytes(data_bytes, "little") & mask
        if f.rd != 0:
            # LR.D 不需要符号扩展; LR.W 由 32 位符号扩展到 64 位
            self.gprs[f.rd] = val if width == AmoWidth.D else sext32(val)
        self.set_reservation(addr, val)
        return 4

    def _amo_sc(self, f, addr: int, width: AmoWidth) -> int:
        """Store-Conditional: 仅预留有效时写入, 成功时 rd 写 0, 失败时写 1."""
        byte_len, mask = amo_width(width)
        if self.reservation_valid and self.reservation_addr == addr:
            data = (self.gprs[f.rs2] & mask).to_bytes(byte_len, "little")
            saved_pc = self.pc
            self.mem_write(addr, data)
            if self.pc != saved_pc:
                return 0
            if f.rd != 0:
                self.gprs[f.rd] = 0
        elif f.rd != 0:
            self.gprs[f.rd] = 1
        self.clear_reservation()
        return 4

    def _amo_rmw(self, f, addr: int, width: AmoWidth, op: AmoFunct5) -> int:
        """读-改-写: 把运算结果写回内存, 旧值写入 rd."""
        byte_len, mask = amo_width(width)
        saved_pc = self.pc
        data_bytes = self.mem_read(addr, byte_len)
        if self.pc != saved_pc:
            return 0
        mem_val = int.from_bytes(data_bytes, "little") & mask
        op_val = self.gprs[f.rs2] & mask
        result = amo_result(op, mem_val, op_val, width, mask)
        saved_pc = self.pc
        self.mem_write(addr, result.to_bytes(byte_len, "little"))
        if self.pc != saved_pc:
            return 0
        if f.rd != 0:
            self.gprs[f.rd] = sext(mem_val, 64) if width == AmoWidth.D else sext32(mem_val)
        return 4

    def handle_jalr(self, instr: int) -> int:
        """Execute JALR: rd = pc+4; pc = (rs1 + imm) & ~1"""
        f = self._f
        rd = f.rd
        rs1 = f.rs1
        imm = f.imm12_se
        next_pc = mask64((self.pc + 4))
        target = mask64((self.gprs[rs1] + imm))
        target &= ~1  # clear LSB to align

        if rd != 0:
            self.gprs[rd] = next_pc
        self.pc = target
        return 0

    def handle_sys(self, instr: int) -> int:
        """执行系统指令 (特权指令或 CSR 访问)."""
        return self.exec_sys(self._f, instr)

    def handle_fence(self, instr: int) -> int:
        """Execute a FENCE / FENCE.I instruction.
        In a single-hart, in-order emulator these are mostly no-ops."""
        fn3 = self._f.func3
        if fn3 == 0b000:  # FENCE
            pass  # no-op: sequential execution is already ordered
        elif fn3 == 0b001:  # FENCE.I
            pass  # TODO: flush instruction cache / pipeline
        else:
            raise ValueError(f"invalid funct3={fn3:#x} for fence")
        return 4

    # ----------------------------------------------------------
    #  JAL / LUI / AUIPC (从 exec_instr 内联代码提取)
    # ----------------------------------------------------------

    def _handle_jal(self, instr: int) -> int:
        """JAL: rd = pc+4; pc += imm.  Returns 0 (pc always modified)."""
        f = self._f
        rd = f.rd
        imm = f.imm_j
        if rd != 0:
            self.gprs[rd] = mask64((self.pc + 4))
        self.pc = mask64((self.pc + imm))
        return 0

    def _handle_lui(self, instr: int) -> int:
        """LUI: rd = imm20 << 12.  Returns 4 (pc advances normally)."""
        f = self._f
        imm20 = sext32(f.imm20_raw << 12)
        rd = f.rd
        if rd != 0:
            self.gprs[rd] = mask64(imm20)
        return 4

    def _handle_auipc(self, instr: int) -> int:
        """AUIPC: rd = pc + (imm20 << 12).  Returns 4 (pc advances normally)."""
        f = self._f
        imm20 = sext32(f.imm20_raw << 12)
        rd = f.rd
        if rd != 0:
            self.gprs[rd] = mask64((self.pc + imm20))
        return 4

    # ----------------------------------------------------------
    #  Top-level dispatch
    # ----------------------------------------------------------
    def exec_instr(
        self,
        instr: int,
    ) -> int:
        """解码并执行一条 RISC-V 指令 (32-bit 标准 / 16-bit 压缩).

        Returns:
            指令字节数, 供调用方推进 PC:
            - 2: 16-bit 压缩指令, PC 未修改
            - 4: 32-bit 标准指令, PC 未修改
            - 0: PC 已被该指令修改 (分支跳转/JAL/JALR/MRET/SRET/trap)
        """
        # 预解码全部字段 — 一次 FFI 调用替代逐个 parse_* Python 调用
        f = decode_fields(instr)
        self._f = f

        # 平台未声明的扩展所对应的指令不存在, 投递 IllInstr 而不进入处理器
        if not check_ext_isa(f, self.ratified_hart_attrs.isa_ext_switches):
            self.deliver_trap(TrapType.IllInstr, tval=instr, is_interrupt=False)
            return 0

        # 16-bit 压缩指令 — 非法编码触发 IllInstr 陷态
        if f.is_compressed:
            try:
                return self.exec_compressed(mask16(instr))
            except MemoryAccessError:
                pass
            except ValueError, NotImplementedError, CsrAccessError:
                self.deliver_trap(TrapType.IllInstr, tval=instr, is_interrupt=False)
            return 0

        # 32-bit 标准指令 — 所有未识别的编码一律触发非法指令陷态
        opcode = f.opcode

        method_name = self._DISPATCH.get(opcode)
        if method_name is None:
            self.deliver_trap(TrapType.IllInstr, tval=instr, is_interrupt=False)
            return 0

        try:
            return getattr(self, method_name)(instr)
        except MemoryAccessError:
            pass
        except ValueError, NotImplementedError, CsrAccessError:
            # 操作码合法但编码字段无效 (如非法 funct3/funct12/nzuimm=0 等)
            self.deliver_trap(TrapType.IllInstr, tval=instr, is_interrupt=False)
        return 0


"""
TODO: 也该考虑一下
执行状态暂存的事情了
"""
