# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
"""特权指令与 CSR 指令.

SysInstrOps 由 decoder/hart.py 的 Hart 组合, 方法以 hart 自身为接收者.
funct3 为 0 时按 funct12 分发 ECALL / EBREAK / MRET / SRET / SFENCE.VMA 等特权
指令, 其余 funct3 按 CSR 指令的种类读写 CSR 寄存器.
"""

from pyremu.core.hart import HartGroup


class SysInstrOps:
    """特权指令与 CSR 指令的处理方法."""

    def _flush_tlbs(self, vpn: int | None, all_harts: HartGroup | None) -> None:
        """SFENCE.VMA 的刷新, 广播到全部 hart.

        本 hart 也参与刷新; vpn 为 None 时刷新全部条目, 否则为 VA>>12 的页号;
        all_harts 为全部 hart 的弱引用视图, 由调用方传入以避免每 hart 持有重复引用.
        本次刷新另计入 TLB 刷新计数, 使加速执行引擎内既有的条目作废.
        """
        self.note_tlb_flush()
        if vpn is None:
            self.itlb.flush_all()
            self.dtlb.flush_all()
            for h in all_harts or []:
                if h is self:
                    continue
                h.itlb.flush_all()
                h.dtlb.flush_all()
            return
        self.itlb.flush(vpn)
        self.dtlb.flush(vpn)
        for h in all_harts or []:
            if h is self:
                continue
            h.itlb.flush(vpn)
            h.dtlb.flush(vpn)

    def _sys_ecall(self, instr: int) -> None:
        """ECALL."""
        self.trap_ecall()

    def _sys_ebreak(self, instr: int) -> None:
        """EBREAK."""
        self.trap_ebreak()

    def _sys_mret(self, instr: int) -> None:
        """MRET."""
        self.trap_mret()

    def _sys_sret(self, instr: int) -> None:
        """SRET."""
        self.trap_sret()

    def _sys_wfi(self, instr: int) -> None:
        """WFI."""
        self.handle_wfi(instr)

    def _sys_sfence_vma(self, instr: int) -> None:
        """SFENCE.VMA: rs1=x0 时刷新全部 TLB, 否则仅刷新该虚地址对应的条目.

        刷新同步到全部 hart. RISC-V 只要求刷新本 hart, 扩大范围不影响正确性,
        且省去核间中断.
        """
        rs1 = self._f.rs1
        vpn = None if rs1 == 0 else self.gprs[rs1] >> 12
        self._flush_tlbs(vpn, self._all_harts)

    def _sys_mfence_did(self, instr: int) -> None:
        """MFENCE.DID: 按内存域刷新全部 hart 的 TLB 与共享 L2 缓存."""
        mdid_val = self.mdid_val
        for h in self._all_harts or [self]:
            h.itlb.flush_by_mdid(mdid_val)
            h.dtlb.flush_by_mdid(mdid_val)
        # 加速执行引擎按页号与内存域查询条目, 无按域刷新的入口, 故整表作废.
        self.note_tlb_flush()
        # 刷新共享 L2 缓存中匹配的条目
        if self._bus is not None:
            l2 = getattr(self._bus, "_l2", None)
            if l2 is not None:
                l2.flush_by_mdid(mdid_val)

    # 特权指令分发表: funct12 映射到方法名
    _SYS_PRIV_OPS: dict[int, str] = {
        0x000: "_sys_ecall",
        0x001: "_sys_ebreak",
        0x302: "_sys_mret",
        0x102: "_sys_sret",
        0x105: "_sys_wfi",
        0x120: "_sys_sfence_vma",
        0x5A0: "_sys_mfence_did",
    }

    def _sys_privileged(self, f, instr: int) -> None:
        """执行 funct3=0 的特权指令, 由 funct12 决定具体操作."""
        funct12 = f.func12
        op = self._SYS_PRIV_OPS.get(funct12)
        if op is None and 0x121 <= funct12 <= 0x13F:
            # SFENCE.VMA: funct7=0b0001001, 其 rs2 编码在 funct12 的低 5 位
            op = "_sys_sfence_vma"
        if op is None:
            raise ValueError(f"unknown privileged funct12={funct12:#05x}")
        getattr(self, op)(instr)

    def _sys_csr(self, f, spec: tuple) -> None:
        """执行 CSR 指令; spec 给出新值算法与写入条件."""
        calc, is_conditional = spec
        csr_addr = f.func12
        is_imm = (f.func3 & 0b100) != 0
        src = f.rs1 if is_imm else self.gprs[f.rs1]
        is_write = (src != 0) if is_conditional else True
        self.validate_csr(csr_addr, is_write=is_write)
        old = self.read_csr(csr_addr)
        if f.rd != 0:
            self.gprs[f.rd] = old
        if is_write:
            self.write_csr(csr_addr, calc(old, src))

    def exec_sys(self, f, instr: int) -> int:
        """执行系统指令 (特权指令或 CSR 访问).

        Returns:
            0: pc 已被修改 (陷态或返回)
            4: pc 正常推进
        """
        saved_pc = self.pc
        if f.func3 == 0:
            self._sys_privileged(f, instr)
        else:
            spec = _CSR_OPS.get(f.func3)
            if spec is None:
                raise ValueError(f"invalid funct3={f.func3:#x} for sys")
            self._sys_csr(f, spec)
        return 0 if self.pc != saved_pc else 4


# CSR 指令: funct3 -> (新值算法, 是否按源操作数是否为零决定写入)
_CSR_OPS = {
    0b001: (lambda old, src: src, False),  # CSRRW
    0b010: (lambda old, src: old | src, True),  # CSRRS
    0b011: (lambda old, src: old & ~src, True),  # CSRRC
    0b101: (lambda old, src: src, False),  # CSRRWI
    0b110: (lambda old, src: old | src, True),  # CSRRSI
    0b111: (lambda old, src: old & ~src, True),  # CSRRCI
}
