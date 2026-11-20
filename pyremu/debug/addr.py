# SPDX-LICENSE-IDENTIFIER: MIT
"""AddrOps — 把调试器输入解析为地址."""

from pyremu.core.registers import csr_addr_from_name, gpr_idx_from_name
from pyremu.debug.attrs import SharedAttrs
from pyremu.debug.utils import parse_addr_literal
from pyremu.utils.mask import mask64


class AddrOps(SharedAttrs):
    """地址解析 — pc、寄存器、CSR、符号与数值字面量."""

    def _find_gpr(self, name: str) -> int | None:
        """按名称查找 GPR 索引 (x12, t0, a0, sp 等)."""
        return gpr_idx_from_name(name)

    def _resolve_addr(self, arg: str) -> int | None:
        """将字符串解析为地址: pc / 寄存器名 / 符号名 / 数值."""
        if arg.lower() == "pc":
            return self.hart.pc
        idx = self._find_gpr(arg)
        if idx is not None:
            return mask64(self.hart.gprs[idx])
        value = self._read_csr_by_name(arg)
        if value != 0 or csr_addr_from_name(arg) is not None:
            return value

        name_addr = self._resolve_symbol_operand(arg)
        if name_addr is not None:
            return name_addr
        return parse_addr_literal(arg)

    def _resolve_symbol_operand(self, name: str) -> int | None:
        """按固件符号、已加载模块、外部符号表的顺序解析符号名."""
        if self._image and self._image.symbols:
            sym_va = self._image.symbols.get(name)
            if sym_va is not None:
                return sym_va + self._load_offset
        module_pa = self._module_runtime_addr_of_name(name)
        if module_pa is not None:
            return module_pa
        if self._sym_symbols:
            sym_va = self._sym_symbols.get(name)
            if sym_va is not None:
                return self._resolve_sym_addr(sym_va)
        return None
