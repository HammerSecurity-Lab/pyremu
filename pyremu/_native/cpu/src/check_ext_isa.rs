//! 按平台声明的扩展判定一条指令能否被解码执行。
//!
//! 每条指令先由编码得到所属扩展的开关, 再取该 hart 的扩展开关。基础整数指令与
//! 特权指令不属于可选扩展, 不受扩展声明约束。
//!
//! 同一份编码到扩展的对应关系在 ``pyremu/core/decoder/check_ext_isa.py`` 中另有
//! 一份实现, 两侧必须逐一对应。

use crate::decode::DecodedFields;
use crate::state::IsaExts;

/// ``func7`` 取 1 的 OP / OP-32 指令属于 M 扩展。
const FUNCT7_M: u8 = 0x01;

/// SYSTEM 中 funct3 非 0 的 6 条指令为 CSR 指令。
#[inline]
fn is_csr_func3(func3: u8) -> bool {
	matches!(func3, 1 | 2 | 3 | 5 | 6 | 7)
}

/// OP (0x33) 指令所属扩展的开关; 属于基础整数指令时返回 true。
fn check_op_isa(exts: &IsaExts, func3: u8, func7: u8) -> bool {
	if func7 == FUNCT7_M {
		return exts.is_m;
	}
	match (func3, func7) {
		(0b010, 0x10) | (0b100, 0x10) | (0b110, 0x10) => exts.is_zba,
		(0b001, 0x14) | (0b001, 0x24) | (0b101, 0x24) | (0b001, 0x34) => exts.is_zbs,
		(0b001, 0x30) | (0b101, 0x30) => exts.is_zbb,
		(0b100, 0x20) | (0b110, 0x20) | (0b111, 0x20) => exts.is_zbb,
		(0b100, 0x05) | (0b101, 0x05) | (0b110, 0x05) | (0b111, 0x05) => exts.is_zbb,
		_ => true,
	}
}

/// OP-IMM (0x13) 指令所属扩展的开关; 属于基础整数指令时返回 true。
fn check_op_imm_isa(exts: &IsaExts, func3: u8, func7: u8) -> bool {
	// funct6 为 funct7 右移一位的结果, 移位量取 6 位时 funct7 的最低位一并归入
	let funct6 = func7 >> 1;
	match (func3, funct6) {
		(0b001, 0x0A) | (0b001, 0x12) | (0b001, 0x1A) => exts.is_zbs,
		(0b001, 0x18) => exts.is_zbb,
		(0b101, 0x12) => exts.is_zbs,
		(0b101, 0x0A) | (0b101, 0x18) | (0b101, 0x1A) => exts.is_zbb,
		_ => true,
	}
}

/// OP-IMM-32 (0x1B) 指令所属扩展的开关; 属于基础整数指令时返回 true。
fn check_op_imm32_isa(exts: &IsaExts, func3: u8, func7: u8) -> bool {
	match (func3, func7) {
		(0b001, 0x04) | (0b001, 0x05) => exts.is_zba,
		(0b001, 0x30) | (0b101, 0x30) => exts.is_zbb,
		_ => true,
	}
}

/// OP-32 (0x3B) 指令所属扩展的开关; 属于基础整数指令时返回 true。
fn check_op32_isa(exts: &IsaExts, func3: u8, func7: u8) -> bool {
	if func7 == FUNCT7_M {
		return exts.is_m;
	}
	match (func3, func7) {
		(0b000, 0x04) | (0b010, 0x10) | (0b100, 0x10) | (0b110, 0x10) => exts.is_zba,
		(0b001, 0x30) | (0b101, 0x30) => exts.is_zbb,
		_ => true,
	}
}

/// 判定该指令所属扩展的开关是否打开。
///
/// 压缩指令只看 ``is_c``; 其余指令按 opcode 取出所属扩展。未列入可选扩展的
/// 编码一律返回 true, 由各处理器自行判定编码是否合法。
pub fn check_ext_isa(exts: &IsaExts, f: &DecodedFields) -> bool {
	if f.is_compressed != 0 {
		return exts.is_c;
	}
	match f.opcode {
		0b01100_11 => check_op_isa(exts, f.func3, f.func7),
		0b00100_11 => check_op_imm_isa(exts, f.func3, f.func7),
		0b01110_11 => check_op32_isa(exts, f.func3, f.func7),
		0b00110_11 => check_op_imm32_isa(exts, f.func3, f.func7),
		0b01011_11 => exts.is_a,
		0b00001_11 | 0b01001_11 => match f.func3 {
			0b010 => exts.is_f,
			0b011 => exts.is_d,
			_ => true,
		},
		0b10100_11 | 0b10000_11 | 0b10001_11 | 0b10010_11 | 0b10011_11 => match f.fmt {
			0 => exts.is_f,
			1 => exts.is_d,
			_ => true,
		},
		0b11100_11 => {
			if is_csr_func3(f.func3) {
				exts.is_zicsr
			} else {
				true
			}
		}
		0b00011_11 => {
			if f.func3 == 0b001 {
				exts.is_zifencei
			} else {
				true
			}
		}
		_ => true,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::decode::decode_fields;

	/// 全部扩展开关关闭的取值。
	fn all_off() -> IsaExts {
		unsafe { std::mem::zeroed() }
	}

	/// 按 opcode、funct3 与 funct7 组装指令字; rd 与 rs 取 0, 不影响扩展开关判定。
	fn instr(opcode: u32, func3: u32, func7: u32) -> u32 {
		(func7 << 25) | (func3 << 12) | opcode
	}

	#[test]
	fn base_add_always_enabled() {
		// add x1, x2, x3
		let f = decode_fields(0x0031_00b3);
		assert!(check_ext_isa(&all_off(), &f));
	}

	#[test]
	fn mul_requires_m_switch() {
		// mul x1, x2, x3, funct7=1
		let f = decode_fields(instr(0x33, 0, 1));
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_m = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn zbb_rol_requires_zbb_switch() {
		// rol x1, x2, x3, funct3=001, funct7=0x30
		let f = decode_fields(instr(0x33, 0b001, 0x30));
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_zbb = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn zba_sh1add_requires_zba_switch() {
		// sh1add x1, x2, x3, funct3=010, funct7=0x10
		let f = decode_fields(instr(0x33, 0b010, 0x10));
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_zba = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn zbs_bset_requires_zbs_switch() {
		// bset x1, x2, x3, funct3=001, funct7=0x14
		let f = decode_fields(instr(0x33, 0b001, 0x14));
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_zbs = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn compressed_requires_c_switch() {
		// c.addi x1, 1
		let f = decode_fields(0x0085);
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_c = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn amo_requires_a_switch() {
		// amoadd.w x1, x2, (x3)
		let f = decode_fields(instr(0x2f, 0b010, 0));
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_a = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn fp_load_requires_f_switch() {
		// flw f1, 0(x2)
		let f = decode_fields(instr(0x07, 0b010, 0));
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_f = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn csr_requires_zicsr_switch() {
		// csrrw x1, 0x300, x2
		let f = decode_fields(instr(0x73, 0b001, 0));
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_zicsr = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn fence_i_requires_zifencei_switch() {
		// fence.i
		let f = decode_fields(0x0000_100f);
		assert!(!check_ext_isa(&all_off(), &f));
		let mut exts = all_off();
		exts.is_zifencei = true;
		assert!(check_ext_isa(&exts, &f));
	}

	#[test]
	fn ecall_without_zicsr_stays_enabled() {
		// ecall 的 funct3 为 0, 不属于 CSR 指令
		let f = decode_fields(0x0000_0073);
		assert!(check_ext_isa(&all_off(), &f));
		assert!(check_ext_isa(&IsaExts::all_enabled(), &f));
	}
}
