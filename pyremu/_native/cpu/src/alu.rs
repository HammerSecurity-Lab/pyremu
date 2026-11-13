//! RISC-V ALU 纯计算操作.
//!
//! 所有函数返回 `Alu64` 结构体:
//!     .value: 存放运算结果
//!     .trap: 记录陷态标志, 0 表示编码合法, 1 表示编码非法并提示产生非法指令陷态.

/// 带陷态标志的 ALU 结果. `trap` 为 1 表示编码非法并提示产生非法指令陷态
#[repr(C)]
pub struct Alu64 {
	pub value: u64,
	pub trap: u8,
}

impl Alu64 {
	#[inline(always)]
	fn ok(value: u64) -> Self {
		Alu64 { value, trap: 0 }
	}
	#[inline(always)]
	fn ill() -> Self {
		Alu64 { value: 0, trap: 1 }
	}
}

/// RISC-V R 型 ALU: funct3 选择运算, funct7 选择变体.
///
/// | funct3 | 0    | 1      | 0x05 | 0x10   | 0x14 | 0x20 | 0x24 | 0x30 | 0x34 |
/// |--------|------|--------|------|--------|------|------|------|------|------|
/// | 000    | ADD  | MUL    |      |        |      | SUB  |      |      |      |
/// | 001    | SLL  | MULH   |      |        | BSET |      | BCLR | ROL  | BINV |
/// | 010    | SLT  | MULHSU |      | SH1ADD |      |      |      |      |      |
/// | 011    | SLTU | MULHU  |      |        |      |      |      |      |      |
/// | 100    | XOR  | DIV    | MIN  | SH2ADD |      | XNOR |      |      |      |
/// | 101    | SRL  | DIVU   | MINU |        |      | SRA  | BEXT | ROR  |      |
/// | 110    | OR   | REM    | MAX  | SH3ADD |      | ORN  |      |      |      |
/// | 111    | AND  | REMU   | MAXU |        |      | ANDN |      |      |      |
#[no_mangle]
pub extern "C" fn exec_alu_op(funct3: u8, funct7: u8, v1: u64, v2: u64) -> Alu64 {
	let shamt = (v2 & 0x3F) as u32;

	match funct3 {
		0b000 => match funct7 {
			0 => Alu64::ok(v1.wrapping_add(v2)),
			1 => Alu64::ok(v1.wrapping_mul(v2)),
			0x20 => Alu64::ok(v1.wrapping_sub(v2)),
			_ => Alu64::ill(),
		},
		0b001 => match funct7 {
			0 => Alu64::ok(v1 << shamt),
			1 => {
				let s1 = v1 as i64 as i128;
				let s2 = v2 as i64 as i128;
				Alu64::ok(((s1 * s2) >> 64) as u64)
			}
			0x14 => Alu64::ok(v1 | (1u64 << shamt)),
			0x24 => Alu64::ok(v1 & !(1u64 << shamt)),
			0x30 => Alu64::ok(v1.rotate_left(shamt)),
			0x34 => Alu64::ok(v1 ^ (1u64 << shamt)),
			_ => Alu64::ill(),
		},
		0b010 => match funct7 {
			0 => Alu64::ok(if (v1 as i64) < (v2 as i64) { 1 } else { 0 }),
			1 => {
				let s1 = v1 as i64 as i128;
				let u2 = v2 as i128;
				Alu64::ok(((s1 * u2) >> 64) as u64)
			}
			0x10 => Alu64::ok((v1 << 1).wrapping_add(v2)),
			_ => Alu64::ill(),
		},
		0b011 => match funct7 {
			0 => Alu64::ok(if v1 < v2 { 1 } else { 0 }),
			1 => {
				let u1 = v1 as u128;
				let u2 = v2 as u128;
				Alu64::ok(((u1 * u2) >> 64) as u64)
			}
			_ => Alu64::ill(),
		},
		0b100 => match funct7 {
			0 => Alu64::ok(v1 ^ v2),
			1 => {
				let s1 = v1 as i64;
				let s2 = v2 as i64;
				let val = if s2 == 0 {
					u64::MAX
				} else if s1 == i64::MIN && s2 == -1 {
					i64::MIN as u64
				} else {
					(s1 / s2) as u64
				};
				Alu64::ok(val)
			}
			0x05 => Alu64::ok(if (v1 as i64) < (v2 as i64) { v1 } else { v2 }),
			0x10 => Alu64::ok((v1 << 2).wrapping_add(v2)),
			0x20 => Alu64::ok(!(v1 ^ v2)),
			_ => Alu64::ill(),
		},
		0b101 => match funct7 {
			0 => Alu64::ok(v1 >> shamt),
			1 => Alu64::ok(if v2 == 0 { u64::MAX } else { v1 / v2 }),
			0x05 => Alu64::ok(if v1 < v2 { v1 } else { v2 }),
			0x20 => Alu64::ok(((v1 as i64) >> shamt) as u64),
			0x24 => Alu64::ok((v1 >> shamt) & 1),
			0x30 => Alu64::ok(v1.rotate_right(shamt)),
			_ => Alu64::ill(),
		},
		0b110 => match funct7 {
			0 => Alu64::ok(v1 | v2),
			1 => {
				let s1 = v1 as i64;
				let s2 = v2 as i64;
				let val = if s2 == 0 {
					v1
				} else if s1 == i64::MIN && s2 == -1 {
					0
				} else {
					(s1 % s2) as u64
				};
				Alu64::ok(val)
			}
			0x05 => Alu64::ok(if (v1 as i64) > (v2 as i64) { v1 } else { v2 }),
			0x10 => Alu64::ok((v1 << 3).wrapping_add(v2)),
			0x20 => Alu64::ok(v1 | !v2),
			_ => Alu64::ill(),
		},
		0b111 => match funct7 {
			0 => Alu64::ok(v1 & v2),
			1 => Alu64::ok(if v2 == 0 { v1 } else { v1 % v2 }),
			0x05 => Alu64::ok(if v1 > v2 { v1 } else { v2 }),
			0x20 => Alu64::ok(v1 & !v2),
			_ => Alu64::ill(),
		},
		_ => Alu64::ill(),
	}
}

/// RISC-V I 型立即数 ALU: funct3 选择运算.
///
/// `imm` 为已经符号扩展的 12 位立即数.
/// `funct7` 的高 6 位即 funct6 字段, 对应 bits[31:26], 用于区分 SRLI 与 SRAI,
/// 以及 Zbb 与 Zbs 中由该字段选择的各子指令.
#[no_mangle]
pub extern "C" fn exec_op_imm(funct3: u8, funct7: u8, v1: u64, imm: u64) -> Alu64 {
	let shamt = (imm & 0x3F) as u32;
	let funct6 = funct7 >> 1;

	match funct3 {
		0b000 => Alu64::ok(v1.wrapping_add(imm)),
		0b001 => match funct6 {
			0 => Alu64::ok(v1 << shamt),
			0x0A => Alu64::ok(v1 | (1u64 << shamt)),
			0x12 => Alu64::ok(v1 & !(1u64 << shamt)),
			0x18 => zbb_unary_imm(v1, shamt),
			0x1A => Alu64::ok(v1 ^ (1u64 << shamt)),
			_ => Alu64::ill(),
		},
		0b010 => Alu64::ok(if (v1 as i64) < (imm as i64) { 1 } else { 0 }),
		0b011 => Alu64::ok(if v1 < imm { 1 } else { 0 }),
		0b100 => Alu64::ok(v1 ^ imm),
		0b101 => match funct6 {
			0 => Alu64::ok(v1 >> shamt),
			0x0A if imm == 0x287 => Alu64::ok(orc_b(v1)),
			0x10 => Alu64::ok(((v1 as i64) >> shamt) as u64),
			0x12 => Alu64::ok((v1 >> shamt) & 1),
			0x18 => Alu64::ok(v1.rotate_right(shamt)),
			0x1A if imm == 0x6B8 => Alu64::ok(v1.swap_bytes()),
			_ => Alu64::ill(),
		},
		0b110 => Alu64::ok(v1 | imm),
		0b111 => Alu64::ok(v1 & imm),
		_ => Alu64::ill(),
	}
}

/// Zbb 中由立即数低 5 位选择的一元运算: clz、ctz、cpop、sext.b、sext.h.
///
/// 其余取值不是有效编码, 返回非法编码的结果.
fn zbb_unary_imm(v: u64, shamt: u32) -> Alu64 {
	match shamt {
		0 => Alu64::ok(v.leading_zeros() as u64),
		1 => Alu64::ok(v.trailing_zeros() as u64),
		2 => Alu64::ok(v.count_ones() as u64),
		4 => Alu64::ok(((v as i8) as i64) as u64),
		5 => Alu64::ok(((v as i16) as i64) as u64),
		_ => Alu64::ill(),
	}
}

/// orc.b: 每个字节只要有一位为 1, 该字节的 8 位全部置为 1, 否则全部置为 0.
fn orc_b(v: u64) -> u64 {
	let mut out = 0u64;
	for i in 0..8u32 {
		if (v >> (i * 8)) & 0xFF != 0 {
			out |= 0xFFu64 << (i * 8);
		}
	}
	out
}

/// RISC-V RV64 32 位字 ALU: 只对低 32 位运算, 结果符号扩展到 64 位.
/// Zba 的 uw 形式例外, 结果取值 64 位, 不作符号扩展.
///
/// | funct3 | 0     | 1      | 0x04   | 0x10      | 0x20  | 0x30 |
/// |--------|-------|--------|--------|-----------|-------|------|
/// | 000    | ADDW  | MULW   | ADD.UW |           | SUBW  |      |
/// | 001    | SLLW  |        |        |           |       | ROLW |
/// | 010    |       |        |        | SH1ADD.UW |       |      |
/// | 100    |       | DIVW   |        | SH2ADD.UW |       |      |
/// | 101    | SRLW  | DIVUW  |        |           | SRAW  | RORW |
/// | 110    |       | REMW   |        | SH3ADD.UW |       |      |
/// | 111    |       | REMUW  |        |           |       |      |
#[no_mangle]
pub extern "C" fn exec_op32(funct3: u8, funct7: u8, v1: u64, v2: u64) -> Alu64 {
	let uw1 = v1 & 0xFFFF_FFFF;

	// Zba 的 uw 形式: 只有 rs1 取低 32 位, rs2 取完整的 64 位参与加法
	match (funct3, funct7) {
		(0b000, 0x04) => return Alu64::ok(uw1.wrapping_add(v2)),
		(0b010, 0x10) => return Alu64::ok((uw1 << 1).wrapping_add(v2)),
		(0b100, 0x10) => return Alu64::ok((uw1 << 2).wrapping_add(v2)),
		(0b110, 0x10) => return Alu64::ok((uw1 << 3).wrapping_add(v2)),
		_ => {}
	}

	let w1 = (v1 & 0xFFFF_FFFF) as i32;
	let w2 = (v2 & 0xFFFF_FFFF) as i32;

	let result_i32: i32 = match funct3 {
		0b000 => match funct7 {
			0 => w1.wrapping_add(w2),
			1 => w1.wrapping_mul(w2),
			0x20 => w1.wrapping_sub(w2),
			_ => return Alu64::ill(),
		},
		0b001 => match funct7 {
			0 => w1 << (w2 & 0x1F),
			0x30 => w1.rotate_left((w2 as u32) & 0x1F),
			_ => return Alu64::ill(),
		},
		0b100 => {
			if funct7 != 1 {
				return Alu64::ill();
			}
			if w2 == 0 {
				-1i32
			} else if w1 == i32::MIN && w2 == -1 {
				i32::MIN
			} else {
				w1 / w2
			}
		}
		0b101 => match funct7 {
			0 => ((w1 as u32) >> (w2 as u32 & 0x1F)) as i32,
			1 => {
				let u1 = w1 as u32;
				let u2 = w2 as u32;
				if u2 == 0 {
					u32::MAX as i32
				} else {
					(u1 / u2) as i32
				}
			}
			0x20 => w1 >> (w2 & 0x1F),
			0x30 => w1.rotate_right((w2 as u32) & 0x1F),
			_ => return Alu64::ill(),
		},
		0b110 => {
			if funct7 != 1 {
				return Alu64::ill();
			}
			if w2 == 0 {
				w1
			} else if w1 == i32::MIN && w2 == -1 {
				0
			} else {
				w1 % w2
			}
		}
		0b111 => {
			if funct7 != 1 {
				return Alu64::ill();
			}
			let u1 = w1 as u32;
			let u2 = w2 as u32;
			if u2 == 0 {
				u1 as i32
			} else {
				(u1 % u2) as i32
			}
		}
		_ => return Alu64::ill(),
	};

	Alu64::ok((result_i32 as i64) as u64)
}

/// RISC-V RV64 32 位字立即数 ALU: 对低 32 位运算, 结果符号扩展到 64 位.
/// slli.uw 例外, 结果为 64 位, 不作符号扩展.
///
/// | funct3 | 0     | 0x04 / 0x05 | 0x20  | 0x30                |
/// |--------|-------|-------------|-------|---------------------|
/// | 000    | ADDIW |             |       |                     |
/// | 001    | SLLIW | SLLI.UW     |       | CLZW / CTZW / CPOPW |
/// | 101    | SRLIW |             | SRAIW | RORIW               |
#[no_mangle]
pub extern "C" fn exec_op_imm32(funct3: u8, funct7: u8, v1: u64, imm: u64) -> Alu64 {
	let w1 = (v1 & 0xFFFF_FFFF) as i32;
	let shamt = imm as u32 & 0x1F;

	// slli.uw 的移位量为 6 位, 第 6 位落在 funct7 的最低位, 故 funct7 取 0x04 或 0x05
	if funct3 == 0b001 && (funct7 >> 1) == 0x02 {
		return Alu64::ok((v1 & 0xFFFF_FFFF) << (imm as u32 & 0x3F));
	}

	let result_i32: i32 = match funct3 {
		0b000 => w1.wrapping_add(imm as i32),
		0b001 => match funct7 {
			0 => w1 << shamt,
			0x30 => match shamt {
				0 => w1.leading_zeros() as i32,
				1 => w1.trailing_zeros() as i32,
				2 => w1.count_ones() as i32,
				_ => return Alu64::ill(),
			},
			_ => return Alu64::ill(),
		},
		0b101 => match funct7 {
			0 => ((w1 as u32) >> shamt) as i32,
			0x20 => w1 >> shamt,
			0x30 => w1.rotate_right(shamt),
			_ => return Alu64::ill(),
		},
		_ => return Alu64::ill(),
	};

	Alu64::ok((result_i32 as i64) as u64)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn v(r: Alu64) -> u64 {
		assert_eq!(r.trap, 0);
		r.value
	}
	fn trap(r: Alu64) -> bool {
		r.trap != 0
	}

	#[test]
	fn test_add() {
		assert_eq!(v(exec_alu_op(0, 0, 10, 5)), 15);
	}
	#[test]
	fn test_sub() {
		assert_eq!(v(exec_alu_op(0, 0x20, 10, 5)), 5);
	}
	#[test]
	fn test_sll() {
		assert_eq!(v(exec_alu_op(1, 0, 1, 3)), 8);
	}
	#[test]
	fn test_xor() {
		assert_eq!(v(exec_alu_op(4, 0, 0xFF, 0x0F)), 0xF0);
	}
	#[test]
	fn test_or() {
		assert_eq!(v(exec_alu_op(6, 0, 0xF0, 0x0F)), 0xFF);
	}
	#[test]
	fn test_and() {
		assert_eq!(v(exec_alu_op(7, 0, 0xFF, 0x0F)), 0x0F);
	}
	#[test]
	fn test_slt_true() {
		assert_eq!(v(exec_alu_op(2, 0, 5, 10)), 1);
	}
	#[test]
	fn test_slt_false() {
		assert_eq!(v(exec_alu_op(2, 0, 10, 5)), 0);
	}
	#[test]
	fn test_sltu_true() {
		assert_eq!(v(exec_alu_op(3, 0, 5, 10)), 1);
	}
	#[test]
	fn test_srl() {
		assert_eq!(v(exec_alu_op(5, 0, 0x100, 4)), 0x10);
	}
	#[test]
	fn test_sra_negative() {
		assert_eq!(
			v(exec_alu_op(5, 0x20, 0xFFFF_FFFF_FFFF_FF00u64, 4)),
			0xFFFF_FFFF_FFFF_FFF0u64
		);
	}
	#[test]
	fn test_div() {
		assert_eq!(v(exec_alu_op(4, 1, 20, 6)), 3);
	}
	#[test]
	fn test_div_by_zero() {
		assert_eq!(v(exec_alu_op(4, 1, 42, 0)), u64::MAX);
	}
	#[test]
	fn test_div_overflow() {
		assert_eq!(
			v(exec_alu_op(4, 1, i64::MIN as u64, (-1i64) as u64)),
			i64::MIN as u64
		);
	}
	#[test]
	fn test_divu() {
		assert_eq!(v(exec_alu_op(5, 1, 20, 6)), 3);
	}
	#[test]
	fn test_rem() {
		assert_eq!(v(exec_alu_op(6, 1, 20, 6)), 2);
	}
	#[test]
	fn test_remu() {
		assert_eq!(v(exec_alu_op(7, 1, 20, 6)), 2);
	}
	#[test]
	fn test_mul() {
		assert_eq!(v(exec_alu_op(0, 1, 6, 7)), 42);
	}
	#[test]
	fn test_alu_ill_funct7() {
		assert!(trap(exec_alu_op(0, 0x0F, 10, 5)));
	}
	#[test]
	fn test_alu_ill_funct3() {
		assert!(trap(exec_alu_op(0xFF, 0, 10, 5)));
	}

	// ---- 64 位 REM: 检查操作数按完整 64 位参与运算而不被截断 ----
	#[test]
	fn test_rem_positive_large() {
		// 0x3FD9CEF920 占 33 位; REM 必须按完整 64 位运算.
		assert_eq!(v(exec_alu_op(6, 1, 0x3FD9CEF920, 7)), 5);
	}
	#[test]
	fn test_rem_negative() {
		// RISC-V 采用截断除法, 被除数为负时余数为负.
		assert_eq!(v(exec_alu_op(6, 1, (-10i64) as u64, 3)), (-1i64) as u64);
	}
	#[test]
	fn test_rem_negative_divisor() {
		assert_eq!(v(exec_alu_op(6, 1, 20, (-6i64) as u64)), 2);
	}
	#[test]
	fn test_rem_by_zero() {
		// 除数为零时 REM 返回被除数
		assert_eq!(v(exec_alu_op(6, 1, 42, 0)), 42);
	}
	#[test]
	fn test_rem_overflow() {
		assert_eq!(v(exec_alu_op(6, 1, i64::MIN as u64, (-1i64) as u64)), 0);
	}
	#[test]
	fn test_remu_large() {
		assert_eq!(v(exec_alu_op(7, 1, 0x3FD9CEF920, 7)), 5);
	}
	#[test]
	fn test_remu_by_zero() {
		assert_eq!(v(exec_alu_op(7, 1, 42, 0)), 42);
	}

	// ---- REMW: 32 位有符号求余, 结果符号扩展 ----
	#[test]
	fn test_remw_positive() {
		assert_eq!(v(exec_op32(6, 1, 20, 6)), 2);
	}
	#[test]
	fn test_remw_negative_dividend() {
		assert_eq!(v(exec_op32(6, 1, (-10i64) as u64, 3)), (-1i64) as u64);
	}
	#[test]
	fn test_remw_sign_extend_negative_result() {
		// w1 = 0xD9CEF920 按 i32 解释为 -640747232, w2 = 7
		// -640747232 / 7 = -91535318.857, 截断后商为 -91535318
		// 余数 r 为 -6
		// 符号扩展后为 0xFFFF_FFFF_FFFF_FFFA
		assert_eq!(
			v(exec_op32(6, 1, 0x3FD9CEF920, 7)),
			0xFFFF_FFFF_FFFF_FFFAu64
		);
	}
	#[test]
	fn test_remw_by_zero() {
		assert_eq!(v(exec_op32(6, 1, 42, 0)), 42);
	}
	#[test]
	fn test_remw_overflow() {
		assert_eq!(v(exec_op32(6, 1, i32::MIN as u64, (-1i64) as u64)), 0);
	}

	// REMUW: 32 位无符号求余, 结果零扩展
	#[test]
	fn test_remuw_positive() {
		assert_eq!(v(exec_op32(7, 1, 20, 6)), 2);
	}
	#[test]
	fn test_remuw_large_u32() {
		// u1 = 0xD9CEF920 = 3654220064, u2 = 7
		// 3654220064 / 7 = 522031437.714...
		// 7 * 522031437 = 3654220059
		// 3654220064 - 3654220059 = 5
		assert_eq!(v(exec_op32(7, 1, 0x3FD9CEF920, 7)), 5);
	}
	#[test]
	fn test_remuw_by_zero() {
		assert_eq!(v(exec_op32(7, 1, 42, 0)), 42);
	}

	// 对该缺陷触发值, REM 与 REMW 的结果不同
	#[test]
	fn test_rem_vs_remw_crash_value() {
		let v1 = 0x3FD9CEF920u64; // 取自栈中的缺陷触发指针
		let v2 = 7u64;
		let r64 = v(exec_alu_op(6, 1, v1, v2)); // REM: 按完整 64 位运算, 结果为 5
		let r32 = v(exec_op32(6, 1, v1, v2)); // REMW: 低 32 位为 0xD9CEF920, 按有符号数解释为 -640747232, 结果为 -6
		assert_eq!(r64, 5);
		assert_eq!(r32, 0xFFFF_FFFF_FFFF_FFFAu64);
		// 必须不同。若相同, 则说明代码实现混淆了 32 位运算与 64 位运算
		assert_ne!(
			r64, r32,
			"REM and REMW MUST differ for this operand — bit-width confusion?"
		);
	}

	// ---- REM 边界: bit63 为 1 的操作数 ----
	#[test]
	fn test_rem_bit63_1_mod_positive() {
		// u64::MAX 即全部位为 1, 对应 -1
		assert_eq!(v(exec_alu_op(6, 1, u64::MAX, 3)), u64::MAX);
	}
	#[test]
	fn test_rem_bit63_1_mod_negative() {
		assert_eq!(v(exec_alu_op(6, 1, u64::MAX, (-3i64) as u64)), u64::MAX);
	}
	#[test]
	fn test_rem_positive_mod_negative() {
		assert_eq!(v(exec_alu_op(6, 1, 20, (-6i64) as u64)), 2);
	}
	#[test]
	fn test_rem_negative_mod_negative() {
		assert_eq!(
			v(exec_alu_op(6, 1, (-20i64) as u64, (-6i64) as u64)),
			(-2i64) as u64
		);
	}

	#[test]
	fn test_remu_bit63_1() {
		// u64::MAX % 3 = 0.  u64::MAX = 0xFFFFFFFFFFFFFFFF = 18446744073709551615.
		// 以 3 作为取模对象时, 2^64 的余数为 1, 故 2^64 - 1 的余数为 0, 该值可被 3 整除.
		assert_eq!(v(exec_alu_op(7, 1, u64::MAX, 3)), 0);
	}

	// 测试 REMW 指令的边界情况：低 32 位的 bit31 为 1
	#[test]
	fn test_remw_bit31_1_mod_positive() {
		// w1 = 0x80000000, 按 i32 解释为 i32::MIN = -2147483648
		// -2147483648 % 3 = -2, 符号扩展后为 0xFFFFFFFFFFFFFFFE
		assert_eq!(
			v(exec_op32(6, 1, 0x8000_0000u64, 3)),
			0xFFFF_FFFF_FFFF_FFFEu64
		);
	}
	#[test]
	fn test_remw_bit31_1_mod_negative() {
		assert_eq!(
			v(exec_op32(6, 1, 0x8000_0000u64, (-3i64) as u64)),
			0xFFFF_FFFF_FFFF_FFFEu64
		);
	}
	#[test]
	fn test_remw_bit31_0_mod_negative() {
		assert_eq!(v(exec_op32(6, 1, 10, (-3i64) as u64)), 1);
	}
	#[test]
	fn test_remw_bit31_0_sign_extend_positive() {
		assert_eq!(v(exec_op32(6, 1, 0x7FFF_FFFFu64, 3)), 1);
	}

	// REMUW 边界情况：bit31 为 1 时按无符号数解释
	#[test]
	fn test_remuw_bit31_1() {
		assert_eq!(v(exec_op32(7, 1, 0x8000_0000u64, 3)), 2);
	}
	#[test]
	fn test_remuw_contrast_remw_bit31_1() {
		// 低 32 位相同, 但 REMUW 按无符号数运算, REMW 按有符号数运算
		let v1 = 0x8000_0000u64;
		let remw_r = v(exec_op32(6, 1, v1, 3)); // 有符号: -2147483648 % 3 = -2
		let remuw_r = v(exec_op32(7, 1, v1, 3)); // 无符号: 2147483648 % 3 = 2
		assert_eq!(remw_r, 0xFFFF_FFFF_FFFF_FFFEu64); // 符号扩展后的 -2
		assert_eq!(remuw_r, 2); // 零扩展后的 2
		assert_ne!(remw_r, remuw_r, "REMW ≠ REMUW for bit31=1 operand");
	}

	#[test]
	fn test_addi() {
		assert_eq!(v(exec_op_imm(0, 0, 10, 5)), 15);
	}
	#[test]
	fn test_addi_negative() {
		assert_eq!(v(exec_op_imm(0, 0, 10, (-2i64) as u64)), 8);
	}
	#[test]
	fn test_slti() {
		assert_eq!(v(exec_op_imm(2, 0, 5, 10)), 1);
	}
	#[test]
	fn test_xori() {
		assert_eq!(v(exec_op_imm(4, 0, 0xFF, 0x0F)), 0xF0);
	}
	#[test]
	fn test_slli_bad_f6() {
		assert!(trap(exec_op_imm(1, 0x7F, 10, 3)));
	}
	#[test]
	fn test_srli_bad_f6() {
		// funct3 为 101 时 funct6 只允许取 0 或 0x10, 该用例取 0x1F.
		assert!(trap(exec_op_imm(5, 0x3E, 0x100, 2)));
	}

	#[test]
	fn test_addw() {
		assert_eq!(v(exec_op32(0, 0, 10, 5)), 15);
	}
	#[test]
	fn test_addw_sign_extend() {
		assert_eq!(v(exec_op32(0, 0, 0x7FFFFFFF, 1)), 0xFFFF_FFFF_8000_0000u64);
	}
	#[test]
	fn test_subw() {
		assert_eq!(v(exec_op32(0, 0x20, 10, 5)), 5);
	}
	#[test]
	fn test_op32_ill() {
		assert!(trap(exec_op32(0b001, 1, 10, 3)));
	}

	#[test]
	fn test_slliw() {
		assert_eq!(v(exec_op_imm32(1, 0, 0x100, 2)), 0x400);
	}
	#[test]
	fn test_sraiw() {
		assert_eq!(
			v(exec_op_imm32(5, 0x20, 0xFFFF_FFFF_8000_0000u64, 1)),
			0xFFFF_FFFF_C000_0000u64
		);
	}
	#[test]
	fn test_op_imm32_ill() {
		assert!(trap(exec_op_imm32(1, 1, 0x100, 2)));
	}

	// ---- Zbb OP-IMM: clz、ctz、cpop、sext.b、sext.h、rori、orc.b、rev8 ----
	#[test]
	fn test_clz_counts_leading_zeros() {
		assert_eq!(v(exec_op_imm(1, 0x30, 0x00FF_FFFF_FFFF_FFFF, 0x600)), 8);
		assert_eq!(v(exec_op_imm(1, 0x30, 0, 0x600)), 64);
	}
	#[test]
	fn test_ctz_counts_trailing_zeros() {
		assert_eq!(v(exec_op_imm(1, 0x30, 0xFFFF_FFFF_FFFF_FF00, 0x601)), 8);
		assert_eq!(v(exec_op_imm(1, 0x30, 0, 0x601)), 64);
	}
	#[test]
	fn test_cpop_counts_ones() {
		assert_eq!(v(exec_op_imm(1, 0x30, 0xFF, 0x602)), 8);
		assert_eq!(v(exec_op_imm(1, 0x30, u64::MAX, 0x602)), 64);
	}
	#[test]
	fn test_sext_b_sign_extends_low_byte() {
		assert_eq!(v(exec_op_imm(1, 0x30, 0x80, 0x604)), 0xFFFF_FFFF_FFFF_FF80);
		assert_eq!(v(exec_op_imm(1, 0x30, 0x7F, 0x604)), 0x7F);
	}
	#[test]
	fn test_sext_h_sign_extends_low_halfword() {
		assert_eq!(
			v(exec_op_imm(1, 0x30, 0x8000, 0x605)),
			0xFFFF_FFFF_FFFF_8000
		);
		assert_eq!(v(exec_op_imm(1, 0x30, 0x7FFF, 0x605)), 0x7FFF);
	}
	#[test]
	fn test_rori() {
		assert_eq!(
			v(exec_op_imm(5, 0x30, 0x8000_0000_0000_0001, 0x601)),
			0xC000_0000_0000_0000
		);
	}
	#[test]
	fn test_orc_b_expands_nonzero_bytes() {
		assert_eq!(v(exec_op_imm(5, 0x14, 0x0F07, 0x287)), 0xFFFF);
		assert_eq!(v(exec_op_imm(5, 0x14, 0, 0x287)), 0);
	}
	#[test]
	fn test_rev8_reverses_bytes() {
		assert_eq!(
			v(exec_op_imm(5, 0x35, 0x0123_4567_89AB_CDEF, 0x6B8)),
			0xEFCD_AB89_6745_2301
		);
	}
	#[test]
	fn test_rev8_reserved_immediate_traps() {
		// rev8 的立即数固定为 0x6B8, 相邻取值为保留编码
		assert!(trap(exec_op_imm(5, 0x35, 0, 0x6B9)));
	}
	#[test]
	fn test_zbb_unary_reserved_shamt_traps() {
		// funct3=001 与 funct6=0x18 时 shamt 只允许取 0、1、2、4、5
		assert!(trap(exec_op_imm(1, 0x30, 0xFF, 0x603)));
	}

	// ---- Zbb R 型: andn、orn、xnor、min、minu、max、maxu、rol、ror ----
	#[test]
	fn test_andn() {
		assert_eq!(v(exec_alu_op(7, 0x20, 0xFF00, 0x0F0F)), 0xF000);
	}
	#[test]
	fn test_orn() {
		assert_eq!(
			v(exec_alu_op(6, 0x20, 0x00FF, 0x0F0F)),
			0xFFFF_FFFF_FFFF_F0FF
		);
	}
	#[test]
	fn test_xnor() {
		assert_eq!(v(exec_alu_op(4, 0x20, 0xFF, 0x0F)), 0xFFFF_FFFF_FFFF_FF0F);
	}
	#[test]
	fn test_min_and_max_compare_signed() {
		assert_eq!(v(exec_alu_op(4, 0x05, u64::MAX, 0x10)), u64::MAX);
		assert_eq!(v(exec_alu_op(6, 0x05, u64::MAX, 0x10)), 0x10);
	}
	#[test]
	fn test_minu_and_maxu_compare_unsigned() {
		assert_eq!(v(exec_alu_op(5, 0x05, u64::MAX, 0x10)), 0x10);
		assert_eq!(v(exec_alu_op(7, 0x05, u64::MAX, 0x10)), u64::MAX);
	}
	#[test]
	fn test_rol_and_ror() {
		assert_eq!(v(exec_alu_op(1, 0x30, 0x8000_0000_0000_0001, 1)), 3);
		assert_eq!(
			v(exec_alu_op(5, 0x30, 0x8000_0000_0000_0001, 1)),
			0xC000_0000_0000_0000
		);
	}
	#[test]
	fn test_rolw_and_rorw_sign_extend() {
		assert_eq!(v(exec_op32(1, 0x30, 0x4000_0000, 1)), 0xFFFF_FFFF_8000_0000);
		assert_eq!(v(exec_op32(5, 0x30, 0x0000_0001, 1)), 0xFFFF_FFFF_8000_0000);
	}
	#[test]
	fn test_clzw_ctzw_cpopw_ignore_high_half() {
		assert_eq!(v(exec_op_imm32(1, 0x30, 0xFFFF_FFFF_0000_0001, 0x600)), 31);
		assert_eq!(v(exec_op_imm32(1, 0x30, 0xFFFF_FFFF_0000_0100, 0x601)), 8);
		assert_eq!(v(exec_op_imm32(1, 0x30, 0xFFFF_FFFF_0000_000F, 0x602)), 4);
	}
	#[test]
	fn test_roriw_rotates_word() {
		assert_eq!(
			v(exec_op_imm32(5, 0x30, 0x1234_5678, 0x604)),
			0xFFFF_FFFF_8123_4567
		);
	}

	// ---- Zba: sh1add、sh2add、sh3add、add.uw、slli.uw ----
	#[test]
	fn test_sh1add_sh2add_sh3add() {
		assert_eq!(v(exec_alu_op(2, 0x10, 5, 3)), 13);
		assert_eq!(v(exec_alu_op(4, 0x10, 5, 3)), 23);
		assert_eq!(v(exec_alu_op(6, 0x10, 5, 3)), 43);
	}
	#[test]
	fn test_add_uw_zero_extends_rs1() {
		// zext32(0xFFFFFFFFFFFFFFFF) + 1 = 0x1_0000_0000;
		// 若按符号扩展把 rs1 取作 -1, 结果会变成 0
		assert_eq!(v(exec_op32(0, 0x04, u64::MAX, 1)), 0x1_0000_0000);
	}
	#[test]
	fn test_sh_add_uw_keeps_rs2_high_half() {
		assert_eq!(
			v(exec_op32(2, 0x10, 0x1_0000_0001, 0x1_0000_0000)),
			0x1_0000_0002
		);
		assert_eq!(
			v(exec_op32(4, 0x10, 0x1_0000_0001, 0x1_0000_0000)),
			0x1_0000_0004
		);
		assert_eq!(
			v(exec_op32(6, 0x10, 0x1_0000_0001, 0x1_0000_0000)),
			0x1_0000_0008
		);
	}
	#[test]
	fn test_slli_uw_zero_extends_rs1() {
		assert_eq!(v(exec_op_imm32(1, 0x04, 0x1_0000_0001, 0x087)), 0x80);
	}
	#[test]
	fn test_slli_uw_shamt_above_31() {
		// shamt=33 使 funct7 的最低位为 1, 与移位量 1 的编码区别只在该位
		assert_eq!(v(exec_op_imm32(1, 0x05, 1, 0xA1)), 0x2_0000_0000);
		assert_eq!(v(exec_op_imm32(1, 0x04, 1, 0x081)), 0x2);
	}

	// ---- Zbs: bset、bclr、binv、bext 与对应的立即数形式 ----
	#[test]
	fn test_bset_bclr_binv() {
		assert_eq!(v(exec_alu_op(1, 0x14, 0, 5)), 0x20);
		assert_eq!(v(exec_alu_op(1, 0x24, 0xFF, 3)), 0xF7);
		assert_eq!(v(exec_alu_op(1, 0x34, 0xFF, 3)), 0xF7);
	}
	#[test]
	fn test_bext_extracts_bit() {
		assert_eq!(v(exec_alu_op(5, 0x24, 0x80, 7)), 1);
		assert_eq!(v(exec_alu_op(5, 0x24, 0x80, 6)), 0);
	}
	#[test]
	fn test_bseti_bclri_binvi() {
		assert_eq!(v(exec_op_imm(1, 0x14, 0, 5)), 0x20);
		assert_eq!(v(exec_op_imm(1, 0x24, 0xFF, 3)), 0xF7);
		assert_eq!(v(exec_op_imm(1, 0x34, 0xFF, 3)), 0xF7);
	}
	#[test]
	fn test_bexti_extracts_bit() {
		assert_eq!(v(exec_op_imm(5, 0x24, 0x80, 7)), 1);
		assert_eq!(v(exec_op_imm(5, 0x24, 0x80, 6)), 0);
	}
}
