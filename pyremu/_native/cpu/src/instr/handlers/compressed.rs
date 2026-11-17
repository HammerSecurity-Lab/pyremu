//! 压缩指令的处理与访存辅助。

use super::*;

/// 压缩指令中 sf 为 0b11 的寄存器-寄存器 ALU 操作:
/// SUB、XOR、OR、AND、SUBW 与 ADDW。非法编码返回 ``None``, 由调用方产生 IllInstr 陷态。
#[inline]
fn c1_alu_reg_op(v1: u64, v2: u64, bit12: u8, bit65: u8) -> Option<u64> {
	if bit12 == 0 {
		Some(match bit65 {
			0b00 => v1.wrapping_sub(v2),
			0b01 => v1 ^ v2,
			0b10 => v1 | v2,
			_ => v1 & v2,
		})
	} else {
		match bit65 {
			0b00 => Some(sext32(v1.wrapping_sub(v2) & 0xffff_ffff)),
			0b01 => Some(sext32(v1.wrapping_add(v2) & 0xffff_ffff)),
			_ => None,
		}
	}
}

/// 按 ``sf`` 字段执行一条压缩 ALU 操作。
/// 非法编码返回 ``None``, 由调用方产生 IllInstr 陷态。
#[inline]
fn exec_c1_alu(state: &HartState, cf: &CompressedFields) -> Option<u64> {
	let v1 = read_gpr(state, cf.rs1p);
	match cf.sf {
		0b00 => {
			let shamt = ((cf.bit12 as u64) << 5) | ((cf.rs2 as u64) & 0x1f);
			Some(v1 >> shamt)
		}
		0b01 => {
			let shamt = ((cf.bit12 as u64) << 5) | ((cf.rs2 as u64) & 0x1f);
			Some(((v1 as i64) >> shamt) as u64)
		}
		0b10 => {
			let imm = sext(((cf.bit12 as u64) << 5) | ((cf.rs2 as u64) & 0x1f), 6);
			Some(v1 & imm)
		}
		0b11 => {
			let v2 = read_gpr(state, cf.rdp);
			c1_alu_reg_op(v1, v2, cf.bit12, cf.bit65)
		}
		_ => None,
	}
}

//  压缩指令的处理函数

pub fn handle_compressed(
	state: &mut HartState,
	half: u16,
	instr_word: u32,
	instr_group: &mut InstrToBeExec,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ClintCtx,
) -> u64 {
	let cf = decode_compressed(half);

	match cf.quadrant {
		0 => handle_c0(state, &cf, instr_word, instr_group, ctx, pmp, dev, clint),
		1 => handle_c1(state, &cf, instr_word),
		2 => handle_c2(state, &cf, instr_word, instr_group, ctx, pmp, dev, clint),
		_ => {
			deliver_illegal_instruction(state, half as u64);
			0
		}
	}
}

/// 压缩指令的栈指针加法与访存指令:
/// C.ADDI4SPN、C.FLD、C.LW、C.LD、C.FSD、C.SW 与 C.SD。
fn handle_c0(
	state: &mut HartState,
	cf: &CompressedFields,
	instr_word: u32,
	instr_group: &mut InstrToBeExec,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ClintCtx,
) -> u64 {
	match cf.funct3 {
		0b000 => {
			// C.ADDI4SPN: rd' 取 sp 与 nzuimm 之和
			if cf.imm == 0 {
				deliver_illegal_instruction(state, instr_word as u64);
				return 0;
			}
			let sp = state.gprs[2]; // x2 = sp
			write_gpr(state, cf.rd, sp.wrapping_add(cf.imm));
			2
		}
		0b001 => {
			// C.FLD: 从 rs1' 加 uimm 的地址读取双精度值到 fpr[rd'], 属于 RV64DC。
			let addr = read_gpr(state, cf.rs1p).wrapping_add(cf.imm);
			let pc_before = state.pc;
			let val = match load_mem_compressed(
				state,
				ctx,
				addr,
				8,
				false,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			) {
				Some(v) => v,
				None => {
					return EXIT_SENTINEL;
				}
			};
			// 陷态与 MMIO 退出的区别在返回值的来源上: 陷态已把 pc 改写到入口
			// 地址, 此时目的寄存器与浮点状态都不得再改; 只比较特权级不够,
			// 委派给 S 模式的陷态从 S 模式发出时特权级不变.
			if state.pc != pc_before {
				return 0;
			}
			state.fprs[cf.rdp as usize] = val;
			state.mstatus |= MSTATUS_FS_LS | MSTATUS_SD_LS;
			2
		}
		0b010 => {
			// C.LW: 从 rs1' 加 uimm 的地址读取 32 位值到 rd'。
			let addr = read_gpr(state, cf.rs1p).wrapping_add(cf.imm);
			let pc_before = state.pc;
			let val = match load_mem_compressed(
				state,
				ctx,
				addr,
				4,
				false,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			) {
				Some(v) => v,
				None => {
					return EXIT_SENTINEL;
				}
			};
			// 陷态与 MMIO 退出的区别在返回值的来源上: 陷态已把 pc 改写到入口
			// 地址, 此时目的寄存器与浮点状态都不得再改; 只比较特权级不够,
			// 委派给 S 模式的陷态从 S 模式发出时特权级不变.
			if state.pc != pc_before {
				return 0;
			}
			let final_val = sext32(val);
			write_gpr(state, cf.rd, final_val);
			2
		}
		0b011 => {
			// C.LD: 从 rs1' 加 uimm 的地址读取 64 位值到 rd'。
			let addr = read_gpr(state, cf.rs1p).wrapping_add(cf.imm);
			let pc_before = state.pc;
			let val = match load_mem_compressed(
				state,
				ctx,
				addr,
				8,
				false,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			) {
				Some(v) => v,
				None => {
					return EXIT_SENTINEL;
				}
			};
			// 陷态与 MMIO 退出的区别在返回值的来源上: 陷态已把 pc 改写到入口
			// 地址, 此时目的寄存器与浮点状态都不得再改; 只比较特权级不够,
			// 委派给 S 模式的陷态从 S 模式发出时特权级不变.
			if state.pc != pc_before {
				return 0;
			}
			write_gpr(state, cf.rd, val);
			2
		}
		0b101 => {
			// C.FSD: 将 fpr[rd'] 的双精度值写入 rs1' 加 uimm 的地址, 属于 RV64DC。
			let addr = read_gpr(state, cf.rs1p).wrapping_add(cf.imm);
			let fpr_val = state.fprs[cf.rdp as usize];
			let pc_before = state.pc;
			let ret = store_mem_compressed(
				state,
				ctx,
				addr,
				fpr_val,
				8,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			);
			if ret == EXIT_SENTINEL {
				return EXIT_SENTINEL;
			}
			// 存储指令本身不改寄存器, 但 C.FSD 与 C.FSDSP 其后会置位 mstatus 的
			// 浮点状态; 陷态已把 pc 改写到入口地址时该置位同样不得执行.
			if state.pc != pc_before {
				return 0;
			}
			state.mstatus |= MSTATUS_FS_LS | MSTATUS_SD_LS;
			2
		}
		0b110 => {
			// C.SW: 将 rs2' 的低 32 位写入 rs1' 加 uimm 的地址。
			let addr = read_gpr(state, cf.rs1p).wrapping_add(cf.imm);
			let rs2_val = read_gpr(state, cf.rdp) & 0xffff_ffff;
			let pc_before = state.pc;
			let ret = store_mem_compressed(
				state,
				ctx,
				addr,
				rs2_val,
				4,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			);
			if ret == EXIT_SENTINEL {
				return EXIT_SENTINEL;
			}
			// 存储指令本身不改寄存器, 但 C.FSD 与 C.FSDSP 其后会置位 mstatus 的
			// 浮点状态; 陷态已把 pc 改写到入口地址时该置位同样不得执行.
			if state.pc != pc_before {
				return 0;
			}
			2
		}
		0b111 => {
			// C.SD: 将 rs2' 写入 rs1' 加 uimm 的地址。
			let addr = read_gpr(state, cf.rs1p).wrapping_add(cf.imm);
			let rs2_val = read_gpr(state, cf.rdp);
			let pc_before = state.pc;
			let ret = store_mem_compressed(
				state,
				ctx,
				addr,
				rs2_val,
				8,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			);
			if ret == EXIT_SENTINEL {
				return EXIT_SENTINEL;
			}
			// 存储指令本身不改寄存器, 但 C.FSD 与 C.FSDSP 其后会置位 mstatus 的
			// 浮点状态; 陷态已把 pc 改写到入口地址时该置位同样不得执行.
			if state.pc != pc_before {
				return 0;
			}
			2
		}
		_ => {
			deliver_illegal_instruction(state, instr_word as u64);
			0
		}
	}
}

/// 压缩指令的立即数运算、寄存器间运算、分支与跳转指令:
/// C.ADDI、C.ADDIW、C.LI、C.LUI、C.ADDI16SP、C.SRLI、C.SRAI、C.ANDI、
/// C.SUB、C.XOR、C.OR、C.AND、C.SUBW、C.ADDW、C.J、C.BEQZ 与 C.BNEZ。
fn handle_c1(state: &mut HartState, cf: &CompressedFields, instr_word: u32) -> u64 {
	match cf.funct3 {
		0b000..=0b010 => {
			// C.ADDI、C.ADDIW 与 C.LI
			let imm = cf.imm;
			if cf.funct3 == 0b000 {
				// C.ADDI: rd 增加 imm
				let v = read_gpr(state, cf.rd).wrapping_add(imm);
				write_gpr(state, cf.rd, v);
			} else if cf.funct3 == 0b001 {
				// C.ADDIW: rd 取 rd 与 imm 之和的符号扩展 32 位值
				let v = read_gpr(state, cf.rd).wrapping_add(imm) & 0xffff_ffff;
				write_gpr(state, cf.rd, sext32(v));
			} else {
				// C.LI: rd 取 imm
				write_gpr(state, cf.rd, imm);
			}
			2
		}
		0b011 => {
			if cf.rd == 2 {
				// C.ADDI16SP: sp 增加 nzimm
				if cf.imm == 0 {
					return EXIT_SENTINEL; // 非法编码
				}
				let sp = state.gprs[2];
				state.gprs[2] = sp.wrapping_add(cf.imm);
			} else {
				// C.LUI: rd 取 nzimm 左移 12 位后的值
				if cf.imm == 0 {
					return EXIT_SENTINEL;
				}
				write_gpr(state, cf.rd, (cf.imm << 12) & 0xffff_ffff_ffff_ffff);
			}
			2
		}
		0b100 => {
			// 压缩 ALU 操作: SRLI、SRAI、ANDI、SUB、XOR、OR、AND、SUBW 与 ADDW
			match exec_c1_alu(state, cf) {
				Some(r) => {
					write_gpr(state, cf.rs1p, r);
					2
				}
				None => {
					deliver_illegal_instruction(state, instr_word as u64);
					0
				}
			}
		}
		0b101 => {
			// C.J: pc 增加 offset
			state.pc = state.pc.wrapping_add(cf.imm);
			0
		}
		0b110 | 0b111 => {
			// C.BEQZ 与 C.BNEZ
			let rs1 = cf.rs1p; // rs1 来自位域 [9:7] 的压缩寄存器编码
			let v = read_gpr(state, rs1);
			let taken = if cf.funct3 == 0b110 { v == 0 } else { v != 0 };
			if taken {
				state.pc = state.pc.wrapping_add(cf.imm);
				0
			} else {
				2
			}
		}
		_ => {
			deliver_illegal_instruction(state, instr_word as u64);
			0
		}
	}
}

/// 压缩指令的栈指针访存与寄存器间运算指令:
/// C.SLLI、C.LWSP、C.LDSP、C.JR、C.MV、C.EBREAK、C.JALR、C.ADD、C.SWSP 与 C.SDSP。
fn handle_c2(
	state: &mut HartState,
	cf: &CompressedFields,
	instr_word: u32,
	instr_group: &mut InstrToBeExec,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ClintCtx,
) -> u64 {
	match cf.funct3 {
		0b000 => {
			// C.SLLI: rd 左移 shamt 位
			let v = read_gpr(state, cf.rd) << cf.imm;
			write_gpr(state, cf.rd, v);
			2
		}
		0b001 => {
			// C.FLDSP: 从 sp 加 uimm 的地址读取双精度值到 fpr[rd], 属于 RV64DC。
			if (state.mstatus & MSTATUS_FS_LS) == 0 {
				deliver_illegal_instruction(state, instr_word as u64);
				return 0;
			}
			let addr = state.gprs[2].wrapping_add(cf.imm);
			let pc_before = state.pc;
			let val = match load_mem_compressed(
				state,
				ctx,
				addr,
				8,
				false,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			) {
				Some(v) => v,
				None => {
					return EXIT_SENTINEL;
				}
			};
			// 陷态与 MMIO 退出的区别在返回值的来源上: 陷态已把 pc 改写到入口
			// 地址, 此时目的寄存器与浮点状态都不得再改; 只比较特权级不够,
			// 委派给 S 模式的陷态从 S 模式发出时特权级不变.
			if state.pc != pc_before {
				return 0;
			}
			state.fprs[cf.rd as usize] = val;
			state.mstatus |= MSTATUS_FS_LS | MSTATUS_SD_LS;
			2
		}
		0b010 => {
			// C.LWSP: 从 sp 加 uimm 的地址读取 32 位值到 rd。
			if cf.rd == 0 {
				deliver_illegal_instruction(state, instr_word as u64);
				return 0;
			}
			let addr = state.gprs[2].wrapping_add(cf.imm);
			let pc_before = state.pc;
			let val = match load_mem_compressed(
				state,
				ctx,
				addr,
				4,
				false,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			) {
				Some(v) => v,
				None => {
					return EXIT_SENTINEL;
				}
			};
			// 陷态与 MMIO 退出的区别在返回值的来源上: 陷态已把 pc 改写到入口
			// 地址, 此时目的寄存器与浮点状态都不得再改; 只比较特权级不够,
			// 委派给 S 模式的陷态从 S 模式发出时特权级不变.
			if state.pc != pc_before {
				return 0;
			}
			let final_val = sext32(val);
			write_gpr(state, cf.rd, final_val);
			2
		}
		0b011 => {
			// C.LDSP: 从 sp 加 uimm 的地址读取 64 位值到 rd。
			if cf.rd == 0 {
				deliver_illegal_instruction(state, instr_word as u64);
				return 0;
			}
			let addr = state.gprs[2].wrapping_add(cf.imm);
			let pc_before = state.pc;
			let val = match load_mem_compressed(
				state,
				ctx,
				addr,
				8,
				false,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			) {
				Some(v) => v,
				None => {
					return EXIT_SENTINEL;
				}
			};
			// 陷态与 MMIO 退出的区别在返回值的来源上: 陷态已把 pc 改写到入口
			// 地址, 此时目的寄存器与浮点状态都不得再改; 只比较特权级不够,
			// 委派给 S 模式的陷态从 S 模式发出时特权级不变.
			if state.pc != pc_before {
				return 0;
			}
			write_gpr(state, cf.rd, val);
			2
		}
		0b100 => {
			let rd_rs1 = cf.rd;
			let rs2 = cf.rs2;
			if rd_rs1 == 0 && rs2 == 0 {
				// 只有 bit12 置位时该编码是 C.EBREAK; bit12 清零的同一编码是
				// 保留的 C.JR x0, 按非法指令投递.
				if cf.bit12 == 0 {
					deliver_illegal_instruction(state, instr_word as u64);
					return 0;
				}
				// C.EBREAK 一律投递断点异常: 半主机的标记序列由 32 位 ebreak
				// 构成, 压缩形式不参与该序列.
				let ebreak_pc = state.pc;
				deliver_trap(
					state,
					mcause_val(exc_code::BREAKPOINT, false),
					ebreak_pc,
				);
				return 0;
			} else if rs2 == 0 {
				let target = read_gpr(state, rd_rs1);
				if cf.bit12 != 0 {
					// C.JALR: ra 取 pc 加 2
					state.gprs[1] = state.pc.wrapping_add(2);
				}
				state.pc = target & !1;
				0
			} else if cf.bit12 != 0 {
				// C.ADD: rd 增加 rs2
				let result_val =
					read_gpr(state, rd_rs1).wrapping_add(read_gpr(state, rs2));
				write_gpr(state, rd_rs1, result_val);
				2
			} else {
				// C.MV: rd 取 rs2
				let v = read_gpr(state, rs2);
				write_gpr(state, rd_rs1, v);
				2
			}
		}
		0b101 => {
			// C.FSDSP: 将 fpr[rs2] 的双精度值写入 sp 加 uimm 的地址, 属于 RV64DC。
			if (state.mstatus & MSTATUS_FS_LS) == 0 {
				deliver_illegal_instruction(state, instr_word as u64);
				return 0;
			}
			let addr = state.gprs[2].wrapping_add(cf.imm2);
			let fpr_val = state.fprs[cf.rs2 as usize];
			let pc_before = state.pc;
			let ret = store_mem_compressed(
				state,
				ctx,
				addr,
				fpr_val,
				8,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			);
			if ret == EXIT_SENTINEL {
				return EXIT_SENTINEL;
			}
			// 存储指令本身不改寄存器, 但 C.FSD 与 C.FSDSP 其后会置位 mstatus 的
			// 浮点状态; 陷态已把 pc 改写到入口地址时该置位同样不得执行.
			if state.pc != pc_before {
				return 0;
			}
			state.mstatus |= MSTATUS_FS_LS | MSTATUS_SD_LS;
			2
		}
		0b110 => {
			// C.SWSP: 将 rs2 的低 32 位写入 sp 加 uimm 的地址。
			let addr = state.gprs[2].wrapping_add(cf.imm2);
			let val = read_gpr(state, cf.rs2) & 0xffff_ffff;
			let pc_before = state.pc;
			let ret = store_mem_compressed(
				state,
				ctx,
				addr,
				val,
				4,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			);
			if ret == EXIT_SENTINEL {
				return EXIT_SENTINEL;
			}
			// 存储指令本身不改寄存器, 但 C.FSD 与 C.FSDSP 其后会置位 mstatus 的
			// 浮点状态; 陷态已把 pc 改写到入口地址时该置位同样不得执行.
			if state.pc != pc_before {
				return 0;
			}
			2
		}
		0b111 => {
			// C.SDSP: 将 rs2 写入 sp 加 uimm 的地址。
			let addr = state.gprs[2].wrapping_add(cf.imm2);
			let val = read_gpr(state, cf.rs2);
			let pc_before = state.pc;
			let ret = store_mem_compressed(
				state,
				ctx,
				addr,
				val,
				8,
				instr_word,
				instr_group,
				pmp,
				dev,
				clint,
			);
			if ret == EXIT_SENTINEL {
				return EXIT_SENTINEL;
			}
			// 存储指令本身不改寄存器, 但 C.FSD 与 C.FSDSP 其后会置位 mstatus 的
			// 浮点状态; 陷态已把 pc 改写到入口地址时该置位同样不得执行.
			if state.pc != pc_before {
				return 0;
			}
			2
		}
		_ => {
			deliver_illegal_instruction(state, instr_word as u64);
			0
		}
	}
}

//  压缩指令的访存辅助函数

/// 压缩指令的访存读取。
///
/// 返回 ``None`` 表示命中设备地址, 需要退出本轮加速执行, 退出原因已写入
/// ``instr_group``; ``Some`` 为读到的数据。
#[inline]
fn load_mem_compressed(
	state: &mut HartState,
	ctx: &WalkCtx,
	va: u64,
	size: u8,
	_signed: bool,
	instr_word: u32,
	instr_group: &mut InstrToBeExec,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ClintCtx,
) -> Option<u64> {
	let tr = match translate_va(state, ctx, va, rwx_read(), pmp) {
		Ok(t) => t,
		Err(TranslateFault::PageFault(cause)) => {
			deliver_trap(state, mcause_val(cause, false), va);
			return Some(0); // 陷态已直接分发; 调用方必须检查 state.mode
		}
		Err(_) => {
			deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
			return Some(0); // 陷态已直接分发; 调用方必须检查 state.mode
		}
	};

	if !pmp_ok(state, tr.pa, size as u32, false, false, pmp) {
		deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
		return Some(0); // 陷态已直接分发; 调用方必须检查 state.mode
	}

	// 跨页访问按两页分别翻译, 取舍与存储路径相同.
	if (va & 0xfff) + (size as u64) > 0x1000 {
		let (val, is_ok) = read_ram_cross_page(state, ctx, va, tr.pa, size, pmp);
		if !is_ok {
			return Some(0); // 陷态已直接分发; 调用方必须检查 state.mode
		}
		return Some(val);
	}

	if let Some(data) = try_handle_clint(&MemAccess::read(tr.pa, size), state, clint)
	{
		return Some(data);
	}

	// IMSIC 的 MMIO 读取一律返回 0, 因为 seteipnum 与 clreipnum 只接受写入。
	// 该分支必须位于 is_device_addr 之前, 否则从 IMSIC 读取的压缩指令会退出到 Python。
	if try_handle_imsic_serial(tr.pa, 0, clint) {
		return Some(0);
	}

	if let Some(data) = try_handle_virtio(tr.pa, false, 0, size, dev) {
		return Some(data);
	}

	// PLIC 直接处理压缩指令的映射访问。
	if let Some(data) =
		try_handle_plic_concurrent(tr.pa, false, 0, size, state, dev.plic)
	{
		return Some(data);
	}

	if is_device_addr(tr.pa, dev) {
		instr_group.exit_reason = exit_reason::MMIO;
		instr_group.exit_instr = instr_word;
		return None;
	}

	// 与非压缩加载路径一致: 目标物理地址不属于主存时投递访问故障, 不得把 0
	// 当作读出的值写入目的寄存器.
	if access::ram_offset(
		tr.pa,
		size as u32,
		ctx.ram_base,
		ctx.ram_size,
		ctx.shadow_base,
		ctx.shadow_size,
	)
	.is_none()
	{
		deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
		return Some(0);
	}

	Some(ram_read(ctx, tr.pa, size))
}

#[inline]
fn store_mem_compressed(
	state: &mut HartState,
	ctx: &WalkCtx,
	va: u64,
	val: u64,
	size: u8,
	instr_word: u32,
	instr_group: &mut InstrToBeExec,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ClintCtx,
) -> u64 {
	let tr = match translate_va(state, ctx, va, rwx_write(), pmp) {
		Ok(t) => t,
		Err(TranslateFault::PageFault(cause)) => {
			deliver_trap(state, mcause_val(cause, false), va);
			return 0;
		}
		Err(_) => {
			deliver_trap(state, mcause_val(exc_code::ST_ACCESS_FAULT, false), va);
			return 0;
		}
	};

	if !pmp_ok(state, tr.pa, size as u32, true, false, pmp) {
		deliver_trap(state, mcause_val(exc_code::ST_ACCESS_FAULT, false), va);
		return 0;
	}

	// 跨页访问按两页分别翻译
	// 发生陷态时本次存储不改动内存. 该分支位于设备处理之前,
	// 设备内存范围按整页对齐, 跨页的访问不会落入设备内存范围.
	if (va & 0xfff) + (size as u64) > 0x1000 {
		write_ram_cross_page(state, ctx, va, tr.pa, val, size, pmp);
		return 0; // 调用方返回 2
	}

	if let Some(_) =
		try_handle_clint(&MemAccess::write(tr.pa, size, val), state, clint)
	{
		return 0;
	}

	// IMSIC 的写入: 中断号 1 与 3 的 IPI 经 CLINT 的 MSIP 分发, 跨 hart 唤醒不退出加速执行。
	// 该分支必须位于 is_device_addr 之前, 否则写 IMSIC 的 seteipnum 的 C.SW 会退出到 Python 的 MMIO 处理。
	// 缺此分支时, 用压缩指令分发 IPI 的固件在多 hart 的 TLB 刷新中停止推进, 因 IPI 未进入目标 hart 的线程。
	if try_handle_imsic_serial(tr.pa, val, clint) {
		return 0;
	}

	if let Some(_) = try_handle_virtio(tr.pa, true, val, size, dev) {
		return 0;
	}

	// PLIC 直接处理压缩指令的映射访问。
	if let Some(_) =
		try_handle_plic_concurrent(tr.pa, true, val, size, state, dev.plic)
	{
		return 0;
	}

	if is_device_addr(tr.pa, dev) {
		instr_group.exit_reason = exit_reason::MMIO;
		instr_group.exit_instr = instr_word;
		return EXIT_SENTINEL;
	}

	// 与非压缩存储路径一致: 目标物理地址不属于主存时投递访问故障, 不得静默丢弃.
	if access::ram_offset(
		tr.pa,
		size as u32,
		ctx.ram_base,
		ctx.ram_size,
		ctx.shadow_base,
		ctx.shadow_size,
	)
	.is_none()
	{
		deliver_trap(state, mcause_val(exc_code::ST_ACCESS_FAULT, false), va);
		return 0;
	}

	ram_write(ctx, tr.pa, val, size);
	0 // 调用方返回 2
}
