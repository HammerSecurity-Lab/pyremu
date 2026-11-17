//! 原子内存操作。

use super::*;

//  AMO 取值操作辅助函数: 按宽度分派 AtomicU32 与 AtomicU64

/// 对一个 32 位值执行一次 AMO 取值操作。``funct5`` 与 ``rs2_val`` 来自
/// 译码结果; 带符号的最小值与最大值操作把操作数按 ``i32`` 解释。
#[inline]
fn amo_fetch_u32(a: &AtomicU32, funct5: u8, rs2_val: u64) -> u32 {
	let rs2_u32 = rs2_val as u32;
	match funct5 {
		0b00001 => a.swap(rs2_u32, Ordering::AcqRel),
		0b00000 => a.fetch_add(rs2_u32, Ordering::AcqRel),
		0b00100 => a.fetch_xor(rs2_u32, Ordering::AcqRel),
		0b01100 => a.fetch_and(rs2_u32, Ordering::AcqRel),
		0b01000 => a.fetch_or(rs2_u32, Ordering::AcqRel),
		0b10000 => a
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |prev| {
				let s = (prev as i32).min(rs2_val as i32);
				Some(s as u32)
			})
			.unwrap(),
		0b10100 => a
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |prev| {
				let s = (prev as i32).max(rs2_val as i32);
				Some(s as u32)
			})
			.unwrap(),
		0b11000 => a.fetch_min(rs2_u32, Ordering::AcqRel),
		0b11100 => a.fetch_max(rs2_u32, Ordering::AcqRel),
		_ => unreachable!(),
	}
}

/// 对一个 64 位值执行一次 AMO 取值操作。
#[inline]
fn amo_fetch_u64(a: &AtomicU64, funct5: u8, rs2_val: u64) -> u64 {
	match funct5 {
		0b00001 => a.swap(rs2_val, Ordering::AcqRel),
		0b00000 => a.fetch_add(rs2_val, Ordering::AcqRel),
		0b00100 => a.fetch_xor(rs2_val, Ordering::AcqRel),
		0b01100 => a.fetch_and(rs2_val, Ordering::AcqRel),
		0b01000 => a.fetch_or(rs2_val, Ordering::AcqRel),
		0b10000 => a
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |prev| {
				Some((prev as i64).min(rs2_val as i64) as u64)
			})
			.unwrap(),
		0b10100 => a
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |prev| {
				Some((prev as i64).max(rs2_val as i64) as u64)
			})
			.unwrap(),
		0b11000 => a.fetch_min(rs2_val, Ordering::AcqRel),
		0b11100 => a.fetch_max(rs2_val, Ordering::AcqRel),
		_ => unreachable!(),
	}
}

/// AMO 算术操作: AMOSWAP、AMOADD、AMOXOR、AMOAND、AMOOR、AMOMIN、
/// AMOMAX、AMOMINU 与 AMOMAXU。
/// 对 ``tr.pa`` 处的字节数组执行原子取值操作, 清除 LR/SC 保留记录,
/// 并把旧值写入 ``rd``。
#[inline]
fn handle_amo_arithmetic(
	state: &mut HartState,
	funct5: u8,
	rd: u8,
	rs2_val: u64,
	width: u8,
	va: u64,
	tr: &TranslateResult,
	ctx: &WalkCtx,
) -> u64 {
	let off = access::ram_offset(
		tr.pa,
		width as u32,
		ctx.ram_base,
		ctx.ram_size,
		ctx.shadow_base,
		ctx.shadow_size,
	);
	if off.is_none() {
		deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
		return 0;
	}
	let ptr = unsafe { ctx.ram.add(off.unwrap() as usize) };
	let loaded: u64 = match width {
		4 => {
			let a = unsafe { &*(ptr as *const AtomicU32) };
			amo_fetch_u32(a, funct5, rs2_val) as u64
		}
		8 => {
			let a = unsafe { &*(ptr as *const AtomicU64) };
			amo_fetch_u64(a, funct5, rs2_val)
		}
		_ => unreachable!(),
	};
	lr_clear_all(ctx);
	write_gpr(state, rd, if width == 4 { sext32(loaded) } else { loaded });
	4
}

//  AMO 处理

pub fn handle_amo(
	state: &mut HartState,
	f: &DecodedFields,
	instr: u32,
	instr_group: &mut InstrToBeExec,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	dev: &DevCtx,
) -> u64 {
	let _aq = (instr >> 26) & 1;
	let _rl = (instr >> 25) & 1;
	let funct5 = f.func7 >> 2; // funct5 为 func7 的高 5 位, 即指令的位域 [31:27]
	let width: u8 = match f.func3 {
		0b010 => 4, // .W
		0b011 => 8, // .D
		_ => {
			deliver_illegal_instruction(state, instr as u64);
			return 0;
		}
	};

	let base = read_gpr(state, f.rs1);
	let va = base; // AMO: rs1 为地址, rs2 为操作数

	// 对齐检查
	if (va & ((width as u64) - 1)) != 0 {
		deliver_trap(state, mcause_val(exc_code::LD_MISALIGNED, false), va);
		return 0;
	}

	// 将虚拟地址翻译为物理地址
	let tr = match translate_va(state, ctx, va, rwx_write(), pmp) {
		Ok(t) => t,
		Err(TranslateFault::PageFault(cause)) => {
			deliver_trap(state, mcause_val(cause, false), va);
			return 0;
		}
		Err(_) => {
			deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
			return 0;
		}
	};

	// PMP 检查
	if !pmp_ok(state, tr.pa, width as u32, true, false, pmp) {
		deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
		return 0;
	}

	let rd = f.rd;
	let rs2_val = read_gpr(state, f.rs2);

	// virtio-blk 直接处理
	if let Some(_) = try_handle_virtio(tr.pa, true, rs2_val, width, dev) {
		return 4;
	}

	// 其余设备地址: 退出加速执行。
	if is_device_addr(tr.pa, dev) {
		instr_group.exit_reason = exit_reason::MMIO;
		instr_group.exit_instr = instr;
		return EXIT_SENTINEL;
	}

	match funct5 {
		0b00010 => {
			// LR.W 与 LR.D
			let loaded = ram_read(ctx, tr.pa, width);
			lr_set(ctx, state.mhartid as u8, tr.pa);
			state.reservation_valid = 1;
			state.reservation_addr = tr.pa;
			state.reservation_value = loaded;
			write_gpr(state, rd, if width == 4 { sext32(loaded) } else { loaded });
			4
		}
		0b00011 => {
			// SC.W 与 SC.D
			let has_reservation = lr_check(ctx, state.mhartid as u8, tr.pa)
				|| (state.reservation_valid != 0 && state.reservation_addr == tr.pa);
			if !has_reservation {
				write_gpr(state, rd, 1);
			} else {
				ram_write(ctx, tr.pa, rs2_val, width);
				write_gpr(state, rd, 0);
			}
			// 成功与失败都清除预留, 与解释器一致.
			state.reservation_valid = 0;
			4
		}
		0b00001 | 0b00000 | 0b00100 | 0b01100 | 0b01000 | 0b10000 | 0b10100
		| 0b11000 | 0b11100 => {
			handle_amo_arithmetic(state, funct5, rd, rs2_val, width, va, &tr, ctx)
		}
		_ => {
			deliver_illegal_instruction(state, instr as u64);
			0
		}
	}
}
