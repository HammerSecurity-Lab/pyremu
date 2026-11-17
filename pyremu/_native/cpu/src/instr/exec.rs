//! 并发执行路径的指令执行: 分派、访存类指令、系统类指令与执行后检查.

use crate::utils::arith::sext;
use std::cell::Cell;
use std::sync::atomic::{self, AtomicU32, AtomicU64, Ordering};

use crate::ffi::{FfiDevCtx, FfiUartCtx, InstrToBeExec};
use crate::instr::atom_instr::handle_amo_concurrent_dispatch;
use crate::instr::fetch::check_bp_hit;
use crate::instr::fpu::{handle_fp_load_concurrent, handle_fp_store_concurrent};
use crate::instr::handlers::{
	handle_compressed, lr_clear_all, pmp_ok, try_handle_virtio, ClintCtx, DevCtx,
	PmpCtx, EXIT_SENTINEL,
};
use crate::instr::op_dispatcher::{
	handle_alu, handle_auipc, handle_br, handle_fence, handle_fp_fma, handle_fp_op,
	handle_jal, handle_jalr, handle_lui, handle_op32, handle_op_imm,
	handle_op_imm32,
};
use crate::interrupt::{
	clint::try_handle_clint_concurrent, try_handle_imsic_concurrent,
	try_handle_imsic_read_concurrent,
};
use crate::mem::access::ram_offset;
use crate::mem::translate::{
	rwx_read, rwx_write, tlb_flush_all, translate_va, TranslateFault, WalkCtx,
};
use crate::peripheral::{
	is_device_addr, plic::try_handle_plic_concurrent,
	uart::try_handle_uart_concurrent,
};
use crate::shared::{ConcurrentClintCtx, ModuleState, StopInfo};
use crate::state::{
	exit_reason, read_gpr, riscv_mode, write_gpr, HartState, CFG_HAS_SEMIHOSTING,
};
use crate::trap::{
	deliver_illegal_instruction, deliver_trap, exc_code, mcause_val,
	priv_ecall_concurrent, priv_mret_concurrent, priv_sret_concurrent,
	priv_wfi_concurrent,
};

pub(crate) fn dispatch_concurrent(
	state: &mut HartState,
	f: &crate::instr::decode::DecodedFields,
	instr: u32,
	ctx: &WalkCtx,
	hart_id: u8,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ConcurrentClintCtx,
	uart: &FfiUartCtx,
	module: &ModuleState,
) -> u64 {
	match f.opcode {
		0b01100_11 => {
			// R 型 ALU，纯计算, 不读写共享状态
			handle_alu(state, f, instr)
		}
		0b00100_11 => handle_op_imm(state, f, instr),
		0b00110_11 => handle_op_imm32(state, f, instr),
		0b01110_11 => handle_op32(state, f, instr),
		0b01101_11 => handle_lui(state, f),
		0b00101_11 => handle_auipc(state, f),
		0b11011_11 => handle_jal(state, f),
		0b11001_11 => handle_jalr(state, f),
		0b11000_11 => handle_br(state, f, instr),
		0b00011_11 => handle_fence(state, f, instr),

		// 加载与存储指令，并发路径需就地处理 CLINT
		0b00000_11 => handle_load_concurrent(
			state, f, instr, ctx, pmp, dev, clint, uart, module,
		),
		0b01000_11 => handle_store_concurrent(
			state, f, instr, ctx, pmp, dev, clint, uart, module,
		),

		// 浮点加载与存储指令 FLW/FLD/FSW/FSD
		0b00001_11 => {
			handle_fp_load_concurrent(state, f, instr, ctx, pmp, dev, module)
		}
		0b01001_11 => {
			handle_fp_store_concurrent(state, f, instr, ctx, pmp, dev, module)
		}

		// 系统指令
		0b11100_11 => handle_system_concurrent(
			state, f, instr, ctx, hart_id, clint, pmp, module, uart,
		),

		// AMO: 并发原子操作路径
		0b01011_11 => {
			handle_amo_concurrent_dispatch(state, f, instr, ctx, pmp, dev, module)
		}

		// F/D 浮点运算指令 OP-FP 与 FMA
		0b10100_11 => handle_fp_op(state, f, instr),
		0b10000_11 | 0b10001_11 | 0b10010_11 | 0b10011_11 => {
			handle_fp_fma(state, f, instr)
		}

		_ => {
			deliver_illegal_instruction(state, instr as u64);
			0
		}
	}
}

pub(crate) fn read_ram_cross_page(
	state: &mut HartState,
	ctx: &WalkCtx,
	va: u64,
	pa_first: u64,
	size: u8,
	pmp: &PmpCtx,
) -> (u64, bool) {
	let page_off = va & 0xfff;
	let bytes_first = (0x1000 - page_off) as u8;

	let mut result: u64 = 0;
	for b in 0..bytes_first {
		let byte = ram_read_raw(ctx, pa_first + (b as u64), 1);
		result |= byte << (b * 8);
	}
	let va2 = va.wrapping_add(bytes_first as u64);
	let tr2 = match translate_va(state, ctx, va2, rwx_read(), pmp) {
		Ok(t) => t,
		Err(TranslateFault::PageFault(cause)) => {
			deliver_trap(state, mcause_val(cause, false), va2);
			return (0, false);
		}
		Err(TranslateFault::AccessFault) => {
			deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va2);
			return (0, false);
		}
	};
	let second_sz = (size - bytes_first) as u32;
	if !pmp_ok(state, tr2.pa, second_sz, false, false, pmp) {
		deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
		return (0, false);
	}

	for b in bytes_first..size {
		let byte =
			ram_read_raw(ctx, tr2.pa.wrapping_add((b - bytes_first) as u64), 1);
		result |= byte << (b * 8);
	}

	(result, true)
}

pub(crate) fn write_ram_cross_page(
	state: &mut HartState,
	ctx: &WalkCtx,
	va: u64,
	pa_first: u64,
	val: u64,
	size: u8,
	pmp: &PmpCtx,
) -> bool {
	let page_off = va & 0xfff;
	let bytes_first = (0x1000 - page_off) as u8;

	// 先翻译并检查第二页, 再写入第一页的字节: 第二页发生陷态时本次存储不得
	// 修改任何内存.
	let va2 = va.wrapping_add(bytes_first as u64);
	let tr2 = match translate_va(state, ctx, va2, rwx_write(), pmp) {
		Ok(t) => t,
		Err(TranslateFault::PageFault(cause)) => {
			deliver_trap(state, mcause_val(cause, false), va2);
			return false;
		}
		Err(TranslateFault::AccessFault) => {
			deliver_trap(state, mcause_val(exc_code::ST_ACCESS_FAULT, false), va2);
			return false;
		}
	};
	let second_sz = (size - bytes_first) as u32;
	if !pmp_ok(state, tr2.pa, second_sz, true, false, pmp) {
		deliver_trap(state, mcause_val(exc_code::ST_ACCESS_FAULT, false), va);
		return false;
	}

	for b in 0..bytes_first {
		let byte = (val >> (b * 8)) as u8;
		ram_write_raw(ctx, pa_first + (b as u64), byte as u64, 1);
	}
	for b in bytes_first..size {
		let byte = (val >> (b * 8)) as u8;
		ram_write_raw(
			ctx,
			tr2.pa.wrapping_add((b - bytes_first) as u64),
			byte as u64,
			1,
		);
	}

	true
}

pub(crate) fn handle_load_concurrent(
	state: &mut HartState,
	f: &crate::instr::decode::DecodedFields,
	instr: u32,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ConcurrentClintCtx,
	uart: &FfiUartCtx,
	module: &ModuleState,
) -> u64 {
	let base = read_gpr(state, f.rs1);
	let va = base.wrapping_add(f.imm12_se);
	let (size, signed) = match f.func3 {
		0b000 => (1u8, true),
		0b001 => (2, true),
		0b010 => (4, true),
		0b011 => (8, false),
		0b100 => (1, false),
		0b101 => (2, false),
		0b110 => (4, false),
		_ => {
			deliver_illegal_instruction(state, instr as u64);
			return 0;
		}
	};

	let aligned = (va & ((size as u64) - 1)) == 0;

	let tr = match translate_va(state, ctx, va, rwx_read(), pmp) {
		Ok(t) => t,
		Err(TranslateFault::PageFault(cause)) => {
			deliver_trap(state, mcause_val(cause, false), va);
			return 0;
		}
		Err(TranslateFault::AccessFault) => {
			deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
			return 0;
		}
	};

	if !pmp_ok(state, tr.pa, size as u32, false, false, pmp) {
		deliver_trap(state, mcause_val(exc_code::LD_ACCESS_FAULT, false), va);
		return 0;
	}

	// CLINT 读取
	if let Some(data) =
		try_handle_clint_concurrent(tr.pa, false, 0, size as u64, state, clint)
	{
		let result_val = if signed {
			match size {
				1 => sext(data, 8),
				2 => sext(data, 16),
				4 => sext(data, 32),
				_ => data,
			}
		} else {
			data
		};
		write_gpr(state, f.rd, result_val);
		return 4;
	}

	// virtio-blk 读取
	if let Some(data) = try_handle_virtio(tr.pa, false, 0, size, dev) {
		let result_val = if signed {
			match size {
				1 => sext(data, 8),
				2 => sext(data, 16),
				4 => sext(data, 32),
				_ => data,
			}
		} else {
			data
		};
		write_gpr(state, f.rd, result_val);
		return 4;
	}

	// UART 读取: 避免轮询 TX FIFO 时退出加速执行
	if let Some(data) =
		try_handle_uart_concurrent(tr.pa, false, 0, state.mhartid as u8, uart)
	{
		let result_val = if signed {
			match size {
				1 => sext(data, 8),
				2 => sext(data, 16),
				4 => sext(data, 32),
				_ => data,
			}
		} else {
			data
		};
		write_gpr(state, f.rd, result_val);
		return 4;
	}

	// 读取 IMSIC : 避免内核初始化读取 IMSIC 时按 MMIO 退出.
	// 可读的 IMSIC MMIO 寄存器一律返回 0; seteipnum 与 clreipnum 只写,
	// 配置寄存器与 topei 寄存器经 CSR 访问.
	if let Some(data) = try_handle_imsic_read_concurrent(tr.pa, clint.num_harts) {
		write_gpr(state, f.rd, data);
		return 4;
	}

	// 处理 PLIC 收到的外部中断: 内核直接映射访问 PLIC 的 priority、pending、enable、
	// threshold 与 claim 寄存器. claim 清除 pending 后立即重算 mip.MEIP 与 mip.SEIP,
	// 不必等到 step_interrupts.
	if let Some(data) =
		try_handle_plic_concurrent(tr.pa, false, 0, size, state, dev.plic)
	{
		let result_val = if signed {
			match size {
				1 => sext(data, 8),
				2 => sext(data, 16),
				4 => sext(data, 32),
				_ => data,
			}
		} else {
			data
		};
		write_gpr(state, f.rd, result_val);
		return 4;
	}

	// 退出本轮, 由 Python 侧处理 MMIO 访问
	if is_device_addr(tr.pa, dev) {
		module.request_stop(StopInfo {
			reason: exit_reason::MMIO,
			hart_id: state.mhartid as u8,
			pc: state.pc,
			instr,
			..StopInfo::empty()
		});
		return EXIT_SENTINEL;
	}

	// PA 位于 ram_base 与 ram_base 加 ram_size 的区间之外时 ram_offset 返回 None.
	if ram_offset(
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
		return 0;
	}

	// 例如，VA 0x1FF8 上的 8 字节访问按 8 字节对齐,
	// 却跨过 4 KiB 页边界. 两个虚拟页可能映射到不相邻的物理页, 故第二页单独翻译
	// 后再拼接字节.
	let val = if (va & 0xfff) + (size as u64) > 0x1000 {
		let (v, ok) = read_ram_cross_page(state, ctx, va, tr.pa, size, pmp);
		if !ok {
			return 0;
		}
		v
	} else if aligned {
		ram_read_raw(ctx, tr.pa, size)
	} else {
		// 同一物理页内地址未对齐: 逐字节读取或写入.
		let mut result: u64 = 0;
		for b in 0..size {
			let byte = ram_read_raw(ctx, tr.pa + (b as u64), 1);
			result |= byte << (b * 8);
		}
		result
	};
	let result_val = if signed {
		match size {
			1 => sext(val, 8),
			2 => sext(val, 16),
			4 => sext(val, 32),
			_ => val,
		}
	} else {
		val
	};
	write_gpr(state, f.rd, result_val);
	4
}

pub(crate) fn handle_store_concurrent(
	state: &mut HartState,
	f: &crate::instr::decode::DecodedFields,
	instr: u32,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ConcurrentClintCtx,
	uart: &FfiUartCtx,
	module: &ModuleState,
) -> u64 {
	let base = read_gpr(state, f.rs1);
	let va = base.wrapping_add(f.imm_s);
	let size: u8 = match f.func3 {
		0b000 => 1,
		0b001 => 2,
		0b010 => 4,
		0b011 => 8,
		_ => {
			deliver_illegal_instruction(state, instr as u64);
			return 0;
		}
	};
	let aligned = (va & ((size as u64) - 1)) == 0;

	let tr = match translate_va(state, ctx, va, rwx_write(), pmp) {
		Ok(t) => t,
		Err(TranslateFault::PageFault(cause)) => {
			deliver_trap(state, mcause_val(cause, false), va);
			return 0;
		}
		Err(TranslateFault::AccessFault) => {
			deliver_trap(state, mcause_val(exc_code::ST_ACCESS_FAULT, false), va);
			return 0;
		}
	};

	if !pmp_ok(state, tr.pa, size as u32, true, false, pmp) {
		deliver_trap(state, mcause_val(exc_code::ST_ACCESS_FAULT, false), va);
		return 0;
	}

	let val = read_gpr(state, f.rs2);

	// 写入 CLINT
	if let Some(_) =
		try_handle_clint_concurrent(tr.pa, true, val, size as u64, state, clint)
	{
		return 4;
	}

	// 写入 UART: 避免 sbi_printf 退出加速执行
	if let Some(_) =
		try_handle_uart_concurrent(tr.pa, true, val, state.mhartid as u8, uart)
	{
		return 4;
	}

	// virtio-blk 写入
	if let Some(_) = try_handle_virtio(tr.pa, true, val, size, dev) {
		return 4;
	}

	// IMSIC IPI 编号经 CLINT MSIP 快速路径投递.
	// PLIC 处理: priority、enable、threshold 与 complete 的写入; 写后立即
	// 重算 mip.MEIP 与 mip.SEIP, 覆盖先挂起后使能与 claim 后电平重新挂起两种情形.
	if try_handle_imsic_concurrent(tr.pa, val, state, clint)
		|| try_handle_plic_concurrent(tr.pa, true, val, size, state, dev.plic)
			.is_some()
	{
		return 4;
	}

	// 退出本轮, 由 Python 侧处理 MMIO 访问
	if is_device_addr(tr.pa, dev) {
		module.request_stop(StopInfo {
			reason: exit_reason::MMIO,
			hart_id: state.mhartid as u8,
			pc: state.pc,
			instr,
			..StopInfo::empty()
		});
		return EXIT_SENTINEL;
	}

	// 越界判定
	if ram_offset(
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

	// 跨页判定必须在地址对齐判定之前.
	if (va & 0xfff) + (size as u64) > 0x1000 {
		if !write_ram_cross_page(state, ctx, va, tr.pa, val, size, pmp) {
			return 0;
		}
	} else if aligned {
		ram_write_raw(ctx, tr.pa, val, size);
	} else {
		// 同一物理页内地址未对齐: 逐字节读取或写入.
		for b in 0..size {
			let byte = (val >> (b * 8)) as u8;
			ram_write_raw(ctx, tr.pa + (b as u64), byte as u64, 1);
		}
	}
	4
}

pub(crate) fn ram_read_raw(ctx: &WalkCtx, pa: u64, size: u8) -> u64 {
	let off = match ram_offset(
		pa,
		size as u32,
		ctx.ram_base,
		ctx.ram_size,
		ctx.shadow_base,
		ctx.shadow_size,
	) {
		Some(o) => o as usize,
		None => {
			return 0;
		}
	};
	let ptr = ctx.ram as *mut u8;
	match size {
		1 => {
			// 原始字节读取之前加 Acquire 屏障: 与其余 hart 线程的 Release
			// 配对, 使该字节值对其他 hart 可见.
			atomic::fence(Ordering::Acquire);
			unsafe { *ptr.add(off) as u64 }
		}
		2 => {
			atomic::fence(Ordering::Acquire);
			let b0 = (unsafe { *ptr.add(off) }) as u64;
			let b1 = (unsafe { *ptr.add(off + 1) }) as u64;
			b0 | (b1 << 8)
		}
		4 if (pa & 3) == 0 => {
			let a = unsafe { &*(ptr.add(off) as *const AtomicU32) };
			a.load(Ordering::Acquire) as u64
		}
		4 => {
			atomic::fence(Ordering::Acquire);
			let b0 = (unsafe { *ptr.add(off) }) as u64;
			let b1 = (unsafe { *ptr.add(off + 1) }) as u64;
			let b2 = (unsafe { *ptr.add(off + 2) }) as u64;
			let b3 = (unsafe { *ptr.add(off + 3) }) as u64;
			b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
		}
		8 if (pa & 7) == 0 => {
			let a = unsafe { &*(ptr.add(off) as *const AtomicU64) };
			let val = a.load(Ordering::Acquire);
			val
		}
		8 => {
			atomic::fence(Ordering::Acquire);
			let b0 = (unsafe { *ptr.add(off) }) as u64;
			let b1 = (unsafe { *ptr.add(off + 1) }) as u64;
			let b2 = (unsafe { *ptr.add(off + 2) }) as u64;
			let b3 = (unsafe { *ptr.add(off + 3) }) as u64;
			let b4 = (unsafe { *ptr.add(off + 4) }) as u64;
			let b5 = (unsafe { *ptr.add(off + 5) }) as u64;
			let b6 = (unsafe { *ptr.add(off + 6) }) as u64;
			let b7 = (unsafe { *ptr.add(off + 7) }) as u64;
			let val = b0
				| (b1 << 8) | (b2 << 16)
				| (b3 << 24) | (b4 << 32)
				| (b5 << 40) | (b6 << 48)
				| (b7 << 56);
			val
		}
		_ => 0,
	}
}

pub(crate) fn ram_write_raw(ctx: &WalkCtx, pa: u64, val: u64, size: u8) {
	let off = match ram_offset(
		pa,
		size as u32,
		ctx.ram_base,
		ctx.ram_size,
		ctx.shadow_base,
		ctx.shadow_size,
	) {
		Some(o) => o as usize,
		None => {
			return;
		}
	};
	// RISC-V 规范 §8.2: 所有 LR 预留必须在写入对其他 hart 可见之前作废.
	// SeqCst 保证其余 hart 先看到预留被清除, 再看到新值, 从而消除 ABA:
	// 若 hart B 的预留看到旧值 V, 本次写入 U, 第三个 hart 又写回 V, 则 B 的 SC
	// 会成功, 而按规范应当失败.
	lr_clear_all(ctx);
	atomic::fence(Ordering::SeqCst);

	let ptr = ctx.ram as *mut u8;
	match size {
		1 => {
			unsafe {
				*ptr.add(off) = val as u8;
			}
			atomic::fence(Ordering::Release);
		}
		2 => {
			unsafe {
				*ptr.add(off) = val as u8;
				*ptr.add(off + 1) = (val >> 8) as u8;
			}
			atomic::fence(Ordering::Release);
		}
		4 if (pa & 3) == 0 => {
			let a = unsafe { &*(ptr.add(off) as *const AtomicU32) };
			a.store(val as u32, Ordering::Release);
		}
		4 => {
			unsafe {
				*ptr.add(off) = val as u8;
				*ptr.add(off + 1) = (val >> 8) as u8;
				*ptr.add(off + 2) = (val >> 16) as u8;
				*ptr.add(off + 3) = (val >> 24) as u8;
			}
			atomic::fence(Ordering::Release);
		}
		8 if (pa & 7) == 0 => {
			let a = unsafe { &*(ptr.add(off) as *const AtomicU64) };
			a.store(val, Ordering::Release);
		}
		8 => {
			unsafe {
				*ptr.add(off) = val as u8;
				*ptr.add(off + 1) = (val >> 8) as u8;
				*ptr.add(off + 2) = (val >> 16) as u8;
				*ptr.add(off + 3) = (val >> 24) as u8;
				*ptr.add(off + 4) = (val >> 32) as u8;
				*ptr.add(off + 5) = (val >> 40) as u8;
				*ptr.add(off + 6) = (val >> 48) as u8;
				*ptr.add(off + 7) = (val >> 56) as u8;
			}
			atomic::fence(Ordering::Release);
		}
		_ => {}
	}
}

/// 处理并发执行引擎中的 CSR 指令, 即 func3 不等于 0b000 的系统指令.
///
/// ``csr::handle_csr`` 需要一个 ``InstrToBeExec`` 记录退出信息, 此处传入零值临时
/// 结构; 该结构的内容在本路径中不使用, 返回值 EXIT_SENTINEL 由调用方按退出处理.
fn handle_csr_concurrent(
	state: &mut HartState,
	f: &crate::instr::decode::DecodedFields,
	instr: u32,
	hart_id: u8,
	clint: &ConcurrentClintCtx,
	pmp: &PmpCtx,
) -> u64 {
	let mut dummy = unsafe { std::mem::zeroed() };
	let mut csr_ctx = crate::csr::CsrContext::new(state, hart_id as u32, pmp, clint);
	return crate::csr::handle_csr(
		&mut csr_ctx,
		f.rd,
		f.rs1,
		f.func12,
		f.func3,
		instr,
		&mut dummy,
	);
}

pub(crate) fn handle_system_concurrent(
	state: &mut HartState,
	f: &crate::instr::decode::DecodedFields,
	instr: u32,
	ctx: &WalkCtx,
	hart_id: u8,
	clint: &ConcurrentClintCtx,
	pmp: &PmpCtx,
	module: &ModuleState,
	dev: &dyn FfiDevCtx,
) -> u64 {
	if f.func3 != 0b000 {
		return handle_csr_concurrent(state, f, instr, hart_id, clint, pmp);
	}

	// func3 等于 0b000: 特权指令
	match f.func12 {
		0 => {
			return priv_ecall_concurrent(state, instr, clint, module, dev);
		}
		1 => {
			if !CFG_HAS_SEMIHOSTING {
				let ebreak_pc = state.pc;
				deliver_trap(
					state,
					mcause_val(exc_code::BREAKPOINT, false),
					ebreak_pc,
				);
				return 0;
			}
			if state.gprs[10] == crate::instr::handlers::SH_SYS_EXIT
				&& crate::instr::handlers::semihosting_match(ctx, state.pc)
			{
				module.request_stop(StopInfo {
					reason: exit_reason::EBREAK,
					hart_id,
					pc: state.pc,
					..StopInfo::empty()
				});
				return 0;
			}
			if let Some(advance) =
				crate::instr::handlers::try_semihosting(state, ctx, state.pc)
			{
				return advance;
			}
			return 4;
		}
		0x302 => {
			return priv_mret_concurrent(state, instr);
		}
		0x102 => {
			return priv_sret_concurrent(state, instr, ctx);
		}
		0x105 => {
			return priv_wfi_concurrent(state, instr);
		}
		f_val if (f_val >> 5) == 0x09 => {
			// SFENCE.VMA: S 模式在 mstatus.TVM=1 时触发 IllInstr
			if state.mode == riscv_mode::S && ((state.mstatus >> 20) & 1) != 0 {
				deliver_illegal_instruction(state, instr as u64);
				return 0;
			}
			// 刷新本 hart 的指令 TLB 与数据 TLB, 并使其余 hart 的条目作废.
			//
			// RISC-V 的 SFENCE.VMA 只刷新执行该指令的 hart 的 TLB, 刷新其余 hart 的
			// 条目本需发送核间中断. 此处改为递增刷新计数; 其余 hart 在取下一条指令前
			// 把该计数与自己上次记录的取值比较, 不相等即把条目全部标为陈旧.
			// 重复标记不影响正确性.
			tlb_flush_all(&mut state.itlb);
			tlb_flush_all(&mut state.dtlb);
			let new_cnt = module
				.tlb_flush_cnt
				.fetch_add(1, Ordering::Release)
				.wrapping_add(1);
			module.tlb_flush_cnt_per_hart[hart_id as usize]
				.store(new_cnt, Ordering::Relaxed);
			return 4;
		}
		0x5a0 => {
			// MFENCE.DID
			for e in state.itlb.iter_mut() {
				if e.mdid == state.mdid {
					e.valid = 0;
				}
			}
			for e in state.dtlb.iter_mut() {
				if e.mdid == state.mdid {
					e.valid = 0;
				}
			}
			return 4;
		}
		_ => {
			deliver_illegal_instruction(state, instr as u64);
			return 0;
		}
	}
}

pub(crate) fn exec_compressed_concurrent(
	state: &mut HartState,
	instr_word: u32,
	pc_before: u64,
	hart_id: u8,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	dev: &DevCtx,
	clint: &ConcurrentClintCtx,
	module: &ModuleState,
	breakpoints: &[u64],
) -> bool {
	let half = (instr_word & 0xffff) as u16;
	let mut instr_group: InstrToBeExec = unsafe { std::mem::zeroed() };
	let _serial_clint = ClintCtx {
		base: clint.base,
		mtime: clint.mtime as *mut u64,
		mtimecmp: clint.mtimecmp as *mut u64,
		msip: clint.msip as *mut u8,
		states: std::ptr::null_mut(),
		num_harts: clint.num_harts,
		timebase_hz: clint.timebase_hz,
		yield_for_ipi: Cell::new(false),
		ipi_sender_hart: Cell::new(0),
		ipi_sender_rounds: Cell::new(0),
		// 压缩存储写入 IMSIC seteipnum 时,
		// ``try_handle_imsic_serial`` 借助这些指针唤醒目标 hart, 避免
		// SMP AIA 模式下的 TLB 失效死锁.
		msip_pending: Cell::new(clint.msip_pending.get()),
		hart_threads: Cell::new(clint.hart_threads.get()),
		hart_states: Cell::new(clint.hart_states.get()),
	};
	let advance = handle_compressed(
		state,
		half,
		instr_word,
		&mut instr_group,
		ctx,
		pmp,
		dev,
		&_serial_clint,
	);

	if advance == EXIT_SENTINEL {
		let reason = if instr_group.exit_reason != exit_reason::NORMAL {
			instr_group.exit_reason
		} else {
			exit_reason::ECALL
		};
		module.request_stop(StopInfo {
			reason,
			hart_id,
			pc: pc_before,
			instr: instr_word,
			..StopInfo::empty()
		});
		return false;
	}

	advance_pc(state, advance, pc_before);

	post_instr_checks(state, hart_id, module, breakpoints)
}

pub(crate) fn post_instr_checks(
	state: &mut HartState,
	hart_id: u8,
	module: &ModuleState,
	breakpoints: &[u64],
) -> bool {
	state.total_instrs = state.total_instrs.wrapping_add(1);

	if check_bp_hit(state.pc, breakpoints, None) {
		module.request_stop(StopInfo {
			reason: exit_reason::BREAKPOINT,
			hart_id,
			pc: state.pc,
			..StopInfo::empty()
		});
		return false;
	}

	true
}

/// 顺序执行的指令在此推进 PC, 条件为 ``advance != 0`` 且 PC 未变.
///
/// ``advance == 0`` 表示指令已改写 PC, 如跳转、陷阱、ecall 与 WFI, 此处不得再推进.
#[inline]
pub(crate) fn advance_pc(state: &mut HartState, advance: u64, pc_before: u64) {
	if advance != 0 && state.pc == pc_before {
		state.pc = state.pc.wrapping_add(advance);
	}
}
