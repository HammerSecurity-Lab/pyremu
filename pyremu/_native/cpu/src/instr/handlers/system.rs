//! 特权指令、ECALL 与 SBI 调用。

use super::*;

//  系统指令处理

#[inline]
fn try_sbi_time_set_timer(state: &mut HartState, clint: &ClintCtx) -> Option<u64> {
	if read_gpr(state, 17) != sbi_eid::TIME
		|| read_gpr(state, 16) != sbi_fid_time::SET_TIMER
	{
		return None;
	}
	let stime_val = read_gpr(state, 10); // a0
	let hid = state.mhartid as usize;
	if hid < (clint.num_harts as usize) {
		unsafe {
			*clint.mtimecmp.add(hid) = stime_val;
		}
	}
	state.stimecmp = stime_val;
	state.gprs[10] = 0; // SBI_SUCCESS
	Some(4)
}

#[inline]
fn try_sbi_ipi_send_ipi(
	state: &mut HartState,
	instr: u32,
	result: &mut InstrToBeExec,
	clint: &ClintCtx,
) -> Option<u64> {
	if read_gpr(state, 17) != sbi_eid::IPI
		|| read_gpr(state, 16) != sbi_fid_ipi::SEND_IPI
	{
		return None;
	}
	let hart_mask = read_gpr(state, 10); // a0
	let mask_base = read_gpr(state, 11); // a1
	if mask_base != 0 {
		// mask_base 不为 0 时交回 Python 处理。
		result.exit_reason = exit_reason::ECALL;
		result.exit_instr = instr;
		return Some(EXIT_SENTINEL);
	}
	// mask_base 为 0 是常见情形。
	let cur = state.mhartid as usize;
	for t in 0..clint.num_harts as u64 {
		if (hart_mask & (1u64 << t)) == 0 {
			continue;
		}
		clint_write_msip(clint, t as usize, cur, 1);
	}
	state.gprs[10] = 0; // SBI_SUCCESS
	Some(4)
}

/// 处理 ECALL。
///
/// SBI 调用约定: a7 即 x17 存放 EID, a6 即 x16 存放 FID。SBI 是 S 模式到 M 模式的接口,
/// 快速路径仅在 S 模式下启用; 非 S 模式发起的 ecall 按特权级分发陷态,
/// 判据与 ``trap::priv_ecall_concurrent`` 相同。其余调用不退出加速执行, 直接分发陷态。
#[inline]
fn handle_ecall_inline(
	state: &mut HartState,
	instr: u32,
	instr_group: &mut InstrToBeExec,
	clint: &ClintCtx,
) -> u64 {
	if state.mode != riscv_mode::S {
		let ecall_cause = match state.mode {
			riscv_mode::U => mcause_val(exc_code::ECALL_UMODE, false),
			_ => mcause_val(exc_code::ECALL_MMODE, false),
		};
		deliver_trap(state, ecall_cause, 0);
		return 0;
	}

	// ---- SBI 快速路径 ----
	if let Some(advance) = try_sbi_time_set_timer(state, clint) {
		return advance;
	}
	if let Some(advance) = try_sbi_ipi_send_ipi(state, instr, instr_group, clint) {
		return advance;
	}

	// ---- 一般 ECALL: 直接分发陷态 ----
	deliver_trap(state, mcause_val(exc_code::ECALL_SMODE, false), 0);
	0
}

/// 分发特权指令: ECALL、EBREAK、MRET、SRET、WFI 与 SFENCE.VMA。
/// ``handle_system`` 在 func3 为 0b000 时调用本函数。
#[inline]
fn dispatch_privileged(
	state: &mut HartState,
	func12: u16,
	instr: u32,
	instr_group: &mut InstrToBeExec,
	clint: &ClintCtx,
	ctx: &WalkCtx,
) -> u64 {
	match func12 {
		0 => handle_ecall_inline(state, instr, instr_group, clint),
		1 => {
			// 调试器服务关闭: 与 Python 引擎的 trap_ebreak 一致, 分发断点异常。
			if !CFG_HAS_SEMIHOSTING {
				let ebreak_pc = state.pc;
				deliver_trap(
					state,
					mcause_val(exc_code::BREAKPOINT, false),
					ebreak_pc,
				);
				return 0;
			}
			// 调试器序列直接处理, 其余情况按 NOP 处理: 没有连接外部调试器。
			if let Some(advance) = try_semihosting(state, ctx, state.pc) {
				return advance;
			}
			4
		}
		0x302 => {
			// MRET
			let mpp = (state.mstatus >> 11) & 0x3;
			let mpie = (state.mstatus >> 7) & 1;
			state.mode = match mpp {
				0 => riscv_mode::U,
				1 => riscv_mode::S,
				3 => riscv_mode::M,
				_ => riscv_mode::M,
			};
			// MIE 取 MPIE 的值, MPIE 置 1
			state.mstatus &= !(1 << 3); // 清除 MIE
			if mpie != 0 {
				state.mstatus |= 1 << 3;
			} // MIE 取 MPIE 的值
			state.mstatus |= 1 << 7; // MPIE 置 1
			state.mstatus &= !(0b11 << 11); // MPP 置 0, 表示 U 模式
								   // 返回特权级低于 M 时清除 MPRV (RISC-V 特权规范 3.3.2 节)
			if state.mode != riscv_mode::M {
				state.mstatus &= !(1 << 17);
			}
			state.pc = state.mepc;
			state.waiting = 0;
			0
		}
		0x102 => {
			// SRET: 检查特权级; mstatus.TSR=1 时 S 模式执行触发 IllInstr
			if state.mode < riscv_mode::S
				|| (state.mode == riscv_mode::S && ((state.mstatus >> 22) & 1) != 0)
			{
				deliver_illegal_instruction(state, instr as u64);
				return 0;
			}
			let spp = (state.mstatus >> 8) & 1;
			let spie = (state.mstatus >> 5) & 1;
			state.mode = if spp == 0 {
				riscv_mode::U
			} else {
				riscv_mode::S
			};
			// SIE 取 SPIE 的值, SPIE 置 1
			state.mstatus &= !(1 << 1); // 清除 SIE
			if spie != 0 {
				state.mstatus |= 1 << 1;
			} // SIE 取 SPIE 的值
			state.mstatus |= 1 << 5; // SPIE 置 1
			state.mstatus &= !(1 << 8); // SPP 置 0, 表示 U 模式
							   // 返回特权级低于 M 时清除 MPRV (RISC-V 特权规范 3.3.2 节)
			state.mstatus &= !(1 << 17);
			state.pc = state.sepc;
			state.waiting = 0;
			0
		}
		0x105 => {
			// WFI: 等待中断。没有待处理中断时, 循环顶部的检查以
			// WFI_WAIT 结束本 hart 的执行轮次。
			let tw = (state.mstatus >> 21) & 1;
			if tw != 0 && state.mode != riscv_mode::M {
				deliver_illegal_instruction(state, instr as u64);
				return 0;
			}
			// wfi_woken 非 0 表示刚被中断从 WFI 唤醒。MRET 返回到 WFI 之后
			// 的 while 循环, 此时把 WFI 视为 NOP 并推进 PC, 使该轮询循环
			// 重新判定循环条件。
			if state.wfi_woken != 0 {
				state.wfi_woken = 0;
				return 4; // 按 NOP 处理, PC 推进至下一条指令
			}
			let pending = state.mip_value() & state.mie;
			if pending != 0 {
				return 4;
			} // 已有待处理中断, 按 NOP 处理
			state.waiting = 1;
			4 // 推进 PC 越过 WFI; 等待在循环顶部处理
		}
		// SFENCE.VMA: funct7 位于位域 [31:25], 取值 0b0001001, rs2 位于位域 [24:20]。
		// 编码满足
		//     funct12 = (funct7 << 5) | rs2 = 0x120 | rs2
		// 故匹配 0x120..0x13F 的全部取值, 使按 ASID 刷新的 sfence.vma x0, rs2
		// 也在此处理, 不产生 IllInstr 陷态。
		f if (f >> 5) == 0x09 => {
			// SFENCE.VMA: S 模式在 mstatus.TVM=1 时触发 IllInstr
			if state.mode == riscv_mode::S && ((state.mstatus >> 20) & 1) != 0 {
				deliver_illegal_instruction(state, instr as u64);
				return 0;
			}
			// 刷新全部 TLB 条目, 即 itlb 与 dtlb。
			// 按 ASID 与 VA 过滤尚未实现, 当前执行全量刷新。
			for e in state.itlb.iter_mut() {
				e.valid = 0;
			}
			for e in state.dtlb.iter_mut() {
				e.valid = 0;
			}
			4
		}
		0x5a0 => {
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
			4
		}
		_ => {
			deliver_illegal_instruction(state, instr as u64);
			0
		}
	}
}

pub fn handle_system(
	state: &mut HartState,
	f: &DecodedFields,
	instr: u32,
	instr_group: &mut InstrToBeExec,
	ctx: &WalkCtx,
	hart_id: u8,
	clint: &ClintCtx,
	pmp: &PmpCtx,
) -> u64 {
	match f.func3 {
		0b000 => {
			dispatch_privileged(state, f.func12, instr, instr_group, clint, ctx)
		}
		0b001 | 0b010 | 0b011 | 0b101 | 0b110 | 0b111 => {
			// CSR 指令可由 funct3 的取值区分:
			//     0b001: CSRRW
			//     0b010: CSRRS
			//     0b011: CSRRC
			//     0b101: CSRRWI
			//     0b110: CSRRSI
			//     0b111: CSRRCI
			// 为 CsrContext 构造临时的 ConcurrentClintCtx, 使计时器中断标识
			// 能够更新 mtimecmp; u64 与 AtomicU64 的内存布局在 x86_64 上相同。
			let conc_clint = crate::shared::ConcurrentClintCtx {
				base: clint.base,
				mtime: clint.mtime as *const std::sync::atomic::AtomicU64,
				mtimecmp: clint.mtimecmp as *const std::sync::atomic::AtomicU64,
				msip: clint.msip as *const std::sync::atomic::AtomicU8,
				num_harts: clint.num_harts,
				msip_pending: std::cell::Cell::new(std::ptr::null()),
				hart_threads: std::cell::Cell::new(std::ptr::null()),
				hart_states: std::cell::Cell::new(std::ptr::null()),
				timebase_hz: 0,
			};
			let mut csr_ctx =
				csr::CsrContext::new(state, hart_id as u32, pmp, &conc_clint);
			let advance = csr::handle_csr(
				&mut csr_ctx,
				f.rd,
				f.rs1,
				f.func12,
				f.func3,
				instr,
				instr_group,
			);
			// 同步 MIP.MSIP 到 CLINT 的 msip: 软件经 CSR 写入清除 MSIP 后,
			// 同时清除 CLINT 的 MSIP 寄存器, 避免 ``build_mip`` 在下次进入
			// 加速执行时再次置位。
			if f.func12 != 0x344 /* MIP */ || f.func12 /* SIP */ == 0x144 {
				return advance;
			}
			let msip_in_mip = (state.mip.load(Ordering::Acquire) >> 3) & 1;
			let msip_in_clint =
				((unsafe { *clint.msip.add(hart_id as usize) }) as u64) & 1;
			if msip_in_mip == 0 && msip_in_clint != 0 {
				unsafe {
					*clint.msip.add(hart_id as usize) = 0;
				}
			} else if msip_in_mip != 0 && msip_in_clint == 0 {
				// CLINT 的 MSIP 为 0 而 state.mip 的 MSIP 仍为 1 时, 以 CLINT
				// 为准清除 state.mip; 此处不回写 CLINT。
				state.mip.fetch_and(!(1 << 3), Ordering::AcqRel);
			}
			advance
		}
		_ => {
			deliver_illegal_instruction(state, instr as u64);
			0
		}
	}
}
