//! 每 hart 一个工作线程: 取指、执行与中断检查的调度循环.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::clock::advance_clock_source;
use crate::consts::*;
use crate::ffi::{FfiExtIrqCtx, FfiPlicCtx, FfiUartCtx, MemCtx};
use crate::instr::check_ext_isa;
use crate::instr::decode::decode_fields;
use crate::instr::exec::{
	advance_pc, dispatch_concurrent, exec_compressed_concurrent, post_instr_checks,
};
use crate::instr::fetch::{
	check_bp_hit, fetch_instr_word, request_not_mainram_exit,
	translate_fetch_pc_concurrent, FetchWord,
};
use crate::instr::handlers::{pmp_ok, DevCtx, PmpCtx, EXIT_SENTINEL};
use crate::instr::Step;
use crate::interrupt::{
	check_and_deliver_interrupt_concurrent,
	clint::{sync_msip, sync_mtip},
	imsic_topei_peek, sync_ext_irq_mip,
	wfi::wfi_spin,
	IID_M_IPI, IID_S_IPI,
};
use crate::mem::translate::{tlb_flush_all, tlb_mark_all_dirty, WalkCtx};
use crate::peripheral::plic::plic_sync_mip_if_legacy;
use crate::shared::{
	ConcurrentClintCtx, ModuleState, SharedDevCtx, SharedMemCtx, SharedPmpCtx,
	StopInfo,
};
use crate::state::{exit_reason, HartState};
use crate::trap::{deliver_illegal_instruction, deliver_trap, exc_code, mcause_val};

/// 由可跨线程传递的 FFI 包装结构构造局部上下文结构.
fn make_contexts(
	mem: SharedMemCtx,
	pmp: SharedPmpCtx,
	dev: SharedDevCtx,
	module: &ModuleState,
) -> (MemCtx, PmpCtx, DevCtx, WalkCtx) {
	let mem_val = MemCtx {
		ram: mem.ram,
		ram_size: mem.ram_size,
		ram_base: mem.ram_base,
		shadow_base: mem.shadow_base,
		shadow_size: mem.shadow_size,
	};
	let pmp_val = PmpCtx {
		cfg: pmp.cfg,
		addr: pmp.addr,
		num: pmp.num,
	};
	let dev_val = DevCtx {
		bases: dev.bases,
		ends: dev.ends,
		num: dev.num,
		virtio_base: dev.virtio_base,
		virtio_raw: dev.virtio_raw,
		plic: dev.plic,
	};
	let walk = WalkCtx {
		ram: mem_val.ram,
		ram_size: mem_val.ram_size,
		ram_base: mem_val.ram_base,
		shadow_base: mem_val.shadow_base,
		shadow_size: mem_val.shadow_size,
		tlb_flush_cnt: &module.tlb_flush_cnt as *const AtomicU64,
		lr_reserved: mem.lr_reserved,
		num_harts: module.wfi_flags.len() as u32,
	};
	(mem_val, pmp_val, dev_val, walk)
}

/// 本 hart 上次记录的刷新计数与该计数不相等时, 把指令 TLB 与数据 TLB 的条目
/// 全部标为陈旧.
fn mark_tlb_dirty_if_stale(
	state: &mut HartState,
	module: &ModuleState,
	hart_id: u8,
) {
	let flush_cnt = module.tlb_flush_cnt.load(Ordering::Acquire);
	let seen =
		module.tlb_flush_cnt_per_hart[hart_id as usize].load(Ordering::Relaxed);
	if seen == flush_cnt {
		return;
	}
	tlb_mark_all_dirty(&mut state.itlb);
	tlb_mark_all_dirty(&mut state.dtlb);
	module.tlb_flush_cnt_per_hart[hart_id as usize]
		.store(flush_cnt, Ordering::Relaxed);
}

/// 处理 WFI 等待与唤醒.
fn handle_wfi_state(
	state: &mut HartState,
	hart_id: u8,
	clint: &ConcurrentClintCtx,
	dev: &DevCtx,
	module: &ModuleState,
	stop_flag: *const u8,
	uart: &FfiUartCtx,
	ext_irq: *mut FfiExtIrqCtx,
) -> Step {
	if state.waiting == 0 {
		return Step::Next;
	}
	// Python 侧有待处理的工作, 如 virtio 的 QueueNotify，则退出本轮,
	if dev.has_pending_python_work() {
		module.request_stop(StopInfo {
			reason: exit_reason::WFI_WAIT,
			hart_id,
			pc: state.pc,
			..StopInfo::empty()
		});
		return Step::Exit;
	}
	if !wfi_spin(
		state,
		hart_id as usize,
		clint,
		module,
		stop_flag,
		uart.rx_notify,
		ext_irq,
	) {
		// 退出 WFI: 等待期间可能有其余 hart 执行了 SFENCE.VMA,
		// 故按刷新计数标记陈旧条目.
		mark_tlb_dirty_if_stale(state, module, hart_id);
		return Step::Exit;
	}
	Step::Next
}

/// 同步硬件中断线路, 并投递优先级最高的挂起中断.
/// 投递了陷阱时返回 ``true``, 调用方应 ``continue`` 主循环.
fn step_interrupts(
	state: &mut HartState,
	_hart_id: u8,
	clint: &ConcurrentClintCtx,
	plic: *mut FfiPlicCtx,
) -> bool {
	sync_mtip(state, clint);
	sync_msip(state, clint);

	// IMSIC 同步不在每指令执行路径上进行: 加速执行开始时, Python 侧
	// _native_sync_plic_mip 与 marshal_imsic 已写入正确的 mip 位. 执行期间 IMSIC
	// 状态只经 CSR 写入改变, 如 stopei 与 mtopei 的 claim、mireg 与 sireg, 这些
	// 路径经 sync_imsic_one() 就地更新 mip; 跨 hart 的 IPI 也直接置位目标 hart 的 mip.
	// 清理陈旧的 MEIP 与 SEIP: sync_imsic 不在每条指令的执行路径上执行, 两位的取值
	// 可能落后于 IMSIC eip; 不清理会投递虚假 SEI, 内核读 stopi 得 0 后转入 STIP,
	// 形成 SEI 与 STIP 反复投递的空转. 清除只在 imsic_topei_peek 返回 0 时进行,
	// 因为 IID=1 与 IID=3 的 IPI 也经这两位投递, 清除会丢掉 IPI, 使 SMP 启动停滞
	// 到定时器介入; 查询只在对应 mip 位已置位时进行.
	if state.imsic_m.present != 0
		&& (state.mip.load(Ordering::Acquire) & (1 << 11)) != 0
	{
		if state.imsic_m.eidelivery != 0 {
			let (val, _) = imsic_topei_peek(&state.imsic_m);
			if val == 0 {
				state.mip.fetch_and(!(1 << 11), Ordering::AcqRel);
			}
		} else {
			// eidelivery 为 0: 仅 IPI 快速路径位 IID=1 与 IID=3 维持 MEIP,
			// 与下方 S 文件的 SEIP 处理同理.
			let ipi_mask: u32 = (1 << IID_S_IPI) | (1 << IID_M_IPI);
			let has_ipi =
				(state.imsic_m.eip[0].load(Ordering::Acquire) & ipi_mask) != 0;
			if !has_ipi {
				state.mip.fetch_and(!(1 << 11), Ordering::AcqRel);
			}
		}
	}
	if state.imsic_s.present != 0
		&& (state.mip.load(Ordering::Acquire) & (1 << 9)) != 0
	{
		if state.imsic_s.eidelivery != 0 {
			let (val, _) = imsic_topei_peek(&state.imsic_s);
			if val == 0 {
				state.mip.fetch_and(!(1 << 9), Ordering::AcqRel);
			}
		} else {
			// eidelivery 为 0: 不查询 topei, 仅按 eip 的 IPI 位 IID=1 与 IID=3
			// 判定是否清除 SEIP; 外部中断由 ext_irq 排空与 PLIC 处理.
			let ipi_mask: u32 = (1 << IID_S_IPI) | (1 << IID_M_IPI);
			let has_ipi =
				(state.imsic_s.eip[0].load(Ordering::Acquire) & ipi_mask) != 0;
			if !has_ipi {
				state.mip.fetch_and(!(1 << 9), Ordering::AcqRel);
			}
		}
	}

	// 仅当 IMSIC 拥有外部中断线路时才强制使能 MEIE: AIA 模式下 OpenSBI 可能不显式
	// 置位 mie.MEIE, IID=1 与 IID=3 的 IPI 经 MEIP 与 SEIP 投递, 分发依赖 IMSIC
	// 中断控制器路径. 例如，传统 PLIC 模式下强制使能会使 M 级外部陷阱进入 OpenSBI 无法
	// 处理的 irqchip, 经 sbi_trap_error 与 sbi_hart_hang 使整个 SMP 启动停滞.
	if state.imsic_m.present != 0
		&& (state.mip.load(Ordering::Acquire) & (1 << 11)) != 0
		&& (state.mie & (1 << 11)) == 0
	{
		state.mie |= 1 << 11;
	}
	if state.imsic_s.present != 0
		&& state.mdid == HOST_MDID
		&& (state.mip.load(Ordering::Acquire) & (1 << 9)) != 0
		&& (state.mie & (1 << 9)) == 0
	{
		state.mie |= 1 << 9;
	}
	// 传统 PLIC 模式下, 按 PLIC 的 pending、enable 与优先级重算 MEIP 与 SEIP,
	// 覆盖设备拉高早于受调试程序使能所产生的置位, 以及读取 claim 寄存器清除
	// pending 之后仍置位的两位. IMSIC 存在、PLIC 基址为 0 或两位均为 0 时跳过.
	plic_sync_mip_if_legacy(state, plic);
	if check_and_deliver_interrupt_concurrent(state, clint) {
		return true;
	}
	false
}

/// 取指流水线: 翻译虚拟地址, 做 PMP 执行权限判定, 读取内存, 匹配断点.
/// 成功返回 ``Ok(pc_before, instr_word)``, 投递陷阱或命中断点时返回 ``Err(step)``.
fn step_fetch_instr(
	state: &mut HartState,
	hart_id: u8,
	ctx: &WalkCtx,
	pmp: &PmpCtx,
	mem: &MemCtx,
	module: &ModuleState,
	breakpoints: &[u64],
) -> Result<(u64, u32), Step> {
	let pc_before = state.pc;
	let page_offset = pc_before & 0xfff;

	// -- 虚拟地址翻译为物理地址 --
	let fetch_pa: u64 =
		match translate_fetch_pc_concurrent(state, ctx, pc_before, pmp) {
			Some(pa) => pa,
			None => {
				let step = if post_instr_checks(state, hart_id, module, breakpoints)
				{
					Step::Continue
				} else {
					Step::Exit
				};
				return Err(step);
			}
		};

	// -- PMP 执行权限判定 --
	if !pmp_ok(state, fetch_pa, 4, false, true, pmp) {
		deliver_trap(
			state,
			mcause_val(exc_code::INSTR_ACCESS_FAULT, false),
			pc_before,
		);
		let step = if post_instr_checks(state, hart_id, module, breakpoints) {
			Step::Continue
		} else {
			Step::Exit
		};
		return Err(step);
	}

	// -- 读取指令字, 处理跨页访问 --
	let instr_word = match fetch_instr_word(
		state,
		ctx,
		mem,
		pc_before,
		page_offset,
		fetch_pa,
		pmp,
	) {
		FetchWord::Word(w) => w,
		FetchWord::NotMainRam => {
			return Err(request_not_mainram_exit(module, hart_id, pc_before));
		}
		FetchWord::Fault => {
			let step = if post_instr_checks(state, hart_id, module, breakpoints) {
				Step::Continue
			} else {
				Step::Exit
			};
			return Err(step);
		}
	};

	// -- 断点判定 --
	if check_bp_hit(pc_before, breakpoints, Some(fetch_pa)) {
		module.request_stop(StopInfo {
			reason: exit_reason::BREAKPOINT,
			hart_id,
			pc: pc_before,
			instr: instr_word,
			..StopInfo::empty()
		});
		return Err(Step::Exit);
	}

	Ok((pc_before, instr_word))
}

//  每 hart 的工作线程主循环

/// IMSIC 是否独占本 hart 的外部中断线路, 任一中断文件的 eidelivery 非 0 即为独占.
///
/// eidelivery 非 0 时 MEIP 与 SEIP 由 IMSIC 的 eip 与 eie 驱动. 该判定决定 RX 通知
/// 是否提前结束本轮: 独占时字节还需 Python 侧从环形缓冲区写入 UART FIFO, 提前退出
/// 使该写入尽早发生; 未被占用时内联置位已足够, 无需退出.
#[inline]
fn imsic_owns_ext_line(state: &HartState) -> bool {
	(state.imsic_m.present != 0 && state.imsic_m.eidelivery != 0)
		|| (state.imsic_s.present != 0 && state.imsic_s.eidelivery != 0)
}

pub(crate) fn hart_worker(
	state: &mut HartState,
	hart_id: u8,
	mem: SharedMemCtx,
	pmp: SharedPmpCtx,
	dev: SharedDevCtx,
	clint: &ConcurrentClintCtx,
	uart: &FfiUartCtx,
	module: &ModuleState,
	breakpoints: &[u64],
	stop_flag: *const u8,
	ext_irq: *mut FfiExtIrqCtx,
) {
	let (_mem_val, _pmp_val, _dev_val, ctx) = make_contexts(mem, pmp, dev, module);
	let mem = &_mem_val;
	let pmp = &_pmp_val;
	let dev = &_dev_val;

	if !module.is_flush_cnt_persistent {
		tlb_flush_all(&mut state.itlb);
		tlb_flush_all(&mut state.dtlb);
	}

	loop {
		// ---- 停机与外部信号检查 ----
		if module.stop_flag.load(Ordering::Acquire)
			|| (!stop_flag.is_null() && (unsafe { *stop_flag != 0 }))
		{
			return;
		}
		// mtime 按本 hart 的指令条数增量推进.
		// 执行循环持续运行, 仅由外部信号暂停, 即 Ctrl+Q 置位 stop_flag.
		advance_clock_source(module, clint, state);
		/*
			外部中断 (UART, VirtIO 等): 守护线程把数据写入 UART 接收 FIFO 后置位挂起,
			此处就地置位 SEIP 与 MEIP, 使受调试程序在本次加速执行内处理该中断.
			仅对未被 IMSIC 占用的线路置位; 无条件置位
			会使 AIA 模式的指令吞吐量下降到约 1/22.
		*/
		sync_ext_irq_mip(state, ext_irq);
		/*
			TermIO RX 通知: termio 线程已把标准输入的新字节写入 RX 环形缓冲区.
			IMSIC 独占外部中断线路时结束本轮, 使 Python 侧把这些字节写入 UART FIFO;
			未被占用时 sync_ext_irq_mip 已在轮内联置位, 无需退出.
			退出不等于投递: Python 经 IMSIC._publish_eip 把实时新增的 eip 位写入共享
			数组, sync_ext_irq_mip 在轮内即可据此置位 SEIP. 退出原因 RX_WAIT 不写入
			Python 侧的 stop_flag, 调试器不把它当作暂停事件; 通知位由 Python 在每轮
			结束时清零, 故每个输入突发至多触发一次退出, 不会每轮重复退出.
		*/
		if imsic_owns_ext_line(state)
			&& !uart.rx_notify.is_null()
			&& (unsafe { *uart.rx_notify != 0 })
		{
			module.request_stop(StopInfo {
				reason: exit_reason::RX_WAIT,
				hart_id,
				pc: state.pc,
				..StopInfo::empty()
			});
			return;
		}
		if state.halted != 0 {
			// 已停机的 hart 退出工作函数. 若在此处自旋, 其余 hart 可能在
			// all_in_wfi 中等待本 hart, 造成引擎死锁.
			module.wfi_flags[hart_id as usize].store(1, Ordering::Release);
			module.wfi_count.fetch_add(1, Ordering::Release);
			return;
		}

		// ---- WFI 等待与唤醒 ----
		let wfi_step = handle_wfi_state(
			state, hart_id, clint, dev, module, stop_flag, uart, ext_irq,
		);
		match wfi_step {
			Step::Exit => {
				return;
			}
			Step::Continue => {
				continue;
			}
			Step::Next => {}
		}

		// ---- 中断 ----
		if step_interrupts(state, hart_id, clint, dev.plic) {
			continue;
		}

		// TLB 一致性维护
		mark_tlb_dirty_if_stale(state, module, hart_id);

		// ---- 取指 ----
		let (pc_before, instr_word) = match step_fetch_instr(
			state,
			hart_id,
			&ctx,
			pmp,
			mem,
			module,
			breakpoints,
		) {
			Ok(v) => v,
			Err(Step::Continue) => {
				continue;
			}
			Err(Step::Exit) => {
				return;
			}
			Err(Step::Next) => unreachable!(),
		};

		// ---- 译码与执行 ----
		let f = decode_fields(instr_word);
		// 平台未声明的扩展所对应的指令不存在, 投递 IllInstr 而不进入处理器.
		// 判定与 Python 侧 ``check_ext_isa`` 一致.
		if !check_ext_isa::check_ext_isa(&state.isa_exts, &f) {
			deliver_illegal_instruction(state, instr_word as u64);
			if !post_instr_checks(state, hart_id, module, breakpoints) {
				return;
			}
			continue;
		}
		if f.is_compressed != 0 {
			if !exec_compressed_concurrent(
				state,
				instr_word,
				pc_before,
				hart_id,
				&ctx,
				pmp,
				dev,
				clint,
				module,
				breakpoints,
			) {
				return;
			}
			continue;
		}
		let advance = dispatch_concurrent(
			state, &f, instr_word, &ctx, hart_id, pmp, dev, clint, uart, module,
		);
		if advance == EXIT_SENTINEL {
			if module.stop_flag.load(Ordering::Acquire) {
				return;
			}
			module.request_stop(StopInfo {
				reason: exit_reason::MMIO,
				hart_id,
				pc: pc_before,
				instr: instr_word,
				..StopInfo::empty()
			});
			return;
		}

		advance_pc(state, advance, pc_before);

		if !post_instr_checks(state, hart_id, module, breakpoints) {
			return;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::clock::NS_PER_INSTR;
	use crate::ffi::FfiUartCtx;
	use crate::instr::exec::{
		handle_load_concurrent, read_ram_cross_page, write_ram_cross_page,
	};
	use crate::instr::handlers::{DevCtx, PmpCtx};
	use crate::mem::translate::WalkCtx;
	use crate::shared::{
		ConcurrentClintCtx, ModuleState, StopInfo, MSIP_PENDING_STRIDE,
	};
	use crate::state::{riscv_mode, HartState, TlbEntry};
	use std::cell::Cell;
	use std::sync::atomic::{AtomicU64, AtomicU8};

	/// 单条 TOR 条目覆盖全部内存, 权限为 RWX.
	/// 需要该上下文是因为按 RISC-V 规范 §3.7.1, num_entries 为 0 时 pmp_ok 拒绝
	/// S 模式与 U 模式的访问.
	fn make_permissive_pmp(cfg: &mut [u8], addr: &mut [u64]) -> PmpCtx {
		// TOR 条目覆盖 [0, addr[0]) 即 [0, u64::MAX), 即全部地址空间.
		// cfg 取值 0x0f 对应 PMP_R, PMP_W, PMP_X 与 PMP_A_TOR.
		cfg[0] = 0x0f;
		addr[0] = u64::MAX;
		PmpCtx {
			cfg: cfg.as_mut_ptr(),
			addr: addr.as_mut_ptr(),
			num: 1,
		}
	}

	/// 在主存中构造最小 4 KiB 页的 Sv39 页表.
	/// 根页表放在物理地址 0x5000, 中间页表放在 0x6000, 末级页表放在 0x7000.
	/// 返回 satp 的取值, 即 Sv39 模式且根页表 PPN 为 5.
	fn setup_two_pages(
		ram: &mut [u8],
		va_a: u64,
		pa_a: u64,
		va_b: u64,
		pa_b: u64,
		perm: u64,
	) -> u64 {
		let vpn_a = crate::mem::mmu::sv39_decompose_va(va_a);
		let vpn_b = crate::mem::mmu::sv39_decompose_va(va_b);
		// 两个虚拟页必须共用同一条根页表与中间页表路径, 即位于同一个 2 MiB 区域.
		assert_eq!(vpn_a.vpn2, vpn_b.vpn2);
		assert_eq!(vpn_a.vpn1, vpn_b.vpn1);

		let satp = (8u64 << 60) | 5; // Sv39, 根页表 PPN 为 5

		// 根页表位于物理地址 0x5000: 指向 PPN 为 6 的中间页表
		let l2_off = 0x5000usize + ((vpn_a.vpn2 * 8) as usize);
		let l2_val = (6u64 << 10) | crate::mem::translate::PTE_V;
		ram[l2_off..l2_off + 8].copy_from_slice(&l2_val.to_le_bytes());

		// 中间页表位于物理地址 0x6000: 指向 PPN 为 7 的末级页表
		let l1_off = 0x6000usize + ((vpn_a.vpn1 * 8) as usize);
		let l1_val = (7u64 << 10) | crate::mem::translate::PTE_V;
		ram[l1_off..l1_off + 8].copy_from_slice(&l1_val.to_le_bytes());

		// 末级页表位于物理地址 0x7000: 两个叶子条目
		let ppn_a = pa_a >> 12;
		let l0_off_a = 0x7000usize + ((vpn_a.vpn0 * 8) as usize);
		let l0_val_a = (ppn_a << 10) | perm | crate::mem::translate::PTE_V;
		ram[l0_off_a..l0_off_a + 8].copy_from_slice(&l0_val_a.to_le_bytes());

		let ppn_b = pa_b >> 12;
		let l0_off_b = 0x7000usize + ((vpn_b.vpn0 * 8) as usize);
		let l0_val_b = (ppn_b << 10) | perm | crate::mem::translate::PTE_V;
		ram[l0_off_b..l0_off_b + 8].copy_from_slice(&l0_val_b.to_le_bytes());

		satp
	}

	/// 跨越 4 KiB 页边界的 8 字节读取必须从两个独立翻译的物理页拼接字节,
	/// 即使虚拟地址按 4 字节对齐也不得走对齐路径.
	///
	/// 映射为虚拟地址 0x1000 到物理地址 0x1000, 虚拟地址 0x2000 到物理地址
	/// 0x3000, 两者不相邻, 跳过物理地址 0x2000. 虚拟地址 0x1FFC 处的 8 字节读取
	/// 按 4 字节对齐而不按 8 字节对齐, 跨入虚拟地址 0x2000, 结果必须是物理地址
	/// 0x1FFC 至 0x1FFF 的字节接物理地址 0x3000 至 0x3003 的字节.
	#[test]
	fn cross_page_read_splices_non_consecutive_pa() {
		const RAM_SIZE: usize = 0x8000;
		let mut ram = vec![0u8; RAM_SIZE];

		// 页 A: 虚拟地址 0x1000 映射到物理地址 0x1000
		// 页 B: 虚拟地址 0x2000 映射到物理地址 0x3000, 与页 A 的物理地址不相邻
		let satp = setup_two_pages(
			&mut ram,
			0x1000,
			0x1000,
			0x2000,
			0x3000,
			crate::mem::translate::PTE_R
				| crate::mem::translate::PTE_W
				| crate::mem::translate::PTE_U,
		);

		// 写入测试数据: 第一个物理页末尾为 0xAA, 第二个物理页开头为 0xBB.
		// 虚拟地址 0x1FFC 对应物理地址 0x1FFC, 前 4 个字节位于页 A.
		// 虚拟地址 0x2000 对应物理地址 0x3000, 第 4 至 7 个字节位于页 B.
		for i in 0x1ffc..0x2000 {
			ram[i] = 0xaa;
		}
		for i in 0x3000..0x3004 {
			ram[i] = 0xbb;
		}

		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::U; // U 模式: 需要页表遍历, PMP 为宽松条目
		state.mmu_mode = 8; // Sv39
		state.satp = satp;
		// 把 dtlb 全部置为无效, 强制进行页表遍历.
		for e in state.dtlb.iter_mut() {
			*e = TlbEntry::empty();
		}

		let ctx = WalkCtx {
			ram: ram.as_mut_ptr(),
			ram_size: RAM_SIZE as u64,
			ram_base: 0,
			shadow_base: 0,
			shadow_size: 0,
			tlb_flush_cnt: std::ptr::null(),
			lr_reserved: std::ptr::null_mut(),
			num_harts: 1,
		};
		// 宽松 PMP: 单条 TOR 条目覆盖全部地址, 不做限制.
		let mut _pmp_cfg = vec![0u8; 64];
		let mut _pmp_addr = vec![0u64; 64];
		let pmp = make_permissive_pmp(&mut _pmp_cfg, &mut _pmp_addr);

		// 在虚拟地址 0x1FFC 处读取 8 字节, 跨越页边界.
		let (val, ok) =
			read_ram_cross_page(&mut state, &ctx, 0x1ffc, 0x1ffc, 8, &pmp);
		assert!(ok, "cross-page read must succeed");

		// 预期结果: 4 个 0xAA 字节与 4 个 0xBB 字节按小端拼接.
		let expected: u64 = 0xbbbb_bbbb_aaaa_aaaa;
		assert_eq!(
			val, expected,
			"cross-page read: expected 0x{expected:016X}, got 0x{val:016X}\
             \n  (4 bytes from PA 0x1FFC + 4 bytes from PA 0x3000)"
		);
	}

	/// 写入一侧的用例: 跨越页边界的 8 字节写入必须把字节分别写入两个独立翻译的物理页.
	#[test]
	fn cross_page_write_scatters_non_consecutive_pa() {
		const RAM_SIZE: usize = 0x8000;
		let mut ram = vec![0u8; RAM_SIZE];

		let satp = setup_two_pages(
			&mut ram,
			0x1000,
			0x1000,
			0x2000,
			0x3000,
			crate::mem::translate::PTE_R
				| crate::mem::translate::PTE_W
				| crate::mem::translate::PTE_U,
		);

		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::U;
		state.mmu_mode = 8;
		state.satp = satp;
		for e in state.dtlb.iter_mut() {
			*e = TlbEntry::empty();
		}

		let ctx = WalkCtx {
			ram: ram.as_mut_ptr(),
			ram_size: RAM_SIZE as u64,
			ram_base: 0,
			shadow_base: 0,
			shadow_size: 0,
			tlb_flush_cnt: std::ptr::null(),
			lr_reserved: std::ptr::null_mut(),
			num_harts: 1,
		};
		let mut _pmp_cfg = vec![0u8; 64];
		let mut _pmp_addr = vec![0u64; 64];
		let pmp = make_permissive_pmp(&mut _pmp_cfg, &mut _pmp_addr);

		// 在虚拟地址 0x1FFC 处写入 0xCCCCCCCC_DDDDDDDD, 每页 4 个字节.
		let val: u64 = 0xcccc_cccc_dddd_dddd;
		let ok =
			write_ram_cross_page(&mut state, &ctx, 0x1ffc, 0x1ffc, val, 8, &pmp);
		assert!(ok, "cross-page write must succeed");

		// 低 4 个字节 0xDDDDDDDD 写入物理地址 0x1FFC 至 0x1FFF, 即页 A.
		assert_eq!(&ram[0x1ffc..0x2000], &[0xdd, 0xdd, 0xdd, 0xdd]);
		// 高 4 个字节 0xCCCCCCCC 写入物理地址 0x3000 至 0x3003, 即页 B.
		assert_eq!(&ram[0x3000..0x3004], &[0xcc, 0xcc, 0xcc, 0xcc]);
		// 物理地址 0x2000 至 0x2FFF 必须保持不变.
		assert!(
			ram[0x2000..0x3000].iter().all(|&b| b == 0),
			"gap between mapped pages must not be written"
		);
	}

	/// 跨页写入的第二页缺页时, 本次存储不得修改第一页的任何字节.
	///
	/// 映射虚拟地址 0x1000 到物理地址 0x1000, 虚拟地址 0x2000 的页表项置为无效。
	/// 虚拟地址 0x1FFC 处的 8 字节写入的前 4 个字节属于第一页, 后 4 个字节触发
	/// StPageFault, mtval 为第二段的虚拟地址 0x2000。
	#[test]
	fn cross_page_write_second_page_fault_writes_nothing() {
		const RAM_SIZE: usize = 0x8000;
		let mut ram = vec![0u8; RAM_SIZE];

		let satp = setup_two_pages(
			&mut ram,
			0x1000,
			0x1000,
			0x2000,
			0x3000,
			crate::mem::translate::PTE_R
				| crate::mem::translate::PTE_W
				| crate::mem::translate::PTE_U,
		);
		// 把虚拟地址 0x2000 的末级页表项置为无效.
		let vpn_b = crate::mem::mmu::sv39_decompose_va(0x2000);
		let l0_off_b = 0x7000usize + ((vpn_b.vpn0 * 8) as usize);
		ram[l0_off_b..l0_off_b + 8].copy_from_slice(&0u64.to_le_bytes());

		// 第一页末尾的 4 个字节预先写入 0xAA.
		for i in 0x1ffc..0x2000 {
			ram[i] = 0xaa;
		}

		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::U;
		state.mmu_mode = 8;
		state.satp = satp;
		for e in state.dtlb.iter_mut() {
			*e = TlbEntry::empty();
		}

		let ctx = WalkCtx {
			ram: ram.as_mut_ptr(),
			ram_size: RAM_SIZE as u64,
			ram_base: 0,
			shadow_base: 0,
			shadow_size: 0,
			tlb_flush_cnt: std::ptr::null(),
			lr_reserved: std::ptr::null_mut(),
			num_harts: 1,
		};
		let mut _pmp_cfg = vec![0u8; 64];
		let mut _pmp_addr = vec![0u64; 64];
		let pmp = make_permissive_pmp(&mut _pmp_cfg, &mut _pmp_addr);

		let ok = write_ram_cross_page(
			&mut state,
			&ctx,
			0x1ffc,
			0x1ffc,
			0xcccc_cccc_dddd_dddd,
			8,
			&pmp,
		);
		assert!(!ok, "second page fault must fail the store");
		assert_eq!(
			state.mcause,
			mcause_val(exc_code::ST_PAGE_FAULT, false),
			"expected StPageFault"
		);
		assert_eq!(
			state.mtval, 0x2000,
			"mtval must be the second chunk address"
		);
		assert_eq!(
			&ram[0x1ffc..0x2000],
			&[0xaa, 0xaa, 0xaa, 0xaa],
			"first page must not be partially written"
		);
	}

	//  rd 与 rs1 相同的用例

	/// rd 与 rs1 相同的加载指令必须先读取基址寄存器, 再写入载入值.
	/// ``lhu a5, 0x336(a5)`` 在 a5 为 7 时曾于虚拟地址 0x33D 处失败, 原因是
	/// 旧值在地址计算之前已被覆盖.
	#[test]
	fn load_rd_equals_rs1_uses_old_value_for_address() {
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::M;
		state.gprs[15] = 0x100; // a5 指向主存内的低地址
		state.mmu_mode = 0; // Bare 模式: 虚拟地址即物理地址

		let mut ram = vec![0xCDu8; 0x1000];
		let ctx = WalkCtx {
			ram: ram.as_mut_ptr(),
			ram_size: 0x1000,
			ram_base: 0,
			shadow_base: 0,
			shadow_size: 0,
			tlb_flush_cnt: std::ptr::null(),
			lr_reserved: std::ptr::null_mut(),
			num_harts: 1,
		};
		let mut _pmp_cfg = vec![0u8; 1];
		let mut _pmp_addr = vec![0u64; 1];
		let pmp = make_permissive_pmp(&mut _pmp_cfg, &mut _pmp_addr);
		let dev = DevCtx {
			bases: std::ptr::null(),
			ends: std::ptr::null(),
			num: 0,
			virtio_base: 0,
			virtio_raw: std::ptr::null_mut(),
			plic: std::ptr::null_mut(),
		};
		// 为加载指令处理函数构造最小的 CLINT 与 UART 上下文.
		let _mtime = std::sync::atomic::AtomicU64::new(0);
		let _mtimecmp = std::sync::atomic::AtomicU64::new(0);
		let _msip = std::sync::atomic::AtomicU8::new(0);
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: &_mtime,
			mtimecmp: &_mtimecmp,
			msip: &_msip,
			num_harts: 1,
			msip_pending: Cell::new(std::ptr::null()),
			hart_threads: Cell::new(std::ptr::null()),
			hart_states: Cell::new(std::ptr::null()),
			timebase_hz: 0, // 单元测试中不推进时钟源
		};
		let _tx_buf = [0u8; 16];
		let _tx_wr = std::sync::atomic::AtomicU32::new(0);
		let uart = FfiUartCtx {
			base: 0,
			tx_buf: _tx_buf.as_ptr() as *mut u8,
			tx_cap: 16,
			tx_wr: &_tx_wr as *const std::sync::atomic::AtomicU32 as *mut u32,
			ie: 0,
			txctrl: 0,
			rxctrl: 0,
			rx_fifo_len: 0,
			tx_notify_fd: -1,
			no_stdout: 0,
			rx_notify: std::ptr::null_mut(),
		};
		let _wfi_flags: Vec<std::sync::atomic::AtomicU8> = (0..1)
			.map(|_| std::sync::atomic::AtomicU8::new(0))
			.collect();
		let _tlb_flush_cnt: Vec<std::sync::atomic::AtomicU64> = (0..1)
			.map(|_| std::sync::atomic::AtomicU64::new(0))
			.collect();
		let _msip_pending: Vec<std::sync::atomic::AtomicU64> = (0
			..MSIP_PENDING_STRIDE)
			.map(|_| std::sync::atomic::AtomicU64::new(0))
			.collect();
		let module = ModuleState {
			stop_flag: std::sync::atomic::AtomicBool::new(false),
			stop_info: std::sync::Mutex::new(StopInfo::empty()),
			wfi_count: std::sync::atomic::AtomicU32::new(0),
			wfi_flags: _wfi_flags.into_boxed_slice(),
			active_hart_num: 1,
			tlb_flush_cnt: std::sync::atomic::AtomicU64::new(0),
			tlb_flush_cnt_per_hart: _tlb_flush_cnt.into_boxed_slice(),
			is_flush_cnt_persistent: false,
			lr_reserved: Box::new([]),
			msip_pending: _msip_pending.into_boxed_slice(),
			st_time_val: std::time::Instant::now(),
			time_base_val: 0,
			instr_ref_num: Box::new([]),
		};
		// opcode 为 0000011, rd 为 15, func3 为 101 即 LHU, rs1 为 15, imm 为 0x336
		let instr: u32 = 0x3367d783u32; // lhu a5, 0x336(a5)
		let f = crate::instr::decode::decode_fields(instr);

		// 在目标地址 0x100 + 0x336 = 0x436 处写入已知数据
		let target_pa = 0x100u64 + 0x336u64;
		ram[target_pa as usize] = 0x42;
		ram[(target_pa as usize) + 1] = 0x13;

		let adv = handle_load_concurrent(
			&mut state, &f, instr, &ctx, &pmp, &dev, &clint, &uart, &module,
		);
		assert_eq!(adv, 4);
		// 执行 lhu 后 a5 应为 0x1342, 即 0x42 与 0x13<<8 的小端拼接
		assert_eq!(
			state.gprs[15], 0x1342,
			"LHU rd==rs1: loaded value must be 0x1342, not the old address"
		);
	}

	/// rd 与 rs1 相同的加载指令触发缺页异常时, 目的寄存器不得被改写.
	/// 内核的陷阱处理函数依赖触发时的寄存器内容.
	#[test]
	fn load_rd_equals_rs1_preserves_rd_on_pagefault() {
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::U; // U 模式: 启用 Sv39
		state.mmu_mode = 8; // Sv39
		state.satp = 8u64 << 60; // Sv39, 根页表 PPN 为 0
		state.stvec = 0x80000400; // S 模式陷阱入口地址
		state.medeleg = 1 << 13; // 把 LdPageFault 委派到 S 模式
		state.gprs[15] = 7; // a5 取 7, 即复现该缺陷时的取值
					  // 主存全为零, 页表遍历必然失败, 因为 PTE 的 V 位为 0
		let mut ram = vec![0u8; 0x1000];
		let ctx = WalkCtx {
			ram: ram.as_mut_ptr(),
			ram_size: 0x1000,
			ram_base: 0,
			shadow_base: 0,
			shadow_size: 0,
			tlb_flush_cnt: std::ptr::null(),
			lr_reserved: std::ptr::null_mut(),
			num_harts: 1,
		};
		let mut _pmp_cfg = vec![0u8; 1];
		let mut _pmp_addr = vec![0u64; 1];
		let pmp = make_permissive_pmp(&mut _pmp_cfg, &mut _pmp_addr);
		let dev = DevCtx {
			bases: std::ptr::null(),
			ends: std::ptr::null(),
			num: 0,
			virtio_base: 0,
			virtio_raw: std::ptr::null_mut(),
			plic: std::ptr::null_mut(),
		};
		let _mtime = std::sync::atomic::AtomicU64::new(0);
		let _mtimecmp = std::sync::atomic::AtomicU64::new(0);
		let _msip = std::sync::atomic::AtomicU8::new(0);
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: &_mtime,
			mtimecmp: &_mtimecmp,
			msip: &_msip,
			num_harts: 1,
			msip_pending: Cell::new(std::ptr::null()),
			hart_threads: Cell::new(std::ptr::null()),
			hart_states: Cell::new(std::ptr::null()),
			timebase_hz: 0, // 单元测试中不推进时钟源
		};
		let _tx_buf = [0u8; 16];
		let _tx_wr = std::sync::atomic::AtomicU32::new(0);
		let uart = FfiUartCtx {
			base: 0,
			tx_buf: _tx_buf.as_ptr() as *mut u8,
			tx_cap: 16,
			tx_wr: &_tx_wr as *const std::sync::atomic::AtomicU32 as *mut u32,
			ie: 0,
			txctrl: 0,
			rxctrl: 0,
			rx_fifo_len: 0,
			tx_notify_fd: -1,
			no_stdout: 0,
			rx_notify: std::ptr::null_mut(),
		};
		let _wfi_flags: Vec<std::sync::atomic::AtomicU8> = (0..1)
			.map(|_| std::sync::atomic::AtomicU8::new(0))
			.collect();
		let _tlb_flush_cnt: Vec<std::sync::atomic::AtomicU64> = (0..1)
			.map(|_| std::sync::atomic::AtomicU64::new(0))
			.collect();
		let _msip_pending: Vec<std::sync::atomic::AtomicU64> = (0
			..MSIP_PENDING_STRIDE)
			.map(|_| std::sync::atomic::AtomicU64::new(0))
			.collect();
		let module = ModuleState {
			stop_flag: std::sync::atomic::AtomicBool::new(false),
			stop_info: std::sync::Mutex::new(StopInfo::empty()),
			wfi_count: std::sync::atomic::AtomicU32::new(0),
			wfi_flags: _wfi_flags.into_boxed_slice(),
			active_hart_num: 1,
			tlb_flush_cnt: std::sync::atomic::AtomicU64::new(0),
			tlb_flush_cnt_per_hart: _tlb_flush_cnt.into_boxed_slice(),
			is_flush_cnt_persistent: false,
			lr_reserved: Box::new([]),
			msip_pending: _msip_pending.into_boxed_slice(),
			st_time_val: std::time::Instant::now(),
			time_base_val: 0,
			instr_ref_num: Box::new([]),
		};

		let instr: u32 = 0x3367d783u32; // lhu a5, 0x336(a5)
		let f = crate::instr::decode::decode_fields(instr);

		let adv = handle_load_concurrent(
			&mut state, &f, instr, &ctx, &pmp, &dev, &clint, &uart, &module,
		);
		// 已投递缺页异常并改写 PC, 故 advance 为 0
		assert_eq!(adv, 0, "page fault must return 0 (PC already redirected)");
		// a5 必须保持原值 7, 不得被改写
		assert_eq!(
			state.gprs[15], 7,
			"rd==rs1 on page fault: a5 must stay 7, not be corrupted to 0 or loaded data"
		);
		// PC 必须已改写为 stvec
		assert_ne!(
			state.pc, 0,
			"PC must be redirected to stvec after page fault"
		);
	}

	/// rd 与 rs1 相同的 CSR 指令先读出 CSR 旧值, 再写入 rd.
	/// CSRRW 在 rd 与 rs1 相同时把 CSR 旧值交换进 rd.
	#[test]
	fn csrrw_rd_equals_rs1_swaps_correctly() {
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::M;
		// a5 为写入 CSR 的值. stvec 的 MODE 取 2 及以上为保留编码, 写入被忽略,
		// 故取 MODE 为 0 的合法值
		state.gprs[15] = 0xdeadbee0;
		state.stvec = 0x80001000; // stvec 的旧值

		let mut result = unsafe { std::mem::zeroed() };
		let pmp = PmpCtx {
			cfg: std::ptr::null_mut(),
			addr: std::ptr::null_mut(),
			num: 0,
		};
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: std::ptr::null(),
			mtimecmp: std::ptr::null(),
			msip: std::ptr::null(),
			num_harts: 1,
			msip_pending: std::cell::Cell::new(std::ptr::null()),
			hart_threads: std::cell::Cell::new(std::ptr::null()),
			hart_states: std::cell::Cell::new(std::ptr::null()),
			timebase_hz: 0, // 单元测试中不推进时钟源
		};
		let mut csr_ctx = crate::csr::CsrContext::new(&mut state, 0, &pmp, &clint);
		// CSRRW a5, stvec, a5: funct3 为 001, rd 为 15, rs1 为 15, csr 为 0x105
		let adv =
			crate::csr::handle_csr(&mut csr_ctx, 15, 15, 0x105, 1, 0, &mut result);
		assert_eq!(adv, 4);
		// a5 此时应为 stvec 的旧值 0x80001000, 而不是写入值
		assert_eq!(
			csr_ctx.state.gprs[15], 0x80001000,
			"CSRRW rd==rs1: a5 must swap to old CSR value"
		);
		// stvec 此时应为 a5 的旧值 0xDEADBEE0
		assert_eq!(
			csr_ctx.state.stvec, 0xdeadbee0,
			"CSRRW rd==rs1: CSR must get old a5 value"
		);
	}

	/// rd 与 rs1 相同的 CSRRS: 把 rs1 的位在 CSR 中置位, 并把 CSR 旧值写入 rd.
	#[test]
	fn csrrs_rd_equals_rs1_sets_bits_correctly() {
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::M;
		state.gprs[10] = 0x0000000f; // a0 为要置位的掩码
		state.mie = 0x00000088; // mie 的 MTIE 与 MSIE 位已置位

		let mut result = unsafe { std::mem::zeroed() };
		let pmp = PmpCtx {
			cfg: std::ptr::null_mut(),
			addr: std::ptr::null_mut(),
			num: 0,
		};
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: std::ptr::null(),
			mtimecmp: std::ptr::null(),
			msip: std::ptr::null(),
			num_harts: 1,
			msip_pending: std::cell::Cell::new(std::ptr::null()),
			hart_threads: std::cell::Cell::new(std::ptr::null()),
			hart_states: std::cell::Cell::new(std::ptr::null()),
			timebase_hz: 0, // 单元测试中不推进时钟源
		};
		let mut csr_ctx = crate::csr::CsrContext::new(&mut state, 0, &pmp, &clint);
		// CSRRS a0, mie, a0: funct3 为 010, rd 为 10, rs1 为 10, csr 为 0x304
		let adv =
			crate::csr::handle_csr(&mut csr_ctx, 10, 10, 0x304, 2, 0, &mut result);
		assert_eq!(adv, 4);
		// a0 应为 mie 的旧值 0x88, 而不是掩码
		assert_eq!(
			csr_ctx.state.gprs[10], 0x88,
			"CSRRS rd==rs1: a0 must hold old MIE, not 0x0F"
		);
		// mie 此时应为 0x88 与 0x0F 的按位或, 即 0x8F
		assert_eq!(
			csr_ctx.state.mie, 0x8f,
			"CSRRS rd==rs1: MIE must have 0x0F bits set"
		);
	}

	#[test]
	fn csrrs_time_rdtime_stays_in_acceleration() {
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mode = riscv_mode::S;
		state.mcounteren = 0b111; // 允许 S 模式读取 cycle 的 bit 0、time 的 bit 1 与 instret 的 bit 2
		let mtime_atomic = AtomicU64::new(0x1234_5678_9abc_def0);

		let mut result = unsafe { std::mem::zeroed() };
		let pmp = PmpCtx {
			cfg: std::ptr::null_mut(),
			addr: std::ptr::null_mut(),
			num: 0,
		};
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: &mtime_atomic as *const AtomicU64,
			mtimecmp: std::ptr::null(),
			msip: std::ptr::null(),
			num_harts: 1,
			msip_pending: std::cell::Cell::new(std::ptr::null()),
			hart_threads: std::cell::Cell::new(std::ptr::null()),
			hart_states: std::cell::Cell::new(std::ptr::null()),
			timebase_hz: 0, // 单元测试中不推进时钟源
		};
		let mut csr_ctx = crate::csr::CsrContext::new(&mut state, 0, &pmp, &clint);

		// csrrs a0, time, x0: funct3 为 010, rd 为 10, rs1 为 0, csr 为 0xC01
		let adv = crate::csr::handle_csr(
			&mut csr_ctx,
			10,
			0,
			0xc01,
			2,
			0xc010_2573,
			&mut result,
		);
		assert_eq!(
			adv, 4,
			"rdtime 必须在一轮加速中完成 (advance=4), 修复前返回 EXIT_SENTINEL"
		);
		assert_eq!(
			result.exit_reason, 0,
			"rdtime 不得设置退出原因, 修复前为 ECALL"
		);
		assert_eq!(
			csr_ctx.state.gprs[10], 0x1234_5678_9abc_def0,
			"a0 必须读到 CLINT 实时 mtime"
		);

		// timeh 即 0xC81: 仅 RV32 存在, RV64 上读取触发 IllInstr
		result.exit_reason = 0;
		let adv = crate::csr::handle_csr(
			&mut csr_ctx,
			11,
			0,
			0xc81,
			2,
			0xc810_25f3,
			&mut result,
		);
		assert_eq!(adv, 0, "rdtimeh 在 RV64 上须触发 IllInstr");
		assert_eq!(result.exit_reason, 0, "IllInstr 不应退出加速执行");
		assert_eq!(
			csr_ctx.state.mcause,
			exc_code::ILL_INSTR as u64,
			"rdtimeh 的陷态原因必须为 IllInstr"
		);

		// cycle 即 0xC00: csrrs a2, cycle, x0 同样只读, 写回值被忽略
		result.exit_reason = 0;
		let adv = crate::csr::handle_csr(
			&mut csr_ctx,
			12,
			0,
			0xc00,
			2,
			0xc000_2673,
			&mut result,
		);
		assert_eq!(adv, 4, "rdcycle 必须一轮加速中完成");
		assert_eq!(result.exit_reason, 0, "rdcycle 不得设置退出原因");
	}

	/// 构造最小的 CLINT 上下文, 定时器与核间中断均关闭, 供中断边界用例使用.
	fn clint_ctx_empty() -> ConcurrentClintCtx {
		let _mtime = Box::new(std::sync::atomic::AtomicU64::new(0));
		let _mtimecmp = Box::new(std::sync::atomic::AtomicU64::new(0));
		let _msip = Box::new(std::sync::atomic::AtomicU8::new(0));
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: &*_mtime,
			mtimecmp: &*_mtimecmp,
			msip: &*_msip,
			num_harts: 1,
			msip_pending: Cell::new(std::ptr::null()),
			hart_threads: Cell::new(std::ptr::null()),
			hart_states: Cell::new(std::ptr::null()),
			timebase_hz: 0, // 单元测试中不推进时钟源
		};
		std::mem::forget(_mtime);
		std::mem::forget(_mtimecmp);
		std::mem::forget(_msip);
		clint
	}

	/// 时钟源只按指令条数推进: 1600 条指令每指令 20 纳秒, 在 10 MHz 下推进 320 个
	/// tick, 与流逝的 10 毫秒或 100 毫秒无关, mtime 的推进量不含实时分量.
	/// 若按流逝时间推进, 低速模拟下内核 HZ 为 250 的定时器 tick 处理一旦超长,
	/// mret 之后会立即再次陷入, 受调试程序停滞, 引擎也无法响应 Ctrl+Q.
	#[test]
	fn advance_clock_source_pure_instruction_advance_independent_of_elapsed() {
		let timebase_hz = 10_000_000u64; // 10 MHz: 1 个 tick 为 100 纳秒
		let base_mtime = 1_000_000u64;
		let mtime_atomic = AtomicU64::new(base_mtime);
		let mtimecmp_atomic = AtomicU64::new(0);
		let msip_atomic = AtomicU8::new(0);
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: &mtime_atomic as *const AtomicU64,
			mtimecmp: &mtimecmp_atomic as *const AtomicU64,
			msip: &msip_atomic as *const AtomicU8,
			num_harts: 1,
			msip_pending: std::cell::Cell::new(std::ptr::null()),
			hart_threads: std::cell::Cell::new(std::ptr::null()),
			hart_states: std::cell::Cell::new(std::ptr::null()),
			timebase_hz,
		};

		// 本轮已执行 1600 条指令: instr_ref_num 为 1000, total_instrs 为 2600.
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mhartid = 0;
		state.total_instrs = 2600;
		let mut module = ModuleState::new(
			1,
			1,
			0,
			vec![0u64].into_boxed_slice(),
			false,
			base_mtime,
			vec![1000u64].into_boxed_slice(),
		);

		// 两种流逝时间下推进量必须一致: 1600 条乘每指令 20 纳秒再乘 10 MHz, 得 320 个 tick.
		for elapsed_ms in [10u64, 100u64] {
			module.st_time_val = std::time::Instant::now()
				.checked_sub(std::time::Duration::from_millis(elapsed_ms))
				.expect("Instant 减法不应下溢");
			mtime_atomic.store(base_mtime, Ordering::Relaxed);
			advance_clock_source(&module, &clint, &state);
			let delta = mtime_atomic.load(Ordering::Relaxed) - base_mtime;
			assert_eq!(
				delta, 320,
				"mtime 必须纯按指令增量推进 (1600 条 -> 320 ticks @20ns/instr), \
				 与流逝 ({elapsed_ms}ms) 无关; 实际 {delta}"
			);
		}
	}

	/// 指令增量为 0 的空闲批次不推进 mtime: 流逝 100 毫秒而指令数为 0 时推进量
	/// 必须为 0. 时钟源只取自指令条数, 空闲期间的补偿由 Python 侧完成; 若批次侧
	/// 再按流逝时间推进, 两处补偿叠加会使 mtime 的推进速度约为真实时间的两倍.
	#[test]
	fn advance_clock_source_zero_instr_does_not_advance() {
		let timebase_hz = 10_000_000u64;
		let base_mtime = 1_000_000u64;
		let mtime_atomic = AtomicU64::new(base_mtime);
		let mtimecmp_atomic = AtomicU64::new(0);
		let msip_atomic = AtomicU8::new(0);
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: &mtime_atomic as *const AtomicU64,
			mtimecmp: &mtimecmp_atomic as *const AtomicU64,
			msip: &msip_atomic as *const AtomicU8,
			num_harts: 1,
			msip_pending: std::cell::Cell::new(std::ptr::null()),
			hart_threads: std::cell::Cell::new(std::ptr::null()),
			hart_states: std::cell::Cell::new(std::ptr::null()),
			timebase_hz,
		};

		// 本轮执行 0 条指令: total_instrs 与 instr_ref_num 均为 1000.
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mhartid = 0;
		state.total_instrs = 1000;
		let mut module = ModuleState::new(
			1,
			1,
			0,
			vec![0u64].into_boxed_slice(),
			false,
			base_mtime,
			vec![1000u64].into_boxed_slice(),
		);

		module.st_time_val = std::time::Instant::now()
			.checked_sub(std::time::Duration::from_millis(100))
			.expect("Instant 减法不应下溢");
		mtime_atomic.store(base_mtime, Ordering::Relaxed);
		advance_clock_source(&module, &clint, &state);
		let delta = mtime_atomic.load(Ordering::Relaxed) - base_mtime;
		assert_eq!(
			delta, 0,
			"0 指令的空闲批次不得推进 mtime (时钟源仅指令, WFI 补偿在 Python 侧); \
			 实际 {delta}"
		);
	}

	/// ``advance_clock_source`` 在目标值不超过 mtime 当前值时以普通读取代替取最大
	/// 值. 该跳过条件若偏激进, mtime 会停在旧值上, 时钟源偏慢, 受调试程序的定时器
	/// 与 rdtime 全部推迟. 本用例按指令逐条推进, 断言 mtime 恒等于
	/// 	time_base_val + floor(instr_delta * timebase_hz * NS_PER_INSTR / 1e9),
	/// 覆盖同一 tick 内的重复取值与跨 tick 的取值变化两种情形.
	#[test]
	fn advance_clock_source_matches_per_instruction_fetch_max() {
		let timebase_hz = 10_000_000u64; // 10 MHz: 1 个 tick 为 100 纳秒, 即 5 条指令
		let base_mtime = 1_000_000u64;
		let ref_instrs = 1000u64;
		let mtime_atomic = AtomicU64::new(base_mtime);
		let mtimecmp_atomic = AtomicU64::new(0);
		let msip_atomic = AtomicU8::new(0);
		let clint = ConcurrentClintCtx {
			base: 0,
			mtime: &mtime_atomic as *const AtomicU64,
			mtimecmp: &mtimecmp_atomic as *const AtomicU64,
			msip: &msip_atomic as *const AtomicU8,
			num_harts: 1,
			msip_pending: std::cell::Cell::new(std::ptr::null()),
			hart_threads: std::cell::Cell::new(std::ptr::null()),
			hart_states: std::cell::Cell::new(std::ptr::null()),
			timebase_hz,
		};
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mhartid = 0;
		let module = ModuleState::new(
			1,
			1,
			0,
			vec![0u64].into_boxed_slice(),
			false,
			base_mtime,
			vec![ref_instrs].into_boxed_slice(),
		);

		// 1024 条指令跨 204 个 tick; 起点先位于 tick 内部, 使两种情形都出现.
		for delta in 5u64..1024 {
			state.total_instrs = ref_instrs + delta;
			advance_clock_source(&module, &clint, &state);
			let expected =
				base_mtime + (delta * timebase_hz * NS_PER_INSTR) / 1_000_000_000;
			let actual = mtime_atomic.load(Ordering::Relaxed);
			assert_eq!(
				actual, expected,
				"指令增量 {delta} 处 mtime 必须等于逐条取最大值的取值; \
				 实际 {actual}, 期望 {expected}"
			);
		}
	}

	/// 纯指令计数的 tick 预算为 1e9 除以 NS_PER_INSTR 与 HZ 的乘积, 与 timebase 无关.
	/// HZ 为 250 时各取值对应的预算:
	///   NS_PER_INSTR 为 20: 2e5 条指令每个 tick, 处理函数实测不超过 5e4, 余量 4 倍
	///   NS_PER_INSTR 为 40: 1e5 条指令每个 tick, 余量 2 倍, 为上界
	///   NS_PER_INSTR 为 80: 5e4 条指令每个 tick, 等于处理函数上限, 无余量
	///   NS_PER_INSTR 为 200: 2e4 条指令每个 tick, 实测仍停滞
	///   NS_PER_INSTR 为 500: 8e3 条指令每个 tick, 实测仍停滞
	/// 预算不足时 mret 之后会立即再次陷入, kernel_init 得不到执行.
	#[test]
	fn advance_clock_source_instruction_floor_meets_hz250_tick_budget() {
		const HZ: u64 = 250;
		let budget = 1_000_000_000u64 / (NS_PER_INSTR * HZ);
		assert!(
			budget >= 100_000,
			"HZ=250 tick 指令预算不足: {budget} 条/tick < 100000 \
			 (handler 实测上限 ~5e4, 需 >=2× 余量; NS_PER_INSTR 过大)"
		);
	}

	#[test]
	fn legacy_plic_meip_does_not_force_enable_meie() {
		// 传统 PLIC 模式下 imsic 不存在时, OpenSBI 的 PLIC irqchip 驱动没有
		// process_hwirqs, 只有 AIA IMSIC 驱动有, 故 sbi_irqchip_init 不会置位
		// mie.MEIE, sbi_irqchip_process 恒返回 SBI_ENODEV. 若对瞬时 MEIP 强制
		// 使能 MEIE, M 级外部陷阱会进入 OpenSBI 无法处理的 irqchip, 经
		// sbi_trap_error 与 sbi_hart_hang 使整个 SMP 启动停滞.
		let clint = clint_ctx_empty();
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mhartid = 0;
		state.mode = riscv_mode::S;
		state.mstatus = 1 << 3; // MIE 为 1, M 级中断可抢占 S 模式
		state.mie = 0; // 中断使能位全为 0, 含 MEIE
		state.mip.store(1 << 11, Ordering::Release); // 瞬时 MEIP

		step_interrupts(&mut state, 0, &clint, std::ptr::null_mut());

		assert_eq!(
			state.mie & (1 << 11),
			0,
			"PLIC 模式下不得强制使能 MEIE — 否则 MEIP 陷阱落入 OpenSBI 无法处理的 irqchip (SBI_ENODEV) -> sbi_hart_hang"
		);
		assert_eq!(
			state.mip.load(Ordering::Acquire) & (1 << 11),
			1 << 11,
			"MEIP 保持 pending (由 Python 侧 batch 边界 _native_sync_plic_mip 同步清除)"
		);
	}

	#[test]
	fn aia_imsic_meip_still_force_enables_meie() {
		// AIA 模式下 imsic 存在时该强制使能必须保留: OpenSBI 的 IMSIC 核间中断
		// 路径经 MEIP 投递 IID=1 与 IID=3, 可能不显式置位 mie.MEIE, 缺少该位时
		// WFI 中的 hart 永远不会被核间中断唤醒, SMP 启动停滞.
		let clint = clint_ctx_empty();
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mhartid = 0;
		state.mode = riscv_mode::S;
		state.mstatus = 1 << 3; // MIE 为 1
		state.mie = 0;
		state.mip.store(1 << 11, Ordering::Release); // MEIP (IMSIC IPI)
		state.imsic_m.present = 1;
		// 使 IMSIC 的 M 模式中断文件持有 IPI 位, 使陈旧位清理保留 MEIP.
		// 否则 eidelivery 为 0 且无 IPI 时会清除 MEIP, 后续断言失去意义.
		state.imsic_m.eip[0]
			.store(1 << crate::interrupt::imsic::IID_M_IPI, Ordering::Release);

		step_interrupts(&mut state, 0, &clint, std::ptr::null_mut());

		assert_eq!(
			state.mie & (1 << 11),
			1 << 11,
			"AIA 模式 (IMSIC present) 下仍须强制使能 MEIE"
		);
	}

	/// 构造一个 SEIP 已置位且 IMSIC S 文件持有挂起位的 hart 状态.
	///
	/// S 模式中断文件必须持有 IID_S_IPI 位: 陈旧位清理在 eidelivery 非 0 且
	/// topei 查询为空时会清除 SEIP, 使后续对 SEIE 的断言失去意义.
	fn aia_state_with_seip_asserted(mdid: u64) -> HartState {
		let mut state: HartState = unsafe { std::mem::zeroed() };
		state.mhartid = 0;
		state.mode = riscv_mode::S;
		state.mstatus = 1 << 3; // MIE 为 1, M 级中断可抢占 S 模式
		state.mie = 0; // 未使能任何中断, 含 SEIE
		state.mdid = mdid;
		state.mip.store(1 << 9, Ordering::Release); // SEIP
		state.imsic_s.present = 1;
		state.imsic_s.eidelivery = 1;
		state.imsic_s.eip[0].store(1 << IID_S_IPI, Ordering::Release);
		state
	}

	#[test]
	fn enclave_context_seip_does_not_force_enable_seie() {
		// SEIP 的产生取决于宿主写入的 IMSIC S 模式中断文件的 eidelivery 与 eie,
		// 以及 PLIC 的 S 模式上下文使能位图, 这些状态不随上下文切换恢复, 也没有
		// 任何一处区分当前驻留的 S 模式上下文. 若替 mdid 不为 0 的飞地打开
		// mie.SEIE, 宿主使能的设备中断会以 SEIP 进入飞地, 而飞地的 stvec 没有
		// cause 9 分支, 于是在同一 PC 上反复重入.
		let clint = clint_ctx_empty();
		let mut state = aia_state_with_seip_asserted(7);

		step_interrupts(&mut state, 0, &clint, std::ptr::null_mut());

		assert_eq!(
			state.mie & (1 << 9),
			0,
			"飞地上下文 (mdid != 0) 下不得强制使能 SEIE — SEIP 归宿主所有, \
			 替飞地打开会把宿主的设备中断投进飞地"
		);
	}

	#[test]
	fn host_context_seip_still_force_enables_seie() {
		// 宿主上下文下该强制使能必须保留: 受调试程序的内核可能不打开该位,
		// 不代为打开则已置位的 SEIP 永远不会投递.
		let clint = clint_ctx_empty();
		let mut state = aia_state_with_seip_asserted(HOST_MDID);

		step_interrupts(&mut state, 0, &clint, std::ptr::null_mut());

		assert_eq!(
			state.mie & (1 << 9),
			1 << 9,
			"宿主上下文 (mdid == HOST_MDID) 下仍须强制使能 SEIE"
		);
	}
}
