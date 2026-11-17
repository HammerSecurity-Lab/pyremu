//! 并发执行路径的取指: 主存取指、跨页取指与地址翻译.

use std::sync::atomic::{self, Ordering};

use crate::ffi::MemCtx;
use crate::instr::exec::ram_read_raw;
use crate::instr::handlers::{pmp_ok, PmpCtx};
use crate::instr::Step;
use crate::mem::access::ram_offset;
use crate::mem::translate::{rwx_exec, translate_va, TranslateFault, WalkCtx};
use crate::shared::{ModuleState, StopInfo};
use crate::state::{exit_reason, riscv_mode, HartState};
use crate::trap::{deliver_trap, exc_code, mcause_val};

pub(crate) fn fetch_instr(
	ram: *const u8,
	ram_size: u64,
	ram_base: u64,
	pa: u64,
) -> Option<u32> {
	let offset = pa.wrapping_sub(ram_base);
	if offset > ram_size.saturating_sub(4) {
		return None;
	}
	let ptr = unsafe { ram.add(offset as usize) };
	// Acquire 屏障与 ram_write_raw 中的 Release 配对, 使本 hart 能读到其余 hart
	// 写入的指令字节, 例如写入随后被改为可执行的页面.
	atomic::fence(Ordering::Acquire);
	let b0 = (unsafe { *ptr }) as u32;
	let b1 = (unsafe { *ptr.add(1) }) as u32;
	let b2 = (unsafe { *ptr.add(2) }) as u32;
	let b3 = (unsafe { *ptr.add(3) }) as u32;
	Some(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}

pub(crate) fn check_bp_hit(
	pc: u64,
	breakpoints: &[u64],
	fetch_pa: Option<u64>,
) -> bool {
	if breakpoints.is_empty() {
		return false;
	}
	// 直接比较虚拟地址, 覆盖设在虚拟地址上的断点.
	if breakpoints.iter().any(|&bp| bp == pc) {
		return true;
	}
	// 再比较物理地址, 覆盖设在物理地址上的断点: 启用 MMU 地址翻译时 PC 是虚拟地址,
	// 断点值可能是物理地址. 判定与 Python 侧 ``_bp_match_pc`` 一致.
	if let Some(pa) = fetch_pa {
		if pa != pc {
			return breakpoints.iter().any(|&bp| bp == pa);
		}
	}
	false
}

pub(crate) fn translate_fetch_pc_concurrent(
	state: &mut HartState,
	ctx: &WalkCtx,
	pc: u64,
	pmp: &PmpCtx,
) -> Option<u64> {
	if state.mmu_mode == 0
		|| state.mode == riscv_mode::M
		|| state.mode == riscv_mode::D
	{
		// Bare 模式、M 模式与 D 模式: 虚拟地址即物理地址.
		return Some(pc);
	}
	match translate_va(state, ctx, pc, rwx_exec(), pmp) {
		Ok(t) => Some(t.pa),
		Err(TranslateFault::PageFault(c)) => {
			deliver_trap(state, mcause_val(c, false), pc);
			None
		}
		Err(TranslateFault::AccessFault) => {
			deliver_trap(state, mcause_val(exc_code::INSTR_ACCESS_FAULT, false), pc);
			None
		}
	}
}

/// ``fetch_instr_word`` 的结果.
pub(crate) enum FetchWord {
	/// 取到的 32 位指令字.
	Word(u32),
	/// 取指的目标物理地址不属于主存.
	NotMainRam,
	/// 已投递陷态.
	Fault,
}

/// 请求退出本轮: 取指的目标物理地址不属于主存.
pub(crate) fn request_not_mainram_exit(
	module: &ModuleState,
	hart_id: u8,
	pc: u64,
) -> Step {
	module.request_stop(StopInfo {
		reason: exit_reason::NOT_MAINRAM,
		hart_id,
		pc,
		..StopInfo::empty()
	});
	Step::Exit
}

/// 从物理内存取一个 32 位指令字.
///
/// PC 位于 4 KiB 页的最后 2 字节内, 即 ``page_offset >= 0xFFE`` 时, 4 字节取指
/// 跨入下一个虚拟页. 两个虚拟页可能映射到不相邻的物理页, 故第二页单独翻译后
/// 各取 2 字节拼接.
#[inline]
pub(crate) fn fetch_instr_word(
	state: &mut HartState,
	ctx: &WalkCtx,
	mem: &MemCtx,
	pc_before: u64,
	page_offset: u64,
	fetch_pa: u64,
	pmp: &PmpCtx,
) -> FetchWord {
	if page_offset < 0xffe {
		return match fetch_instr(mem.ram, mem.ram_size, mem.ram_base, fetch_pa) {
			Some(w) => FetchWord::Word(w),
			None => FetchWord::NotMainRam,
		};
	}
	// 取当前页末尾的 2 个字节与下一内存页开头的 2 个字节.
	let fetch_pa2 = match translate_fetch_pc_concurrent(
		state,
		ctx,
		pc_before.wrapping_add(2),
		pmp,
	) {
		Some(pa) => pa,
		None => {
			return FetchWord::Fault;
		}
	};
	// 第二页同样做 PMP 判定, 长度取实际读取的 2 字节: 取 4 字节会把判定范围
	// 伸进第三个页, 在 PMP 区间恰于页边界结束时误报访问故障.
	if !pmp_ok(state, fetch_pa2, 2, false, true, pmp) {
		deliver_trap(
			state,
			mcause_val(exc_code::INSTR_ACCESS_FAULT, false),
			pc_before,
		);
		return FetchWord::Fault;
	}
	// 两页都必须位于主存: ram_read_raw 在内存范围外返回 0, 故先判定再读取.
	if ram_offset(
		fetch_pa,
		2,
		mem.ram_base,
		mem.ram_size,
		mem.shadow_base,
		mem.shadow_size,
	)
	.is_none()
		|| ram_offset(
			fetch_pa2,
			2,
			mem.ram_base,
			mem.ram_size,
			mem.shadow_base,
			mem.shadow_size,
		)
		.is_none()
	{
		return FetchWord::NotMainRam;
	}
	// 从两个物理页各读 2 字节, 按小端拼接.
	let lo = ram_read_raw(ctx, fetch_pa, 2) as u32;
	let hi = ram_read_raw(ctx, fetch_pa2, 2) as u32;
	FetchWord::Word(lo | (hi << 16))
}
