//! 加速执行引擎的 Sv39 页表遍历与 TLB 管理.
//!
//! 本模块直接在 RAM 上完成 Sv39 页表遍历, 并管理 ``HartState`` 中的
//! ``TlbEntry`` 数组. 遍历读取页表项时置位 A 位, 访问为写入时在叶子页表项
//! 上置位 D 位, 与 RISC-V 特权级规范 §4.3.2 一致.
//!
//! # SUM 与 MXR
//!
//! - SUM: mstatus 的 bit 18, 为 1 时 S 模式可以访问 U=1 的页, 否则时
//!   S 模式访问用户页产生故障.
//! - MXR: mstatus 的 bit 19, 为 1 时 X=1 且 R=0 的页可以被读取, 不影响
//!   写入与取指.

use crate::mem::access;
use crate::mem::mmu::{pte_assemble_pa, pte_parse, sv39_decompose_va};
use crate::mem::pmp::{pmp_ok, PmpCtx};
use crate::state::{riscv_mode, HartState, TlbEntry, CFG_NO_TLB, TLB_ENTRIES};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

//  页表遍历的上下文

/// 地址翻译与 LR/SC 共用的上下文.
mod ram;
mod sv39;
mod tlb;

#[cfg(test)]
pub(crate) use self::sv39::{PTE_A, PTE_D, PTE_V};
pub(crate) use self::sv39::{PTE_R, PTE_U, PTE_W, PTE_X};

pub(crate) use self::ram::{
	lr_check, lr_clear_all, lr_set, ram_offset, ram_read, ram_write,
};
pub use self::sv39::sv39_walk;
pub use self::tlb::{
	tlb_flush_all, tlb_flush_vpn, tlb_insert, tlb_lookup, tlb_mark_all_dirty,
	TlbResult,
};

#[cfg(test)]
mod tests;

pub struct WalkCtx {
	pub ram: *mut u8,
	pub ram_size: u64,
	pub ram_base: u64,
	pub shadow_base: u64,
	pub shadow_size: u64,
	/// 已发生的 TLB 刷新次数. 各 hart 在取下一条指令之前比较该计数与自己上次
	/// 见到的取值, 不相等即把自己的条目全部标为陈旧. 条目不被丢弃, 下一次访问
	/// 重走页表, 仍然有效的翻译得以保留.
	pub tlb_flush_cnt: *const AtomicU64,
	/// 为每个 hart 的 LR 记录状态所用的空间, 以 hart 编号为索引.
	/// LR 把 `lr_reserved[hid]` 置为 `pa`, 任意写入清除全部槽位.
	/// 该数组在 ``ModuleState`` 中分配, 指针经 FFI 传入.
	pub lr_reserved: *mut AtomicU64,
	pub num_harts: u32,
}

/// 地址翻译的结果.
#[derive(Debug)]
pub struct TranslateResult {
	pub pa: u64,
	pub perm: u8,
	pub level: u8,
}

/// 地址翻译失败时产生的陷态编码.
#[derive(Debug, PartialEq)]
pub enum TranslateFault {
	PageFault(u64), // 原因编码: 取指 12, 读取 13, 写入 15
	AccessFault,
}

//  访问类别

/// 访问类别的位: 读权限、写权限、执行权限.
///
/// 一次访问由这三位的组合给出, 即 `translate_va` 的 `rwx` 参数. 三种访问由
/// 三个构造函数给出, 判定取 `has_read`、`has_write` 与 `has_exec`.
pub const RWX_READ: u8 = 0b001;
pub const RWX_WRITE: u8 = 0b010;
pub const RWX_EXEC: u8 = 0b100;

/// 数据读取访问.
#[inline]
pub fn rwx_read() -> u8 {
	RWX_READ
}

/// 数据写入访问. 写访问同时要求页面的读权限, 故取值为读位与写位.
#[inline]
pub fn rwx_write() -> u8 {
	RWX_READ | RWX_WRITE
}

/// 取指访问.
#[inline]
pub fn rwx_exec() -> u8 {
	RWX_EXEC
}

/// 本次访问是否请求读权限.
#[inline]
pub fn has_read(rwx: u8) -> bool {
	rwx & RWX_READ != 0
}

/// 本次访问是否请求写权限.
#[inline]
pub fn has_write(rwx: u8) -> bool {
	rwx & RWX_WRITE != 0
}

/// 本次访问是否请求执行权限.
#[inline]
pub fn has_exec(rwx: u8) -> bool {
	rwx & RWX_EXEC != 0
}

/// 本次访问要求页表项具备的权限位.
///
/// 取指不要求 R 位: RISC-V 允许 R=0 且 W=0 且 X=1 的页被取指, X 位的判定由
/// `translate_va` 的 `check_pte_perm` 在遍历之后完成. 数据读取在 `mstatus.MXR`
/// 置位时同样不要求 R 位, 此时仅可执行的页可以被读取, R 位与 X 位同样在遍历
/// 之后判定. 其余情形数据读取要求 R 位. 数据写入要求 R 位与 W 位, 与 MXR 无关.
#[inline]
fn pte_perm_needed(rwx: u8, is_mxr: bool) -> u64 {
	let mut need = 0u64;
	if has_read(rwx) && !has_exec(rwx) && !is_mxr {
		need |= PTE_R;
	}
	if has_write(rwx) {
		need |= PTE_R | PTE_W;
	}
	need
}

/// 记录一次 TLB 查询结果. 权限检查未通过的命中同样计为命中, 此时 TLB 已给出地址翻译结果.
#[inline]
fn record_tlb_access(state: &mut HartState, is_execute: bool, is_hit: bool) {
	let counter = match (is_execute, is_hit) {
		(true, true) => &mut state.itlb_hits,
		(true, false) => &mut state.itlb_misses,
		(false, true) => &mut state.dtlb_hits,
		(false, false) => &mut state.dtlb_misses,
	};
	*counter = counter.wrapping_add(1);
}

/// 查询 TLB 并记录本次翻译结果, 供 translate_va 在未命中时继续页表遍历.
///
/// CFG_NO_TLB 为真时不做查询也不记录, 一律按未命中处理.
#[inline]
fn tlb_probe_counted(
	state: &mut HartState,
	ctx: &WalkCtx,
	va: u64,
	vpn: u64,
	asid: u16,
	eff_mode: u8,
	is_write: bool,
	is_execute: bool,
) -> TlbProbeResult {
	if CFG_NO_TLB {
		// CFG_NO_TLB 为真时 TLB 查询与插入一并跳过, 每次地址翻译都完整遍历
		// Sv39 页表, 用于隔离地址翻译相关的性能问题. 该常量由 mk/emu-feats.mk
		// 经 Makefile 生成到 configs_gen.rs, 与 Python 侧读取的 PYREMU_NO_TLB
		// 取同一值.
		return TlbProbeResult::Walk(None);
	}
	let tlb = if is_execute {
		&mut state.itlb
	} else {
		&mut state.dtlb
	};
	let probe = tlb_probe(
		tlb,
		vpn,
		va,
		asid,
		if ctx.tlb_flush_cnt.is_null() {
			None
		} else {
			Some(unsafe { &*ctx.tlb_flush_cnt })
		},
		eff_mode,
		state.mstatus,
		is_write,
		is_execute,
	);
	let is_hit = !matches!(probe, TlbProbeResult::Walk(_));
	record_tlb_access(state, is_execute, is_hit);
	probe
}

//  LR/SC 辅助函数

/// 设置本 hart 的 LR. `pa` 为 0 表示没有预留.
#[inline]

fn effective_mode(state: &HartState) -> Option<u8> {
	// D 模式与 M 模式一样无需使用 MMU.
	if state.mode == riscv_mode::D {
		return None;
	}
	if state.mode != riscv_mode::M {
		return Some(state.mode);
	}
	let mprv = (state.mstatus >> 17) & 1;
	let mpp = (state.mstatus >> 11) & 3;
	if mprv == 0 || mpp == riscv_mode::M as u64 {
		return None; // Bare 模式, 无需翻译
	}
	Some(mpp as u8)
}

/// 结合 SUM、MXR 与 U 位检查页表项的权限.
///
/// 访问被允许时返回 `true`.
fn check_pte_perm(
	perm: u8,
	eff_mode: u8,
	mstatus: u64,
	is_write: bool,
	is_execute: bool,
) -> bool {
	let perm = perm as u64;
	let pte_u = (perm & PTE_U) != 0;
	let pte_r = (perm & PTE_R) != 0;
	let pte_w = (perm & PTE_W) != 0;
	let pte_x = (perm & PTE_X) != 0;

	// U 位检查
	if eff_mode == riscv_mode::U {
		if !pte_u {
			return false;
		}
	} else if eff_mode == riscv_mode::S {
		// SUM=1 允许 S 模式数据访问 U=1 的页, 但取指永不放行: RISC-V §4.3.2
		// 规定 S 模式不能从 U 页取指, 与 SUM 无关.
		// 早期实现遗漏 is_execute 分支, 使 SUM 放行了 S 模式对 U 页的取指,
		// 与 Python mem_check_aux._check_pte_perm 分歧.
		if pte_u && (is_execute || (mstatus & (1 << 18)) == 0) {
			return false;
		}
	}

	if is_execute {
		return pte_x;
	}
	if is_write {
		return pte_r && pte_w;
	}
	// MXR=1 时 X=1 且 R=0 的页可以被读取
	if !pte_r {
		if (mstatus & (1 << 19)) != 0 && pte_x {
			return true;
		}
		return false;
	}
	true
}

/// 由 TLB 条目与虚拟地址合成物理地址.
#[inline]
fn reconstruct_tlb_pa(entry: &TlbEntry, va: u64) -> u64 {
	let offset = va & 0xFFF;
	let pa = match entry.level {
		// 1 GiB 超级页: PPN[17:0] 取自虚拟地址的 vpn1 与 vpn0
		2 => {
			let ppn = (entry.ppn & 0xFFFF_FFFF_FFFC_0000) | ((va >> 12) & 0x3_FFFF);
			(ppn << 12) | offset
		}
		// 2 MiB 超级页: PPN[8:0] 取自虚拟地址的 vpn0
		1 => {
			let ppn = (entry.ppn & 0xFFFF_FFFF_FFFF_FE00) | ((va >> 12) & 0x1FF);
			(ppn << 12) | offset
		}
		_ => (entry.ppn << 12) | offset,
	};
	pa & 0xFFFF_FFFF_FFFF_FFFF
}

/// 返回本次访问对应的缺页原因编码.
#[inline]
fn fault_code(is_execute: bool, is_write: bool) -> u64 {
	if is_execute {
		12
	} else if is_write {
		15
	} else {
		13
	}
}

//  带 SFENCE.VMA 保护的 TLB 查询

/// TLB 查询结果.
enum TlbProbeResult {
	/// 命中, 直接返回该翻译.
	Hit(TranslateResult),
	/// 命中, 但权限检查未通过, 返回该故障.
	Fault(TranslateFault),
	/// 转页表遍历, 命中但已陈旧的条目所占用槽位可以复用.
	Walk(Option<usize>),
}

/// 查询 `vpn` 对应的条目. `tlb_flush_cnt` 非空时, 在命中之后再次读取该计数:
/// 两次取值不相等说明查询期间有别的 hart 改写了页表, 该条目作废并转页表遍历.
/// 为空时按普通查询处理, 用于单 hart 路径.
#[inline]
fn tlb_probe(
	tlb: &mut [TlbEntry],
	vpn: u64,
	va: u64,
	asid: u16,
	tlb_flush_cnt: Option<&AtomicU64>,
	eff_mode: u8,
	mstatus: u64,
	is_write: bool,
	is_execute: bool,
) -> TlbProbeResult {
	let flush_cnt_before = tlb_flush_cnt.map(|g| g.load(Ordering::Acquire));
	match tlb_lookup(tlb, vpn, asid) {
		TlbResult::Hit(idx) => {
			if let Some(g) = tlb_flush_cnt {
				if flush_cnt_before != Some(g.load(Ordering::Acquire)) {
					tlb[idx].valid = 0; // 需使之失效并重新遍历
					return TlbProbeResult::Walk(None);
				}
			}
			let e = &tlb[idx];
			if !check_pte_perm(e.perm, eff_mode, mstatus, is_write, is_execute) {
				return TlbProbeResult::Fault(TranslateFault::PageFault(
					fault_code(is_execute, is_write),
				));
			}
			let pa = reconstruct_tlb_pa(e, va);
			TlbProbeResult::Hit(TranslateResult {
				pa,
				perm: e.perm,
				level: e.level,
			})
		}
		TlbResult::DirtyReuse(idx) => TlbProbeResult::Walk(Some(idx)),
		TlbResult::Miss => TlbProbeResult::Walk(None),
	}
}

//  地址翻译的主入口

/// 把虚拟地址翻译为物理地址.
///
/// `rwx` 给出本次访问请求的读权限、写权限与执行权限的位组合, 取值由 `rwx_read`、
/// `rwx_write` 与 `rwx_exec` 给出. 成功时返回 `Ok(TranslateResult)`, 含物理地址、
/// 权限与页的级别; 失败时返回 `Err(TranslateFault)`. 遍历中读取页表页与置位 A 位、
/// D 位的写入都先经 PMP 检查, 被拒绝时返回 `TranslateFault::AccessFault`.
pub fn translate_va(
	state: &mut HartState,
	ctx: &WalkCtx,
	va: u64,
	rwx: u8,
	pmp: &PmpCtx,
) -> Result<TranslateResult, TranslateFault> {
	let is_write = has_write(rwx);
	let is_execute = has_exec(rwx);

	// ---- Bare 模式与 M 模式绕过 MMU ----
	if state.mmu_mode != 8 {
		return Ok(TranslateResult {
			pa: va & 0xFFFF_FFFF_FFFF_FFFF,
			perm: 0xF,
			level: 0,
		});
	}

	let eff_mode = match effective_mode(state) {
		Some(m) => m,
		None => {
			return Ok(TranslateResult {
				pa: va & 0xFFFF_FFFF_FFFF_FFFF,
				perm: 0xF,
				level: 0,
			});
		}
	};

	let vpn = va >> 12;

	// ---- TLB 查询 ----
	let asid = ((state.satp >> 44) & 0xFFFF) as u16;

	// 查询之前先记下刷新计数. 遍历期间别的 hart 若改写了页表, 本次取得的页表项
	// 已经失效, 该次翻译不写入 TLB, 由写入之前的那次比较判定.
	let flush_cnt_before = if ctx.tlb_flush_cnt.is_null() {
		None
	} else {
		Some(unsafe { &*ctx.tlb_flush_cnt }.load(Ordering::Acquire))
	};

	let reuse_idx = match tlb_probe_counted(
		state, ctx, va, vpn, asid, eff_mode, is_write, is_execute,
	) {
		TlbProbeResult::Hit(result) => return Ok(result),
		TlbProbeResult::Fault(fault) => return Err(fault),
		TlbProbeResult::Walk(reuse) => reuse,
	};

	// ---- 页表遍历 ----
	let result = match sv39_walk(ctx, state, pmp, state.satp, va, rwx)? {
		Some(r) => r,
		None => {
			return Err(TranslateFault::PageFault(fault_code(is_execute, is_write)))
		}
	};

	if !check_pte_perm(result.perm, eff_mode, state.mstatus, is_write, is_execute) {
		return Err(TranslateFault::PageFault(fault_code(is_execute, is_write)));
	}

	// ---- 遍历完成之后, 写入 TLB 之前, 再次比较刷新计数 ----
	// 两次取值不相等说明遍历期间页表被改写, 刚取得的页表项可能已失效. 此时不写入
	// TLB: 陈旧条目不进入缓存, 下一次查询按当前的页表项重新遍历.
	let is_flush_cnt_unchanged = match flush_cnt_before {
		None => true,
		Some(gb) => {
			let ga = unsafe { &*ctx.tlb_flush_cnt }.load(Ordering::Acquire);
			gb == ga
		}
	};

	// ---- 刷新计数未变且 TLB 已启用时写入 TLB ----
	if is_flush_cnt_unchanged && !CFG_NO_TLB {
		let tlb_mut = if is_execute {
			&mut state.itlb
		} else {
			&mut state.dtlb
		};
		tlb_insert(
			tlb_mut,
			reuse_idx,
			vpn,
			result.ppn_for_tlb(vpn),
			result.perm,
			result.level,
			state.mdid,
			asid,
		);
	}

	Ok(result)
}

impl TranslateResult {
	/// 合成写入 TLB 的页号.
	///
	/// 超级页条目抹去取自虚拟地址的低位, 由 `reconstruct_tlb_pa` 在命中时补回.
	fn ppn_for_tlb(&self, _vpn: u64) -> u64 {
		match self.level {
			2 => (self.pa >> 12) & 0xFFFF_FFFF_FFFC_0000,
			1 => (self.pa >> 12) & 0xFFFF_FFFF_FFFF_FE00,
			_ => self.pa >> 12,
		}
	}
}

//  测试
