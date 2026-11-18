//! Sv39 页表遍历与页表项读写.

use super::*;

fn read_pte(ctx: &WalkCtx, pa: u64) -> u64 {
	let off = match ram_offset(ctx, pa, 8) {
		Some(o) => o,
		None => return 0,
	};
	// Sv39 的页表项地址恒为 8 字节对齐: root_ppn << 12 + vpn * 8.
	let ptr = unsafe { ctx.ram.add(off) };
	let a = unsafe { &*(ptr as *const AtomicU64) };
	let raw = a.load(Ordering::Acquire);
	raw
}

/// 以比较并交换的方式写入 64 位页表项原值, 用于置位 A 位与 D 位.
///
/// 新值与读取到的值相同时直接返回真, 不发起写入. 否则使用 `compare_exchange`,
/// 成功时 AcqRel, 失败时为 Acquire, 仅在页表项仍等于 `expected` 时
/// 写入, 写入成功返回真.
///
/// 比较失败说明其他 hart 已并发修改该页表项, 调用方须重新读取并重新校验,
/// 避免用陈旧的 A 位与 D 位覆盖并发的解除映射或重映射.
#[inline]
fn write_pte_cas(ctx: &WalkCtx, pa: u64, expected: u64, new_val: u64) -> bool {
	if new_val == expected {
		return true;
	}
	let off = match ram_offset(ctx, pa, 8) {
		Some(o) => o,
		None => return false,
	};
	let ptr = unsafe { ctx.ram.add(off) };
	let a = unsafe { &*(ptr as *const AtomicU64) };
	a.compare_exchange(expected, new_val, Ordering::AcqRel, Ordering::Acquire)
		.is_ok()
}

//  页表项标志位常量

#[allow(dead_code)]
pub(crate) const PTE_V: u64 = 1 << 0;
pub(crate) const PTE_R: u64 = 1 << 1;
pub(crate) const PTE_W: u64 = 1 << 2;
pub(crate) const PTE_X: u64 = 1 << 3;
pub(crate) const PTE_U: u64 = 1 << 4;
pub(crate) const PTE_A: u64 = 1 << 6;
pub(crate) const PTE_D: u64 = 1 << 7;

const SATP_MODE_SV39: u64 = 8;

//  Sv39 三级页表遍历的辅助函数

/// 读取一个页表项, 读取之前先经 PMP 检查.
///
/// hart 隐式读取页表页, 与显式访存受同一组 PMP 条目约束, 权限一律按读取判定,
/// 特权级与 mstatus 取本次遍历发生时的取值. 被拒绝时返回
/// `TranslateFault::AccessFault`, 由 `translate_va` 的调用方按原访问的类型投递
/// 访问故障: 取指为 1, 读取为 5, 写入为 7, tval 取原访问的虚拟地址.
#[inline]
fn read_pte_checked(
	state: &HartState,
	pmp: &PmpCtx,
	ctx: &WalkCtx,
	addr: u64,
) -> Result<u64, TranslateFault> {
	if !pmp_ok(state, addr, 8, false, false, pmp) {
		return Err(TranslateFault::AccessFault);
	}
	Ok(read_pte(ctx, addr))
}

/// 写入页表项之前先经 PMP 检查.
///
/// 遍历中置位页表项的 A 位与 D 位, 是 hart 在页表遍历期间对页表页发起的物理写入,
/// 与遍历读取页表页受同一组 PMP 条目约束, 权限按写入判定. 被拒绝时返回
/// `TranslateFault::AccessFault`, 由调用方按原访问的类型投递访问故障.
#[inline]
fn write_pte_cas_checked(
	state: &HartState,
	pmp: &PmpCtx,
	ctx: &WalkCtx,
	addr: u64,
	expected: u64,
	new_val: u64,
) -> Result<bool, TranslateFault> {
	if new_val == expected {
		return Ok(true);
	}
	if !pmp_ok(state, addr, 8, true, false, pmp) {
		return Err(TranslateFault::AccessFault);
	}
	Ok(write_pte_cas(ctx, addr, expected, new_val))
}

/// 读取并校验 L2 根页表项, 设置其 A 位.
/// 成功时返回该页表项的原值与解析结果.
/// 判定页表项是否满足 Sv39 对保留位的约束.
///
/// 未实现 Svnapot、Svpbmt 与 Svade, 页表项的位 [63:54] 为保留位, 必须为 0;
/// 非叶页表项的 D、A 与 U 位同为保留位, 必须为 0。任一约束被违反时该页表项
/// 无效, 按缺页处理。W 置位而 R 清零属保留编码, 不在此判定, 由权限检查投递
/// 缺页, 使这样的页表项不会被当作指向下一级页表的指针。
#[inline]
fn is_pte_walkable(raw: u64) -> bool {
	if raw & PTE_V == 0 || (raw >> 54) != 0 {
		return false;
	}
	if (raw & (PTE_R | PTE_W | PTE_X)) == 0 && (raw & (PTE_D | PTE_A | PTE_U)) != 0 {
		return false;
	}
	true
}

fn walk_l2(
	ctx: &WalkCtx,
	state: &HartState,
	pmp: &PmpCtx,
	root_ppn: u64,
	vpn2: u64,
) -> Result<Option<(u64, crate::mem::mmu::PteFields)>, TranslateFault> {
	let addr = (root_ppn << 12).wrapping_add(vpn2 * 8);
	let raw = read_pte_checked(state, pmp, ctx, addr)?;
	if !is_pte_walkable(raw) {
		return Ok(None);
	}
	let pte = pte_parse(raw);
	// 1 GiB 超级页要求 PPN[1:0] 为 0, 否则该页表项无效 (RISC-V 特权规范 §4.3.1).
	if pte.is_leaf != 0 && (pte.ppn & 0x3_ffff) != 0 {
		return Ok(None);
	}
	Ok(Some((raw, pte)))
}

/// 由有效的 L2 指针读取 L1 页表项, 返回原值与解析结果, 无效时返回 None.
/// 以原子方式在 L1 页表项上置位 A 位.
fn walk_l1(
	ctx: &WalkCtx,
	state: &HartState,
	pmp: &PmpCtx,
	l2_ppn: u64,
	vpn1: u64,
) -> Result<Option<(u64, crate::mem::mmu::PteFields)>, TranslateFault> {
	let addr = (l2_ppn << 12).wrapping_add(vpn1 * 8);
	let raw = read_pte_checked(state, pmp, ctx, addr)?;
	if !is_pte_walkable(raw) {
		return Ok(None);
	}
	let pte = pte_parse(raw);
	// 2 MiB 超级页要求 PPN[0] 为 0, 否则该页表项无效 (RISC-V 特权规范 §4.3.1).
	if pte.is_leaf != 0 && (pte.ppn & 0x1ff) != 0 {
		return Ok(None);
	}
	Ok(Some((raw, pte)))
}

/// 处理超级页叶子页表项, 检查权限, 置位 A 位与 D 位, 合成物理地址.
///
/// `level` 为 1 时对应 2 MiB 页, 为 2 时对应 1 GiB 页. 两种情形下物理页号的
/// 低位都取自虚拟地址, 由 `pte_assemble_pa` 完成拼接.
fn walk_superpage_leaf(
	ctx: &WalkCtx,
	state: &HartState,
	pmp: &PmpCtx,
	pte_addr: u64,
	raw: u64,
	pte_ppn: u64,
	perm: u8,
	level: u8,
	va: u64,
	rwx: u8,
) -> Result<Option<TranslateResult>, TranslateFault> {
	// MXR 置位时数据读取可以读取仅可执行的页, 由 check_pte_perm 在遍历之后判定,
	// 此处不要求 R 位.
	let is_mxr = (state.mstatus & (1 << 19)) != 0;
	let need_perm = pte_perm_needed(rwx, is_mxr);
	if perm as u64 & need_perm != need_perm {
		return Ok(None);
	}
	let want_a = raw & PTE_A == 0;
	let want_d = has_write(rwx) && raw & PTE_D == 0;
	let pa = pte_assemble_pa(pte_ppn, va, level);
	if !want_a && !want_d {
		return Ok(Some(TranslateResult { pa, perm, level }));
	}

	let mut new_raw = raw;
	if want_a {
		new_raw |= PTE_A;
	}
	if want_d {
		new_raw |= PTE_D;
	}
	if !write_pte_cas_checked(state, pmp, ctx, pte_addr, raw, new_raw)? {
		// 比较失败说明其他 hart 已并发修改该页表项.
		// 重新读取并重新校验, 避免使用陈旧的映射.
		let raw2 = read_pte_checked(state, pmp, ctx, pte_addr)?;
		let pte2 = pte_parse(raw2);
		if pte2.v == 0
			|| pte2.is_leaf == 0
			|| pte2.perm as u64 & need_perm != need_perm
		{
			return Ok(None);
		}
		let pa2 = pte_assemble_pa(pte2.ppn, va, level);
		return Ok(Some(TranslateResult {
			pa: pa2,
			perm: pte2.perm,
			level,
		}));
	}
	Ok(Some(TranslateResult { pa, perm, level }))
}

/// 由有效的 L1 指针读取 L0 叶子页表项, 返回 4 KiB 页的翻译结果, 无效时返回 None.
/// 在叶子页表项上置位 A 位, 写入访问时同时置位 D 位.
fn walk_l0(
	ctx: &WalkCtx,
	state: &HartState,
	pmp: &PmpCtx,
	l1_ppn: u64,
	vpn0: u64,
	offset: u64,
	rwx: u8,
) -> Result<Option<TranslateResult>, TranslateFault> {
	let addr = (l1_ppn << 12).wrapping_add(vpn0 * 8);
	let raw = read_pte_checked(state, pmp, ctx, addr)?;
	let pte = pte_parse(raw);
	if !is_pte_walkable(raw) || pte.is_leaf == 0 {
		return Ok(None);
	}
	// MXR 置位时数据读取可以读取仅可执行的页, 由 check_pte_perm 在遍历之后判定,
	// 此处不要求 R 位.
	let is_mxr = (state.mstatus & (1 << 19)) != 0;
	let need_perm = pte_perm_needed(rwx, is_mxr);
	if pte.perm as u64 & need_perm != need_perm {
		return Ok(None);
	}
	let want_a = raw & PTE_A == 0;
	let want_d = has_write(rwx) && raw & PTE_D == 0;
	if want_a || want_d {
		let mut new_raw = raw;
		if want_a {
			new_raw |= PTE_A;
		}
		if want_d {
			new_raw |= PTE_D;
		}
		if !write_pte_cas_checked(state, pmp, ctx, addr, raw, new_raw)? {
			let raw2 = read_pte_checked(state, pmp, ctx, addr)?;
			let pte2 = pte_parse(raw2);
			if pte2.v == 0 || pte2.is_leaf == 0 {
				return Ok(None);
			}
			if pte2.perm as u64 & need_perm != need_perm {
				return Ok(None);
			}
			let pa = (pte2.ppn << 12) | offset;
			return Ok(Some(TranslateResult {
				pa: pa & 0xFFFF_FFFF_FFFF_FFFF,
				perm: pte2.perm,
				level: 0,
			}));
		}
	}

	let pa = (pte.ppn << 12) | offset;
	Ok(Some(TranslateResult {
		pa: pa & 0xFFFF_FFFF_FFFF_FFFF,
		perm: pte.perm,
		level: 0,
	}))
}

//  Sv39 页表遍历的入口

/// 完成一次 Sv39 页表遍历, 并置位硬件维护的 A 位与 D 位.
///
/// 命中 4 KiB 页、2 MiB 超级页或 1 GiB 超级页时返回 `Ok(Some(TranslateResult))`;
/// 遇到无效或不存在的页表项时返回 `Ok(None)`; 读取页表项或置位 A 位、D 位的
/// 写入被 PMP 拒绝时返回 `Err(TranslateFault::AccessFault)`.
pub fn sv39_walk(
	ctx: &WalkCtx,
	state: &HartState,
	pmp: &PmpCtx,
	satp: u64,
	va: u64,
	rwx: u8,
) -> Result<Option<TranslateResult>, TranslateFault> {
	let mode = satp >> 60;
	if mode != SATP_MODE_SV39 {
		return Ok(None);
	}
	let root_ppn = satp & 0xF_FFFF_FFFF;
	let vpn = sv39_decompose_va(va);

	let (l2_raw, l2_pte) = match walk_l2(ctx, state, pmp, root_ppn, vpn.vpn2)? {
		Some(v) => v,
		None => return Ok(None),
	};

	// 根页表的叶子页表项对应 1 GiB 超级页
	if l2_pte.is_leaf != 0 {
		let l2_addr = (root_ppn << 12).wrapping_add(vpn.vpn2 * 8);
		return walk_superpage_leaf(
			ctx,
			state,
			pmp,
			l2_addr,
			l2_raw,
			l2_pte.ppn,
			l2_pte.perm,
			2,
			va,
			rwx,
		);
	}

	if l2_pte.is_ptr == 0 {
		return Ok(None);
	}

	let (l1_raw, l1_pte) = match walk_l1(ctx, state, pmp, l2_pte.ppn, vpn.vpn1)? {
		Some(v) => v,
		None => return Ok(None),
	};

	if l1_pte.is_leaf != 0 {
		let l1_addr = (l2_pte.ppn << 12).wrapping_add(vpn.vpn1 * 8);
		return walk_superpage_leaf(
			ctx,
			state,
			pmp,
			l1_addr,
			l1_raw,
			l1_pte.ppn,
			l1_pte.perm,
			1,
			va,
			rwx,
		);
	}

	walk_l0(ctx, state, pmp, l1_pte.ppn, vpn.vpn0, vpn.offset, rwx)
}

//  TLB 操作

// 条目总数由 mk/processor.mk 的 TLB_ENTRIES 给出, 经 makefile 生成 configs_gen.rs,
// 与 Python 侧 configs_gen.py 取自同一处配置, 两侧容量因此始终一致.
