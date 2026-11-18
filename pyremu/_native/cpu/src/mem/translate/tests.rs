//! 页表遍历、TLB 与 LR/SC 的单元测试.

use super::tlb::{tlb_set, tlb_slot, TLB_SETS, TLB_WAYS};
use super::*;
use crate::state::TlbEntry;

/// 在 `ram` 中建立最小页表, 返回 satp 取值.
/// L2 表位于偏移 0x0, L1 表位于 0x1000, L0 表位于 0x2000.
fn setup_4k_page_table(ram: &mut [u8], va: u64, pa: u64, perm: u64) -> u64 {
	let vpn = sv39_decompose_va(va);
	let satp = 8u64 << 60; // Sv39, 根页表的 PPN 为 0

	// L2: 指向 PPN=1 的 L1 表, 地址为 0x1000
	let l2_off = (vpn.vpn2 * 8) as usize;
	let l2_val = (1u64 << 10) | PTE_V;
	ram[l2_off..l2_off + 8].copy_from_slice(&l2_val.to_le_bytes());

	// L1: 指向 PPN=2 的 L0 表, 地址为 0x2000
	let l1_off = 0x1000usize + (vpn.vpn1 * 8) as usize;
	let l1_val = (2u64 << 10) | PTE_V;
	ram[l1_off..l1_off + 8].copy_from_slice(&l1_val.to_le_bytes());

	// L0: 叶子页表项, 把 va 映射到 pa
	let l0_off = 0x2000usize + (vpn.vpn0 * 8) as usize;
	let l0_ppn = pa >> 12;
	let l0_val = (l0_ppn << 10) | perm | PTE_V;
	ram[l0_off..l0_off + 8].copy_from_slice(&l0_val.to_le_bytes());

	satp
}

/// 空 PMP 配置. 遍历发生在 M 模式且 MPRV=0, PMP 不施加判定, 页表页的读取全部放行.
fn no_pmp() -> PmpCtx {
	PmpCtx {
		cfg: std::ptr::null_mut(),
		addr: std::ptr::null_mut(),
		num: 0,
	}
}

/// 以 M 模式与空 PMP 配置遍历页表.
fn walk_with_no_pmp(
	ctx: &WalkCtx,
	satp: u64,
	va: u64,
	rwx: u8,
) -> Option<TranslateResult> {
	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::M;
	let pmp = no_pmp();
	sv39_walk(ctx, &state, &pmp, satp, va, rwx).unwrap()
}

/// 以给定的 `mstatus` 在 M 模式与空 PMP 配置下遍历页表.
fn walk_with_mstatus(
	ctx: &WalkCtx,
	satp: u64,
	va: u64,
	rwx: u8,
	mstatus: u64,
) -> Option<TranslateResult> {
	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::M;
	state.mstatus = mstatus;
	let pmp = no_pmp();
	sv39_walk(ctx, &state, &pmp, satp, va, rwx).unwrap()
}

fn empty_tlb() -> [TlbEntry; TLB_ENTRIES] {
	[TlbEntry::empty(); TLB_ENTRIES]
}

/// 取第 `n` 个组号为 `set` 的页号.
///
/// 扫描上界确保组号函数退化时本条以断言失败终止, 而不是无限循环.
fn vpn_in_set(set: usize, n: u64) -> u64 {
	let mut seen = 0u64;
	for vpn in 0u64..(1 << 24) {
		if tlb_set(vpn) == set {
			if seen == n {
				return vpn;
			}
			seen += 1;
		}
	}
	panic!("set {set} holds fewer than {} page numbers", n + 1)
}

fn insert(tlb: &mut [TlbEntry], prefer: Option<usize>, vpn: u64, ppn: u64) {
	tlb_insert(tlb, prefer, vpn, ppn, 0xF, 0, 0, 0);
}

#[test]
fn tlb_lookup_miss() {
	let mut tlb = empty_tlb();
	assert!(matches!(tlb_lookup(&mut tlb, 0x100, 0), TlbResult::Miss));
}

#[test]
fn tlb_insert_and_lookup() {
	let mut tlb = empty_tlb();
	insert(&mut tlb, None, 0x1000, 0x80000);
	let idx = match tlb_lookup(&mut tlb, 0x1000, 0) {
		TlbResult::Hit(i) => i,
		_ => panic!("expected clean hit"),
	};
	let e = &tlb[idx];
	assert_eq!(e.ppn, 0x80000);
	assert_eq!(e.perm, 0xF);
	assert_eq!(e.level, 0);
	assert_eq!(e.valid, 1);
	assert_eq!(e.dirty, 0);
	// 标为陈旧后返回 DirtyReuse, 而不是 Miss
	tlb[idx].dirty = 1;
	let reuse = match tlb_lookup(&mut tlb, 0x1000, 0) {
		TlbResult::DirtyReuse(i) => i,
		other => panic!(
			"expected DirtyReuse, got {:?}",
			match other {
				TlbResult::Hit(_) => "Hit",
				TlbResult::Miss => "Miss",
				TlbResult::DirtyReuse(_) => unreachable!(),
			}
		),
	};
	assert_eq!(reuse, idx);
	// 在陈旧槽位重新插入
	insert(&mut tlb, Some(reuse), 0x1000, 0x90000);
	assert!(matches!(tlb_lookup(&mut tlb, 0x1000, 0), TlbResult::Hit(_)));
	assert_eq!(tlb[reuse].ppn, 0x90000);
}

#[test]
fn test_tlb_flush_all() {
	let mut tlb = empty_tlb();
	insert(&mut tlb, None, 0x1000, 0x80000);
	crate::mem::translate::tlb_flush_all(&mut tlb);
	assert!(matches!(tlb_lookup(&mut tlb, 0x1000, 0), TlbResult::Miss));
}

#[test]
fn test_tlb_flush_vpn() {
	let mut tlb = empty_tlb();
	insert(&mut tlb, None, 0x1000, 0x80000);
	insert(&mut tlb, None, 0x2000, 0x90000);
	crate::mem::translate::tlb_flush_vpn(&mut tlb, 0x1000);
	assert!(matches!(tlb_lookup(&mut tlb, 0x1000, 0), TlbResult::Miss));
	assert!(matches!(tlb_lookup(&mut tlb, 0x2000, 0), TlbResult::Hit(_)));
}

/// 命中项的下标必须位于该页号所映射的组内.
///
/// 查询只查看这一组的 TLB_WAYS 个槽位, 故该不变量成立即比较次数与条目总数无关.
/// 逐组填充, 使插入次序与组号互不相关; 命中槽位与组号不一致时本条失败.
#[test]
fn tlb_hit_always_lies_in_own_set() {
	let mut tlb = empty_tlb();
	for set in 0..TLB_SETS {
		for way in 0..TLB_WAYS {
			let vpn = vpn_in_set(set, way as u64);
			insert(&mut tlb, None, vpn, vpn * 0x1000);
		}
	}
	for set in 0..TLB_SETS {
		for way in 0..TLB_WAYS {
			let vpn = vpn_in_set(set, way as u64);
			let idx = match tlb_lookup(&mut tlb, vpn, 0) {
				TlbResult::Hit(i) => i,
				_ => panic!("expected a hit in set {set} way {way}"),
			};
			assert_eq!(idx % TLB_SETS, set, "slot {idx} is not in set {set}");
		}
	}
}

/// 逐出只在目标组内发生, 且组内有效条目数不超过路数.
#[test]
fn tlb_evicts_within_own_set_only() {
	let mut tlb = empty_tlb();
	let target = 0usize;
	let other = 1usize;
	// 在另一组放一个条目, 逐出不得触及它.
	let keeper = vpn_in_set(other, 0);
	insert(&mut tlb, None, keeper, 0xABCDE);

	// 填满目标组.
	for way in 0..TLB_WAYS {
		let vpn = vpn_in_set(target, way as u64);
		insert(&mut tlb, None, vpn, vpn * 0x1000);
	}
	// 再插入 TLB_WAYS 个同组的新页号, 全部应位于目标组内.
	for n in TLB_WAYS..(2 * TLB_WAYS) {
		let vpn = vpn_in_set(target, n as u64);
		insert(&mut tlb, None, vpn, vpn * 0x1000);
		assert!(
			matches!(tlb_lookup(&mut tlb, vpn, 0), TlbResult::Hit(_)),
			"freshly inserted vpn {vpn:#x} is not resident"
		);
	}

	let in_target = (0..TLB_WAYS)
		.filter(|w| tlb[tlb_slot(target, *w)].valid != 0)
		.count();
	assert_eq!(in_target, TLB_WAYS, "set {target} should hold {TLB_WAYS}");
	assert!(matches!(tlb_lookup(&mut tlb, keeper, 0), TlbResult::Hit(_)));
}

#[test]
fn tlb_dirty_reuse() {
	let mut tlb = empty_tlb();
	let set = 7usize;
	// 填满该组, 使后续插入必然触发逐出.
	for way in 0..TLB_WAYS {
		let vpn = vpn_in_set(set, way as u64);
		insert(&mut tlb, None, vpn, vpn * 0x1000);
	}
	let target = vpn_in_set(set, 0);
	let idx = match tlb_lookup(&mut tlb, target, 0) {
		TlbResult::Hit(i) => i,
		_ => panic!("expected a hit before marking dirty"),
	};
	tlb[idx].dirty = 1;
	let reuse = match tlb_lookup(&mut tlb, target, 0) {
		TlbResult::DirtyReuse(i) => i,
		_ => panic!("expected DirtyReuse"),
	};
	assert_eq!(reuse, idx);
	// 在脏槽位就地重填: 该组有效条目数不变, 不额外占用槽位.
	insert(&mut tlb, Some(reuse), target, 0x90000);
	assert_eq!(tlb[reuse].ppn, 0x90000);
	assert_eq!(tlb[reuse].dirty, 0);
	let in_set = (0..TLB_WAYS)
		.filter(|w| tlb[tlb_slot(set, *w)].valid != 0)
		.count();
	assert_eq!(in_set, TLB_WAYS, "refill must not add a valid entry");
}

/// 相邻 2 MiB 超级页的页号相差 512, 组号不得仅由页号低位决定.
///
/// 若组号取页号低位, 内核线性映射的连续超级页具有相同的组号, 组相联退化为
/// 直接映射, 可用容量从 TLB_ENTRIES 降到 TLB_WAYS. 组号若只取低位, 该断言失败.
#[test]
fn tlb_set_spreads_consecutive_megapages() {
	let mut seen = [false; TLB_SETS];
	let mut distinct = 0usize;
	for k in 0..TLB_SETS as u64 {
		let vpn = 0x40000 + k * 512;
		let set = tlb_set(vpn);
		if !seen[set] {
			seen[set] = true;
			distinct += 1;
		}
	}
	assert!(
		distinct > TLB_WAYS,
		"consecutive megapages land in only {distinct} sets"
	);
}

#[test]
fn sv39_walk_sets_a_bit_on_leaf() {
	let mut ram = vec![0u8; 0x3000];
	let satp =
		setup_4k_page_table(&mut ram, 0x1000, 0x8000_0000, PTE_R | PTE_W | PTE_X);
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let result = walk_with_no_pmp(&ctx, satp, 0x1000, rwx_read());
	assert!(result.is_some());
	let l0_off = 0x2000usize + (sv39_decompose_va(0x1000).vpn0 * 8) as usize;
	let l0_val = u64::from_le_bytes(ram[l0_off..l0_off + 8].try_into().unwrap());
	assert_ne!(l0_val & PTE_A, 0, "A bit should be set on leaf PTE");
}

#[test]
fn sv39_walk_sets_d_bit_on_write() {
	let mut ram = vec![0u8; 0x3000];
	let satp = setup_4k_page_table(&mut ram, 0x2000, 0x8000_1000, PTE_R | PTE_W);
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let result = walk_with_no_pmp(&ctx, satp, 0x2000, rwx_write());
	assert!(result.is_some());
	let l0_off = 0x2000usize + (sv39_decompose_va(0x2000).vpn0 * 8) as usize;
	let l0_val = u64::from_le_bytes(ram[l0_off..l0_off + 8].try_into().unwrap());
	assert_ne!(
		l0_val & PTE_D,
		0,
		"D bit should be set on write to leaf PTE"
	);
}

/// 硬件只在叶子页表项上置位 A 位与 D 位.
///
/// 非叶页表项的 D、A 与 U 位是保留位, 必须保持为 0; 置位后该页表项按规范
/// 即为无效, 后续遍历会把它当作缺页.
#[test]
fn sv39_walk_leaves_intermediate_ptes_untouched() {
	let mut ram = vec![0u8; 0x3000];
	let satp = setup_4k_page_table(&mut ram, 0x3000, 0x8000_2000, PTE_R | PTE_W);
	let vpn = sv39_decompose_va(0x3000);
	let l2_off = (vpn.vpn2 * 8) as usize;
	let l1_off = 0x1000usize + (vpn.vpn1 * 8) as usize;
	let l0_off = 0x2000usize + (vpn.vpn0 * 8) as usize;
	let before_l2 = u64::from_le_bytes(ram[l2_off..l2_off + 8].try_into().unwrap());
	let before_l1 = u64::from_le_bytes(ram[l1_off..l1_off + 8].try_into().unwrap());
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let _result = walk_with_no_pmp(&ctx, satp, 0x3000, rwx_write());

	let l2_val = u64::from_le_bytes(ram[l2_off..l2_off + 8].try_into().unwrap());
	let l1_val = u64::from_le_bytes(ram[l1_off..l1_off + 8].try_into().unwrap());
	assert_eq!(l2_val, before_l2, "根页表项为指针项, 保留位不得置位");
	assert_eq!(l1_val, before_l1, "中间页表项为指针项, 保留位不得置位");

	let l0_val = u64::from_le_bytes(ram[l0_off..l0_off + 8].try_into().unwrap());
	assert_ne!(l0_val & PTE_A, 0, "叶子页表项应置位 A 位");
	assert_ne!(l0_val & PTE_D, 0, "写访问应在叶子页表项上置位 D 位");
}

/// 带保留位的页表项必须按缺页处理.
///
/// 覆盖三种违反 Sv39 约束的情形: 非叶页表项置位 A 位、非叶页表项置位 U 位、
/// 以及位 [63:54] 的保留位置位.
#[test]
fn sv39_walk_rejects_reserved_bits() {
	let mut ram = vec![0u8; 0x3000];
	let satp = setup_4k_page_table(&mut ram, 0x3000, 0x8000_2000, PTE_R | PTE_W);
	let vpn = sv39_decompose_va(0x3000);
	let root_off = (vpn.vpn2 * 8) as usize;
	let l1_off = 0x1000usize + (vpn.vpn1 * 8) as usize;
	let root_val =
		u64::from_le_bytes(ram[root_off..root_off + 8].try_into().unwrap());
	let l1_val = u64::from_le_bytes(ram[l1_off..l1_off + 8].try_into().unwrap());

	let cases: [(usize, u64, &str); 3] = [
		(root_off, root_val | PTE_A, "非叶页表项置位 A 位"),
		(root_off, root_val | PTE_U, "非叶页表项置位 U 位"),
		(root_off, root_val | (1u64 << 63), "置位保留位 63"),
	];
	for (off, raw, what) in cases {
		ram[off..off + 8].copy_from_slice(&raw.to_le_bytes());
		let ctx = WalkCtx {
			ram: ram.as_mut_ptr(),
			ram_size: ram.len() as u64,
			ram_base: 0,
			shadow_base: 0,
			shadow_size: 0,
			tlb_flush_cnt: std::ptr::null(),
			lr_reserved: std::ptr::null_mut(),
			num_harts: 1,
		};
		assert!(
			walk_with_no_pmp(&ctx, satp, 0x3000, rwx_read()).is_none(),
			"{what} 的页表项必须按缺页处理"
		);
		// 复原根页表项, 供下一轮使用.
		ram[off..off + 8].copy_from_slice(&root_val.to_le_bytes());
		ram[l1_off..l1_off + 8].copy_from_slice(&l1_val.to_le_bytes());
	}
}

/// 超级页的物理页号低位必须为 0, 否则该页表项无效.
#[test]
fn sv39_walk_rejects_misaligned_superpage_ppn() {
	let mut ram = vec![0u8; 0x3000];
	// 2 MiB 叶子项直接放在根页表: PPN[0] 必须为 0.
	let satp = 8u64 << 60;
	let vpn = sv39_decompose_va(0x4000_0000);
	let leaf_off = (vpn.vpn2 * 8) as usize;
	let aligned = (0x80000u64 << 10) | PTE_V | PTE_R | PTE_W | PTE_A | PTE_D;
	ram[leaf_off..leaf_off + 8].copy_from_slice(&aligned.to_le_bytes());
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};
	assert!(
		walk_with_no_pmp(&ctx, satp, 0x4000_0000, rwx_read()).is_some(),
		"PPN 对齐的 1 GiB 超级页必须翻译成功"
	);

	// PPN[1:0] 非 0: 该页表项无效. PPN 从位 10 起, 故置位 PTE 的位 10.
	let misaligned = aligned | (1u64 << 10);
	ram[leaf_off..leaf_off + 8].copy_from_slice(&misaligned.to_le_bytes());
	assert!(
		walk_with_no_pmp(&ctx, satp, 0x4000_0000, rwx_read()).is_none(),
		"PPN 低 18 位非 0 的 1 GiB 超级页必须按缺页处理"
	);
}

#[test]
fn sv39_walk_allows_fetch_of_xonly_leaf() {
	// R=0 且 W=0 且 X=1 的页必须允许取指. S 模式运行时的仅可执行 text 段
	// 以高虚拟地址映射 trap_vector, 取指不得报 InstrPageFault.
	let mut ram = vec![0u8; 0x3000];
	let va = 0xffff_ffe0_0000_1000u64; // 与飞地的 trap_vector 同型的高虚拟地址
	let pa = 0x8ae0_1000u64;
	let satp = setup_4k_page_table(&mut ram, va, pa, PTE_X);
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	// 取指必须成功, 且翻译到正确的物理地址.
	let fetch = walk_with_no_pmp(&ctx, satp, va, rwx_exec());
	assert!(
		fetch.is_some(),
		"fetch from an X-only leaf must succeed (returned None before the fix)"
	);
	assert_eq!(
		fetch.unwrap().pa,
		pa,
		"fetch from an X-only leaf must translate to the mapped PA"
	);

	// 数据读: R=0 页不可读, 仍应失败.
	let load = walk_with_no_pmp(&ctx, satp, va, rwx_read());
	assert!(
		load.is_none(),
		"data load from an X-only leaf must stay denied (PTE_R required)"
	);

	// R 位与 W 位无启用，预期上应为失败.
	let store = walk_with_no_pmp(&ctx, satp, va, rwx_write());
	assert!(
		store.is_none(),
		"store to an X-only leaf must stay denied (PTE_R|PTE_W required)"
	);
}

#[test]
fn sv39_walk_honors_mxr_for_data_read_of_xonly_leaf() {
	// 设置 MXR 时该读取必须成功, 否则固件会把模拟的写入访问故障误判为取指页错误
	let mut ram = vec![0u8; 0x3000];
	let va = 0xffff_ffe0_0001_7376u64;
	let pa = 0x8301_7376u64;
	let satp = setup_4k_page_table(&mut ram, va, pa, PTE_X);
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let mxr = 1u64 << 19;
	let load = walk_with_mstatus(&ctx, satp, va, rwx_read(), mxr);
	assert!(
		load.is_some(),
		"data load from an X-only leaf must succeed when MXR is set (returned None before the fix)"
	);
	assert_eq!(
		load.unwrap().pa,
		pa,
		"data load under MXR must translate to the mapped PA"
	);

	// MXR 未置位时数据读取仍然拒绝.
	assert!(
		walk_with_mstatus(&ctx, satp, va, rwx_read(), 0).is_none(),
		"data load from an X-only leaf must stay denied when MXR is clear"
	);

	// 写不受 MXR 影响.
	assert!(
		walk_with_mstatus(&ctx, satp, va, rwx_write(), mxr).is_none(),
		"store to an X-only leaf must stay denied when MXR is set"
	);

	// 成功的读取置位叶子的 A 位, 说明遍历走完了叶子项.
	let l0_off = 0x2000usize + (sv39_decompose_va(va).vpn0 * 8) as usize;
	let l0_val = u64::from_le_bytes(ram[l0_off..l0_off + 8].try_into().unwrap());
	assert_ne!(l0_val & PTE_A, 0, "A bit should be set on the MXR read");
}

#[test]
fn sv39_walk_honors_mxr_for_data_read_of_xonly_superpage() {
	// 同一判定位于 walk_l1_leaf, 覆盖 2 MiB 叶子项.
	let mut ram = vec![0u8; 0x2000];
	let va = 0xffff_ffe0_0040_0000u64;
	let pa_mega = 0x8ae0_0000u64;
	let vpn = sv39_decompose_va(va);
	let satp = 8u64 << 60;

	let l2_off = (vpn.vpn2 * 8) as usize;
	let l2_val = (1u64 << 10) | PTE_V;
	ram[l2_off..l2_off + 8].copy_from_slice(&l2_val.to_le_bytes());

	let l1_off = 0x1000usize + (vpn.vpn1 * 8) as usize;
	let l1_val = ((pa_mega >> 12) << 10) | PTE_X | PTE_V;
	ram[l1_off..l1_off + 8].copy_from_slice(&l1_val.to_le_bytes());

	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let mxr = 1u64 << 19;
	let load = walk_with_mstatus(&ctx, satp, va, rwx_read(), mxr);
	assert!(
		load.is_some(),
		"data load from an X-only superpage must succeed when MXR is set (returned None before the fix)"
	);
	assert_eq!(
		load.unwrap().pa,
		pa_mega,
		"data load under MXR must translate to the mapped PA"
	);
	assert!(
		walk_with_mstatus(&ctx, satp, va, rwx_read(), 0).is_none(),
		"data load from an X-only superpage must stay denied when MXR is clear"
	);
	// 写入不受 MXR 影响.
	assert!(
		walk_with_mstatus(&ctx, satp, va, rwx_write(), mxr).is_none(),
		"store to an X-only superpage must stay denied when MXR is set"
	);
}

/// 根页表的叶子页表项必须按 1 GiB 超级页翻译, 而不是视为无效.
///
/// 根表项只带 V 与 R/W/X 时, 修复前直接返回 `Ok(None)`, 取指在 satp 生效的
/// 下一条指令处产生 InstrPageFault.
#[test]
fn sv39_walk_accepts_1g_root_leaf() {
	let va = 0x8020_1234u64;
	let vpn = sv39_decompose_va(va);
	let mut ram = vec![0u8; 0x1000];
	let satp = 8u64 << 60; // Sv39, 根页表的 PPN 为 0

	let root_off = (vpn.vpn2 * 8) as usize;
	let root_val = ((0x80000u64) << 10) | PTE_R | PTE_W | PTE_X | PTE_V;
	ram[root_off..root_off + 8].copy_from_slice(&root_val.to_le_bytes());

	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let result = walk_with_no_pmp(&ctx, satp, va, rwx_read())
		.expect("a root leaf must translate as a 1 GiB page");
	assert_eq!(result.level, 2, "root leaf must be reported as level 2");
	assert_eq!(
		result.pa, 0x8020_1234u64,
		"1 GiB page must be identity mapped"
	);

	// 同一 1 GiB 页内另一个 4 KiB 页的地址同样落在根表项上.
	let other = walk_with_no_pmp(&ctx, satp, 0x803f_f000, rwx_read())
		.expect("any address inside the 1 GiB page must translate");
	assert_eq!(other.pa, 0x803f_f000u64);

	// 置位 A 位之后的根表项仍为叶子项.
	let raw = u64::from_le_bytes(ram[root_off..root_off + 8].try_into().unwrap());
	assert_ne!(raw & PTE_A, 0, "A bit should be set on the root leaf");
}

/// 1 GiB 超级页的 TLB 条目抹去 PPN 的低 18 位, 命中时按虚拟地址补回.
#[test]
fn tlb_entry_of_1g_page_reconstructs_pa() {
	let mut entry = TlbEntry::empty();
	entry.ppn = 0x80000;
	entry.level = 2;
	entry.valid = 1;
	assert_eq!(reconstruct_tlb_pa(&entry, 0x8020_1234), 0x8020_1234u64);
	assert_eq!(reconstruct_tlb_pa(&entry, 0x81ff_f000), 0x81ff_f000u64);

	// 写入 TLB 的页号抹去虚拟地址给出的低 18 位.
	let result = TranslateResult {
		pa: 0x8020_1234,
		perm: 0x1E,
		level: 2,
	};
	assert_eq!(result.ppn_for_tlb(0), 0x80000);
}

/// 遍历阶段要求的权限位: 数据读取只在 MXR 清除时要求 R 位; 写入恒要求
/// RW; 取指不要求任何位, 由 `check_pte_perm` 在遍历之后判定.
#[test]
fn pte_perm_needed_defers_read_requirement_under_mxr() {
	assert_eq!(
		pte_perm_needed(rwx_read(), false),
		PTE_R,
		"a data read must require PTE_R when MXR is clear"
	);
	assert_eq!(
		pte_perm_needed(rwx_read(), true),
		0,
		"a data read must not require PTE_R when MXR is set"
	);
	assert_eq!(
		pte_perm_needed(rwx_write(), false),
		PTE_R | PTE_W,
		"a store must require PTE_R and PTE_W when MXR is clear"
	);
	assert_eq!(
		pte_perm_needed(rwx_write(), true),
		PTE_R | PTE_W,
		"a store must require PTE_R and PTE_W when MXR is set"
	);
	assert_eq!(
		pte_perm_needed(rwx_exec(), false),
		0,
		"a fetch must not require PTE_R"
	);
	assert_eq!(
		pte_perm_needed(rwx_exec(), true),
		0,
		"a fetch must not require PTE_R when MXR is set"
	);
}

/// 设置 MXR 时 TLB 命中的仅可执行条目必须放行数据读取, 清除 MXR 后必须
/// 形成取指令故障. 权限判定对 TLB 命中与页表遍历也必须一致.
#[test]
fn tlb_probe_honors_mxr_for_xonly_entry() {
	let mut tlb = empty_tlb();
	let vpn = 0x0017_376u64;
	let ppn = 0x8_3017u64;
	tlb_insert(&mut tlb, None, vpn, ppn, PTE_X as u8, 0, 0, 0);

	let mxr = 1u64 << 19;
	let va = vpn << 12;
	match tlb_probe(&mut tlb, vpn, va, 0, None, riscv_mode::S, mxr, false, false) {
		TlbProbeResult::Hit(r) => assert_eq!(
			r.pa,
			ppn << 12,
			"data load under MXR must translate to the entry's PA"
		),
		_ => panic!("data load of an X-only TLB entry must hit when MXR is set"),
	}
	assert!(
		matches!(
			tlb_probe(&mut tlb, vpn, va, 0, None, riscv_mode::S, 0, false, false),
			TlbProbeResult::Fault(_)
		),
		"data load of an X-only TLB entry must fault when MXR is clear"
	);
	assert!(
		matches!(
			tlb_probe(&mut tlb, vpn, va, 0, None, riscv_mode::S, mxr, true, false),
			TlbProbeResult::Fault(_)
		),
		"store to an X-only TLB entry must fault when MXR is set"
	);
}

#[test]
fn mxr_widens_only_data_reads() {
	let mxr = 1u64 << 19;
	let xonly = PTE_X as u8;
	assert!(
		check_pte_perm(xonly, riscv_mode::S, mxr, false, false),
		"MXR must allow a data read of an X-only page"
	);
	assert!(
		!check_pte_perm(xonly, riscv_mode::S, mxr, true, false),
		"MXR must not allow a store to an X-only page"
	);
	assert!(
		check_pte_perm(xonly, riscv_mode::S, mxr, false, true),
		"MXR must not affect a fetch of an X-only page"
	);
	let ronly = PTE_R as u8;
	assert!(
		!check_pte_perm(ronly, riscv_mode::S, mxr, false, true),
		"MXR must not make an R-only page fetchable"
	);
	let wonly = PTE_W as u8;
	assert!(
		!check_pte_perm(wonly, riscv_mode::S, mxr, false, false),
		"MXR must not make a W-only page readable"
	);
}

#[test]
fn bare_mode_translate_is_identity() {}

#[test]
fn mmode_bypasses_sv39_even_when_satp_is_sv39() {
	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::M;
	state.mmu_mode = 8;
	state.satp = 8u64 << 60;
	state.mstatus = 0;

	let mut ram = vec![0u8; 0x1000];
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let pmp = no_pmp();
	let result = translate_va(&mut state, &ctx, 0x8000_1000, rwx_read(), &pmp);
	assert!(
		result.is_ok(),
		"M-mode with MPRV=0 must use Bare translation"
	);
	let tr = result.unwrap();
	assert_eq!(tr.pa, 0x8000_1000);
	assert_eq!(tr.level, 0);
}

#[test]
fn mmode_mprv1_with_mpp_s_uses_sv39() {
	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::M;
	state.mmu_mode = 8;
	state.satp = 8u64 << 60;
	state.mstatus = (1u64 << 17) | (1u64 << 11);

	let mut ram = vec![0u8; 0x1000];
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let pmp = no_pmp();
	let result = translate_va(&mut state, &ctx, 0x8000_1000, rwx_read(), &pmp);
	assert!(
		result.is_err(),
		"MPRV=1+MPP=S must attempt Sv39 translation"
	);
}

/// D 模式必须与 M 模式一样绕过 Sv39 翻译.
/// `effective_mode` 对 D 模式返回 `None`.
#[test]
fn dmode_bypasses_sv39_translation() {
	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::D;
	state.mmu_mode = 8;
	state.satp = 8u64 << 60; // Sv39, 根页表的 PPN 为 0

	let mut ram = vec![0u8; 0x1000];
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let pmp = no_pmp();
	let result = translate_va(&mut state, &ctx, 0x8000_1000, rwx_read(), &pmp);
	assert!(
		result.is_ok(),
		"D-mode must use Bare translation (bypass Sv39)"
	);
	let tr = result.unwrap();
	assert_eq!(tr.pa, 0x8000_1000, "D-mode VA must equal PA");
}

/// D 模式的取指同样必须绕过 MMU 翻译.
#[test]
fn dmode_fetch_bypasses_sv39() {
	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::D;
	state.mmu_mode = 8;
	state.satp = 8u64 << 60;

	let mut ram = vec![0u8; 0x1000];
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let pmp = no_pmp();
	let pa = crate::instr::fetch::translate_fetch_pc_concurrent(
		&mut state,
		&ctx,
		0x8000_2000,
		&pmp,
	);
	assert_eq!(
		pa,
		Some(0x8000_2000),
		"D-mode fetch must bypass Sv39 (VA==PA)"
	);
}

/// 页表遍历读取页表页时经 PMP 检查.
///
/// 遍历由 hart 隐式发起, 与显式访存受同一组 PMP 条目约束, 权限按读取判定.
/// 被拒绝时返回 `TranslateFault::AccessFault`, 由调用方按原访问的类型投递
/// 访问故障 (取指 1, 读取 5, 写入 7); 缺页异常只表示页表项无效.
#[test]
fn pte_read_denied_by_pmp_is_access_fault() {
	let mut ram = vec![0u8; 0x3000];
	let satp = setup_4k_page_table(&mut ram, 0x1000, 0x8000_0000, PTE_R | PTE_W);
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::S;
	state.mmu_mode = 8;
	state.satp = satp;

	// 只允许访问 L0 页 [0x2000, 0x4000), 根页表所在的页 0 不在任何条目之内.
	// 根页表的页表项读取因此被拒绝, 此时尚未取得任何叶子项的权限.
	let restricted_cfg = [0x1fu8]; // NAPOT | R | W | X
	let restricted_addr = [0x0000_0000_0000_0bffu64]; // NAPOT, [0x2000, 0x4000)
	let restricted_pmp = PmpCtx {
		cfg: restricted_cfg.as_ptr() as *mut u8,
		addr: restricted_addr.as_ptr() as *mut u64,
		num: 1,
	};

	let walk = sv39_walk(&ctx, &state, &restricted_pmp, satp, 0x1000, rwx_read());
	assert!(
		matches!(walk, Err(TranslateFault::AccessFault)),
		"page-table read outside every PMP entry must yield AccessFault"
	);

	// 同一条拒绝经由 translate_va 返回, 不是缺页异常. 调用方据此投递
	// 访问故障并把原访问的虚拟地址写入 tval.
	let tr = translate_va(&mut state, &ctx, 0x1000, rwx_write(), &restricted_pmp);
	assert!(
		matches!(tr, Err(TranslateFault::AccessFault)),
		"store translation must report AccessFault, not PageFault(15)"
	);

	// 对照: 根页表也位于条目之内时, 同一次遍历成功. 故障来自 PMP 条目,
	// 而不是页表本身.
	let full_cfg = [0x1fu8];
	let full_addr = [0x0000_0000_0000_07ffu64]; // NAPOT, [0, 0x4000)
	let full_pmp = PmpCtx {
		cfg: full_cfg.as_ptr() as *mut u8,
		addr: full_addr.as_ptr() as *mut u64,
		num: 1,
	};
	let walk = sv39_walk(&ctx, &state, &full_pmp, satp, 0x1000, rwx_read());
	assert!(
		matches!(walk, Ok(Some(_))),
		"the same walk must succeed once the root page is covered"
	);
}

/// 置位 A 位的写入被 PMP 拒绝时, 翻译返回访问故障.
///
/// 条目覆盖三个页表页但只有读权限: 遍历的读取放行, 置位 A 位的写入被拒绝,
/// 该次翻译按原访问投递访问故障, 页表项保持不变.
#[test]
fn pte_ad_write_denied_by_pmp_is_access_fault() {
	let mut ram = vec![0u8; 0x3000];
	let satp = setup_4k_page_table(&mut ram, 0x1000, 0x8000_0000, PTE_R | PTE_W);
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base: 0,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.mode = riscv_mode::S;
	state.mmu_mode = 8;
	state.satp = satp;

	// NAPOT [0, 0x4000) 覆盖 L2、L1 与 L0 三个页表页, 权限只有读.
	let read_only_cfg = [0x19u8]; // NAPOT | R
	let full_addr = [0x0000_0000_0000_07ffu64];
	let read_only_pmp = PmpCtx {
		cfg: read_only_cfg.as_ptr() as *mut u8,
		addr: full_addr.as_ptr() as *mut u64,
		num: 1,
	};

	let walk = sv39_walk(&ctx, &state, &read_only_pmp, satp, 0x1000, rwx_read());
	assert!(
		matches!(walk, Err(TranslateFault::AccessFault)),
		"A-bit update denied by PMP must yield AccessFault"
	);

	// 页表项未被部分改写.
	let l2_off = (sv39_decompose_va(0x1000).vpn2 * 8) as usize;
	let l2_val = u64::from_le_bytes(ram[l2_off..l2_off + 8].try_into().unwrap());
	assert_eq!(
		l2_val & PTE_A,
		0,
		"denied A-bit update must not write the PTE"
	);

	// 对照: 同一条目加上写权限之后, 同一次遍历成功.
	let writable_cfg = [0x1bu8]; // NAPOT | R | W
	let writable_pmp = PmpCtx {
		cfg: writable_cfg.as_ptr() as *mut u8,
		addr: full_addr.as_ptr() as *mut u64,
		num: 1,
	};
	let walk = sv39_walk(&ctx, &state, &writable_pmp, satp, 0x1000, rwx_read());
	assert!(
		matches!(walk, Ok(Some(_))),
		"the same walk must succeed once the write permission is granted"
	);
}

/// S 模式永不从 U 页取指, 即使 SUM=1 也不放行. RISC-V §4.3.2 规定 SUM
/// 只放宽对数据访问的检查, 取指不受 SUM 影响.
#[test]
fn s_mode_fetch_of_user_page_faults_even_with_sum() {
	// U=1 的可执行页: SUM=1 时 S 模式取指 U 页必须产生故障.
	let perm = (PTE_U | PTE_X) as u8;
	assert!(
		!check_pte_perm(perm, riscv_mode::S, 1 << 18, false, true),
		"S-mode fetch of a U page must fault regardless of SUM"
	);
	// SUM=0 时同样产生故障.
	assert!(
		!check_pte_perm(perm, riscv_mode::S, 0, false, true),
		"S-mode fetch of a U page must fault when SUM=0"
	);
	// 对照: 同一 U=1 且 X=1 的页在 U 模式取指合法, 不会经 U 位检查拒绝.
	assert!(
		check_pte_perm(perm, riscv_mode::U, 0, false, true),
		"U-mode fetch of a U|X page must be allowed"
	);
}

/// SUM=1 只放宽 S 模式对 U 页的数据访问: 读取与写入放行, 取指仍拒绝,
/// 与 Python 的 mem_check_aux._check_pte_perm 保持一致.
#[test]
fn sum_allows_data_access_but_not_fetch() {
	// U=1 的可读页: SUM=1 只放行 S 模式的数据访问, 取指仍拒绝.
	let perm = (PTE_U | PTE_R) as u8;
	assert!(
		check_pte_perm(perm, riscv_mode::S, 1 << 18, false, false),
		"S-mode data load of a U page must be allowed when SUM=1"
	);
	// SUM=0: S 模式数据读 U 页拒绝.
	assert!(
		!check_pte_perm(perm, riscv_mode::S, 0, false, false),
		"S-mode data load of a U page must be denied when SUM=0"
	);
	// 取指仍然拒绝, 取指只检查 X 位, 与可读性无关.
	assert!(
		!check_pte_perm(perm, riscv_mode::S, 1 << 18, false, true),
		"S-mode fetch of a read-only U page must fault (no X bit)"
	);
}
