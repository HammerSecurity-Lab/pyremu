//! TLB 的组相联布局、查找、插入与刷新.

use super::*;

const fn tlb_sz() -> usize {
	TLB_ENTRIES
}

//  组相联结构

/// 组相联的路数. 条目数组按组划分: 第 s 组的第 w 路位于 s + w * TLB_SETS.
pub(super) const TLB_WAYS: usize = 4;

/// 组数. 组号由页号的乘法散列高位给出, 故必须为 2 的整数次幂.
pub(super) const TLB_SETS: usize = TLB_ENTRIES / TLB_WAYS;

// 改动 mk/processor.mk 的 TLB_ENTRIES 时须同时满足: 为 2 的整数次幂, 且不小于
// 路数. 在此于编译期检查, 不满足则编译失败.
const _: () = assert!(TLB_WAYS.is_power_of_two());
const _: () = assert!(TLB_ENTRIES.is_power_of_two());
const _: () = assert!(TLB_ENTRIES >= TLB_WAYS);

#[inline]
const fn tlb_set_bits() -> u32 {
	TLB_SETS.trailing_zeros()
}

/// 由页号算出所属的组号.
///
/// 取乘法散列的高位, 而非页号的低位: 相邻 2 MiB 超级页的页号相差 512, 低位均
/// 能被 512 整除, 直接取低位会使内核线性映射的连续超级页具有相同的组号,
/// 组相联退化为直接映射.
#[inline]
pub(super) fn tlb_set(vpn: u64) -> usize {
	const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
	(vpn.wrapping_mul(GOLDEN) >> (64 - tlb_set_bits())) as usize
}

/// 第 s 组第 w 路的条目下标.
#[inline]
pub(super) const fn tlb_slot(set: usize, way: usize) -> usize {
	set + way * TLB_SETS
}

/// 在某组内取一个可逐出的条目: 优先空槽位, 其次未被访问的槽位,
/// 全部被访问过时清除访问位后取第 0 路.
///
/// 只查看该组的 TLB_WAYS 个槽位, 与组数无关.
#[inline]
fn set_victim(tlb: &mut [TlbEntry], set: usize) -> usize {
	for w in 0..TLB_WAYS {
		let idx = tlb_slot(set, w);
		if tlb[idx].valid == 0 {
			return idx;
		}
	}
	for w in 0..TLB_WAYS {
		let idx = tlb_slot(set, w);
		if tlb[idx].accessed == 0 {
			return idx;
		}
	}
	for w in 0..TLB_WAYS {
		let idx = tlb_slot(set, w);
		tlb[idx].accessed = 0;
	}
	tlb_slot(set, 0)
}

/// TLB 查询结果.
pub enum TlbResult {
	/// 命中有效条目, 翻译可以直接使用.
	Hit(usize),
	/// 在指定槽位命中陈旧条目, 需要重新遍历页表,
	/// 调用方应把新的翻译写入该槽位以避免浪费.
	DirtyReuse(usize),
	/// 没有匹配的条目.
	Miss,
}

/// 查找与 `vpn` 匹配的 TLB 条目.
///
/// - `Hit(idx)`: 命中有效条目, 查询时把访问位置 1.
/// - `DirtyReuse(idx)`: 命中陈旧条目, 调用方须重新遍历并写回该下标.
/// - `Miss`: 没有匹配的条目.
///
/// 只查看页号所映射的那一组内的 TLB_WAYS 个条目, 比较次数不随条目总数增长.
#[inline]
pub fn tlb_lookup(tlb: &mut [TlbEntry], vpn: u64, asid: u16) -> TlbResult {
	let set = tlb_set(vpn);
	for w in 0..TLB_WAYS {
		let i = tlb_slot(set, w);
		if tlb[i].valid == 0 || tlb[i].vpn != vpn {
			continue;
		}
		// 带 ASID 标记: 地址空间不同即未命中.
		// asid 为 0 表示 Bare 模式, 不带标记, 与任意条目匹配.
		if asid != 0 && tlb[i].asid != 0 && tlb[i].asid != asid {
			continue;
		}
		if tlb[i].dirty != 0 {
			return TlbResult::DirtyReuse(i);
		}
		tlb[i].accessed = 1;
		return TlbResult::Hit(i);
	}
	TlbResult::Miss
}

/// 在某组内取一个条目下标, 供插入使用.
///
/// 页号已在该组内时返回其下标, 使重复插入就地更新而不额外占用槽位;
/// 否则返回该组内可逐出的条目.
#[inline]
fn tlb_slot_for_insert(tlb: &mut [TlbEntry], set: usize, vpn: u64) -> usize {
	for w in 0..TLB_WAYS {
		let idx = tlb_slot(set, w);
		if tlb[idx].valid != 0 && tlb[idx].vpn == vpn {
			return idx;
		}
	}
	set_victim(tlb, set)
}

/// 把 `vpn` 的翻译写入其所属的组, 已存在时就地更新.
///
/// `prefer_idx` 取先前 `DirtyReuse` 给出的槽位下标, 仅当该槽位位于 `vpn`
/// 所映射的组内时采用. 组外的槽位无法被后续查询命中, 此时改用该组内可逐出的条目.
#[inline]
pub fn tlb_insert(
	tlb: &mut [TlbEntry],
	prefer_idx: Option<usize>,
	vpn: u64,
	ppn: u64,
	perm: u8,
	level: u8,
	mdid: u64,
	asid: u16,
) {
	let set = tlb_set(vpn);
	// 槽位 i 属于第 i % TLB_SETS 组, 故该判据即"该槽位位于本页号所映射的组内".
	// 组号由页号唯一决定, 组外槽位无法被后续查询命中, 不能用于存放本条翻译.
	let idx = match prefer_idx {
		Some(i) if i < tlb_sz() && i % TLB_SETS == set => i,
		_ => tlb_slot_for_insert(tlb, set, vpn),
	};
	tlb[idx].vpn = vpn;
	tlb[idx].ppn = ppn;
	tlb[idx].perm = perm;
	tlb[idx].level = level;
	tlb[idx].valid = 1;
	tlb[idx].mdid = mdid;
	tlb[idx].dirty = 0;
	tlb[idx].accessed = 1;
	tlb[idx].asid = asid;
	tlb[idx].tlb_epoch = 0;
}

/// 把全部有效条目标为陈旧. 在 TLB 刷新计数发生变化时调用: 下一次查询重走页表,
/// 取得当前的物理页号.
#[inline]
pub fn tlb_mark_all_dirty(tlb: &mut [TlbEntry]) {
	for e in tlb.iter_mut() {
		if e.valid != 0 {
			e.dirty = 1;
		}
	}
}

/// 刷新整个 TLB, 使全部条目失效.
#[inline]
pub fn tlb_flush_all(tlb: &mut [TlbEntry]) {
	for e in tlb.iter_mut() {
		e.valid = 0;
		e.dirty = 0;
		e.accessed = 0;
	}
}

/// 从 TLB 中刷新指定页号对应的条目.
#[inline]
pub fn tlb_flush_vpn(tlb: &mut [TlbEntry], vpn: u64) {
	for e in tlb.iter_mut() {
		if e.valid != 0 && e.vpn == vpn {
			e.valid = 0;
		}
	}
}

//  translate_va 的辅助函数: 有效特权级与权限检查
