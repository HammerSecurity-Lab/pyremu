//! 主存直接访问与 LR/SC 保留地址.

use super::*;

pub(crate) fn lr_set(ctx: &WalkCtx, hid: u8, pa: u64) {
	if ctx.lr_reserved.is_null() {
		return;
	}
	unsafe { &*ctx.lr_reserved.add(hid as usize) }.store(pa, Ordering::Release);
}

/// 判定本 hart 是否仍持有 `pa`.
#[inline]
pub(crate) fn lr_check(ctx: &WalkCtx, hid: u8, pa: u64) -> bool {
	if ctx.lr_reserved.is_null() {
		return false;
	}
	pa != 0
		&& unsafe { &*ctx.lr_reserved.add(hid as usize) }.load(Ordering::Acquire)
			== pa
}

/// 清除全部 hart 的预留. 每次写入与 AMO 写操作都调用本函数.
#[inline]
pub(crate) fn lr_clear_all(ctx: &WalkCtx) {
	if ctx.lr_reserved.is_null() {
		return;
	}
	for i in 0..ctx.num_harts as usize {
		unsafe { &*ctx.lr_reserved.add(i) }.store(0, Ordering::Release);
	}
}

//  RAM 读取与写入, 使用 Acquire 与 Release 保证并发安全

/// 从 RAM 的物理地址 `pa` 读取 `size` 个字节, 按小端序组织.
/// 地址对齐的 4 字节与 8 字节读取使用 Acquire 保证并发安全.
#[inline]
pub(crate) fn ram_read(ctx: &WalkCtx, pa: u64, size: u8) -> u64 {
	let off = access::ram_offset(
		pa,
		size as u32,
		ctx.ram_base,
		ctx.ram_size,
		ctx.shadow_base,
		ctx.shadow_size,
	);
	if off.is_none() {
		return 0;
	}
	let ptr = unsafe { ctx.ram.add(off.unwrap() as usize) };
	match size {
		1 => unsafe { *ptr as u64 },
		2 => {
			let b0 = unsafe { *ptr } as u64;
			let b1 = unsafe { *ptr.add(1) } as u64;
			b0 | (b1 << 8)
		}
		4 if (pa & 3) == 0 => {
			let a = unsafe { &*(ptr as *const AtomicU32) };
			a.load(Ordering::Acquire) as u64
		}
		4 => {
			let b0 = unsafe { *ptr } as u64;
			let b1 = unsafe { *ptr.add(1) } as u64;
			let b2 = unsafe { *ptr.add(2) } as u64;
			let b3 = unsafe { *ptr.add(3) } as u64;
			b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
		}
		8 if (pa & 7) == 0 => {
			let a = unsafe { &*(ptr as *const AtomicU64) };
			a.load(Ordering::Acquire)
		}
		8 => {
			let b = |i: usize| unsafe { *ptr.add(i) } as u64;
			b(0) | (b(1) << 8)
				| (b(2) << 16)
				| (b(3) << 24)
				| (b(4) << 32)
				| (b(5) << 40)
				| (b(6) << 48)
				| (b(7) << 56)
		}
		_ => 0,
	}
}

/// 把 `val` 的 `size` 个字节写入 RAM 的物理地址 `pa`, 按小端序组织.
/// 地址对齐的 4 字节与 8 字节写入使用 Release 保证并发安全. 写入生效之前先清除全部
/// LR 预留, 避免 ABA 情形.
#[inline]
pub(crate) fn ram_write(ctx: &WalkCtx, pa: u64, val: u64, size: u8) -> bool {
	let off = access::ram_offset(
		pa,
		size as u32,
		ctx.ram_base,
		ctx.ram_size,
		ctx.shadow_base,
		ctx.shadow_size,
	);
	if off.is_none() {
		return false;
	}
	lr_clear_all(ctx);
	std::sync::atomic::fence(Ordering::SeqCst);
	let ptr = unsafe { ctx.ram.add(off.unwrap() as usize) };
	match size {
		1 => unsafe {
			*ptr = val as u8;
		},
		2 => unsafe {
			*ptr = val as u8;
			*ptr.add(1) = (val >> 8) as u8;
		},
		4 if (pa & 3) == 0 => {
			let a = unsafe { &*(ptr as *const AtomicU32) };
			a.store(val as u32, Ordering::Release);
		}
		4 => unsafe {
			*ptr = val as u8;
			for i in 1..4 {
				*ptr.add(i) = (val >> (i << 3)) as u8;
			}
		},
		8 if (pa & 7) == 0 => {
			let a = unsafe { &*(ptr as *const AtomicU64) };
			a.store(val, Ordering::Release);
		}
		8 => unsafe {
			*ptr = val as u8;
			for i in 1..8 {
				*ptr.add(i) = (val >> (i << 3)) as u8;
			}
		},
		_ => return false,
	}
	true
}

//  页表遍历的 RAM 访问

/// 计算 RAM 内的偏移; 地址超出范围时返回 None.
#[inline]
pub(crate) fn ram_offset(ctx: &WalkCtx, pa: u64, size: u64) -> Option<usize> {
	let end = pa + size;
	if pa >= ctx.ram_base && end <= ctx.ram_base + ctx.ram_size {
		return Some((pa - ctx.ram_base) as usize);
	}
	if ctx.shadow_size > 0 {
		let sh_end = ctx.shadow_base + ctx.shadow_size;
		if pa >= ctx.shadow_base && end <= sh_end {
			return Some((pa - ctx.shadow_base) as usize);
		}
	}
	None
}
