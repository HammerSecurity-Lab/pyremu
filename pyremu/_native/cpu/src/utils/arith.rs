//! 位宽与符号扩展辅助.

/// 从指定位宽按符号位扩展为 64 位.
#[inline]
pub(crate) fn sext(val: u64, bits: u32) -> u64 {
	let half = 1u64 << (bits - 1);
	(val & (half - 1)).wrapping_sub(val & half) & u64::MAX
}

/// 把 32 位值按符号位扩展为 64 位.
#[inline]
pub(crate) fn sext32(val: u64) -> u64 {
	val as i32 as i64 as u64
}

/// 把 12 位值按符号位扩展为 64 位.
#[inline]
pub(crate) fn sext12(val: u64) -> u64 {
	sext(val, 12)
}

/// 把 13 位值按符号位扩展为 64 位.
#[inline]
pub(crate) fn sext13(val: u64) -> u64 {
	sext(val, 13)
}

/// 把 21 位值按符号位扩展为 64 位.
#[inline]
pub(crate) fn sext21(val: u64) -> u64 {
	sext(val, 21)
}
