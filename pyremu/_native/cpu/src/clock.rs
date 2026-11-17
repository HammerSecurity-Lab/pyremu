//! 加速执行引擎的时钟推进与定时器唤醒.

use std::sync::atomic::Ordering;

use crate::shared::{ConcurrentClintCtx, ModuleState};
use crate::state::HartState;

/// 软件看门狗轮询周期, 单位为微秒, 兼作看门狗自身阻塞的周期.
///
/// 处于 WFI 等待的 hart 按此周期自行醒来重新检查停止标志.
pub(crate) const WATCHDOG_POLL_US: u64 = 5_000;

/// 纳秒与秒的换算常数, 用于把 Duration 换算为时钟计数.
const NS_PER_SEC: u64 = 1_000_000_000;
/// 指令计数推进的换算比率, 即每条指令对应的受调试程序时间, 单位为纳秒.
///
/// 取值为 20, 即每条指令 20 纳秒.
pub const NS_PER_INSTR: u64 = 20;

/// 按指令计数推进 mtime, 时钟源只取指令条数, 不含实时分量.
///
/// - 单一时钟源
/// - 单调递增
pub(crate) fn advance_clock_source(
	module: &ModuleState,
	clint: &ConcurrentClintCtx,
	state: &HartState,
) {
	if clint.timebase_hz == 0 {
		return;
	}
	let hid = state.mhartid as usize;
	if hid >= module.instr_ref_num.len() {
		return;
	}
	let instr_delta = state.total_instrs.wrapping_sub(module.instr_ref_num[hid]);
	// instr_delta * timebase_hz * NS_PER_INSTR 的峰值约为 4M * 10MHz = 4e13,
	// 远小于 u64 上限, 无需使用 u128.
	let ticks = instr_delta
		.saturating_mul(clint.timebase_hz)
		.saturating_mul(NS_PER_INSTR)
		/ NS_PER_SEC;
	let target = module.time_base_val.wrapping_add(ticks);
	// mtime 只增不减, 目标值不超过当前值时该操作不改变任何值.
	if unsafe { &*clint.mtime }.load(Ordering::Relaxed) < target {
		unsafe { &*clint.mtime }.fetch_max(target, Ordering::Relaxed);
	}
}

#[inline]
pub(crate) fn timer_deadline_own(
	own_total_instrs: u64,
	now_mtime: u64,
	timecmp: u64,
	timebase_hz: u64,
) -> u64 {
	if timecmp == 0 || timecmp <= now_mtime {
		return 0;
	}
	let ticks_per_instr_scale = timebase_hz.saturating_mul(NS_PER_INSTR);
	if ticks_per_instr_scale == 0 {
		return 0;
	}
	let ticks = timecmp - now_mtime;
	let offset = ticks
		.saturating_mul(NS_PER_SEC) // 向上取整
		.saturating_add(ticks_per_instr_scale - 1)
		.checked_div(ticks_per_instr_scale)
		.unwrap_or(u64::MAX);
	own_total_instrs.wrapping_add(offset)
}
