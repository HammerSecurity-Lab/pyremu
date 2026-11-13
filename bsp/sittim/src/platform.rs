//! 平台特性。
//!
//! M 模式在 CREATE 完成后会经 a4 传入平台特性字, entry.s 将其保存在 s4 并作为
//! main_before_mmu 的最后一个参数传入。此后由本模块保存, 供启动阶段之后查询。
//! 位号与固件侧 enclave_types.h 的 PLATFORM_FEATURE_* 定义一致。

use core::sync::atomic::{AtomicU64, Ordering};

/// 可写 stimecmp, 即 S 模式定时器不经机器模式的 mtimecmp 设置。
const FEATURE_SSTC: u64 = 1 << 0;
/// 平台提供时间扩展与涉及时间相关的寄存器或设备, S 模式可取得时钟源读数。
const FEATURE_TIME_CSR: u64 = 1 << 1;

/// 本平台的特性字。启动阶段写入一次, 此后只读。
static FEATURES: AtomicU64 = AtomicU64::new(0);

/// 平台特性: 每一项对应特性字中的一位。
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PlatformFeatures(u64);

impl PlatformFeatures {
	/// 读取本平台的特性字。
	#[inline]
	pub fn load() -> Self {
		Self(FEATURES.load(Ordering::Acquire))
	}

	/// 平台是否可写 stimecmp。
	#[inline]
	pub fn has_sstc(self) -> bool {
		self.0 & FEATURE_SSTC != 0
	}

	/// 平台是否提供时间扩展与涉及时间相关的寄存器或设备。
	#[inline]
	pub fn has_time_csr(self) -> bool {
		self.0 & FEATURE_TIME_CSR != 0
	}
}

/// 记录 M 模式传入的特性字。只在启动阶段调用一次。
#[inline]
pub fn init(features: u64) {
	FEATURES.store(features, Ordering::Release);
}
