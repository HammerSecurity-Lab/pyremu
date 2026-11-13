//! 平台特性字的单元测试入口。
//!
//! 特性字由 M 模式在 CREATE 之后经 a4 传入, 每一位对应平台的一项能力。本层只验证位号与
//! 判定之间的一一对应: time CSR 一位对应时钟源可用, 与 Sstc 一位互不影响。

#![allow(dead_code)]

#[path = "../src/platform.rs"]
mod platform;

use crate::platform::PlatformFeatures;

/// 每一项能力只由自己的位决定, 其余位不参与判定。
///
/// 时钟源可用只取 time CSR 一位: 平台只提供 time CSR 而不提供 Sstc 时, 本内核仍能取得
/// 时钟源读数, 该位单独置位就必须满足查询。
#[test]
fn test_feature_bits_map_to_capabilities() {
	// 特性字, 是否可写 stimecmp, 是否提供 time CSR
	let cases: [(u64, bool, bool); 4] = [
		(0x0, false, false),
		(0x1, true, false),
		(0x2, false, true),
		(0x3, true, true),
	];
	for (word, is_sstc, is_time_csr) in cases {
		platform::init(word);
		let features = PlatformFeatures::load();
		assert_eq!(features.has_sstc(), is_sstc, "word=0x{word:x}");
		assert_eq!(features.has_time_csr(), is_time_csr, "word=0x{word:x}");
	}
}
