//! 加载与存储、系统、原子操作及压缩指令的处理函数。
//!
//! 每个处理函数接收 ``&mut HartState``、译码结果与访存上下文,
//! 返回 PC 推进量, 取值为 0、2 或 4, 或者返回 ``EXIT_SENTINEL``,
//! 表示必须返回 Python 侧取得对应的处理。
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::csr;
use crate::ffi::InstrToBeExec;
use crate::instr::decode::{decode_compressed, CompressedFields, DecodedFields};
use crate::instr::exec::{read_ram_cross_page, write_ram_cross_page};
pub use crate::interrupt::clint::ClintCtx;
pub(crate) use crate::interrupt::clint::{clint_write_msip, try_handle_clint};
use crate::mem::access;
pub use crate::mem::pmp::{pmp_ok, PmpCtx};
pub(crate) use crate::mem::translate::{
	lr_check, lr_clear_all, lr_set, ram_read, ram_write, rwx_read, rwx_write,
	translate_va, TranslateFault, TranslateResult, WalkCtx,
};
use crate::peripheral::plic::try_handle_plic_concurrent;
pub use crate::peripheral::{is_device_addr, virtio::try_handle_virtio, DevCtx};
use crate::state::{
	exit_reason, read_gpr, riscv_mode, write_gpr, HartState, CFG_HAS_SEMIHOSTING,
};
use crate::trap::{deliver_illegal_instruction, deliver_trap, exc_code, mcause_val};
use crate::utils::arith::{sext, sext32};

pub use crate::csr::EXIT_SENTINEL;

#[allow(dead_code)]
mod sbi_eid {
	pub const TIME: u64 = 0x54494d45; // "TIME", 定时器扩展
	pub const IPI: u64 = 0x735049; // "IPI", 核间中断
	pub const RFNC: u64 = 0x52464e43; // "RFNC", 远程 fence, 用于跨核刷新 TLB
	pub const HSM: u64 = 0x48534d; // "HSM", hart 状态管理
}

mod sbi_fid_time {
	pub const SET_TIMER: u64 = 0;
}

mod sbi_fid_ipi {
	pub const SEND_IPI: u64 = 0;
}

/// mstatus 的 FS 字段取 Dirty, 表示浮点状态已被修改.
const MSTATUS_FS_LS: u64 = 0b11 << 13;
/// mstatus 的 SD 位, 表示浮点或向量状态已是脏的.
const MSTATUS_SD_LS: u64 = 1 << 63;

pub mod amo;
pub mod compressed;
pub mod semihosting;
pub mod system;
#[cfg(test)]
mod tests;

pub use amo::handle_amo;
pub use compressed::handle_compressed;
pub(crate) use semihosting::{semihosting_match, try_semihosting, SH_SYS_EXIT};
pub use system::handle_system;

//  CLINT 的 MMIO 访问处理

//  CLINT 的 MMIO 访问处理

/// 可能由 CLINT 直接处理的一次访存描述。
///
/// 所有字段均为 ``u64``, 避免因内存对齐问题造成运行期间的程序异常。
/// ``is_write`` 为 0 表示读取, 为 1 表示写入。
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct MemAccess {
	pub(crate) pa: u64,
	pub(crate) is_write: u64,
	pub(crate) write_data: u64,
	pub(crate) size: u64,
}

impl MemAccess {
	pub(crate) fn read(pa: u64, size: u8) -> Self {
		Self {
			pa,
			is_write: 0,
			write_data: 0,
			size: size as u64,
		}
	}
	pub(crate) fn write(pa: u64, size: u8, data: u64) -> Self {
		Self {
			pa,
			is_write: 1,
			write_data: data,
			size: size as u64,
		}
	}
}

/// 串行路径上对 IMSIC 地址的处理。
///
/// 地址译码与上下文提取在此完成, 路由、eip 改写与唤醒线程由
/// ``imsic_handle_seteipnum`` 与 ``imsic_handle_clreipnum`` 处理.
/// pa 位于 IMSIC 的 seteipnum 或 clreipnum 寄存器内时返回 true.
fn try_handle_imsic_serial(pa: u64, val: u64, clint: &ClintCtx) -> bool {
	if !crate::state::CFG_AIA {
		return false;
	}
	let addr = match crate::interrupt::decode_imsic_addr(pa, clint.num_harts as u64)
	{
		Some(a) => a,
		None => {
			return false;
		}
	};
	if addr.reg_off != 0x0000 && addr.reg_off != 0x0008 {
		return false;
	}
	let file_tag: u64 = if addr.is_sfile { 0x1000 } else { 0x0000 };
	let eip_num = val as u32;

	// 读取路径: 按 AIA 规范, IMSIC 的全部 MMIO 读取均返回 0,
	// seteipnum 与 clreipnum 只可写。读取路径的调用点传入 val==0,
	// 以区分读取与写入。
	if eip_num == 0 {
		return true;
	}

	// 写入路径: 全部中断标识都交给并发路径使用的
	// seteipnum 与 clreipnum 辅助函数处理。
	match addr.reg_off {
		0x0000 => {
			let handled = crate::interrupt::imsic::imsic_handle_seteipnum(
				clint.hart_states.get(),
				clint.hart_threads.get(),
				clint.num_harts,
				addr.hart,
				file_tag,
				eip_num,
			);
			handled
		}
		0x0008 => {
			crate::interrupt::imsic::imsic_handle_clreipnum(
				clint.hart_states.get(),
				addr.hart,
				file_tag,
				eip_num,
			);
			true
		}
		_ => unreachable!(),
	}
}
