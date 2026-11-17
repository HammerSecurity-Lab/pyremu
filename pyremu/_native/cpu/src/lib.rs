//! Pyremu 动态链接加速执行引擎, 提供
//!     RISC-V 指令分发,
//!     TLB与PMP匹配,
//!     Sv39 页表遍历与 ALU 运算.
//! 全部公开符号以 `#[no_mangle] pub extern "C"` 导出供 ctypes 调用.

mod clock;
mod concurrent;
mod consts;
pub mod csr;
mod ffi;
mod hart_sched;
pub mod instr;
mod interrupt;
pub mod mem;
mod peripheral;
mod shared;
mod state;
mod trap;
mod utils;

pub use consts::*;
pub use ffi::*;
pub use instr::alu::*;
pub use instr::decode::*;
pub use mem::access::*;
pub use mem::mmu::*;
pub use mem::pmp::*;
pub use state::*;
