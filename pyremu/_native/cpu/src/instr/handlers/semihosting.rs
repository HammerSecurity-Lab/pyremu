//! 半主机的识别与分派。

use super::*;

//
// 半主机(semihosting)是固件与宿主调试器或模拟器以特定陷态序列通信的调试机制,
// RISC-V 的半主机调用序列为:
//
//   slli zero, zero, 0x1f    0x01f01013      入口标记
//   ebreak                   0x00100073      陷态
//   srai zero, zero, 0x7     0x40705013      出口标记
//
// OpenSBI 以 CONFIG_SEMIHOSTING=y 构建时用半主机做早期控制台输出。
// 模拟器截获该序列并分派半主机操作, 如 SYS_WRITE 与 SYS_WRITEC。

/// 入口标记, 即 ``slli zero, zero, 0x1f``。
const SEMIHOSTING_PRE: u32 = 0x01f01013;
/// 出口标记, 即 ``srai zero, zero, 0x7``。
const SEMIHOSTING_POST: u32 = 0x40705013;

/// 操作码。
pub(super) const SH_SYS_OPEN: u64 = 0x01;
pub(super) const SH_SYS_WRITEC: u64 = 0x03;
pub(super) const SH_SYS_WRITE: u64 = 0x05;
pub(super) const SH_SYS_ISTTY: u64 = 0x09;
/// SYS_EXIT: 停机序列的操作码。
pub(crate) const SH_SYS_EXIT: u64 = 0x18;

/// 从 RAM 的物理地址 ``pa`` 读取一个 64 位值。Bare 模式下虚拟地址等于物理地址。
#[inline]
unsafe fn read_ram_u64(ctx: &WalkCtx, pa: u64) -> u64 {
	if pa + 8 > ctx.ram_base + ctx.ram_size || pa < ctx.ram_base {
		return 0;
	}
	let off = (pa - ctx.ram_base) as isize;
	(ctx.ram.offset(off) as *const u64).read_unaligned()
}

/// 从 RAM 的物理地址 ``pa`` 读取一个字节。
#[inline]
unsafe fn read_ram_u8(ctx: &WalkCtx, pa: u64) -> u8 {
	if pa >= ctx.ram_base + ctx.ram_size || pa < ctx.ram_base {
		return 0;
	}
	let off = (pa - ctx.ram_base) as isize;
	*ctx.ram.offset(off)
}

/// 记录最近一次附加 ``[hart X]`` 标记的 hart 编号。
/// 只在输出 hart 改变时附加标记, 不在每次换行时附加, 避免固件逐行打印多个字段时
/// 输出在同一行内交错。
static SH_LAST_TAGGED_HART: Mutex<Option<u64>> = Mutex::new(None);

/// 把 ``data`` 写入 stderr, 仅在输出 hart 改变时附加 ``[hart X]`` 标记,
/// 不在每次换行时附加。
fn write_labeled_stderr(data: &[u8], hart_id: u64) {
	extern "C" {
		fn write(fd: i32, buf: *const u8, count: usize) -> isize;
	}

	// 仅在输出 hart 改变时附加标记。
	{
		let mut last = SH_LAST_TAGGED_HART.lock().unwrap();
		if *last != Some(hart_id) {
			// 粗体蓝色的 ANSI 前缀。
			let prefix = format!("\x1b[1;34m[hart {}]\x1b[0m ", hart_id);
			let prefix_bytes = prefix.as_bytes();
			let mut off = 0;
			while off < prefix_bytes.len() {
				let n = unsafe {
					write(2, prefix_bytes[off..].as_ptr(), prefix_bytes.len() - off)
				};
				if n <= 0 {
					break;
				}
				off += n as usize;
			}
			*last = Some(hart_id);
		}
	}

	// 把数据写入 stderr, 不按换行附加标记。
	let mut off = 0;
	while off < data.len() {
		let n = unsafe { write(2, data[off..].as_ptr(), data.len() - off) };
		if n <= 0 {
			break;
		}
		off += n as usize;
	}
}

/// 直接向文件描述符写入, 不经过 Rust 标准输入输出的锁, 避免与 Python 侧
/// rich 与 prompt_toolkit 对终端控制的争用。写入 stderr, 即文件描述符 2,
/// 使半主机输出不改动调试器的终端界面。
#[allow(unused)]
fn raw_write_stderr(data: &[u8]) {
	extern "C" {
		fn write(fd: i32, buf: *const u8, count: usize) -> isize;
	}
	let mut off = 0usize;
	while off < data.len() {
		let remaining = &data[off..];
		let n = unsafe { write(2, remaining.as_ptr(), remaining.len()) };
		if n <= 0 {
			break;
		}
		off += n as usize;
	}
}

/// 执行一次半主机操作, 返回写入 ``a0`` 的值。
fn semihosting_dispatch(
	ctx: &WalkCtx,
	op: u64,
	param_block: u64,
	hart_id: u64,
) -> u64 {
	match op {
		SH_SYS_WRITEC => {
			let ch = unsafe { read_ram_u8(ctx, param_block) };
			write_labeled_stderr(&[ch], hart_id);
			0
		}
		SH_SYS_WRITE => {
			let fd = unsafe { read_ram_u64(ctx, param_block) };
			let buf_addr = unsafe { read_ram_u64(ctx, param_block + 8) };
			let len = unsafe { read_ram_u64(ctx, param_block + 16) };
			if len == 0 {
				return 0;
			}
			// 全部输出写入 stderr, 即文件描述符 2; stdout 由调试器的
			// rich 与 prompt_toolkit 终端界面占用。
			if fd != 1 && fd != 2 {
				return -1i64 as u64;
			}
			if buf_addr >= ctx.ram_base
				&& buf_addr + len <= ctx.ram_base + ctx.ram_size
			{
				let off = (buf_addr - ctx.ram_base) as isize;
				let data = unsafe {
					std::slice::from_raw_parts(ctx.ram.offset(off), len as usize)
				};
				write_labeled_stderr(data, hart_id);
				return 0;
			}
			return -1i64 as u64;
		}
		SH_SYS_OPEN => {
			// 返回一个合法的文件描述符, 使固件的探测得到成功结果。
			1
		}
		SH_SYS_ISTTY => {
			let fd = unsafe { read_ram_u64(ctx, param_block) };
			u64::from(fd <= 2)
		}
		_ => -1i64 as u64,
	}
}

/// 检查 ``ebreak_pc`` 前后是否为半主机标记序列
/// ``slli x0, x0, 0x1f; ebreak; srai x0, x0, 7``。
/// 该序列仅在虚拟地址等于物理地址时成立, 即 M 模式且翻译模式为 Bare。
pub(crate) fn semihosting_match(ctx: &WalkCtx, ebreak_pc: u64) -> bool {
	// 半主机仅在虚拟地址等于物理地址时成立, 即 M 模式且翻译模式为 Bare。
	if ebreak_pc < ctx.ram_base || ebreak_pc + 4 > ctx.ram_base + ctx.ram_size {
		return false;
	}
	let ram_off = (ebreak_pc - ctx.ram_base) as isize;
	if ram_off < 4 {
		return false;
	}

	// 检查 ebreak 之前的标记
	let prev: u32 =
		unsafe { (ctx.ram.offset(ram_off - 4) as *const u32).read_unaligned() };
	if prev != u32::from_le(SEMIHOSTING_PRE) {
		return false;
	}

	// 检查 ebreak 之后的标记
	let next: u32 =
		unsafe { (ctx.ram.offset(ram_off + 4) as *const u32).read_unaligned() };
	next == u32::from_le(SEMIHOSTING_POST)
}

// 半主机服务由配置项 PYREMU_HAS_SEMIHOSTING 控制, 生成值见
// ``configs_gen.rs`` 的 ``CFG_HAS_SEMIHOSTING``。取值为 0 时标记序列按普通
// ebreak 分发断点陷态: 固件的半主机探测因此判定宿主不支持, 控制台回落到
// UART, 输出经发送环形缓冲区写入每 hart 的日志。

/// 检查 ``ebreak_pc`` 处是否属于一次半主机调用序列。
///
/// 若 ebreak 前后的指令与半主机标记一致, 本函数执行该操作, 更新 ``a0``,
/// 返回 ``Some(8)``, 即跳过 4 字节的 ebreak 与 4 字节的出口标记。
/// 普通 ebreak 返回 ``None``; ``CFG_HAS_SEMIHOSTING`` 为假时所有 ebreak 均返回 ``None``。
pub fn try_semihosting(
	state: &mut HartState,
	ctx: &WalkCtx,
	ebreak_pc: u64,
) -> Option<u64> {
	if !CFG_HAS_SEMIHOSTING || !semihosting_match(ctx, ebreak_pc) {
		return None;
	}

	let op = state.gprs[10]; // a0
	let param_block = state.gprs[11]; // a1
	let hart_id = state.mhartid;
	state.gprs[10] = semihosting_dispatch(ctx, op, param_block, hart_id);

	// 跳过 ebreak 与出口标记共 8 字节, 其后的 sext.w、bltz、sub 与 j
	// 自行处理返回值。
	Some(8)
}
