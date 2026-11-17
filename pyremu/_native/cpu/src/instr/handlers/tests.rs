//! handlers 的单元测试。

use super::compressed::*;
use super::semihosting::{SH_SYS_WRITE, SH_SYS_WRITEC};
use super::*;
use crate::mem::translate::WalkCtx;
use crate::state::HartState;
use std::cell::Cell;
use std::mem;

#[test]
fn sext32_sign_extends() {
	assert_eq!(sext32(0x7fffffff), 0x7fffffff);
	assert_eq!(sext32(0x80000000), 0xffff_ffff_8000_0000u64);
	assert_eq!(sext32(0xffffffff), 0xffff_ffff_ffff_ffffu64);
}

#[test]
fn sext_various_widths() {
	assert_eq!(sext(0xff, 8), 0xffff_ffff_ffff_ffffu64);
	assert_eq!(sext(0x7f, 8), 0x7f);
	assert_eq!(sext(0x8000, 16), 0xffff_ffff_ffff_8000u64);
	assert_eq!(sext(0x7fff, 16), 0x7fff);
}

/// 直接测试: MemAccess::write 与 try_handle_clint 共同置位 MSIP。
#[test]
fn try_handle_clint_msip_write_direct() {
	let mut s0: HartState = unsafe { mem::zeroed() };
	s0.mhartid = 0;
	let mut s1: HartState = unsafe { mem::zeroed() };
	s1.mhartid = 1;

	let mut mtime: u64 = 0;
	let mut mtimecmp: [u64; 2] = [u64::MAX; 2];
	let mut msip: [u8; 2] = [0; 2];

	let mut states = [s0, s1];
	let ctx = ClintCtx {
		base: 0x200_0000,
		mtime: &mut mtime as *mut u64,
		mtimecmp: mtimecmp.as_mut_ptr(),
		msip: msip.as_mut_ptr(),
		states: states.as_mut_ptr(),
		num_harts: 2,
		timebase_hz: 0, // 单元测试: 时钟源不推进, mtime 保持不变
		yield_for_ipi: Cell::new(false),
		ipi_sender_hart: Cell::new(0),
		ipi_sender_rounds: Cell::new(0),
		msip_pending: Cell::new(std::ptr::null()),
		hart_threads: Cell::new(std::ptr::null()),
		hart_states: Cell::new(std::ptr::null()),
	};

	// 写入 MSIP[1], 目标为另一个 hart
	let access = MemAccess::write(0x200_0004, 4, 1);
	let result = try_handle_clint(&access, &states[0], &ctx);
	assert_eq!(result, Some(0));
	assert_eq!(msip[1], 1, "direct: MSIP[1] must be 1");
	assert!(
		(states[1].mip.load(Ordering::Acquire) & (1 << 3)) != 0,
		"direct: hart 1 mip must have MSIP"
	);
	assert!(
		ctx.yield_for_ipi.get(),
		"direct: cross-hart must set yield flag"
	);
	assert_eq!(
		ctx.ipi_sender_hart.get(),
		0,
		"direct: sender hart must be tracked for short-slice"
	);
	assert_eq!(
		ctx.ipi_sender_rounds.get(),
		16,
		"direct: short-slice rounds must be initialised"
	);

	// 写入 MSIP[0], 自己向自己分发 IPI 时不得置位 yield 标志, 也不记录发送方
	ctx.yield_for_ipi.set(false);
	ctx.ipi_sender_rounds.set(0);
	let access_self = MemAccess::write(0x200_0000, 4, 1);
	let result2 = try_handle_clint(&access_self, &states[0], &ctx);
	assert_eq!(result2, Some(0));
	assert_eq!(msip[0], 1, "direct: MSIP[0] must be 1 after self-IPI");
	assert!(
		!ctx.yield_for_ipi.get(),
		"direct: self-IPI must NOT set yield flag"
	);
	assert_eq!(
		ctx.ipi_sender_rounds.get(),
		0,
		"direct: self-IPI must NOT set short-slice rounds"
	);
}

/// MSIP 的清零同样经 ``clint_write_msip`` 完成, 并清除目标 hart 的 mip 位。
#[test]
fn try_handle_clint_msip_clear_updates_mip() {
	let mut s0: HartState = unsafe { mem::zeroed() };
	s0.mhartid = 0;
	s0.mip.store(1 << 3, Ordering::Release); // MSIP 处于挂起状态

	let mut mtime: u64 = 0;
	let mut mtimecmp: [u64; 2] = [u64::MAX; 2];
	let mut msip: [u8; 2] = [1, 1]; // 两个 MSIP 均已置位

	let mut states = [s0, unsafe { mem::zeroed() }];
	let ctx = ClintCtx {
		base: 0x200_0000,
		mtime: &mut mtime as *mut u64,
		mtimecmp: mtimecmp.as_mut_ptr(),
		msip: msip.as_mut_ptr(),
		states: states.as_mut_ptr(),
		num_harts: 2,
		timebase_hz: 0, // 单元测试: 时钟源不推进, mtime 保持不变
		yield_for_ipi: Cell::new(false),
		ipi_sender_hart: Cell::new(0),
		ipi_sender_rounds: Cell::new(0),
		msip_pending: Cell::new(std::ptr::null()),
		hart_threads: Cell::new(std::ptr::null()),
		hart_states: Cell::new(std::ptr::null()),
	};

	// 清除 MSIP[0], 目标 hart 与当前 hart 均为 0
	let access = MemAccess::write(0x200_0000, 4, 0);
	let result = try_handle_clint(&access, &states[0], &ctx);
	assert_eq!(result, Some(0));
	assert_eq!(msip[0], 0, "MSIP[0] should be cleared");
	assert_eq!(
		states[0].mip.load(Ordering::Acquire) & (1 << 3),
		0,
		"mip.MSIP must be 0 after clear"
	);
	// 清除自己的 MSIP 不得置位 yield 标志, 也不记录发送方
	assert!(!ctx.yield_for_ipi.get(), "MSIP clear should not set yield");
	assert_eq!(
		ctx.ipi_sender_rounds.get(),
		0,
		"MSIP clear should not set short-slice rounds"
	);
}

//  半主机测试

/// 在 RAM 的 ``offset`` 处构造半主机陷态序列。
/// 返回 ebreak 指令的地址, 即 ram_base 加 offset。
fn write_semihosting_seq(ram: &mut [u8], ram_base: u64, offset: usize) -> u64 {
	let pre: [u8; 4] = (0x01f01013u32).to_le_bytes(); // slli zero, zero, 0x1f
	let ebr: [u8; 4] = (0x00100073u32).to_le_bytes(); // ebreak
	let post: [u8; 4] = (0x40705013u32).to_le_bytes(); // srai zero, zero, 0x7

	ram[offset - 4..offset].copy_from_slice(&pre);
	ram[offset..offset + 4].copy_from_slice(&ebr);
	ram[offset + 4..offset + 8].copy_from_slice(&post);
	ram_base + (offset as u64)
}

/// 把 64 位值写入 RAM 的 ``offset`` 处。
fn write_ram_u64(ram: &mut [u8], offset: usize, val: u64) {
	ram[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

#[test]
fn semihosting_writec_outputs_char() {
	if !CFG_HAS_SEMIHOSTING {
		return;
	}

	let mut ram: Vec<u8> = vec![0u8; 0x200];
	let ram_base: u64 = 0x8000_0000;

	// 在偏移 0x100 处放置一个字符
	ram[0x100] = b'X';

	// 在偏移 0x80 处放置半主机序列, 其 ebreak 位于该处
	let ebreak_pc = write_semihosting_seq(&mut ram, ram_base, 0x80);

	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.gprs[10] = SH_SYS_WRITEC; // a0 取操作码 WRITEC
	state.gprs[11] = ram_base + 0x100; // a1 指向字符 'X'
	state.pc = ebreak_pc;
	state.mode = crate::state::riscv_mode::M;

	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let result = try_semihosting(&mut state, &ctx, ebreak_pc);
	assert_eq!(result, Some(8), "should return skip-8 for semihosting");
	assert_eq!(state.gprs[10], 0, "WRITEC should return 0 on success");
}

#[test]
fn semihosting_write_outputs_buffer() {
	if !CFG_HAS_SEMIHOSTING {
		return;
	}

	let mut ram: Vec<u8> = vec![0u8; 0x200];
	let ram_base: u64 = 0x8000_0000;

	let msg = b"Hello";
	let msg_off = 0x100;
	ram[msg_off..msg_off + 5].copy_from_slice(msg);

	// 偏移 0x80 处的参数块:
	//     偏移 0: 文件描述符, 1 表示 stdout
	//     偏移 8: 缓冲区地址
	//     偏移 16: 长度
	write_ram_u64(&mut ram, 0x80, 1); // 文件描述符取 1
	write_ram_u64(&mut ram, 0x88, ram_base + (msg_off as u64)); // 缓冲区地址
	write_ram_u64(&mut ram, 0x90, 5); // 长度

	// 在偏移 0xa0 处放置半主机序列, 其 ebreak 位于该处
	let ebreak_pc = write_semihosting_seq(&mut ram, ram_base, 0xa0);

	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.gprs[10] = SH_SYS_WRITE; // a0 取操作码 WRITE
	state.gprs[11] = ram_base + 0x80; // a1 指向参数块
	state.pc = ebreak_pc;
	state.mode = crate::state::riscv_mode::M;

	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let result = try_semihosting(&mut state, &ctx, ebreak_pc);
	assert_eq!(result, Some(8), "should return skip-8 for semihosting");
	assert_eq!(state.gprs[10], 0, "WRITE should return 0 on success");
}

#[test]
fn semihosting_regular_ebreak_not_handled() {
	let mut ram: Vec<u8> = vec![0u8; 0x200];
	let ram_base: u64 = 0x8000_0000;

	// 放置没有半主机标记的 ebreak
	let ebr_addr = ram_base + 0x80;
	let ebr: [u8; 4] = (0x00100073u32).to_le_bytes();
	ram[0x80..0x84].copy_from_slice(&ebr);

	let mut state: HartState = unsafe { std::mem::zeroed() };
	state.pc = ebr_addr;
	state.mode = crate::state::riscv_mode::M;

	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};

	let result = try_semihosting(&mut state, &ctx, ebr_addr);
	assert_eq!(result, None, "plain ebreak should NOT be semihosting");
}

fn make_dev_ctx(bases: &[u64], ends: &[u64]) -> DevCtx {
	DevCtx {
		bases: if bases.is_empty() {
			std::ptr::null()
		} else {
			bases.as_ptr()
		},
		ends: if ends.is_empty() {
			std::ptr::null()
		} else {
			ends.as_ptr()
		},
		num: bases.len() as u8,
		virtio_base: 0,
		virtio_raw: std::ptr::null_mut(),
		plic: std::ptr::null_mut(),
	}
}

/// 覆盖整个物理地址空间的 TOR 条目, R、W 与 X 位均置位, 供访存测试放行。
fn make_dev_test_pmp(cfg: &mut [u8], addr: &mut [u64]) -> PmpCtx {
	cfg[0] = 0x0f;
	addr[0] = u64::MAX;
	PmpCtx {
		cfg: cfg.as_mut_ptr(),
		addr: addr.as_mut_ptr(),
		num: 1,
	}
}

fn make_test_clint(
	mtime: &mut u64,
	mtimecmp: &mut [u64],
	msip: &mut [u8],
) -> ClintCtx {
	ClintCtx {
		base: 0x200_0000,
		mtime: mtime as *mut u64,
		mtimecmp: mtimecmp.as_mut_ptr(),
		msip: msip.as_mut_ptr(),
		states: std::ptr::null_mut(),
		num_harts: 1,
		timebase_hz: 0,
		yield_for_ipi: Cell::new(false),
		ipi_sender_hart: Cell::new(0),
		ipi_sender_rounds: Cell::new(0),
		msip_pending: Cell::new(std::ptr::null()),
		hart_threads: Cell::new(std::ptr::null()),
		hart_states: Cell::new(std::ptr::null()),
	}
}

/// 内存中的全 1 数据是合法内容, 如内核的 ``~0UL``、``-1`` 以及全 1 的
/// 浮点 NaN 载荷, 不得与 ``EXIT_SENTINEL`` 混淆而中断加速执行。
#[test]
fn compressed_load_all_ones_from_ram_is_not_exit() {
	let mut ram: Vec<u8> = vec![0u8; 0x400];
	let ram_base: u64 = 0x8000_0000;
	ram[0x100..0x108].copy_from_slice(&u64::MAX.to_le_bytes());

	let mut state: HartState = unsafe { mem::zeroed() };
	state.mode = crate::state::riscv_mode::M;
	state.gprs[2] = ram_base + 0x100; // sp
	state.gprs[9] = ram_base + 0x100; // s1

	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};
	let mut cfg = [0u8; 64];
	let mut addr = [0u64; 64];
	let pmp = make_dev_test_pmp(&mut cfg, &mut addr);
	let dev = make_dev_ctx(&[], &[]);
	let mut mtime: u64 = 0;
	let mut mtimecmp = [u64::MAX; 1];
	let mut msip = [0u8; 1];
	let clint = make_test_clint(&mut mtime, &mut mtimecmp, &mut msip);

	// C.LDSP x5, 0(sp)
	let mut group: InstrToBeExec = unsafe { mem::zeroed() };
	let advance = handle_compressed(
		&mut state, 0x6282, 0x6282, &mut group, &ctx, &pmp, &dev, &clint,
	);
	assert_eq!(advance, 2, "读到全 1 的普通内存不得被判为设备退出");
	assert_eq!(state.gprs[5], u64::MAX, "寄存器应拿到内存里真实的全 1 数据");
	assert_eq!(group.exit_reason, exit_reason::NORMAL);

	// C.LD x10, 0(s1)
	let mut group2: InstrToBeExec = unsafe { mem::zeroed() };
	let advance2 = handle_compressed(
		&mut state,
		0x6088,
		0x6088,
		&mut group2,
		&ctx,
		&pmp,
		&dev,
		&clint,
	);
	assert_eq!(advance2, 2, "C.LD 同样不得误判为设备退出");
	assert_eq!(state.gprs[10], u64::MAX);
}

/// 设备访问必须退出到 Python 且退出原因标记为 MMIO。
#[test]
fn compressed_device_access_exits_with_mmio_reason() {
	let mut ram: Vec<u8> = vec![0u8; 0x400];
	let ram_base: u64 = 0x8000_0000;
	let dev_base: u64 = 0x1000_0000;
	let dev_end: u64 = 0x1000_1000;

	let mut state: HartState = unsafe { mem::zeroed() };
	state.mode = crate::state::riscv_mode::M;
	state.gprs[2] = dev_base; // sp 指向设备
	state.gprs[5] = 0xdead_beef;

	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram.len() as u64,
		ram_base,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};
	let mut cfg = [0u8; 64];
	let mut addr = [0u64; 64];
	let pmp = make_dev_test_pmp(&mut cfg, &mut addr);
	let bases = [dev_base];
	let ends = [dev_end];
	let dev = make_dev_ctx(&bases, &ends);
	let mut mtime: u64 = 0;
	let mut mtimecmp = [u64::MAX; 1];
	let mut msip = [0u8; 1];
	let clint = make_test_clint(&mut mtime, &mut mtimecmp, &mut msip);

	// C.SDSP x5, 0(sp)
	let mut group: InstrToBeExec = unsafe { mem::zeroed() };
	let advance = handle_compressed(
		&mut state, 0xe016, 0xe016, &mut group, &ctx, &pmp, &dev, &clint,
	);
	assert_eq!(advance, EXIT_SENTINEL, "设备存储必须退出到 Python");
	assert_eq!(group.exit_reason, exit_reason::MMIO, "退出原因必须为 MMIO");

	// C.LDSP x5, 0(sp)
	let mut group2: InstrToBeExec = unsafe { mem::zeroed() };
	let advance2 = handle_compressed(
		&mut state,
		0x6282,
		0x6282,
		&mut group2,
		&ctx,
		&pmp,
		&dev,
		&clint,
	);
	assert_eq!(advance2, EXIT_SENTINEL, "设备读取必须退出到 Python");
	assert_eq!(group2.exit_reason, exit_reason::MMIO, "退出原因必须为 MMIO");
}

/// 压缩加载指令发生缺页时不得写目的寄存器.
///
/// 委派给 S 模式的缺页陷态从 S 模式发出时特权级不变, 只比较特权级无法识别
/// 陷态已经分发; 目的寄存器被写入 0 之后, 内核的异常表处理会带着这个错误
/// 的值继续执行, 进而按错误的地址或长度访问内存.
#[test]
fn compressed_load_fault_leaves_destination_unchanged() {
	let ram_size = 0x10000usize;
	let ram_base: u64 = 0x8000_0000;
	// 主存全为 0: 根页表的每个页表项 V 位为 0, 遍历必然缺页.
	let mut ram: Vec<u8> = vec![0u8; ram_size];
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram_size as u64,
		ram_base,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};
	let mut cfg = [0u8; 64];
	let mut addr = [0u64; 64];
	let pmp = make_dev_test_pmp(&mut cfg, &mut addr);
	let dev = make_dev_ctx(&[], &[]);
	let mut mtime: u64 = 0;
	let mut mtimecmp = [u64::MAX; 1];
	let mut msip = [0u8; 1];
	let clint = make_test_clint(&mut mtime, &mut mtimecmp, &mut msip);

	let mut state: HartState = unsafe { mem::zeroed() };
	state.mode = crate::state::riscv_mode::S;
	state.mmu_mode = 8; // Sv39
	state.satp = (8u64 << 60) | 8; // 根页表 PPN 为 8
	state.medeleg = 1 << 13; // LdPageFault 委派到 S 模式
	state.stvec = 0x8000_1000;
	state.pc = 0x2000;
	state.gprs[10] = 0xdead_beef_dead_beef; // 目的寄存器 a0
	state.gprs[11] = 0x2000; // 基址 a1

	// C.LW x10, 0(x11)
	let mut group: InstrToBeExec = unsafe { mem::zeroed() };
	let advance = handle_compressed(
		&mut state, 0x4188, 0x4188, &mut group, &ctx, &pmp, &dev, &clint,
	);

	assert_eq!(
		state.gprs[10], 0xdead_beef_dead_beef,
		"发生缺页时目的寄存器不得被改写"
	);
	assert_eq!(state.sepc, 0x2000, "sepc 应保存触发缺页的指令地址");
	assert_eq!(state.pc, 0x8000_1000, "pc 应指向 stvec 入口");
	assert_eq!(advance, 0, "陷态已分发, 不得返回推进量");
}

/// 压缩存储指令的目标物理地址不属于主存时必须投递访问故障.
///
/// 与非压缩存储路径一致: 静默丢弃写入会使受调试程序在没有任何迹象的情况下
/// 少写一次, 且 pc 照常推进.
#[test]
fn compressed_store_outside_ram_raises_access_fault() {
	let ram_size = 0x10000usize;
	let ram_base: u64 = 0x8000_0000;
	let mut ram: Vec<u8> = vec![0u8; ram_size];
	let ctx = WalkCtx {
		ram: ram.as_mut_ptr(),
		ram_size: ram_size as u64,
		ram_base,
		shadow_base: 0,
		shadow_size: 0,
		tlb_flush_cnt: std::ptr::null(),
		lr_reserved: std::ptr::null_mut(),
		num_harts: 1,
	};
	let mut cfg = [0u8; 64];
	let mut addr = [0u64; 64];
	let pmp = make_dev_test_pmp(&mut cfg, &mut addr);
	let dev = make_dev_ctx(&[], &[]);
	let mut mtime: u64 = 0;
	let mut mtimecmp = [u64::MAX; 1];
	let mut msip = [0u8; 1];
	let clint = make_test_clint(&mut mtime, &mut mtimecmp, &mut msip);

	let mut state: HartState = unsafe { mem::zeroed() };
	state.mode = crate::state::riscv_mode::M; // M 模式按 Bare 模式翻译
	state.mmu_mode = 0;
	state.mtvec = 0x8000_2000;
	state.pc = 0x2000;
	state.gprs[10] = 0x1122_3344_5566_7788; // 待存入的值 a0
	state.gprs[11] = 0x1000; // 目标地址 a1, 落在主存之外

	// C.SD x10, 0(x11)
	let mut group: InstrToBeExec = unsafe { mem::zeroed() };
	let advance = handle_compressed(
		&mut state, 0xe188, 0xe188, &mut group, &ctx, &pmp, &dev, &clint,
	);

	assert_eq!(
		state.mcause,
		exc_code::ST_ACCESS_FAULT,
		"目标物理地址不属于主存时必须投递存储访问故障"
	);
	assert_eq!(state.mtval, 0x1000, "mtval 应保存目标虚拟地址");
	assert_eq!(state.pc, 0x8000_2000, "pc 应指向 mtvec 入口");
	assert_eq!(advance, 0, "陷态已分发, 不得返回推进量");
}
