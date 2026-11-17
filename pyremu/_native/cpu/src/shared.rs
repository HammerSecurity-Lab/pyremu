//! 并发执行引擎的共享状态: 跨线程传递的 FFI 包装结构与每轮执行共享的模块状态.

use std::cell::Cell;
use std::sync::{
	atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering},
	Mutex,
};

use crate::ffi::{FfiClintCtx, FfiPlicCtx, FfiVirtIoCtx};
use crate::state::{exit_reason, HartState};

//  FFI 裸指针的 Send 与 Sync 包装类型
//
// Python 在整个 FFI 调用期间占有对内存的使用权，例如 bytearray, ctypes 数组.
// 这些包装类型断言 Send 与 Sync, 使其可以安全地跨线程边界传递.

/// 设置 ``MemCtx`` 的 Send 与 Sync 类型.
///
/// # Safety
/// Python 侧的 FFI 调用方必须保持其传递的内存是有效的.
#[derive(Clone, Copy)]
pub(crate) struct SharedMemCtx {
	pub ram: *mut u8,
	pub ram_size: u64,
	pub ram_base: u64,
	pub shadow_base: u64,
	pub shadow_size: u64,
	/// 每个 hart 的 LR 与 SC 预留槽位. LR 把 slot[hid] 置为物理地址,
	/// 任一存储指令清除所有槽位. 该数组在 ``ModuleState`` 中分配.
	pub lr_reserved: *mut AtomicU64,
}
unsafe impl Send for SharedMemCtx {}
unsafe impl Sync for SharedMemCtx {}

/// 包装 PMP 指针的 Send 与 Sync 类型.
#[derive(Clone, Copy)]
pub(crate) struct SharedPmpCtx {
	pub cfg: *mut u8,
	pub addr: *mut u64,
	pub num: u8,
}
unsafe impl Send for SharedPmpCtx {}
unsafe impl Sync for SharedPmpCtx {}

/// 包装设备 MMIO 指针的 Send 与 Sync 类型.
#[derive(Clone, Copy)]
pub(crate) struct SharedDevCtx {
	pub bases: *const u64,
	pub ends: *const u64,
	pub num: u8,
	pub virtio_base: u64,
	pub virtio_raw: *mut FfiVirtIoCtx,
	pub plic: *mut FfiPlicCtx,
}
unsafe impl Send for SharedDevCtx {}
unsafe impl Sync for SharedDevCtx {}

//  并发安全的 CLINT 上下文结构

/// 可供各 hart 线程并发访问的 CLINT 状态.
///
/// 全部字段为原子类型, 或在初始化之后只读.
/// 指针来自 Python ctypes 数组的类型转换; 在 x86-64 上 ``AtomicU64`` 与 ``u64`` 的
/// 布局相同, 即 8 字节大小与 8 字节对齐; ``AtomicU8`` 与 ``u8`` 的布局相同,
/// 即 1 字节大小与 1 字节对齐.
///
/// MSIP 建模为边沿计数器而非电平: 每次写入 1 都递增该 hart 的计数器,
/// ``sync_msip`` 与此前记录的取值比较以识别新的边沿. 连续写入 1 而中间没有
/// 写入 0 的情形因此不会漏检, 纯电平检测会漏掉这种情形.
pub struct ConcurrentClintCtx {
	pub base: u64,
	/// 共享 mtime 计数器, 由 ``advance_clock_source`` 按已执行的指令条数
	/// 推进, 据此换算受调试程序的 mtime.
	pub mtime: *const AtomicU64,
	/// 每个 hart 的 mtimecmp 寄存器, 按 hart_id 索引.
	pub mtimecmp: *const AtomicU64,
	/// 每个 hart 的 MSIP 电平字节, 按 hart_id 索引.
	pub msip: *const AtomicU8,
	/// mtime 时钟源频率, 单位为 Hz; 为 0 时表示禁用时钟源.
	pub timebase_hz: u64,
	pub num_harts: u32,
	pub msip_pending: Cell<*const AtomicU64>,
	pub hart_threads: Cell<*const std::thread::Thread>,
	/// 每个 hart 的 ``HartState`` 数组.
	///
	/// 双重用途:
	/// 1. 跨 hart 读取 ``stimecmp`` (SSTC). ``wfi_check_all_idle`` 据此在全部
	///    hart 处于 WFI 空闲时确定下一截止时间并以 WFI_WAIT 退出. 此处不推进
	///    mtime; Python 侧按真实剩余休眠时间与流逝时间补偿 mtime. 传统 PLIC 模式与
	///    AIA 模式都需要该指针, 内核的时钟事件设备在传统 PLIC 模式下同样使用 SSTC.
	/// 2. AIA 模式下 ``try_handle_imsic_concurrent`` 跨 hart 置位或清除目标 hart 的
	///    IMSIC eip 位, 即 seteipnum 与 clreipnum 的 MMIO 访问.
	///
	/// 由 ``run_parallel`` 在成功解析 FFI 后无条件写入.
	pub hart_states: Cell<*const HartState>,
}

// 安全性: Python 在 FFI 调用期间保持 ctypes 数组有效, 全部指针都指向正确对齐的原子类型.
unsafe impl Send for ConcurrentClintCtx {}
unsafe impl Sync for ConcurrentClintCtx {}

impl ConcurrentClintCtx {
	/// 由 FFI 的 ``FfiClintCtx`` 裸指针构造.
	///
	/// # Safety
	///
	/// 调用方必须保证底层 ctypes 数组的生命周期长于本结构.
	/// 在 x86-64 上把 ``*mut u64`` 转换为 ``*const AtomicU64`` 是合法的,
	/// 因为两种类型的大小与对齐相同.
	pub unsafe fn from_ffi(raw: &FfiClintCtx, num_harts: u32) -> Self {
		ConcurrentClintCtx {
			base: raw.base,
			mtime: raw.mtime as *const AtomicU64,
			mtimecmp: raw.mtimecmp as *const AtomicU64,
			msip: raw.msip as *const AtomicU8,
			timebase_hz: raw.timebase_hz,
			num_harts,
			msip_pending: Cell::new(std::ptr::null()),
			hart_threads: Cell::new(std::ptr::null()),
			hart_states: Cell::new(std::ptr::null()),
		}
	}

	/// 取 hart_id 对应的 MSIP 待处理状态, 未初始化时返回空指针.
	///
	/// 槽位地址为 ``msip_pending`` 数组首地址加 ``hart_id * MSIP_PENDING_STRIDE``,
	/// 与 ``ModuleState::new`` 的分配跨步一致.
	#[inline]
	pub(crate) fn msip_pending_slot(&self, hart_id: usize) -> *const AtomicU64 {
		let base = self.msip_pending.get();
		if base.is_null() {
			return std::ptr::null();
		}
		unsafe { base.add(hart_id * MSIP_PENDING_STRIDE) }
	}
}

/// hart 置位全局停止标志的原因.
#[derive(Clone, Copy)]
pub struct StopInfo {
	pub reason: u8,
	pub hart_id: u8,
	pub pc: u64,
	pub instr: u32,
	pub trap_cause: u32,
	pub trap_tval: u64,
	pub trap_is_interrupt: u8,
	pub trap_delegated: u8,
}

impl StopInfo {
	pub const fn empty() -> Self {
		StopInfo {
			reason: exit_reason::NORMAL,
			hart_id: 0,
			pc: 0,
			instr: 0,
			trap_cause: 0,
			trap_tval: 0,
			trap_is_interrupt: 0,
			trap_delegated: 0,
		}
	}
}

/// 每 hart 的 MSIP 待处理槽位占用的元素个数 — hart 索引乘本值即该 hart 的槽位下标,
/// 相邻 hart 的槽位相距 64 字节.
///
/// 槽位由向其发送 IPI 的 hart 置位, 由本 hart 的 ``sync_msip`` 读取并写入 0.
pub const MSIP_PENDING_STRIDE: usize = 8;

/// 各 hart 线程共享的全局协调状态.
///
/// 每次 ``run_parallel`` 调用对应一个实例
pub struct ModuleState {
	/// 为真时, 全部 hart 线程必须在下一条指令退出.
	pub stop_flag: AtomicBool,
	/// 停止事件的具体信息, 由触发停止的 hart 写入.
	/// 由 ``Mutex`` 保护, 保证只有一个 hart 写入.
	pub stop_info: Mutex<StopInfo>,
	/// 当前处于 WFI 自旋等待的 hart 数量.
	pub wfi_count: AtomicU32,
	/// 每个 hart 的 WFI 状态标志, 下标为 hart_id.
	/// hart 进入 WFI 时把自身槽位置为 1, 离开时置为 0.
	pub wfi_flags: Box<[AtomicU8]>,
	/// 未停机的 hart 数量. 在线程创建之前设置一次, 之后只读.
	pub active_hart_num: u32,
	/// 已发生的 TLB 刷新次数. 使既有翻译条目失效的动作各算一次: 受调试程序
	/// 执行 SFENCE.VMA 或改写 satp, 调试器刷新 TLB 或回滚快照, 装入固件.
	/// 该计数由调用方持有, 引擎在每轮开始时装入, 结束时写回, 故两次调用之间
	/// 发生的刷新对引擎内的条目同样生效.
	///
	/// 用计数而不是一个"已失效"标志: 标志上的清除与置位并发时, 清除可能覆盖
	/// 紧随其后的置位, 使某个 hart 漏掉一次失效; 计数只增不减, 各 hart 比较
	/// 取值即可判定, 多标记不影响正确性. 由此不必为跨 hart 失效发送核间中断.
	pub tlb_flush_cnt: AtomicU64,
	/// 各 hart 上次见到的 ``tlb_flush_cnt``. 与 ``tlb_flush_cnt`` 不相等时,
	/// 该 hart 在取下一条指令或访问数据之前把自己两个 TLB 的条目全部标为陈旧,
	/// 下一次访问重新遍历页表.
	pub tlb_flush_cnt_per_hart: Box<[AtomicU64]>,
	/// 调用方是否给出了上述两处计数的存放位置. 为真时计数跨调用保留, 引擎
	/// 进入执行循环时不清空任何条目. 为假时计数只在本轮内有效, 各 hart 在
	/// 进入执行循环之前清空自己的两个 TLB — 上一轮留下的条目是否仍然有效
	/// 没有判定依据.
	pub is_flush_cnt_persistent: bool,
	/// 每个 hart 的 LR 与 SC 预留内存空间. 用于保存该 hart 预留的物理地址,
	/// 0 表示没有预留. 任一存储指令写入同一物理地址时清除所有 hart 上匹配
	/// 的预留, 保证多 hart 下 LR 与 SC 的语义正确. RISC-V 规范 §8.2 规定:
	/// 某 hart 上成功的 SC 使该 hart 上的任何 LR 失效, 任何 hart 上成功的
	/// AMO、SC 或存储指令写入预留集合时, 使该 hart 上的任何 LR 失效.
	pub lr_reserved: Box<[AtomicU64]>,
	/// 每个 hart 的跨线程 MSIP 通知. 其余 hart 写入该 hart 的 CLINT MSIP 时,
	/// 在此处以 Release 原子地置位; 本 hart 的 ``sync_msip`` 以 swap(0, Acquire)
	/// 读出并清除, 再合并进 ``HartState.mip``. 这样避免了发送方直接写入与接收方
	/// ``sync_mtip`` 与 ``sync_msip`` 调用之间对 ``HartState.mip`` 的非原子读改写竞争.
	pub msip_pending: Box<[AtomicU64]>,
	pub st_time_val: std::time::Instant,
	/// ``marshal_hart`` 写入的 mtime 基准值.
	pub time_base_val: u64,
	/// 每 hart 在本轮加速执行开始时的指令计数, 由 ``marshal_hart`` 记录.
	/// ``advance_clock_source`` 用 ``state.total_instrs - instr_ref_num[hid]``
	pub instr_ref_num: Box<[u64]>,
}

impl ModuleState {
	pub fn new(
		num_harts: u32,
		active_hart_num: u32,
		init_flush_cnt: u64,
		init_flush_cnt_per_hart: Box<[u64]>,
		is_flush_cnt_persistent: bool,
		time_base_val: u64,
		instr_ref_num: Box<[u64]>,
	) -> Self {
		let mut v = Vec::with_capacity(num_harts as usize);
		let mut gv = Vec::with_capacity(num_harts as usize);
		let mut rv = Vec::with_capacity(num_harts as usize);
		let mut mv = Vec::with_capacity(num_harts as usize * MSIP_PENDING_STRIDE);
		for hid in 0..num_harts as usize {
			v.push(AtomicU8::new(0));
			gv.push(AtomicU64::new(init_flush_cnt_per_hart[hid]));
			rv.push(AtomicU64::new(0));
		}
		for _ in 0..num_harts as usize * MSIP_PENDING_STRIDE {
			mv.push(AtomicU64::new(0));
		}
		ModuleState {
			stop_flag: AtomicBool::new(false),
			stop_info: Mutex::new(StopInfo::empty()),
			wfi_count: AtomicU32::new(0),
			wfi_flags: v.into_boxed_slice(),
			active_hart_num,
			tlb_flush_cnt: AtomicU64::new(init_flush_cnt),
			tlb_flush_cnt_per_hart: gv.into_boxed_slice(),
			is_flush_cnt_persistent,
			lr_reserved: rv.into_boxed_slice(),
			msip_pending: mv.into_boxed_slice(),
			st_time_val: std::time::Instant::now(),
			time_base_val,
			instr_ref_num,
		}
	}

	/// 使能停止标志并记录原因. 只有第一个调用方生效, 后续调用方被忽略.
	pub fn request_stop(&self, info: StopInfo) {
		if self.stop_flag.swap(true, Ordering::Release) {
			return; // 已处于停止状态
		}
		if let Ok(mut guard) = self.stop_info.lock() {
			*guard = info;
		}
	}

	/// 判定未停机的 hart 是否全部处于 WFI 等待.
	#[inline]
	pub fn all_in_wfi(&self) -> bool {
		self.wfi_count.load(Ordering::Acquire) >= self.active_hart_num
	}
}
