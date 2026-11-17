//! 指令执行: 取指解码、扩展判定、分派与本机实现的运算.

pub mod alu;
pub mod atom_instr;
pub mod check_ext_isa;
pub mod decode;
pub mod exec;
pub mod fetch;
pub mod fpu;
pub mod handlers;
pub mod op_dispatcher;

/// 单条指令执行完毕后由工作线程采取的下一步动作.
pub(crate) enum Step {
	/// 进入下一个流水线阶段.
	Next,
	/// 回到主循环开头.
	Continue,
	/// 立即退出工作函数.
	Exit,
}
