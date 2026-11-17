/* enclave_abi.h - Linux 飞地设备的用户态接口.
 *
 * /dev/tee_enclave: 以 ioctl 管理飞地生命周期.
 * ioctl 经 SBI ecall 转入 OpenSBI 的 M 模式飞地扩展, 扩展标识 0x20221222.
 *
 * 本文件定义设备路径、SBI 功能号、ioctl 命令码、参数结构体与运行状态枚举,
 * 是驱动、评测工具与 M 模式固件之间共享的接口约定.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ENCLAVE_ABI_H
#define ENCLAVE_ABI_H

#include <stdint.h>
#include <sys/ioctl.h>

#define TEE_DEVICE_PATH "/dev/tee_enclave"
#define TEE_IOC_MAGIC	'T'

#define SBI_ENCLAVE_CREATE			  400
#define SBI_ENCLAVE_ENTER			  401
#define SBI_ENCLAVE_SHUTDOWN		  403
#define SBI_ENCLAVE_SUSPEND			  404
#define SBI_ENCLAVE_RESUME			  405
#define SBI_ENCLAVE_GET_ID			  407
#define SBI_ENCLAVE_GET_HARTID		  408
#define SBI_ENCLAVE_GET_AVAILABLE_MEM 409
#define SBI_ENCLAVE_REQUEST_SHUTDOWN  410
#define SBI_ENCLAVE_MEM_ALLOC		  500

#define SBI_ENCLAVE_MODULE_REQ	  503
#define SBI_ENCLAVE_MODULE_SIZE	  504
#define SBI_ENCLAVE_MODULE_IMG	  505
#define SBI_ENCLAVE_MODULE_RESULT 508

/* 创建飞地, 返回飞地编号. 成功时不返回: 控制已转入飞地, 调用方只在出错时
 * 看到返回值.
 */
#define TEE_IOC_CREATE _IO(TEE_IOC_MAGIC, 0)

/* 以载荷进入既有飞地.
 * 仅在飞地把控制交还宿主时返回, 或在调用期出错时返回. 交还原因见
 * enum tee_run_state.
 */
#define TEE_IOC_ENTER _IOW(TEE_IOC_MAGIC, 1, struct tee_enclave_args)

// 查询当前 mdid, 取值 0 表示宿主.
#define TEE_IOC_GET_ID _IOR(TEE_IOC_MAGIC, 2, uint64_t)

// 查询可用内存池, 单位为 2 MiB 分区.
#define TEE_IOC_GET_MEM _IOR(TEE_IOC_MAGIC, 3, struct tee_mem_info)

// 挂起当前飞地并返回宿主, 仅在飞地内有效.
#define TEE_IOC_SUSPEND _IO(TEE_IOC_MAGIC, 4)

/* 按编号恢复已挂起的飞地.
 * 返回规则与 TEE_IOC_ENTER 相同. 入参为 struct tee_enclave_token_args.
 */
#define TEE_IOC_RESUME _IOW(TEE_IOC_MAGIC, 5, struct tee_enclave_token_args)

/* 终止当前飞地: 清除内存, 释放槽位并执行 mfence.did.
 * 入参为 struct tee_enclave_token_args.
 *
 * 目标飞地正运行在其它 hart 上时不做同步终止: M 模式代为置位终止请求并向该
 * hart 发定向 IPI, 随后本调用在 M 模式内等待到该编号的飞地不再存在, 故返回时
 * 该飞地已不存在. 终止结果由该 hart 上阻塞中的 ENTER 或 RESUME 回传. 只请求
 * 终止而不等待其结果时用 TEE_IOC_REQUEST_SHUTDOWN.
 */
#define TEE_IOC_SHUTDOWN _IOW(TEE_IOC_MAGIC, 6, struct tee_enclave_token_args)

/* 请求持有该飞地的 hart 自行终止它.
 * 与 TEE_IOC_SHUTDOWN 的分工: 本命令只表示请求已受理并经 IPI 送达, 不返回终止
 * 结果; 令牌在 M 模式锁内校验通过后才置位. 飞地经 SBI 411 读到该请求后走自退出
 * 路径.
 */
#define TEE_IOC_REQUEST_SHUTDOWN                                                    \
	_IOWR(TEE_IOC_MAGIC, 7, struct tee_enclave_token_args)

/* 与 TEE_IOC_CREATE 相同, 但由宿主指定管理令牌: 令牌为入参, 新飞地编号为出参.
 * TEE_IOC_CREATE 登记的令牌恒为 0, 需要真令牌时改用本命令.
 */
#define TEE_IOC_CREATE_EX _IOWR(TEE_IOC_MAGIC, 8, struct tee_enclave_token_args)

/* 模块三个命令共用 struct tee_enclave_args, 各自的专属字段在该结构的匿名 union
 * 中按命令取用. 505 的映像缓冲区经内核缓冲区中转, 因为 M 模式只读取 U=0 的页.
 */
#define TEE_IOC_MODULE_REQ	_IOWR(TEE_IOC_MAGIC, 9, struct tee_enclave_args)
#define TEE_IOC_MODULE_SIZE _IOWR(TEE_IOC_MAGIC, 10, struct tee_enclave_args)
#define TEE_IOC_MODULE_IMG	_IOWR(TEE_IOC_MAGIC, 11, struct tee_enclave_args)

/* 模块请求的类别, 与 M 模式的 ENCLAVE_MODULE_KIND_* 一致. 宿主按类别决定
 * 报告映像字节数还是交付映像. */
#define TEE_MODULE_KIND_NONE 0
#define TEE_MODULE_KIND_SIZE 1
#define TEE_MODULE_KIND_LOAD 2

/* 交付结果, 与 M 模式的 ENCLAVE_MODULE_STATUS_* 一致. */
#define TEE_MODULE_STATUS_NONE	 0 /* 尚无结果 */
#define TEE_MODULE_STATUS_OK	 1 /* 映像已写入接收缓冲区 */
#define TEE_MODULE_STATUS_NOENT	 2 /* 模块不存在, 宿主报告的字节数为 0 */
#define TEE_MODULE_STATUS_WRFAIL 3 /* 交付的字节数与报告的不符, 或写入失败 */

/* 模块编号取该值表示无挂起请求. */
#define TEE_MODULE_ID_NONE 0xFFFFFFFFULL

/* ---- ENTER 与 RESUME 的 ioctl 返回值: 飞地运行状态 ----
 *
 * M 模式把控制交还宿主时, 按 SBI 返回规范把本次运行的状态枚举填入 a1, 即
 * sbiret.value; a0 仅在调用期出错时为负错误码. 驱动据此把 ENTER 与 RESUME 的
 * ioctl 返回值定义为 enum tee_run_state:
 *
 *   rc >= 0: 控制已交还宿主, rc 即枚举值;
 *   rc < 0: 调用期失败, 取值为 errno, 载荷未被转入运行, 无状态可读.
 *
 * 该枚举描述飞地此刻处于哪种情形, 由发起方与退出码两部分构成, 不是成功或失败
 * 的结论; 调用方据此决定继续 RESUME、判成功或判失败.
 *
 * 调用期失败的错误码中有两个为本扩展专有, 须与本飞地的运行状态区分开:
 *   EBUSY  该编号飞地的请求队列已存满. M 模式回 SBI_ERR_ENCLAVE_QUEUE_FULL,
 *          驱动折算为 EBUSY. 本次请求未被受理, 已排队的请求不受影响, 稍后重试
 *          可被受理;
 *   ENOENT 等待期间该编号的飞地已被终止. M 模式回 SBI_ERR_ENCLAVE_GONE, 驱动
 *          折算为 ENOENT. 重试同一编号不会成功.
 * 资源暂不可得本身不构成失败: 请求方 hart 在 M 模式内按到达顺序等待, 条件成立
 * 才继续把这次请求做完, 故返回之时结果已在手中, 调用方不需要重试循环.
 */
enum tee_run_state {
	TEE_RUN_SUSPENDED  = 0, /* 时间片配额让出: 载荷存活挂起, 应 RESUME 继续 */
	TEE_RUN_EXITED	   = 1, /* 载荷经 SHUTDOWN 自行结束, 退出码为 0 */
	TEE_RUN_EXITED_ERR = 2, /* 载荷经 SHUTDOWN 自行结束, 退出码非 0 */
	TEE_RUN_ABORTED	   = 3, /* 仅在终止类别落在枚举之外时写入, 当前不可达 */
	TEE_RUN_HOST_KILL  = 4, /* 宿主请求终止, 载荷未运行到退出 */
};

/* ---- ENTER 与 RESUME 返回值的退出码解包 ----
 *
 * 载荷自行结束时, M 模式把退出码打包进 a1 的高 32 位, 低 32 位仍为
 * enum tee_run_state 的取值. 宿主以如下宏拆分 ioctl 返回值:
 *   TEE_RUN_STATE(rc) 取低 32 位, 与 enum tee_run_state 比较;
 *   TEE_EXIT_CODE(rc) 取高 32 位, 仅 EXITED_ERR 时非零.
 * 其余状态 SUSPENDED、ABORTED 与 HOST_KILL 的高 32 位恒为 0. 调用期失败
 * rc < 0 时无打包语义, 不应调用解包宏.
 */
#define TEE_RUN_STATE(rc) ((int)((rc) & 0xFFFFFFFFULL))
#define TEE_EXIT_CODE(rc) ((uint64_t)((rc) >> 32))

struct tee_mem_info {
	uint64_t free_total;	 /* 空闲的 2 MiB 分区数 */
	uint64_t max_contiguous; /* 最大连续空闲分区数 */
};

/* 以管理令牌鉴权的宿主侧命令参数.
 *
 * 飞地编号与创建时登记的管理令牌这一对字段由 CREATE_EX、SHUTDOWN、RESUME 与
 * REQUEST_SHUTDOWN 四者共用. CREATE_EX 的 enclave_id 为出参, 令牌为入参;
 * 其余三者的两个字段均为入参. TEE_IOC_CREATE 登记的令牌恒为 0, 需要真令牌时
 * 用 TEE_IOC_CREATE_EX. */
struct tee_enclave_token_args {
	uint64_t enclave_id; /* 目标飞地编号; CREATE_EX 时为出参, 返回新飞地编号 */
	uint64_t token;		 /* 创建时登记的管理令牌 */
};

/* ENTER 与模块三个命令 MODULE_REQ、MODULE_SIZE、MODULE_IMG 共用的参数结构体.
 * enclave_id 与 token 为四者共有的入参: token 是创建该飞地时登记的管理令牌,
 * M 模式在锁内比对后才载入飞地. 各命令的专属字段在匿名 union 中按命令取用.
 * 505 号调用交付的字节写入该飞地 S 模式运行时经 509 号调用登记的接收缓冲区,
 * 其物理地址按该运行时自己的页表查询得到, 宿主不指定. */
struct tee_enclave_args {
	uint64_t enclave_id;
	uint64_t token;
	union {
		/* ENTER: 载荷指针、载荷长度与交给载荷的 argv. */
		struct {
			uint64_t payload_ptr;
			uint64_t payload_size;
			uint64_t argc;
			uint64_t argv_ptr;
		} enter;
		/* MODULE_REQ: 模块编号与请求类别均为出参. */
		struct {
			uint64_t module_id;
			uint64_t kind;
		} req;
		/* MODULE_SIZE: size 为入参, 取 0 表示宿主侧不存在该模块; status 为
		 * 出参. */
		struct {
			uint64_t size;
			uint64_t status;
		} size;
		/* MODULE_IMG: buf_ptr 与 size 为入参, 指向用户缓冲区; status 与 pa 为
		 * 出参. 505 号调用还以 a2 回传实际写入的字节数, 而内核的 sbi_ecall
		 * 只取回 a0 与 a1, 故该值不回传用户态; 成功时它等于入参 size, 飞地侧
		 * 另经 508 号调用读取它. */
		struct {
			uint64_t buf_ptr;
			uint64_t size;
			uint64_t status;
			uint64_t pa;
		} image;
	};
};

#endif /* ENCLAVE_ABI_H */
