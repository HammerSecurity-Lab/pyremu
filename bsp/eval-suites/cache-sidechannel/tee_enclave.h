/* tee_enclave.h - Linux TEE enclave driver userspace interface
 *
 * /dev/tee_enclave: ioctl-based enclave lifecycle management.
 * SBI ecall (ext_id=0x20221222) bridges to OpenSBI M-mode enclave extension.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef TEE_ENCLAVE_H
#define TEE_ENCLAVE_H

#include <stdint.h>
#include <sys/ioctl.h>

#define TEE_DEVICE_PATH "/dev/tee_enclave"

/* SBI function IDs  */
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
/* 503 至 505: 宿主应答飞地挂起的模块请求, 三者均以 "飞地编号 + 管理令牌" 鉴权.
 * 508 为飞地侧调用: 取回本模块的交付结果. */
#define SBI_ENCLAVE_MODULE_REQ	  503
#define SBI_ENCLAVE_MODULE_SIZE	  504
#define SBI_ENCLAVE_MODULE_IMG	  505
#define SBI_ENCLAVE_MODULE_RESULT 508

/* ---- ioctl command codes ---- */

#define TEE_IOC_MAGIC 'T'

#define TEE_IOC_GET_ID	_IOR(TEE_IOC_MAGIC, 2, uint64_t)
#define TEE_IOC_GET_MEM _IOR(TEE_IOC_MAGIC, 3, struct tee_mem_info)

#define TEE_IOC_CREATE	 _IO(TEE_IOC_MAGIC, 0)
#define TEE_IOC_ENTER	 _IOW(TEE_IOC_MAGIC, 1, struct tee_enclave_args)
#define TEE_IOC_SUSPEND	 _IO(TEE_IOC_MAGIC, 4)
#define TEE_IOC_RESUME	 _IOW(TEE_IOC_MAGIC, 5, struct tee_enclave_token_args)
#define TEE_IOC_SHUTDOWN _IOW(TEE_IOC_MAGIC, 6, struct tee_enclave_token_args)
#define TEE_IOC_REQUEST_SHUTDOWN                                                    \
	_IOWR(TEE_IOC_MAGIC, 7, struct tee_enclave_token_args)
#define TEE_IOC_CREATE_EX _IOWR(TEE_IOC_MAGIC, 8, struct tee_enclave_token_args)

/* 模块三个命令共用 struct tee_enclave_args, 各自的专属字段在其中的匿名 union 中
 * 按命令取用. 505 的映像缓冲区经内核缓冲区中转 (M 模式只读 U=0 的页). */
#define TEE_IOC_MODULE_REQ	_IOWR(TEE_IOC_MAGIC, 9, struct tee_enclave_args)
#define TEE_IOC_MODULE_SIZE _IOWR(TEE_IOC_MAGIC, 10, struct tee_enclave_args)
#define TEE_IOC_MODULE_IMG	_IOWR(TEE_IOC_MAGIC, 11, struct tee_enclave_args)

enum tee_run_state {
	TEE_RUN_SUSPENDED =
		0, /* 时间片配额让出: 载荷存活挂起, 应 RESUME 继续 (非终止) */
	TEE_RUN_EXITED	   = 1, /* 载荷自行结束 (SHUTDOWN), 退出码 0: 自然跑完 */
	TEE_RUN_EXITED_ERR = 2, /* 载荷自行结束 (SHUTDOWN), 退出码非 0: 载荷自报出错 */
	TEE_RUN_ABORTED	   = 3, /* 仅在终止类别落在枚举之外时写入, 当前不可达 */
	TEE_RUN_HOST_KILL  = 4, /* host 请求终止, 载荷未运行到退出 */
};

#define TEE_RUN_STATE(rc) ((int)((rc) & 0xFFFFFFFFULL))
#define TEE_EXIT_CODE(rc) ((uint64_t)((rc) >> 32))

struct tee_mem_info {
	uint64_t free_total;	 /* free 2 MiB partitions */
	uint64_t max_contiguous; /* largest contiguous run */
};

struct tee_enclave_token_args {
	uint64_t enclave_id; /* 目标飞地 id (CREATE_EX 时为出参: 新飞地 id) */
	uint64_t token;		 /* 创建时登记的管理令牌 */
};

/* 模块请求的类别, 与 M 模式的 ENCLAVE_MODULE_KIND_* 一致. 宿主按类别决定是
 * 报告映像字节数还是交付映像. */
#define TEE_MODULE_KIND_NONE 0
#define TEE_MODULE_KIND_SIZE 1
#define TEE_MODULE_KIND_LOAD 2

/* 交付款项的结果, 与 M 模式的 ENCLAVE_MODULE_STATUS_* 一致. */
#define TEE_MODULE_STATUS_NONE	 0 /* 尚无结果 */
#define TEE_MODULE_STATUS_OK	 1 /* 映像已写入接收缓冲区 */
#define TEE_MODULE_STATUS_NOENT	 2 /* 模块不存在 (宿主报告字节数为 0) */
#define TEE_MODULE_STATUS_WRFAIL 3 /* 交付的字节数与报告的不符, 或写入失败 */

/* 模块编号取该值表示无挂起请求. */
#define TEE_MODULE_ID_NONE 0xFFFFFFFFULL

/* ENTER 与模块三个命令 (MODULE_REQ / MODULE_SIZE / MODULE_IMG) 共用的参数结构体.
 * enclave_id 与 token 为四者共有的入参: token 是创建该飞地时登记的管理令牌,
 * M 模式在锁内比对后才载入飞地; 各命令的专属字段在匿名 union 中按命令取用.
 * 505 号调用交付的字节写入该飞地的 S 模式运行时经 509 号调用登记的接收缓冲区,
 * 其物理地址按该运行时自己的页表查询得到, 宿主不指定. */
struct tee_enclave_args {
	uint64_t enclave_id;
	uint64_t token;
	union {
		/* ENTER: 载荷指针与长度, 以及交给载荷的 argv. */
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
		/* MODULE_SIZE: size 为入参, 取 0 表示宿主侧不存在该模块; status 为出参. */
		struct {
			uint64_t size;
			uint64_t status;
		} size;
		/* MODULE_IMG: buf_ptr 与 size 为入参 (用户缓冲区), 其余为出参.
		 * 505 号调用还以 a2 回传实际写入的字节数, 而内核的 sbi_ecall 只取回
		 * a0 与 a1, 故该值不回传用户态; 成功时它等于入参 size, 飞地侧另经
		 * 508 号调用读取它. */
		struct {
			uint64_t buf_ptr;
			uint64_t size;
			uint64_t status;
			uint64_t pa;
		} image;
	};
};

#endif /* TEE_ENCLAVE_H */
