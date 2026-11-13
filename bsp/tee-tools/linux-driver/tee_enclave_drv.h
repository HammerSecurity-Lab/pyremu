/*
    tee_enclave_drv.h — /dev/tee_enclave 的 ABI 声明

    本头文件声明驱动与用户态共用的 SBI 调用号、ioctl 命令号与参数结构体,
    实现留在 tee_enclave_drv.c.

    SPDX-License-Identifier: MIT
 */

#ifndef TEE_ENCLAVE_DRV_H
#define TEE_ENCLAVE_DRV_H

#include <linux/ioctl.h>

#define SBI_ENCLAVE_EXT_ID	 0x20221222ULL
#define SBI_ENCLAVE_CREATE	 400
#define SBI_ENCLAVE_ENTER	 401
#define SBI_ENCLAVE_SHUTDOWN 403
#define SBI_ENCLAVE_SUSPEND	 404
#define SBI_ENCLAVE_RESUME	 405
#define SBI_ENCLAVE_GET_ID	 407
#define SBI_ENCLAVE_GET_MEM	 409

/* 410 需两个参数 (enclave_id, mgmt_token), 见 request_shutdown.c. */
#define SBI_ENCLAVE_REQUEST_SHUTDOWN 410
/*
 *503 至 505: 宿主应答飞地挂起的模块请求, 三者均以 "飞地编号 + 管理令牌" 作为输入进行鉴权
*/
#define SBI_ENCLAVE_MODULE_REQ	503
#define SBI_ENCLAVE_MODULE_SIZE 504
#define SBI_ENCLAVE_MODULE_IMG	505

// Linux TEE 驱动调用号及魔数声明
#define TEE_IOC_MAGIC			 'T'
#define TEE_IOC_CREATE			 _IO(TEE_IOC_MAGIC, 0)
#define TEE_IOC_ENTER			 _IOW(TEE_IOC_MAGIC, 1, struct tee_enclave_args)
#define TEE_IOC_GET_ID			 _IOR(TEE_IOC_MAGIC, 2, unsigned long long)
#define TEE_IOC_GET_MEM			 _IOR(TEE_IOC_MAGIC, 3, struct tee_mem_info)
#define TEE_IOC_SUSPEND			 _IO(TEE_IOC_MAGIC, 4)
#define TEE_IOC_RESUME			 _IOW(TEE_IOC_MAGIC, 5, struct tee_enclave_token_args)
#define TEE_IOC_SHUTDOWN		 _IOW(TEE_IOC_MAGIC, 6, struct tee_enclave_token_args)
#define TEE_IOC_REQUEST_SHUTDOWN _IOWR(TEE_IOC_MAGIC, 7, struct tee_enclave_token_args)
#define TEE_IOC_CREATE_EX		 _IOWR(TEE_IOC_MAGIC, 8, struct tee_enclave_token_args)
#define TEE_IOC_MODULE_REQ		 _IOWR(TEE_IOC_MAGIC, 9, struct tee_enclave_args)
#define TEE_IOC_MODULE_SIZE		 _IOWR(TEE_IOC_MAGIC, 10, struct tee_enclave_args)
#define TEE_IOC_MODULE_IMG		 _IOWR(TEE_IOC_MAGIC, 11, struct tee_enclave_args)

/* argv 长度上限: 防止超大 argc 或超长字符串作为恶意输入. */
#define TEE_MAX_ARGC	  128
#define TEE_MAX_ARGSTRLEN 4096

/* 飞地扩展专用的两个 SBI 错误码, 取值与固件的 enclave_types.h 一致.
   两者都不在asm/sbi.h 内故需要在此定义. */
#define SBI_ERR_ENCLAVE_QUEUE_FULL (-15)
#define SBI_ERR_ENCLAVE_GONE	   (-16)

/*
 * 模块请求的类别, 与 M 模式 ENCLAVE_MODULE_KIND_ 及用户态 tee_module_kind 对应.
 */
#define TEE_MODULE_KIND_NONE 0
#define TEE_MODULE_KIND_SIZE 1
#define TEE_MODULE_KIND_LOAD 2

/* 模块编号取该值表示无挂起请求. */
#define TEE_MODULE_ID_NONE 0xFFFFFFFFULL

struct tee_mem_info {
	unsigned long long free_total;
	unsigned long long max_contiguous;
};

/* {enclave_id, tee_token}被 CREATE_EX(400)、SHUTDOWN(403)、RESUME(405)、REQUEST_SHUTDOWN(410)
 * 共用, 令牌由M模式通过比对后才执行.
 *
 * CREATE_EX 的 enclave_id 是出参 (令牌入参), 其余三者两者皆入参;
 * 沿用 ABI 的 TEE_IOC_CREATE 只能登记令牌 0,
 * 故需要真令牌时用 TEE_IOC_CREATE_EX.
 */
struct tee_enclave_token_args {
	unsigned long long enclave_id;
	unsigned long long token;
};

/* ENTER 与模块三个命令 (MODULE_REQ / MODULE_SIZE / MODULE_IMG) 共用的参数结构体.
 * M 模式在进入临界区比对成功后，才会载入飞地;
 * 各命令的专属字段在匿名 union 中按命令取用. 505 号调用交付的字节写入该飞地的
 * S 模式运行时经 509 号调用登记的接收缓冲区, 其物理地址按该运行时自己的页表查询
 * 得到, 宿主不指定. */
struct tee_enclave_args {
	unsigned long long enclave_id;
	unsigned long long token;
	union {
		/* ENTER: 载荷指针与长度, 以及交给载荷的 argv. */
		struct {
			unsigned long long payload_ptr;
			unsigned long long payload_size;
			unsigned long long argc;
			unsigned long long argv_ptr;
		} enter;
		/* MODULE_REQ: 模块编号与请求类别均为出参. */
		struct {
			unsigned long long module_id;
			unsigned long long kind;
		} req;
		/* MODULE_SIZE: size 为入参, 取 0 表示宿主侧不存在该模块; status 为出参. */
		struct {
			unsigned long long size;
			unsigned long long status;
		} size;
		/* MODULE_IMG: buf_ptr 与 size 为入参, 其余为出参.
		 * 505 号调用还以 a2 回传实际写入的字节数, 而内核的 sbi_ecall 只取回
		 * a0 与 a1, 故该值不回传用户态; 成功时它等于入参 size,
         * 飞地侧另经 508 号调用读取它.
         */
		struct {
			unsigned long long buf_ptr;
			unsigned long long size;
			unsigned long long status;
			unsigned long long pa;
		} image;
	};
};

#endif /* TEE_ENCLAVE_DRV_H */
