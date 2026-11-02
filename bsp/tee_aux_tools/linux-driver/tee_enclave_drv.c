/*
    tee_enclave_drv.c — Linux enclave management driver

    本驱动的 ENTER/RESUME ioctl 直接以该枚举作为返回值:
      rc >= 0 表示控制已交还 host, rc 即枚举值;
      rc < 0 为调用期失败 (errno), 载荷未被转入运行.
      其余 ioctl (CREATE/SUSPEND/SHUTDOWN) 保持 rc < 0 为错误否则 0 的既有语义.

    SPDX-License-Identifier: MIT
 */

#include <asm/sbi.h>
#include <linux/context_tracking.h>
#include <linux/fs.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "tee_enclave_drv.h"

#define DEVICE_NAME "tee_enclave"

/*
 * tee_guest_enter 让 RCU 不再等待本 hart 进入 RCU 扩展静默态,
 * tee_guest_exit 在控制交还后恢复. 两者要求关中断 且 current->mm 非空.
 * 关中断同时使这期间到达的宿主 IPI 推迟到控制交还之后处理.
 *
 * 用 local_irq_save/restore 而非 disable/enable: 交还与进入时的中断状态一致.
 */
static inline unsigned long tee_guest_enter(void) {
	unsigned long flags;

	preempt_disable();
	local_irq_save(flags);
	context_tracking_guest_enter();
	return flags;
}

static inline void tee_guest_exit(unsigned long flags) {
	context_tracking_guest_exit();
	local_irq_restore(flags);
	preempt_enable();
}

static inline struct sbiret sbi_enclave_ecall_5(
	unsigned long func_id,
	unsigned long a0_val,
	unsigned long a1_val,
	unsigned long a2_val,
	unsigned long a3_val,
	unsigned long a4_val
) {
	return sbi_ecall(
		SBI_ENCLAVE_EXT_ID, func_id, a0_val, a1_val, a2_val, a3_val, a4_val, 0
	);
}

/* ENTER 需六个参数:
 * a0..a4 为 enclave_id,argc,argv,payload地址,载荷长度,
 * a5 为管理令牌.
 */
static inline struct sbiret sbi_enclave_ecall_6(
	unsigned long func_id,
	unsigned long a0_val,
	unsigned long a1_val,
	unsigned long a2_val,
	unsigned long a3_val,
	unsigned long a4_val,
	unsigned long a5_val
) {
	return sbi_ecall(
		SBI_ENCLAVE_EXT_ID, func_id, a0_val, a1_val, a2_val, a3_val, a4_val, a5_val
	);
}

static inline struct sbiret sbi_enclave_ecall_2(
	unsigned long func_id,
	unsigned long a0_val,
	unsigned long a1_val
) {
	return sbi_ecall(SBI_ENCLAVE_EXT_ID, func_id, a0_val, a1_val, 0, 0, 0, 0);
}

/* MODULE_SIZE: a0..a2 为 enclave_id,token,映像字节数. */
static inline struct sbiret sbi_enclave_ecall_3(
	unsigned long func_id,
	unsigned long a0_val,
	unsigned long a1_val,
	unsigned long a2_val
) {
	return sbi_ecall(SBI_ENCLAVE_EXT_ID, func_id, a0_val, a1_val, a2_val, 0, 0, 0);
}

/* MODULE_IMG: a0..a3 为 enclave_id,token,宿主缓冲区地址,映像字节数. */
static inline struct sbiret sbi_enclave_ecall_4(
	unsigned long func_id,
	unsigned long a0_val,
	unsigned long a1_val,
	unsigned long a2_val,
	unsigned long a3_val
) {
	return sbi_ecall(SBI_ENCLAVE_EXT_ID, func_id, a0_val, a1_val, a2_val, a3_val, 0, 0);
}

static inline struct sbiret sbi_enclave_ecall_0(unsigned long func_id) {
	return sbi_ecall(SBI_ENCLAVE_EXT_ID, func_id, 0, 0, 0, 0, 0, 0);
}

static inline struct sbiret sbi_enclave_ecall_1(
	unsigned long func_id,
	unsigned long a0_val
) {
	return sbi_ecall(SBI_ENCLAVE_EXT_ID, func_id, a0_val, 0, 0, 0, 0, 0);
}

static int serialize_argv(
	unsigned long long argv_ptr,
	unsigned long long argc,
	void **out_buf
) {
	unsigned long *uargv = NULL;
	size_t *lens		 = NULL;
	void *buf			 = NULL;
	int rc				 = 0;

	*out_buf = NULL;
	if (argc == 0 || argv_ptr == 0) {
		return 0;
	}
	if (argc > TEE_MAX_ARGC) {
		return -E2BIG;
	}

	size_t nargc = (size_t)argc;

	uargv = kmalloc_array(nargc, sizeof(unsigned long), GFP_KERNEL);
	if (!uargv) {
		return -ENOMEM;
	}
	if (
		copy_from_user(
			uargv, (void __user *)(unsigned long)argv_ptr,
			nargc * sizeof(unsigned long)
		) //
	) {
		rc = -EFAULT;
		goto out;
	}

	lens = kmalloc_array(nargc, sizeof(size_t), GFP_KERNEL);
	if (!lens) {
		rc = -ENOMEM;
		goto out;
	}
	size_t total = nargc * sizeof(unsigned long);
	for (size_t i = 0; i < nargc; i++) {
		long n = strnlen_user((char __user *)uargv[i], TEE_MAX_ARGSTRLEN);
		if (n == 0) {
			rc = -EFAULT;
			goto out;
		}
		if (n > TEE_MAX_ARGSTRLEN) {
			rc = -E2BIG;
			goto out;
		}
		lens[i] = (size_t)n;
		total += (size_t)n;
	}

	buf = vmalloc(total);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	unsigned long *slots = buf;
	char *strs			 = (char *)(slots + nargc);
	size_t off			 = 0;
	for (size_t i = 0; i < nargc; i++) {
		slots[i] = (unsigned long)(strs + off);
		if (copy_from_user(strs + off, (char __user *)uargv[i], lens[i])) {
			vfree(buf);
			buf = NULL;
			rc	= -EFAULT;
			goto out;
		}
		off += lens[i];
	}

	*out_buf = buf;
	buf		 = NULL;

out:
	kfree(lens);
	kfree(uargv);
	return rc;
}

/* SBI 错误码解释 */
static int sbi_err_to_errno(long err) {
	switch (err) {
	case SBI_ERR_FAILURE:
		return -EIO;
	case SBI_ERR_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case SBI_ERR_INVALID_PARAM:
	case SBI_ERR_INVALID_STATE:
		return -EINVAL;
	case SBI_ERR_DENIED:
	case SBI_ERR_DENIED_LOCKED:
		return -EACCES;
	case SBI_ERR_INVALID_ADDRESS:
		return -EFAULT;
	case SBI_ERR_ALREADY_AVAILABLE:
	case SBI_ERR_ALREADY_STARTED:
	case SBI_ERR_ALREADY_STOPPED:
		return -EALREADY;
	case SBI_ERR_NO_SHMEM:
		return -ENOMEM;
	case SBI_ERR_BAD_RANGE:
		return -ERANGE;
	case SBI_ERR_TIMEOUT:
		return -ETIMEDOUT;
	case SBI_ERR_ENCLAVE_QUEUE_FULL:
		/* 请求队列已存满: 本次请求未被受理, 已排队的请求不受影响, 稍后重试可被受理. */
		return -EBUSY;
	case SBI_ERR_ENCLAVE_GONE:
		/* 等待期内该编号的飞地已被终止: 该对象不再存在, 重试同一编号不会成功. */
		return -ENOENT;
	case SBI_ERR_IO:
	default:
		return -EIO;
	}
}

static long tee_ioctl(
	struct file *filp,
	unsigned int cmd,
	unsigned long arg
) {
	struct sbiret ret;
	long rc = 0;

	switch (cmd) {

	/* CREATE: 创建新可信应用并移交执行权 */
	case TEE_IOC_CREATE: {
		unsigned long ct_flags = tee_guest_enter();
		ret					   = sbi_enclave_ecall_0(SBI_ENCLAVE_CREATE);
		tee_guest_exit(ct_flags);
		/* CREATE enters the enclave; SUSPEND returns with a0 = enclave_id.
         * Negative a0 = SBI error, positive a0 = enclave_id on success. */
		if ((long)ret.error < 0) {
			pr_err("tee_enclave: CREATE(400) failed, error=%ld\n", ret.error);
			return sbi_err_to_errno((long)ret.error);
		}
		/* Write enclave_id back to userspace args[0]. */
		if (copy_to_user((void __user *)arg, &ret.error, sizeof(unsigned long long))) {
			return -EFAULT;
		}
		return 0;
	}

	/* ---- ENTER: load payload into existing enclave and enter it ---- */
	case TEE_IOC_ENTER: {
		struct tee_enclave_args kargs;
		void *payload_buf = NULL;
		void *argv_buf	  = NULL;

		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}

		if (kargs.enter.payload_size == 0 || kargs.enter.payload_size > (128UL << 20)) {
			return -EINVAL;
		}

		/* 将载荷从用户空间复制到内核空间 */
		payload_buf = vmalloc(kargs.enter.payload_size);
		if (!payload_buf) {
			return -ENOMEM;
		}

		if (copy_from_user(
				payload_buf, (void __user *)(unsigned long)kargs.enter.payload_ptr,
				kargs.enter.payload_size
			)) {
			rc = -EFAULT;
			goto out_free_payload;
		}

		/* 序列化参数. */
		rc = serialize_argv(kargs.enter.argv_ptr, kargs.enter.argc, &argv_buf);
		if (rc < 0) {
			goto out_free_payload;
		}

		unsigned long ct_flags = tee_guest_enter();
		ret					   = sbi_enclave_ecall_6(
			SBI_ENCLAVE_ENTER, kargs.enclave_id, kargs.enter.argc,
			(unsigned long)argv_buf, (unsigned long)payload_buf, kargs.enter.payload_size,
			kargs.token
		);
		tee_guest_exit(ct_flags);

		if ((long)ret.error < 0) {
			pr_err("tee_enclave: ENTER(401) failed, error=%ld\n", ret.error);
			rc = sbi_err_to_errno((long)ret.error);
		} else {
			rc = (long)ret.value;
		}

	out_free_payload:
		vfree(argv_buf);
		vfree(payload_buf);
		return rc;
	}

	/* ---- GET_ID: 获取当前mdid的值 */
	case TEE_IOC_GET_ID: {
		ret = sbi_enclave_ecall_0(SBI_ENCLAVE_GET_ID);
		/* a0 = 当前mdid的取值 */
		if (copy_to_user((void __user *)arg, &ret.error, sizeof(unsigned long long))) {
			return -EFAULT;
		}
		return 0;
	}

	// GET_MEM: 查询可信应用内存池可用的容量
	case TEE_IOC_GET_MEM: {
		struct tee_mem_info info;
		ret = sbi_enclave_ecall_0(SBI_ENCLAVE_GET_MEM);
		/*
            a0 = free_total,
            a1 = max_contiguous
        */
		info.free_total		= ret.error;
		info.max_contiguous = ret.value;
		if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
			return -EFAULT;
		}
		return 0;
	}

	/* ---- SUSPEND: yield from enclave back to host ---- */
	case TEE_IOC_SUSPEND: {
		ret = sbi_enclave_ecall_0(SBI_ENCLAVE_SUSPEND);
		/* SUSPEND returns a0 = enclave_id on success (>0),
         * a0 < 0 on failure.  skip_regs_update=1 so mepc is already advanced. */
		if ((long)ret.error < 0) {
			pr_err("tee_enclave: SUSPEND(404) failed, error=%ld\n", ret.error);
			return sbi_err_to_errno((long)ret.error);
		}
		return 0;
	}

	// RESUME: 按照enclave_id尝试恢复其执行
	case TEE_IOC_RESUME: {
		struct tee_enclave_token_args kargs;

		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}
		unsigned long ct_flags = tee_guest_enter();
		ret = sbi_enclave_ecall_2(SBI_ENCLAVE_RESUME, kargs.enclave_id, kargs.token);
		tee_guest_exit(ct_flags);
		if ((long)ret.error < 0) {
			pr_err(
				"tee_enclave: RESUME(405) id=%llu failed, error=%ld\n", kargs.enclave_id,
				ret.error
			);
			rc = sbi_err_to_errno((long)ret.error);
		} else {
			/* 同 ENTER: 控制已交还 host, a1 即运行状态枚举 tee_run_state. */
			rc = (long)ret.value;
		}
		return rc;
	}

	case TEE_IOC_SHUTDOWN: {
		struct tee_enclave_token_args kargs;
		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}
		unsigned long ct_flags = tee_guest_enter();
		ret = sbi_enclave_ecall_2(SBI_ENCLAVE_SHUTDOWN, kargs.enclave_id, kargs.token);
		tee_guest_exit(ct_flags);
		if ((long)ret.error < 0) {
			pr_err(
				"tee_enclave: SHUTDOWN(403) id=%llu failed, error=%ld\n",
				kargs.enclave_id, ret.error
			);
			return sbi_err_to_errno((long)ret.error);
		}
		return 0;
	}

	case TEE_IOC_CREATE_EX: {
		struct tee_enclave_token_args kargs;

		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}

		/* a0 = 管理令牌; M 模式在进入飞地前读取并存进 meta. */
		unsigned long ct_flags = tee_guest_enter();
		ret					   = sbi_enclave_ecall_1(SBI_ENCLAVE_CREATE, kargs.token);
		tee_guest_exit(ct_flags);
		if ((long)ret.error < 0) {
			pr_err("tee_enclave: CREATE_EX(400) failed, error=%ld\n", ret.error);
			return sbi_err_to_errno((long)ret.error);
		}
		/* 同 CREATE: 成功时 a0 为 enclave_id. */
		kargs.enclave_id = (unsigned long long)ret.error;
		if (copy_to_user((void __user *)arg, &kargs, sizeof(kargs))) {
			return -EFAULT;
		}
		return 0;
	}

	// REQUEST_SHUTDOWN: 请求持有飞地的 hart 终止
	case TEE_IOC_REQUEST_SHUTDOWN: {
		struct tee_enclave_token_args kargs;

		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}

		ret = sbi_enclave_ecall_2(
			SBI_ENCLAVE_REQUEST_SHUTDOWN, kargs.enclave_id, kargs.token
		);
		if ((long)ret.error < 0) {
			pr_err(
				"tee_enclave: REQUEST_SHUTDOWN(410) id=%llu failed, error=%ld\n",
				kargs.enclave_id, ret.error
			);
			return sbi_err_to_errno((long)ret.error);
		}
		return 0;
	}

	/*
     * MODULE_REQ: 取回飞地挂起的模块请求 (503)
	 * 读取映像文件失败后可在下次 RESUME 循环中重试
	*/
	case TEE_IOC_MODULE_REQ: {
		struct tee_enclave_args kargs;

		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}

		ret = sbi_enclave_ecall_2(SBI_ENCLAVE_MODULE_REQ, kargs.enclave_id, kargs.token);
		if ((long)ret.error < 0) {
			pr_err(
				"tee_enclave: MODULE_REQ(503) id=%llu failed, error=%ld\n",
				kargs.enclave_id, ret.error
			);
			return sbi_err_to_errno((long)ret.error);
		}
		kargs.req.module_id = (unsigned long long)ret.error;
		kargs.req.kind		= (unsigned long long)ret.value;
		if (copy_to_user((void __user *)arg, &kargs, sizeof(kargs))) {
			return -EFAULT;
		}
		return 0;
	}

	/* ---- MODULE_SIZE: 报告映像字节数 (504) ----
	 *
	 * size 取 0 表示宿主侧不存在该模块, 由 M 模式记入交付结果供飞地读取, 故此处
	 * 放行. 字节数不由本驱动设上界: 505 号调用交付的字节数须与它相等, 且不大于该
	 * 飞地登记的接收缓冲区, 故可交付的字节数以该飞地拥有的内存为限. */
	case TEE_IOC_MODULE_SIZE: {
		struct tee_enclave_args kargs;

		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}

		ret = sbi_enclave_ecall_3(
			SBI_ENCLAVE_MODULE_SIZE, kargs.enclave_id, kargs.token, kargs.size.size
		);
		if ((long)ret.error < 0) {
			pr_err(
				"tee_enclave: MODULE_SIZE(504) id=%llu size=%llu failed, error=%ld\n",
				kargs.enclave_id, kargs.size.size, ret.error
			);
			return sbi_err_to_errno((long)ret.error);
		}
		kargs.size.status = (unsigned long long)ret.error;
		if (copy_to_user((void __user *)arg, &kargs, sizeof(kargs))) {
			return -EFAULT;
		}
		return 0;
	}

	/* ---- MODULE_IMG: 传递映像字节 (505) ----
	 *
	 * M 模式经 sbi_load_* 在置位 MPRV 的条件下读取该缓冲区, 该系列只访问 U=0
	 * 的页, 故用户缓冲区的页不可直接交给它, 先经内核缓冲区中转.
     * 写入的目标物理地址按该飞地的 S 模式运行时自己的页表查询得到, 用户态不指定.
     */
	case TEE_IOC_MODULE_IMG: {
		struct tee_enclave_args kargs;
		void *image_buf = NULL;

		if (copy_from_user(&kargs, (void __user *)arg, sizeof(kargs))) {
			return -EFAULT;
		}
		if (kargs.image.size == 0) {
			return -EINVAL;
		}

		image_buf = vmalloc(kargs.image.size);
		if (!image_buf) {
			return -ENOMEM;
		}
		if (copy_from_user(
				image_buf, (void __user *)(unsigned long)kargs.image.buf_ptr,
				kargs.image.size
			)) {
			rc = -EFAULT;
			goto out_free_image;
		}

		ret = sbi_enclave_ecall_4(
			SBI_ENCLAVE_MODULE_IMG, kargs.enclave_id, kargs.token,
			(unsigned long)image_buf, kargs.image.size
		);
		if ((long)ret.error < 0) {
			pr_err(
				"tee_enclave: MODULE_IMG(505) id=%llu size=%llu failed, error=%ld\n",
				kargs.enclave_id, kargs.image.size, ret.error
			);
			rc = sbi_err_to_errno((long)ret.error);
			goto out_free_image;
		}
		kargs.image.status = (unsigned long long)ret.error;
		kargs.image.pa	   = (unsigned long long)ret.value;
		rc				   = 0;
		if (copy_to_user((void __user *)arg, &kargs, sizeof(kargs))) {
			rc = -EFAULT;
		}
	out_free_image:
		vfree(image_buf);
		return rc;
	}

	default:
		return -ENOTTY;
	}

	return rc;
}

static const struct file_operations tee_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl = tee_ioctl,
};

static struct miscdevice tee_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = DEVICE_NAME,
	.fops  = &tee_fops,
};

/// init
static int __init tee_init(void) {
	int rc = misc_register(&tee_miscdev);
	if (rc) {
		pr_err("tee_enclave: misc_register failed: %d\n", rc);
	} else {
		pr_info("tee_enclave: /dev/%s registered\n", DEVICE_NAME);
	}
	return rc;
}

/// exit
static void __exit tee_exit(void) {
	misc_deregister(&tee_miscdev);
	pr_info("tee_enclave: unloaded\n");
}

module_init(tee_init);
module_exit(tee_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Abydos Lab");
MODULE_DESCRIPTION("TEE enclave driver interacting with sbi");
