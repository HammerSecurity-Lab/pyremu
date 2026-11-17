/* host_util.h - 评测套件宿主侧的公共工具.
 *
 * 设备 ioctl 的调用包装, 载荷文件读取, hart 绑定与检查结果打印.
 * 实现位于 host_util.c, 各宿主程序以 -I../common 找到本头文件.
 */
#ifndef HOST_UTIL_H
#define HOST_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* 以 syscall 直接调用 ioctl, 返回值保持原始语义: 失败时为 -errno. */
long host_ioctl(
	int fd,
	unsigned long req,
	void *arg
);

/* 读取整个文件到新分配的缓冲区, 成功时返回缓冲区并把字节数写入 out_size. */
uint8_t *host_read_file(
	const char *path,
	size_t *out_size
);

/* 取本进程可运行的 hart 集合, 返回个数, 编号写入 harts[]; 失败返回 -1. */
int host_online_harts(
	int *harts,
	int max
);

/* 把本进程绑定到 hart 上, 成功返回 0. */
int host_pin_to_hart(int hart);

/* 绑定本进程并等到它确实运行在目标 hart 上, 返回实测 hart. */
int host_pin_and_settle(int hart);

/* 打印一条检查结果: >> regress-check <name>: PASS|FAIL. */
void host_report(
	const char *name,
	int ok
);

#endif /* HOST_UTIL_H */
