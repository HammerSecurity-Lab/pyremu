/* host_util.c - 评测套件宿主侧的公共工具实现. */

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "host_util.h"

long host_ioctl(
	int fd,
	unsigned long req,
	void *arg
) {
	return syscall(SYS_ioctl, fd, req, arg);
}

uint8_t *host_read_file(
	const char *path,
	size_t *out_sz
) {
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	long sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (sz <= 0) {
		fclose(fp);
		return NULL;
	}
	uint8_t *buf = malloc((size_t)sz);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
		free(buf);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	*out_sz = (size_t)sz;
	return buf;
}

/* 取本进程可运行的 hart 集合, 返回个数, 编号写入 harts[]; 失败返回 -1. */
int host_online_harts(
	int *harts,
	int max
) {
	cpu_set_t set;

	if (sched_getaffinity(0, sizeof(set), &set) != 0) {
		return -1;
	}
	int count = 0;
	for (int cpu = 0; cpu < CPU_SETSIZE && count < max; cpu++) {
		if (CPU_ISSET(cpu, &set)) {
			harts[count++] = cpu;
		}
	}
	return count;
}

/* 把本进程绑定在一个 hart 上, 成功返回 0. */
int host_pin_to_hart(int hart) {
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(hart, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

int host_pin_and_settle(int hart) {
	if (host_pin_to_hart(hart) != 0) {
		return -2;
	}
	for (int i = 0; i < 1000; i++) {
		int cpu = sched_getcpu();
		if (cpu == hart || cpu < 0) {
			return cpu;
		}
		sched_yield();
		usleep(1000);
	}
	return sched_getcpu();
}

void host_report(
	const char *name,
	int ok
) {
	printf(">> regress-check %s: %s\n", name, ok ? "PASS" : "FAIL");
}
