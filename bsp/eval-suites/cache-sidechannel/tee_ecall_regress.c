/* tee_ecall_regress.c - TEE 飞地 ecall handler 修复的功能回归测试
 *
 * 用法: ./tee_ecall_regress <payload_dir> [modules_dir]
 * 编译: riscv64-linux-gnu-gcc -static -O2 -I../mod-loader tee_ecall_regress.c \
 *           ../mod-loader/mod-loader.c -o bin/tee_ecall_regress
 *
 * SPDX-License-Identifier: MIT
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "mod-loader.h"
#include "tee_enclave.h"

#define HOST_MDID		  0
#define MAX_ENCLAVE_SLOTS 257

#define ENCLAVE_PARTITION_SIZE (2ULL << 20)
#define ENCLAVE_PAGE_SIZE	   4096ULL

#define MAX_PAYLOADS 64
#define PATH_MAX_LEN 512

// 判定"内存池已耗尽"所需的连续 CREATE 失败次数
#define POOL_EXHAUST_CONSEC_FAILS 32

/* trailer 魔数与布局, 与 syscall::inject_manifest 逐字节一致。 */
#define VFS_MANIFEST_MAGIC	 "VSFMANIF"
#define VFS_MANIFEST_TRAILER 24

/* 注入到飞地文件系统的路径。 */
#define CHIBICC_SRC_VPATH "/test/inp_src.c"
#define CHIBICC_OUT_VPATH "/test/out.s"

/* cfrac 的测试入参: 1000000007 * 1000000009 的合数 (约 60 bit).
 * cfrac 是 mimalloc-bench 的内存压力基准, 其默认内置合数 (41 位) 需完整分解
 * 才 return 0; 本回归判定的是"转入飞地执行后自行退出", 用小合数即可覆盖,
 * 无需等待大合数分解完毕. */
#define CFRAC_SMOKE_N "1000000016000000063"

static int fd	  = -1;
static int g_fail = 0;

/* 模块目录由 main 经第二个参数给出; 未给出时 g_has_modules 为假, 应答流程不启用. */
static struct mod_loader_table g_modules;
static int g_has_modules = 0;

static void regress_log(
	const char *name,
	int ok
) {
	printf(">> regress-check %s: %s\n", name, ok ? "PASS" : "FAIL");
	if (!ok) {
		g_fail = 1;
	}
}

/* ---- ioctl 封装 ----
 * 六个封装一律返回 long, 并一律用 syscall() 直调 ioctl: 内核把运行状态与退出码打包在
 * 同一 64 位返回值中, 而 libc 的 ioctl 原型返回 int, 会把高 32 位截掉, 使退出码恒读为 0.
 * 返回值不同, 对应的执行情况也不同, 具体为:
 *	rc >= 0	控制已交还 host, rc 即 enum tee_run_state 的状态枚举值, 由进入飞地与恢复
 *		飞地两个封装返回
 *	rc == 0	调用成功, 由创建、指定令牌创建、终止与查询内存四个封装返回
 *	rc < 0	调用期失败, 取值为 -errno, 载荷未被转入运行 */

/* 运行状态枚举的名称映射, 供报告标签区分载荷的终止形态. */
static const char *run_state_name(int rc) {
	switch (rc) {
	case TEE_RUN_SUSPENDED:
		return "suspended";
	case TEE_RUN_EXITED:
		return "exited";
	case TEE_RUN_EXITED_ERR:
		return "exited-err";
	case TEE_RUN_ABORTED:
		return "aborted";
	case TEE_RUN_HOST_KILL:
		return "host-kill";
	default:
		return "unknown";
	}
}

static long do_resume(
	uint64_t enclave_id,
	uint64_t token
) {
	/* TEE_IOC_RESUME 为 _IOW, 驱动经 copy_from_user 读取 struct
	 * tee_enclave_token_args, 内含目标飞地编号与管理令牌. */
	struct tee_enclave_token_args args = {
		.enclave_id = enclave_id,
		.token		= token,
	};
	long rc = syscall(SYS_ioctl, fd, TEE_IOC_RESUME, &args);
	if (rc < 0) {
		return -errno;
	}
	return rc;
}

static long do_create(uint64_t *enclave_id) {
	/* CREATE 成功后控制转移到飞地, SUSPEND 后返回; *enclave_id 接收新 ID.
	 * 本路径登记的管理令牌恒为 0, 故其飞地的后续 RESUME/SHUTDOWN/ENTER 均以
	 * 令牌 0 调用; 需要真令牌时用 do_create_ex. */
	long rc = syscall(SYS_ioctl, fd, TEE_IOC_CREATE, enclave_id);
	if (rc < 0) {
		return -errno;
	}
	return 0;
}

/* 由 host 指定管理令牌的 CREATE: 令牌存入飞地 meta, 后续 ENTER/RESUME/SHUTDOWN
 * 必须携带同一令牌, 否则被 M 模式拒绝 (-EACCES). */
static long do_create_ex(
	uint64_t token,
	uint64_t *enclave_id
) {
	struct tee_enclave_token_args args = {
		.enclave_id = 0,
		.token		= token,
	};
	long rc = syscall(SYS_ioctl, fd, TEE_IOC_CREATE_EX, &args);
	if (rc < 0) {
		return -errno;
	}
	*enclave_id = args.enclave_id;
	return 0;
}

static long do_shutdown(
	uint64_t enclave_id,
	uint64_t token
) {
	struct tee_enclave_token_args args = {
		.enclave_id = enclave_id,
		.token		= token,
	};
	long rc = syscall(SYS_ioctl, fd, TEE_IOC_SHUTDOWN, &args);
	if (rc < 0) {
		return -errno;
	}
	return 0;
}

static long do_get_mem(struct tee_mem_info *info) {
	long rc = syscall(SYS_ioctl, fd, TEE_IOC_GET_MEM, info);
	if (rc < 0) {
		return -errno;
	}
	return 0;
}

static long do_enter(const struct tee_enclave_args *args) {
	long rc = syscall(SYS_ioctl, fd, TEE_IOC_ENTER, args);
	if (rc < 0) {
		return -errno;
	}
	return rc;
}

/* 运行载荷直到它正常结束, 或终止于抛出的错误、hang、host请求终止这几种异常形态:
 * 调用方仅在返回 TEE_RUN_EXITED 时判定载荷正常跑完.
*/
static long run_till_norm_done(
	const struct tee_enclave_args *args,
	uint64_t enclave_id
) {
	long rc = do_enter(args);
	for (;;) {
		if (rc != TEE_RUN_SUSPENDED) {
			break;
		}
		if (g_has_modules) {
			mod_loader_serve(fd, &g_modules, enclave_id, args->token);
		}
		//复用 ENTER 时使用过的同一令牌.
		rc = do_resume(enclave_id, args->token);
	}
	return rc;
}

/* 载荷读取与目录扫描 */

static uint8_t *read_file(
	const char *path,
	size_t *out_size
) {
	FILE *fp = fopen(path, "rb");
	if (!fp) {
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
	*out_size = (size_t)sz;
	return buf;
}

static int cmp_path(
	const void *a,
	const void *b
) {
	/* paths 是 char[512] 数组, qsort 传入的是元素地址,
	 * 直接按字符串比较即可; 若按 char* 数组解引用会把首 8 字节当指针。 */
	return strncmp((const char *)a, (const char *)b, PATH_MAX_LEN);
}

/* 读取首 4 字节, 判定普通文件是否带 ELF 头. */
static int is_elf_payload(const char *path) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return 0;
	}
	unsigned char magic[4];
	ssize_t n = read(fd, magic, sizeof(magic));
	close(fd);
	return n == (ssize_t)sizeof(magic) &&
		   magic[0] == 0x7f &&
		   magic[1] == 'E' &&
		   magic[2] == 'L' &&
		   magic[3] == 'F';
}

/* 扫描目录收集 ELF 载荷, 排序保证输出顺序确定. */
static int scan_payloads(
	const char *dir,
	char (*paths)[PATH_MAX_LEN]
) {
	DIR *d = opendir(dir);
	if (!d) {
		return -1;
	}
	int count = 0;
	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && count < MAX_PAYLOADS) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		char full[PATH_MAX_LEN];
		snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
		struct stat st;
		if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
			continue;
		}
		if (!is_elf_payload(full)) {
			printf("[regress] skipped non-ELF file: %s\n", full);
			continue;
		}
		snprintf(paths[count], PATH_MAX_LEN, "%s", full);
		count++;
	}
	closedir(d);
	qsort(paths, (size_t)count, sizeof(paths[0]), cmp_path);
	return count;
}

/* ---- 测试用例 ---- */

/* suspend-from-host: 宿主调用 SUSPEND 应被拒绝. */
static void test_suspend_from_host(void) {
	regress_log("suspend-from-host", ioctl(fd, TEE_IOC_SUSPEND, 0) < 0);
}

static void test_first_create_boot(void) {
	uint64_t id = 0;
	int ok		= (do_create(&id) == 0);
	if (ok) {
		ok = (do_shutdown(id, 0) == 0);
	}
	regress_log("create-first-boot", ok);
}

/*
 * 拒绝型测试项:
 *   1. 宿主id
 *   2. 越界 eid
 *   3. 已经释放的eid
 */
static void test_resume_validation(void) {
	// 测试1
	regress_log("resume-hostmdid", do_resume(HOST_MDID, 0) != 0);
	// 测试2
	regress_log("resume-out-of-range", do_resume(MAX_ENCLAVE_SLOTS, 0) != 0);
	// 测试2-增强
	srand(0x20221222);
	int all_rejected = 1;
	for (int i = 0; i < 64; i++) {
		uint64_t goal = MAX_ENCLAVE_SLOTS + (rand() & 0x7FFF);
		if (do_resume(goal, 0) == 0) {
			all_rejected = 0;
			break;
		}
	}
	regress_log("resume-random-scan", all_rejected);
	// 测试3
	int all_not_found = 1;
	for (int i = 0; i < 8; i++) {
		uint64_t recycled_id = 0;
		if (do_create(&recycled_id) != 0 || do_shutdown(recycled_id, 0) != 0) {
			all_not_found = 0;
			break;
		}
		if (do_resume(recycled_id, 0) == 0) {
			all_not_found = 0;
			break;
		}
	}
	regress_log("resume-not-found", all_not_found);
}

/*
 * 类似于resume的shutdown测试项.
 *   1. 宿主
 *   2. 随机越界id
 *   3. 存在且活跃的可信应用
 *   4. 不存在的可信应用
 */
static void test_shutdown_validation(void) {
	// 测试1
	regress_log("shutdown-hostmdid", do_shutdown(HOST_MDID, 0) != 0);

	// 测试2
	srand(0x20221222);
	int all_rejected = 1;
	for (int i = 0; i < 64; i++) {
		uint64_t goal = MAX_ENCLAVE_SLOTS + (rand() & 0x7FFF);
		if (do_shutdown(goal, 0) == 0) {
			all_rejected = 0;
			break;
		}
	}
	regress_log("shutdown-random-scan", all_rejected);

	// 测试3、4
	int all_lifetime_ok = 1;
	for (int i = 0; i < 8; i++) {
		uint64_t id = 0;
		if (do_create(&id) != 0) {
			all_lifetime_ok = 0;
			break;
		}
		/* 存在，应当成功. */
		if (do_shutdown(id, 0) != 0) {
			all_lifetime_ok = 0;
			break;
		}
		/* 不存在，应当失败 */
		if (do_shutdown(id, 0) == 0) {
			all_lifetime_ok = 0;
			break;
		}
	}
	regress_log("shutdown-lifetime", all_lifetime_ok);
}

static int pick_smallest_payload(
	const char (*paths)[PATH_MAX_LEN],
	int count,
	char *out_path
) {
	long smallest = -1;
	for (int i = 0; i < count; i++) {
		struct stat st;
		if (stat(paths[i], &st) != 0 || !S_ISREG(st.st_mode)) {
			continue;
		}
		if (smallest < 0 || (long)st.st_size < smallest) {
			smallest = (long)st.st_size;
			snprintf(out_path, PATH_MAX_LEN, "%.*s", PATH_MAX_LEN - 1, paths[i]);
		}
	}
	return smallest < 0 ? -1 : 0;
}

static void test_token_validation(
	const char (*paths)[PATH_MAX_LEN],
	int count
) {
	const uint64_t right_token = 0x5A5A1234ULL;
	const uint64_t wrong_token = 0xDEADBEEFULL;

	uint64_t id = 0;
	if (do_create_ex(right_token, &id) != 0) {
		regress_log("token-shutdown-rejected", 0);
		regress_log("token-resume-rejected", 0);
		regress_log("token-enter-rejected", 0);
		regress_log("token-accepted", 0);
		return;
	}

	regress_log("token-shutdown-rejected", do_shutdown(id, wrong_token) == -EACCES);
	regress_log("token-resume-rejected", do_resume(id, wrong_token) == -EACCES);

	char probe_path[PATH_MAX_LEN];
	size_t size	   = 0;
	uint8_t *bytes = NULL;
	if (pick_smallest_payload(paths, count, probe_path) == 0) {
		bytes = read_file(probe_path, &size);
	}
	if (!bytes) {
		/* 载荷不可读属测试环境故障, ENTER 一项无法判定. */
		regress_log("token-enter-rejected", 0);
		regress_log("token-accepted", 0);
		return;
	}
	struct tee_enclave_args args = {
		.enclave_id			= id,
		.enter.payload_ptr	= (uint64_t)bytes,
		.enter.payload_size = size,
		.enter.argc			= 0,
		.enter.argv_ptr		= 0,
		.token				= wrong_token,
	};
	regress_log("token-enter-rejected", do_enter(&args) == -EACCES);
	free(bytes);

	regress_log("token-accepted", do_shutdown(id, right_token) == 0);
}

static void exec_payload(
	const char *path,
	const char *label_prefix,
	int argc,
	char *const *argv
) {
	size_t size		 = 0;
	uint8_t *payload = read_file(path, &size);
	if (!payload) {
		regress_log(label_prefix, 0);
		return;
	}

	uint64_t enclave_id = 0;
	if (do_create(&enclave_id) != 0) {
		fprintf(stderr, "CREATE failed for '%s'\n", path);
		free(payload);
		regress_log(label_prefix, 0);
		return;
	}

	struct tee_enclave_args args = {
		.enclave_id			= enclave_id,
		.enter.payload_ptr	= (uint64_t)payload,
		.enter.payload_size = size,
		.enter.argc			= argc,
		.enter.argv_ptr		= (uint64_t)argv,
	};

	long rc = run_till_norm_done(&args, enclave_id);

	/* 低 32 位运行状态与高 32 位退出码. */
	int run_state;
	const char *term;
	char term_buf[64];
	if (rc < 0) {
		run_state = -1;
		term	  = "enter-failed";
	} else {
		run_state = TEE_RUN_STATE(rc);
		term	  = run_state_name(run_state);
		if (run_state == TEE_RUN_EXITED_ERR) {
			snprintf(
				term_buf, sizeof(term_buf), "exited-err code=%llu",
				(unsigned long long)TEE_EXIT_CODE(rc)
			);
			term = term_buf;
		}
	}

	if (run_state == TEE_RUN_SUSPENDED) {
		do_shutdown(enclave_id, 0);
	}

	char label[PATH_MAX_LEN];
	snprintf(label, sizeof(label), "%s (%s)", label_prefix, term);
	regress_log(label, run_state == TEE_RUN_EXITED);

	free(payload);
}

static void exec_payload_bytes(
	const uint8_t *payload,
	size_t size,
	const char *label_prefix,
	int argc,
	char *const *argv
) {
	uint64_t enclave_id = 0;
	if (do_create(&enclave_id) != 0) {
		fprintf(stderr, "CREATE failed for '%s'\n", label_prefix);
		regress_log(label_prefix, 0);
		return;
	}
	// 设置载荷参数与额外输入配置信息
	struct tee_enclave_args args = {
		.enclave_id			= enclave_id,
		.enter.payload_ptr	= (uint64_t)payload,
		.enter.payload_size = size,
		.enter.argc			= argc,
		.enter.argv_ptr		= (uint64_t)argv,
	};

	long rc = run_till_norm_done(&args, enclave_id);

	int run_state;
	const char *term;
	char term_buf[64];
	if (rc < 0) {
		run_state = -1;
		term	  = "enter-failed";
	} else {
		run_state = TEE_RUN_STATE(rc);
		term	  = run_state_name(run_state);
		if (run_state == TEE_RUN_EXITED_ERR) {
			snprintf(
				term_buf, sizeof(term_buf), "exited-err code=%llu",
				(unsigned long long)TEE_EXIT_CODE(rc)
			);
			term = term_buf;
		}
	}

	if (run_state == TEE_RUN_SUSPENDED) {
		do_shutdown(enclave_id, 0);
	}

	char label[PATH_MAX_LEN];
	snprintf(label, sizeof(label), "%s (%s)", label_prefix, term);
	regress_log(label, run_state == TEE_RUN_EXITED);
}

static void test_chibicc(const char *path) {
	/* 源文件路径: <payload_dir>/test/inp_src.c (payload_dir 即 chibicc 所在目录)。 */
	char src_path[PATH_MAX_LEN];
	const char *slash = strrchr(path, '/');
	size_t dir_len	  = slash ? (size_t)(slash - path) : 0;
	snprintf(src_path, sizeof(src_path), "%.*s/test/inp_src.c", (int)dir_len, path);

	size_t src_size = 0;
	uint8_t *src	= read_file(src_path, &src_size);
	if (!src) {
		regress_log("load chibicc (src-missing)", 0);
		return;
	}

	size_t elf_size = 0;
	uint8_t *elf	= read_file(path, &elf_size);
	if (!elf) {
		regress_log("load chibicc (elf-missing)", 0);
		free(src);
		return;
	}

	/* compound payload: [ELF][注入路径][源数据][24 字节 trailer]。 */
	uint32_t vpath_len	 = (uint32_t)strlen(CHIBICC_SRC_VPATH);
	size_t compound_size = elf_size + vpath_len + src_size + VFS_MANIFEST_TRAILER;
	uint8_t *compound	 = malloc(compound_size);
	if (!compound) {
		regress_log("load chibicc (oom)", 0);
		free(src);
		free(elf);
		return;
	}

	uint8_t *p = compound;
	memcpy(p, elf, elf_size);
	p += elf_size;
	uint32_t path_off = (uint32_t)elf_size;
	memcpy(p, CHIBICC_SRC_VPATH, vpath_len);
	p += vpath_len;
	uint32_t data_off = (uint32_t)(elf_size + vpath_len);
	memcpy(p, src, src_size);
	p += src_size;

	/* trailer: magic + 四个小端 u32 (riscv64 为小端, 原生 memcpy 即 LE)。 */
	memcpy(p, VFS_MANIFEST_MAGIC, 8);
	p += 8;
	uint32_t trailer[4] = {path_off, vpath_len, data_off, (uint32_t)src_size};
	memcpy(p, trailer, sizeof(trailer));

	char *argv_cc1[] = {
		"chibicc",		   "-cc1",		  "-cc1-input",
		CHIBICC_SRC_VPATH, "-cc1-output", CHIBICC_OUT_VPATH,
	};

	exec_payload_bytes(compound, compound_size, "load chibicc", 6, argv_cc1);

	free(compound);
	free(src);
	free(elf);
}

static void test_malloc_churn(const char *path) {
	/* argv[0] 仅占位; t-test1 自 argv[1] 起解析:
	 * <n-total> <n-parallel> <n-allocs> <size-max> <bins>. */
	char *const argv_par1[] = {"malloc_churn", "8", "1", "4000", "10000", "32"};
	char *const argv_par2[] = {"malloc_churn", "8", "2", "4000", "10000", "32"};
	exec_payload(path, "malloc_churn-p1", 6, argv_par1);
	exec_payload(path, "malloc_churn-p2", 6, argv_par2);
}

static const struct {
	const char *vm_bytes;
	const char *timeout;
	const char *label;
} STRESS_VM_TIERS[] = {
	{"512M", "3s", "stress_ng 512M"},
	{"1G", "3s", "stress_ng 1G"},
	{"2G", "3s", "stress_ng 2G"},
};

/* 逐个载荷加载并判定终止形态. */
static void test_load_payload(const char *path) {
	const char *base_name = strrchr(path, '/');
	base_name			  = base_name ? base_name + 1 : path;

	size_t t;

	/* malloc_churn 是多线程并发载荷, 需真实并发参数, 由 test_malloc_churn 以
	 * n-parallel=1/2 分别驱动. */
	if (strcmp(base_name, "malloc_churn") == 0) {
		test_malloc_churn(path);
		return;
	}

	/* chibicc 是编译器载荷, 走 -cc1 模式 fopen 真实源文件; 源经 compound payload
	 * 注入文件系统, 与下方通用固定 argv (atoi 得 0) 语义不同。 */
	if (strcmp(base_name, "chibicc") == 0) {
		test_chibicc(path);
		return;
	}

	/* stress_ng 是压力测试工具: 未给出 --timeout 时每个压力源默认运行 1 天
	 * (stress-ng.c 的默认取值), 且它无条件调用 fork() 派生工作进程. 若落到下方
	 * 通用 argv, 该工具会因无法识别 "regress_arg" 而以非 0 退出码返回
	 * ("unrecognised option" 与 "no stress workers invoked"). 此处按内存档位
	 * 逐档驱动, 入参形态与 bsp/eval-suites/fn_apps/Makefile 的 check 目标一致. */
	if (strcmp(base_name, "stress_ng") == 0) {
		for (t = 0; t < sizeof(STRESS_VM_TIERS) / sizeof(STRESS_VM_TIERS[0]); t++) {
			char *const argv_stress[] = {
				"stress_ng",
				"--vm",
				"1",
				"--vm-bytes",
				(char *)STRESS_VM_TIERS[t].vm_bytes,
				"--timeout",
				(char *)STRESS_VM_TIERS[t].timeout,
			};
			exec_payload(path, STRESS_VM_TIERS[t].label, 7, argv_stress);
		}
		return;
	}

	/* 其余载荷: 固定两个参数的 argv, 覆盖 M-mode measure_argv_total 预扫描路径.
	 * cfrac 例外: 其内置合数 (41 位) 需完整分解才 return 0, 耗时远长于其余载荷;
	 * 把 argv[1] 换成 CFRAC_SMOKE_N 小合数, 使载荷自行分解并以 0 退出. */
	char *payload_argv[] = {"payload", "regress_arg"};
	if (strcmp(base_name, "cfrac") == 0) {
		payload_argv[1] = CFRAC_SMOKE_N;
	}

	char label[PATH_MAX_LEN];
	/* label 需容纳 "load " 前缀, 文件名以 strnlen 截断. */
	int name_len = (int)strnlen(base_name, (size_t)sizeof(label) - 16);
	snprintf(label, sizeof(label), "load %.*s", name_len, base_name);
	exec_payload(path, label, 2, payload_argv);
}

/* 填充阶段不选用的载荷, 按文件名匹配.
 * linalg 及其矩阵尺寸变体不复用: 分解的计算量随矩阵维数的三次方增长, 填充阶段会反复
 * 重跑同一批载荷. */
static const char *const MEM_FILL_SKIP[] = {
	"ising", "linalg", "cfrac",
	// "json_calc", "json_cpp",
	"Lfunc", "modular_form", "chibicc", "stress_ng", "linalg_2m", "linalg_4m",
	"linalg_8m", "linalg_16m"
};

/* 向上取整到 size 的整数倍, 与 M-mode 侧的 ROUNDUP 宏同义. */
static uint64_t round_up(
	uint64_t value,
	uint64_t size
) {
	return (value + size - 1) / size * size;
}

static uint64_t enter_partitions(uint64_t payload_size) {
	uint64_t total_span = round_up(payload_size, ENCLAVE_PAGE_SIZE);
	return round_up(total_span, ENCLAVE_PARTITION_SIZE) / ENCLAVE_PARTITION_SIZE + 1;
}

/* 内存池 OOM 拒绝 + SHUTDOWN 释放 (修复 2 / 修复 3):
 * 以载荷名单中的载荷反复 CREATE + ENTER 使飞地保持在线占用分区, 直到池耗尽.
 * 判定 OOM 的阈值: 连续 POOL_EXHAUST_CONSEC_FAILS 次 CREATE 失败才认为池已耗尽
 * (而非首次失败即判定), 之后 SHUTDOWN 全部先前创建的飞地, free_total 应回到
 * 基线; 槽位可复用. */
static void test_mem_pool(
	const char (*paths)[PATH_MAX_LEN],
	int count
) {
	struct tee_mem_info base;
	if (do_get_mem(&base) != 0) {
		regress_log("mem-oom-rejected", 0);
		return;
	}
	printf("[regress] mem baseline free_total=%lu\n", base.free_total);

	// 从扫描结果中剔除执行时间过长的载荷, 填充阶段只在其余载荷间循环.
	char fill_paths[MAX_PAYLOADS][PATH_MAX_LEN];
	int fill_count = 0;
	for (int i = 0; i < count; i++) {
		const char *base_name = strrchr(paths[i], '/');
		base_name			  = base_name ? base_name + 1 : paths[i];
		int skip			  = 0;
		for (
			size_t j = 0; j < sizeof(MEM_FILL_SKIP) / sizeof(MEM_FILL_SKIP[0]); j++
		) {
			if (strcmp(base_name, MEM_FILL_SKIP[j]) == 0) {
				skip = 1;
				break;
			}
		}
		if (!skip) {
			// 用显式精度而非 %s: 源与目标同为 PATH_MAX_LEN, 编译器无法据此判定
			// 输出有界, 会就截断风险告警.
			snprintf(
				fill_paths[fill_count], PATH_MAX_LEN, "%.*s", PATH_MAX_LEN - 1,
				paths[i]
			);
			fill_count++;
		}
	}
	if (fill_count == 0) {
		// 填充名单为空属于测试环境故障, 池耗尽无法判定.
		regress_log("mem-oom-rejected", 0);
		return;
	}
	printf("regress mem fill payloads: %d\n", fill_count);

	// 反复 CREATE + ENTER 直到连续 POOL_EXHAUST_CONSEC_FAILS 次 CREATE 失败.
	// 槽位数上限 256 (MAX_ENCLAVE_SLOTS-1) 作循环界限, 正常情况下池会在远小于
	// 256 个飞地时耗尽.
	uint64_t ids[256];
	int n					= 0;
	int consec_fail			= 0;
	int oom_rejected		= 0;
	int contiguity_violated = 0;
	int payload_read_failed = 0;
	int is_fill_err_exit	= 0;
	while (n < 256) {
		uint64_t id = 0;
		if (do_create(&id) != 0) {
			// 连续 POOL_EXHAUST_CONSEC_FAILS 次 CREATE 失败 -> 判定池耗尽
			// (避免瞬时失败误判; 见宏注释).
			if (++consec_fail >= POOL_EXHAUST_CONSEC_FAILS) {
				oom_rejected = 1;
				break;
			}
			continue;
		}
		consec_fail = 0;

		// ENTER 装载填充载荷, 使飞地保持在线占用分区.
		const char *path = fill_paths[n % fill_count];
		size_t size		 = 0;
		uint8_t *payload = read_file(path, &size);
		if (!payload) {
			// 载荷不可读属于测试环境故障, 既非池耗尽也非连续性破坏.
			// 此处必须跳出: 若 continue 而不推进 n, 而 consec_fail 已被本次成功的
			// CREATE 清零, 则循环既不耗尽也不终止.
			do_shutdown(id, 0);
			payload_read_failed = 1;
			break;
		}
		struct tee_enclave_args args = {
			.enclave_id			= id,
			.enter.payload_ptr	= (uint64_t)payload,
			.enter.payload_size = size,
			.enter.argc			= 0,
			.enter.argv_ptr		= 0,
		};

		uint64_t need = enter_partitions((uint64_t)size);
		struct tee_mem_info cur;
		long got	  = do_get_mem(&cur);
		long enter_rc = do_enter(&args);
		if (got == 0 && enter_rc < 0 && cur.free_total >= need) {
			contiguity_violated = 1;
		}

		if (enter_rc >= 0 && TEE_RUN_STATE(enter_rc) == TEE_RUN_EXITED_ERR) {
			if (!is_fill_err_exit) {
				fprintf(
					stderr, "fill payload '%s' exited with error code=%llu\n", path,
					(unsigned long long)TEE_EXIT_CODE(enter_rc)
				);
			}
			is_fill_err_exit = 1;
		}
		free(payload);
		ids[n++] = id;
	}

	regress_log("mem-oom-rejected", oom_rejected && n > 0);
	regress_log("mem-contiguity", !contiguity_violated);
	regress_log("mem-payload-read", !payload_read_failed);
	regress_log("mem-fill-no-error", !is_fill_err_exit);
	for (int i = 0; i < n; i++) {
		// 逐个通过 SHUTDOWN 回收
		do_shutdown(ids[i], 0);
	}
	struct tee_mem_info after;
	if (do_get_mem(&after) != 0) {
		regress_log("mem-shutdown-freed", 0);
		return;
	}
	regress_log("mem-shutdown-freed", after.free_total == base.free_total);

	// 回收后槽位可复用: 再 CREATE 一次成功并 SHUTDOWN.
	uint64_t id2 = 0;
	int reusable = (do_create(&id2) == 0 && do_shutdown(id2, 0) == 0);
	regress_log("mem-reusable", reusable);
}

// 入口
int main(
	int argc,
	char **argv
) {
	const char *dir			= (argc > 1) ? argv[1] : "bsp/eval-suites/fn_apps/bin";
	const char *modules_dir = (argc > 2) ? argv[2] : NULL;

	puts("=== TEE Ecall Handler Regression ===\n");

	fd = open(TEE_DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open " TEE_DEVICE_PATH " failed (errno=%d)\n", errno);
		return 1;
	}
	printf("[regress] opened %s\n", TEE_DEVICE_PATH);

	/* 目录路径过长即退出: 此时表内各项的路径无法表示, 载荷的模块取入必然失败, 而
	 * 失败原因会与取入逻辑本身的缺陷混在一起, 难以区分. */
	if (modules_dir != NULL) {
		int n = mod_loader_table_init(&g_modules, modules_dir);
		if (n < 0) {
			fprintf(stderr, "module table for '%s' failed (%d)\n", modules_dir, n);
			close(fd);
			return 1;
		}
		g_has_modules = 1;
		printf(
			"[regress] module dir '%s' (%d modules, images are read on request)\n",
			modules_dir, n
		);
		for (int i = 0; i < g_modules.count; i++) {
			printf(
				"[regress]   module id=%u path=%s\n", g_modules.entries[i].module_id,
				g_modules.entries[i].path
			);
		}
	} else {
		printf(
			"[regress] module dir not given; module requests are left unanswered\n"
		);
	}

	test_first_create_boot();
	test_suspend_from_host();
	test_resume_validation();
	test_shutdown_validation();

	char paths[MAX_PAYLOADS][PATH_MAX_LEN];
	int count = scan_payloads(dir, paths);
	if (count <= 0) {
		fprintf(stderr, "no payloads found in '%s'\n", dir);
		close(fd);
		return 1;
	}
	printf("[regress] payload dir '%s' (%d payloads)\n", dir, count);

	// 放在载荷名录扫描之后, 又先于载荷加载与内存池填充.
	test_token_validation(paths, count);

	for (int i = 0; i < count; i++) {
		test_load_payload(paths[i]);
	}

	// 放在载荷加载之后执行
	test_mem_pool(paths, count);

	close(fd);
	printf("\n[regress] summary: %s\n", g_fail ? "FAILED" : "ALL PASS");
	return g_fail ? 1 : 0;
}
