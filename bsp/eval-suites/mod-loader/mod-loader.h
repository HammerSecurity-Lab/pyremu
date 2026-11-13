/* mod-loader.h - 宿主侧的模块请求服务
 *
 * 飞地取入模块时经 M 模式让出并等待宿主应答, 见 bsp/custom-opensbi/lib/enclave_ext/
 * enclave_api/ext_mod/ 下的 handler. 宿主的动作是: 取出挂起的请求, 按请求类别报告
 * 映像的字节数或交付映像的字节, 然后恢复飞地. 本文件提供该应答流程与模块表,
 * 供回归工具 (bsp/eval-suites/cache-sidechannel/tee_ecall_regress.c) 与最小应用
 * 装载器 (bsp/eval-suites/app-loader/) 共用.
 *
 * 模块表在编译期由同目录的 ext_mod_table.inc 给出, 每项为模块编号与映像文件名,
 * 映像文件名相对模块目录给出. 该文件由 bsp/sittim/modules 的 mod-tbl 目标生成:
 * 编号取自各模块源码中声明的 MODULE_ID. 映像声明的编号与请求的编号不一致时,
 * 取入在飞地内以编号不符而失败.
 *
 * 模块表只登记编号与路径, 映像文件本身按需读取: 飞地请求某个模块时,
 * mod_loader_serve 才打开该映像并报告其字节数或交付其字节.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef MOD_LOADER_H
#define MOD_LOADER_H

#include <stdint.h>

#include "tee_enclave.h"

/* 映像文件路径与清单行的长度上限. */
#define MOD_LOADER_PATH_MAX 512
/* 一次登记的最大模块数. */
#define MOD_LOADER_TABLE_MAX 32

struct mod_loader_entry {
	uint32_t module_id;
	char path[MOD_LOADER_PATH_MAX];
};

struct mod_loader_table {
	struct mod_loader_entry entries[MOD_LOADER_TABLE_MAX];
	int count;
};

/* 以dir为模块目录填写table, 返回登记的模块数. 各项的路径由dir与编译期登记
 * 的映像文件名拼接得到; 拼接结果超出 MOD_LOADER_PATH_MAX 时返回 -ENAMETOOLONG, 不做
 * 部分登记. 本函数不访问映像文件. */
int mod_loader_table_init(
	struct mod_loader_table *table,
	const char *dir
);

/* 服务一次挂起的模块请求. 返回 1 表示已应答一项请求, 0 表示当前无挂起请求,
 * 负 errno 表示调用期失败. */
int mod_loader_serve(
	int fd,
	const struct mod_loader_table *table,
	uint64_t enclave_id,
	uint64_t token
);

#endif /* MOD_LOADER_H */
