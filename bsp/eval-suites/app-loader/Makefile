# bsp/eval-suites/app-loader/Makefile
# 最小扩展应用装载器 (源目录, 部署为 /eval/app-loader)
#
# 目标:
#   make all     编译宿主程序
#   make clean   清理
#
# enclave_abi.h 与模块请求服务 mod_loader.* 由 ../common 提供, 二者是 Linux 驱动
# 用户态接口与宿主应答流程的唯一定义, 各工具经包含路径引用, 不复写副本.

include ../common/toolchain.mk

phony =

# 取消 GNU Make 内置的 %: %.c 隐式模式规则:
# 防止在源码目录直接生成无 bin/ 前缀的二进制.
%: %.c

OUT_DIR = bin

all: $(OUT_DIR)/app-loader
phony += all

$(OUT_DIR)/app-loader: app-loader.c $(EVAL_INCLUDE)/enclave_abi.h \
                       $(EVAL_INCLUDE)/mod_loader.c \
                       $(EVAL_INCLUDE)/mod_loader.h \
                       $(EVAL_INCLUDE)/ext_mod_table.inc
	@mkdir -p $(@D)
	$(CROSS_CC) $(HOST_CFLAGS) -I$(EVAL_INCLUDE) \
		app-loader.c $(EVAL_INCLUDE)/mod_loader.c -o $@

clean:
	rm -rf $(OUT_DIR)
phony += clean

.PHONY: $(phony)
