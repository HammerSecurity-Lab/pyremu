# bsp/eval-suites/app-loader/Makefile
# 最小扩展应用装载器 (源目录, 部署为 /eval/app-loader)
#
# 目标:
#   make all     编译宿主程序
#   make clean   清理
#
# tee_enclave.h 取自 ../cache-sidechannel: 该头是 Linux 驱动用户态接口的唯一定义,
# 各工具目录各留一份副本已在部署时出现过未同步的副本, 故本工具经包含路径引用它,
# 不复写第二份。

phony =

# 取消 GNU Make 内置的 %: %.c 隐式模式规则:
# 防止在源码目录直接生成无 bin/ 前缀的二进制.
%: %.c

CROSS_CC ?= $(shell command -v riscv64-linux-gnu-gcc 2>/dev/null || echo riscv64-unknown-linux-gnu-gcc)
CFLAGS	 = -static -O2 -Wall

OUT_DIR	  = bin
CACHE_SC_DIR = ../cache-sidechannel
MOD_LOADER_DIR = ../mod-loader

INCLUDES  = -I$(CACHE_SC_DIR) -I$(MOD_LOADER_DIR)
MOD_LOADER_SRC = $(MOD_LOADER_DIR)/mod-loader.c
MOD_LOADER_HDR = $(MOD_LOADER_DIR)/mod-loader.h
MOD_LOADER_INC = $(MOD_LOADER_DIR)/ext_mod_table.inc

all: $(OUT_DIR)/app-loader
phony += all

$(OUT_DIR)/app-loader: app-loader.c ../cache-sidechannel/tee_enclave.h \
                       $(MOD_LOADER_SRC) $(MOD_LOADER_HDR) $(MOD_LOADER_INC)
	@mkdir -p $(@D)
	$(CROSS_CC) $(CFLAGS) $(INCLUDES) app-loader.c $(MOD_LOADER_SRC) -o $@

clean:
	rm -rf $(OUT_DIR)
phony += clean

.PHONY: $(phony)
