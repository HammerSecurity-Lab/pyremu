# fn_apps/Makefile — 统一构建所有飞地载荷
#
#   1. 检测 bsp/musl-gc-sysroot, 缺失时自动构建
#   2. 逐个构建 Rust 载荷、C 载荷与 C++ 载荷,
#      名单见下方三个载荷名单变量
#   3. 收集最终静态 ELF 到 bin/, 供可信应用加载
#
# 用法:
#   make              # 构建全部载荷到 bin/
#   make <name>       # 仅构建单个载荷, 可取的名字见下方三个载荷名单变量
#   make check        # qemu-riscv64 下逐个运行测试项, 输出含 FAIL 即报错
#   make clean        # 清理 cargo 产物、stress-ng 的构建产物与 bin/
#
# 依赖: vendor/musl 与 vendor/busybox 子模块 + clang/llvm-ar/llvm-ranlib

include config.mk

CARGO   := cargo
TARGET  := riscv64gc-unknown-linux-musl
PROFILE ?= release

# 各子目录 Makefile 与上游构建的并行度
JOBS ?= 4

# cargo 的 --release 开关
ifeq ($(PROFILE),release)
CARGO_RELEASE := --release
else
CARGO_RELEASE :=
endif

# 目录名 -> cargo 包名 (orbit 的包名为 orbit_payload)
pkg_of = $(if $(filter orbit,$(1)),orbit_payload,$(1))

RUST_PAYLOADS := orbit chem graphene ising fem dsp
# linalg 除默认矩阵维数外另有四个尺寸变体, 由独立规则产出
LINALG_VARIANTS := linalg_2m linalg_4m linalg_8m linalg_16m
# malloc_churn 为多线程 C 载荷, check 目标需传并发参数, 故单列一条规则
# 归类上仍属 C 载荷.
C_PAYLOADS   := knots cfrac chibicc json_calc malloc_churn stress_ng nc_udp
# json_cpp 与 json_calc 同一源码目录, 仅实现语言不同
CPP_PAYLOADS := dune json_cpp
ALL_PAYLOADS := $(RUST_PAYLOADS) linalg $(C_PAYLOADS) $(CPP_PAYLOADS)

BIN := $(abspath bin)

.PHONY: all check clean langlands $(ALL_PAYLOADS)

all: $(ALL_PAYLOADS)

$(MUSL_LIB)/libc.a:
	@test -f "$(MUSL_SRC)/Makefile" || { \
		echo "错误: 缺少 vendor/musl 子模块, 请先执行: git submodule update --init vendor/musl"; \
		exit 1; }
	@echo ">> 缺少 musl-gc-sysroot, 开始构建 ..."
	"$(REPO)/bsp/build-musl-sysroot.sh"

define rust_rule
$(1): $(MUSL_LIB)/libc.a
	$(CARGO) build $(CARGO_RELEASE) -p $(call pkg_of,$(1))
	@mkdir -p $(BIN)
	cp target/$(TARGET)/$(PROFILE)/$(call pkg_of,$(1)) $(BIN)/$(1)
	@echo "  -> $(BIN)/$(1)"
endef
$(foreach p,$(RUST_PAYLOADS),$(eval $(call rust_rule,$(p))))

linalg: $(MUSL_LIB)/libc.a
	@mkdir -p $(BIN)
	$(CARGO) build $(CARGO_RELEASE) -p linalg
	cp target/$(TARGET)/$(PROFILE)/linalg $(BIN)/linalg
	$(CARGO) build $(CARGO_RELEASE) -p linalg --features 2mib
	cp target/$(TARGET)/$(PROFILE)/linalg $(BIN)/linalg_2m
	$(CARGO) build $(CARGO_RELEASE) -p linalg --features 4mib
	cp target/$(TARGET)/$(PROFILE)/linalg $(BIN)/linalg_4m
	$(CARGO) build $(CARGO_RELEASE) -p linalg --features 8mib
	cp target/$(TARGET)/$(PROFILE)/linalg $(BIN)/linalg_8m
	$(CARGO) build $(CARGO_RELEASE) -p linalg --features 16mib
	cp target/$(TARGET)/$(PROFILE)/linalg $(BIN)/linalg_16m
	@echo "  -> $(BIN)/linalg $(addprefix $(BIN)/,$(LINALG_VARIANTS))"

knots: $(MUSL_LIB)/libc.a
	$(MAKE) -C knots
	@mkdir -p $(BIN)
	cp knots/build/knots_payload $(BIN)/knots
	@echo "  -> $(BIN)/knots"

cfrac: $(MUSL_LIB)/libc.a
	$(MAKE) -C cfrac
	@mkdir -p $(BIN)
	cp cfrac/build/cfrac_payload $(BIN)/cfrac
	@echo "  -> $(BIN)/cfrac"

chibicc: $(MUSL_LIB)/libc.a
	$(MAKE) -C chibicc
	@mkdir -p $(BIN)
	cp chibicc/build/chibicc_payload $(BIN)/chibicc
	@echo "  -> $(BIN)/chibicc"

json_calc: $(MUSL_LIB)/libc.a
	$(MAKE) -C json_calc build/json_calc_payload
	@mkdir -p $(BIN)
	cp json_calc/build/json_calc_payload $(BIN)/json_calc
	@echo "  -> $(BIN)/json_calc"

# json_cpp: 同目录的 nlohmann/json 实现
json_cpp: $(MUSL_LIB)/libc.a
	$(MAKE) -C json_calc build/json_cpp_payload
	@mkdir -p $(BIN)
	cp json_calc/build/json_cpp_payload $(BIN)/json_cpp
	@echo "  -> $(BIN)/json_cpp"

# malloc_churn: Wolfram Gloger 多线程 malloc 压力测试.
# 源码目录名为 malloc-churn, 产物名与载荷名一致.
malloc_churn: $(MUSL_LIB)/libc.a
	$(MAKE) -C malloc-churn
	@mkdir -p $(BIN)
	cp malloc-churn/build/malloc_churn $(BIN)/malloc_churn
	@echo "  -> $(BIN)/malloc_churn"

nc_udp: $(MUSL_LIB)/libc.a
	$(MAKE) -C nc_udp
	@mkdir -p $(BIN)
	cp nc_udp/build/nc_udp_payload $(BIN)/nc_udp
	@echo "  -> $(BIN)/nc_udp"

SNG_SRC   := $(abspath stress-ng)
# 内核头文件符号链接与 libgcc_eh 副本的存放目录
SNG_BUILD := $(abspath build/stress-ng)
# riscv64 内核 UAPI 头的来源目录, 由 linux-libc-dev-riscv64-cross 提供
SNG_KHDR_SRC  := /usr/riscv64-linux-gnu/include
SNG_KHDR_DIRS := linux asm asm-generic drm misc mtd rdma scsi sound video xen
SNG_TRIPLE    := riscv64-linux-musl
SNG_INCLUDES  := -isystem $(shell $(CLANG) -print-resource-dir)/include \
	-isystem $(MUSL_SRC)/include -isystem $(MUSL_SRC)/arch/riscv64 \
	-isystem $(MUSL_SRC)/arch/generic -isystem $(MUSL_SRC)/obj/include
SNG_CC  := $(CLANG) --target=$(SNG_TRIPLE) $(ARCH) -static -fuse-ld=lld -nostdinc \
	$(SNG_INCLUDES) -isystem $(SNG_BUILD)/khdr -B$(MUSL_LIB) -L$(MUSL_LIB) -L$(SNG_BUILD)/lib
SNG_CXX := clang++ --target=$(SNG_TRIPLE) $(ARCH) -static -fuse-ld=lld -nostdinc \
	$(SNG_INCLUDES) -isystem $(MUSL_SYSROOT)/include/c++/v1 \
	-isystem $(SNG_BUILD)/khdr -B$(MUSL_LIB) -L$(MUSL_LIB) -L$(SNG_BUILD)/lib

stress_ng: $(MUSL_LIB)/libc.a
	@test -f "$(SNG_SRC)/Makefile" || { \
		echo "错误: 缺少 stress-ng 子模块, 请先执行: git submodule update --init bsp/eval-suites/fn_apps/stress-ng"; \
		exit 1; }
	@test -d "$(SNG_KHDR_SRC)/linux" || { \
		echo "错误: 缺少 riscv64 内核头文件 $(SNG_KHDR_SRC)/linux"; \
		echo "  安装: apt install gcc-riscv64-linux-gnu (随附 linux-libc-dev-riscv64-cross)"; \
		exit 1; }
	set -e; \
	mkdir -p $(SNG_BUILD)/khdr $(SNG_BUILD)/lib; \
	for d in $(SNG_KHDR_DIRS); do ln -sfn "$(SNG_KHDR_SRC)/$$d" "$(SNG_BUILD)/khdr/$$d"; done; \
	cp $(MUSL_LIB)/libgcc.a $(SNG_BUILD)/lib/libgcc_eh.a
	$(MAKE) -C $(SNG_SRC) CC='$(SNG_CC)' CXX='$(SNG_CXX)' STATIC=1 \
		-o apparmor-data.h -j$(JOBS)
	@mkdir -p $(BIN)
	cp $(SNG_SRC)/stress-ng $(BIN)/stress_ng
	@echo "  -> $(BIN)/stress_ng"

# C++ 载荷: DUNE FEM
dune: $(MUSL_LIB)/libc.a
	$(MAKE) -C dune
	@mkdir -p $(BIN)
	cp dune/build/dune_payload $(BIN)/dune
	@echo "  -> $(BIN)/dune"

# Langlands: 依赖 FLINT 的数论载荷
LANGLANDS_DIR := $(abspath Langlands)

langlands:
	@test -f $(LANGLANDS_DIR)/build/sysroot/lib/libflint.a || { \
		echo "错误: 缺少 FLINT 依赖 sysroot, 请先执行: $(LANGLANDS_DIR)/build-deps.sh"; \
		exit 1; }
	$(MAKE) -C $(LANGLANDS_DIR)/Lfunc
	$(MAKE) -C $(LANGLANDS_DIR)/modular-form
	@mkdir -p $(BIN)
	cp $(LANGLANDS_DIR)/Lfunc/build/Lfunc_payload $(BIN)/Lfunc
	cp $(LANGLANDS_DIR)/modular-form/build/modular-form_payload $(BIN)/modular_form
	@echo "  -> $(BIN)/Lfunc $(BIN)/modular_form"

# 基本检查: qemu 逐个运行, 输出含 FAIL 即失败
check: $(ALL_PAYLOADS)
	@MAKE="$(MAKE)" sh $(CURDIR)/check-payloads.sh "$(QEMU)" "$(BIN)" \
		$(ALL_PAYLOADS) $(LINALG_VARIANTS)

clean:
	$(CARGO) clean
	$(MAKE) -C knots clean
	$(MAKE) -C json_calc clean
	$(MAKE) -C malloc-churn clean
	$(MAKE) -C nc_udp clean
	$(MAKE) -C stress-ng clean
	$(MAKE) -C $(LANGLANDS_DIR)/Lfunc clean
	$(MAKE) -C $(LANGLANDS_DIR)/modular-form clean
	rm -rf $(SNG_BUILD)
	rm -rf $(BIN)
