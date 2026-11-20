# SPDX-LICENSE-IDENTIFIER: MIT
#
# 指纹载荷: 目标 riscv64gc-unknown-linux-musl 的静态 ELF.
#
# 算法取自 crates.io 的 fprint-mindtct 与 fprint-bozorth3; 交叉链接使用仓库自带的
# musl 库与 clang 驱动.

REPO   := $(abspath ../../../../..)
MUSL   := $(REPO)/bsp/musl-gc-sysroot/lib
CLANG  ?= clang
TARGET := riscv64gc-unknown-linux-musl
OUT    := target/$(TARGET)/release/fingerprint

# 链接参数: 目标三元组交给 clang, 静态链接, 不使用 PIE,
# 并从仓库的 musl 库目录取 crt 目标文件与 libc.a.
LINK_ARGS := -C link-arg=--target=riscv64-linux-musl \
             -C link-arg=-fuse-ld=lld \
             -C link-arg=-no-pie \
             -C link-arg=-static \
             -C link-arg=-B$(MUSL) \
             -C link-arg=-L$(MUSL)

phony = all host clean

all:
	CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_LINKER=$(CLANG) \
	RUSTFLAGS="$(LINK_ARGS)" \
	cargo build --release --target $(TARGET)
	@echo "[$(OUT) built]"

host:
	cargo run --quiet --target x86_64-unknown-linux-gnu -- selftest

clean:
	cargo clean

.PHONY: $(phony)
