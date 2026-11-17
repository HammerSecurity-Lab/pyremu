# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
# 测试固件构建 — 统一入口, 由顶层 makefile 的 `make test` 自动调用.

tests_dir      = build
elf_dir        = $(tests_dir)/elf
bin_dir        = $(tests_dir)/firm-bin
llvm_mc  = llvm-mc
lld      = ld.lld
ASFLAGS  = --arch=riscv64 --triple=riscv64 --mattr=+m,+a


phony = all
all: build-multi build-lottery build-s2u

build-multi:
	$(MAKE) -C src-env/multi-proc elf_dir=../../build/elf
phony += build-multi

build-lottery:
	@mkdir -p $(elf_dir)
	$(llvm_mc) $(ASFLAGS) src-env/lottery_boot.s --filetype=obj -o lottery_boot.tmp
	$(lld) -T src-env/multi-proc/multi.ld lottery_boot.tmp \
		-o $(elf_dir)/lottery_boot.elf
	-rm -f lottery_boot.tmp
phony += build-lottery

build-s2u:
	$(MAKE) -C src-env/s2u elf_dir=../../build/elf
phony += build-s2u

clean:
	-rm -f $(elf_dir)/kernel.elf $(elf_dir)/kernel_ab.elf $(elf_dir)/lottery_boot.elf
	$(MAKE) -C src-env/multi-proc clean
	$(MAKE) -C src-env/s2u clean
phony += clean

.PHONY: $(phony)
