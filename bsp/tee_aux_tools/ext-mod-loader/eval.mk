# 用法:
#   make load         装载 PAYLOAD 指定的载荷，默认取 orbit
#   make help         显示本帮助
#   make install      加载 TEE 驱动
#   make uninstall    卸载 TEE 驱动
#
# 模块目录 /modules 由 local-build.sh 安装:
# 模块映像位于该目录. 模块编号与映像文件名的对应在本工具编译时确定.

DRV		= ../tee_enclave_drv.ko
BIN		= ext_mod_loader
BIN_DIR	= /eval/ext-mod-loader
MODULES	?= /modules
PAYLOAD	?= /eval/cache-probe-exploit/fn_apps/orbit

.PHONY: load help install uninstall

load: install
	"$(BIN_DIR)/$(BIN)" "$(PAYLOAD)" "$(MODULES)"

help:
	@echo "=== /eval/ext-mod-loader ==="
	@echo ""
	@echo "  make load         PAYLOAD=[payload to be loaded], default load orbit"
	@echo "  make install      insmod driver"
	@echo "  make uninstall    rmmod driver"
	@echo ""

install:
	@if [ -c /dev/tee_enclave ]; then \
		echo "/dev/tee_enclave has been created"; \
	else \
		/sbin/insmod "$(BIN_DIR)/$(DRV)" && echo "/dev/tee_enclave is ready."; \
	fi

uninstall:
	@/sbin/rmmod tee_enclave_drv 2>/dev/null && echo "" || true
