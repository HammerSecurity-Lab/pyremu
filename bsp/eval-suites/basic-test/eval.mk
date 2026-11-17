# /eval/basic-test/Makefile — TEE 飞地生命周期批处理测试套件
#
# 用法:
#   make help             显示本帮助
#   make install          加载 TEE 驱动 (insmod)
#   make stress           批处理飞地生命周期压力测试 (2/20/200/2000/20000)
#   make concurrent-enter 同一飞地的并发 ENTER 排队与按到达顺序服务
#   make uninstall        卸载 TEE 驱动
#
# 另见: /eval/cache-sidechannel/ 缓存侧信道探测与利用测试套件.

DRV     = /eval/tee_enclave_drv.ko
STRESS  = tee_stress
CONCUR  = tee_concurrent_enter
PAYLOAD = stress_payload

TEE_BIN_DIR := /eval/basic-test

.PHONY: help install stress concurrent-enter uninstall

help:
	@echo "=== /eval 飞地生命周期批处理测试套件 ==="
	@echo ""
	@echo "  make stress           批处理飞地生命周期压力测试 (2/20/200/2000/20000)"
	@echo "  make concurrent-enter 同一飞地的并发 ENTER (单所有者检查)"
	@echo ""
	@echo "  make install          加载驱动 (insmod)"
	@echo "  make uninstall        卸载驱动 (rmmod)"

install:
	@if [ -c /dev/tee_enclave ]; then \
		echo "[eval] 驱动已加载 (/dev/tee_enclave 存在)"; \
	else \
		echo "[eval] 加载驱动..."; \
		/sbin/insmod "$(DRV)" && echo "[eval] 驱动加载完成. /dev/tee_enclave 就绪."; \
	fi

stress: install
	@echo "=== 飞地生命周期压力测试 ==="
	@echo "  批次: 2 -> 20 -> 200 -> 2000 -> 20000"
	@echo ""
	"$(TEE_BIN_DIR)/$(STRESS)" "$(TEE_BIN_DIR)/$(PAYLOAD)"

concurrent-enter: install
	@echo "=== 飞地并发 ENTER 测试 ==="
	@echo "  同一飞地不得由两个 hart 同时进入"
	@echo ""
	"$(TEE_BIN_DIR)/$(CONCUR)" "$(TEE_BIN_DIR)/$(PAYLOAD)" 5

uninstall:
	@/sbin/rmmod tee_enclave_drv 2>/dev/null && echo "[eval] 驱动已卸载" || true
