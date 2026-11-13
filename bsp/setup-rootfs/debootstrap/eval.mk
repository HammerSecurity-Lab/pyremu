# /eval/Makefile — TEE test suite entry point
#
#   make help                  Show this help
#   make probe                 Side-channel probe & exploit tests
#   make stress                Batch enclave lifecycle stress tests
#   make modules               Load an enclave application through the standalone loader

.PHONY: help probe stress modules

help:
	@echo "=== /eval TEE Test Suite ==="
	@echo "  make probe    cache-sidechannel (all cache side channels: Flush+Reload + lifetime + concurrency + TLB/integrity)"
	@echo "  make stress   basic-test (batch enclave lifecycle 2/20/200/2000/20000)"
	@echo "  make modules  ext_app_loader (one payload, one module from /modules)"
	@echo ""
	@echo "  cd cache-sidechannel && make help   for attack details (including blocking DoS: malice-avail)"
	@echo "  cd basic-test && make help            for batch lifecycle details"
	@echo "  cd ext_app_loader && make help        for loader details"

probe:
	$(MAKE) -C cache-sidechannel probe

stress:
	$(MAKE) -C basic-test stress

modules:
	$(MAKE) -C ext_app_loader load
