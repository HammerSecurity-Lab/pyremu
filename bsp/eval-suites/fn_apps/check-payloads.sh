#!/bin/sh
# 逐个运行载荷, 输出含 FAIL 即返回非 0.
# 用法: check-payloads.sh <qemu 命令> <bin 目录> <载荷名>...
# 在 fn_apps 目录下执行.
set -u

curr_dir=$(pwd)
make_cmd=${MAKE:-make}
qemu=$1
bin=$2
shift 2
fail=0

for name in "$@"; do
	echo "testcases: $name"
	ok=1
	case $name in
	chibicc)
		"$qemu" "$bin/$name" -cc1 -x c -cc1-input - -cc1-output - \
			< "$curr_dir/chibicc/test/inp_src.c" 2>&1 | grep -q '.globl main' || ok=0
		;;
	malloc_churn)
		"$qemu" "$bin/$name" 6 2 1000 1000 32 2>&1 | grep -q 'Done\.' || ok=0
		;;
	stress_ng)
		"$qemu" "$bin/$name" --vm 1 --vm-bytes 2M --timeout 3s 2>&1 \
			| grep -q 'successful run completed' || ok=0
		;;
	nc_udp)
		"$make_cmd" -C "$curr_dir/nc_udp" check >/dev/null 2>&1 || ok=0
		;;
	*)
		"$qemu" "$bin/$name" 2>&1 | grep -q 'FAIL' && ok=0
		;;
	esac
	if [ $ok -eq 1 ]; then
		echo "   [PASS] $name"
	else
		echo "   [FAIL] $name"
		fail=1
	fi
done

"$make_cmd" -C "$curr_dir/cfrac" check-argv0 || fail=1

exit $fail
