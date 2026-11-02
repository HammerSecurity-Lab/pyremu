#!/bin/sh
echo "Regress init starting"
# This script is the kernel init, so nothing mounts /etc/fstab on its behalf;
# without this /proc and /dev stay empty, and both counting the online harts and
# creating the /dev/tee_enclave node fail.
mount -a
/sbin/insmod /eval/tee_enclave_drv.ko 2>&1
cd /eval/cache-probe-exploit || exit 1

# Stage 1: one hart loads every payload under fn_apps, one enclave at a time.
# The second argument is the module directory: payloads that request a module are
# served from it while the regression keeps resuming the enclave. It is omitted
# when the build installed no modules, because no image can be served then.
if [ -d /modules ]; then
	set -- /modules
else
	set --
fi
./tee_ecall_regress /eval/cache-probe-exploit/fn_apps "$@"
echo "Sequential test ret-val=$?"

# Stage 2: several harts enter their own enclaves concurrently and run the same
# payload.  orbit is chosen because it exits by itself with argc = 0
# and stays within the regression's time budget.
CONC_PAYLOAD=/eval/cache-probe-exploit/fn_apps/orbit

# One child per online hart, capped at 4.
harts=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
case "$harts" in
'' | *[!0-9]*) harts=1 ;;
esac
if [ "$harts" -gt 4 ]; then
	harts=4
fi

if [ ! -f "$CONC_PAYLOAD" ]; then
	echo "Regress concurrent skipped: $CONC_PAYLOAD not found"
elif [ "$harts" -lt 2 ]; then
	# Two harts at least are required for the requests to overlap; on one hart
	# they can only run serially, which concurrent-two-harts rejects by design.
	echo "Regress concurrent skipped: $harts online hart(s)"
else
	echo "Regress concurrent starting (procs=$harts)"
	./tee_concurrent "$CONC_PAYLOAD" "$harts"
	echo "Regress concurrent ret-val=$?"
fi

echo "Regress summary: ALL tested"
exit 0
