#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# SPDX-LICENSE-IDENTIFIER: MIT
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2026
# Created at 2026/07/09 星期四 17:57:40
# Last modified at 2026/07/09 星期四 22:25:08
set -euo pipefail

SUITE="trixie"
ROOTFS_DIR="./tmp-rootfs" # relative path to this shell script
MIRROR="https://mirrors.tuna.tsinghua.edu.cn/debian"
EXT4_IMG_SIZE_MB=4096
EXT4_IMG_FILE="./riscv-sd.ext4"
CPIO_OUT="./debian-riscv-initrd.cpio.gz"
HOSTNAME="riscv-trixie-sd"
ROOT_PASSWD="Password..."

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
NC='\033[0m' # No Color

GCC_CROSS="riscv64-linux-gnu-gcc"
QEMU_BIN="/usr/bin/qemu-riscv64-static"

# Source trees: this script sits at bsp/setup-rootfs/debootstrap, so the repository
# root is three levels up. Resolve both once and derive every other directory from
# them; a path that does not exist yet must not be resolved with cd, since a failed
# cd ends the script under set -e.
CURR_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${CURR_DIR}/../../.." && pwd)"

TOY_SRC="${REPO_DIR}/tests/src-rv8"
TOY_DEST="${ROOTFS_DIR}/eval/toy-progs"
FNAPP_SRC="${REPO_DIR}/bsp/eval-suites/fn_apps"
SIDECHANNEL_DEST="${ROOTFS_DIR}/eval/cache-sidechannel"
FNAPP_DEST="${ROOTFS_DIR}/eval/fn_apps"
BASIC_SRC="${REPO_DIR}/bsp/eval-suites/basic-test"
BASIC_DEST="${ROOTFS_DIR}/eval/basic-test"
# Headless regression entry, installed as /eval/regress.sh and booted as the
# kernel init by the headless test.
REGRESS_SRC="${CURR_DIR}/regress.sh"
# Enclave modules: the images are installed into /modules; the id-to-file mapping is
# compiled into the regression tool and the module loader.
MODULE_SRC="${REPO_DIR}/bsp/sittim/modules"
MODULE_DEST="${ROOTFS_DIR}/modules"
# The module build invokes the signer as its last step, so that tree receives build
# products from this script too.
MODULE_SIGN_SRC="${REPO_DIR}/bsp/tee-tools/signer"
# Application loader: a host program, deployed as /eval/app-loader together with its
# eval.mk (installed as that directory's Makefile).
EXT_APP_SRC="${REPO_DIR}/bsp/eval-suites/app-loader"
EXT_APP_DEST="${ROOTFS_DIR}/eval/app-loader"
# Bodies kept next to this script: the in-chroot setup and the top-level
# /eval/Makefile, which delegates to the per-tool makefiles.
CHROOT_SETUP_SRC="${CURR_DIR}/chroot-setup.sh"
EVAL_MK_SRC="${CURR_DIR}/eval.mk"
CROSS_CC=""
TEE_DRV_SRC="${REPO_DIR}/bsp/tee-tools/linux-driver"
SIDECHANNEL_SRC="${REPO_DIR}/bsp/eval-suites/cache-sidechannel"
KDIR="${REPO_DIR}/bsp/linux"
CARGO_BIN="$(command -v cargo 2>/dev/null || true)"
INVOKER_HOME=""
LANGLANDS_SYSROOT="${FNAPP_SRC}/Langlands/build/sysroot/lib/libflint.a"
CARGO_ENV=()

cleanup_mount() {
    mountpoint -q "${ROOTFS_DIR}/tmp" && umount -l "${ROOTFS_DIR}/tmp"
    mountpoint -q "${ROOTFS_DIR}/dev/pts" && umount -l "${ROOTFS_DIR}/dev/pts"
    mountpoint -q "${ROOTFS_DIR}/dev" && umount -l "${ROOTFS_DIR}/dev"
    mountpoint -q "${ROOTFS_DIR}/sys" && umount -l "${ROOTFS_DIR}/sys"
    mountpoint -q "${ROOTFS_DIR}/proc" && umount -l "${ROOTFS_DIR}/proc"
	echo "unmount done"
}

usage() {
	cat <<EOF
用法: $0

构建 Debian trixie riscv64 的根文件系统归档与块设备镜像, 需以 root 执行.
无参数, 无选项.

产物, 相对当前工作目录:
    debian-riscv-initrd.cpio.gz   根文件系统归档
    riscv-sd.ext4                 块设备镜像

先删除 tmp-rootfs 并覆盖上述两个产物; 测试程序与驱动按可用的工具链选择性构建.
EOF
}

case "${1:-}" in
    -h | --help)
        usage
        exit 0
        ;;
esac

# executed by root
if [ "$(id -u)" -ne 0 ]; then
	echo -e "${RED}require root privilege${NC}"
	exit 1
fi
# /etc/os-release and debian
if [ ! -f "/etc/os-release" ]; then
    echo -e "${RED}[ERROR] require debian-distribution. /etc/os-release is lacked.${NC}"
    exit 1
fi
. "/etc/os-release"
if [[ "${ID}" != "debian" && ! "${ID_LIKE:-}" =~ debian ]]; then
    echo -e "${RED}[ERROR] unable to execute this shell script${NC}"
    echo "recognize distribution as: ${PRETTY_NAME}"
    echo "only support Debian / Ubuntu / Kali / PopOS"
    exit 1
fi

trap cleanup_mount EXIT

# environment setup
apt update && apt install -y debootstrap qemu-user-static binfmt-support e2fsprogs util-linux
if [ -d "${ROOTFS_DIR}" ]; then
    echo ">> clean up pre-existed ${ROOTFS_DIR}"
    rm -rf "${ROOTFS_DIR}"
fi
mkdir -p "${ROOTFS_DIR}"

# compile by standard interpreter and fetch essential dependecies
if [ ! -f "${QEMU_BIN}" ]; then
    QEMU_BIN="$(which qemu-riscv64-static 2>/dev/null || true)"
fi
if [ -z "${QEMU_BIN}" ] || [ ! -f "${QEMU_BIN}" ]; then
    echo -e "${RED}[ERROR] qemu-riscv64-static not found.${NC}"
    echo "Install it with: apt install qemu-user-static"
    exit 1
fi
echo ">> qemu-riscv64-static: ${QEMU_BIN}"

debootstrap --arch=riscv64 --foreign --variant=minbase "${SUITE}" "${ROOTFS_DIR}" "${MIRROR}"
# qemu for emulating the basic target environment
install -D -m755 "${QEMU_BIN}" "${ROOTFS_DIR}/usr/bin/qemu-riscv64-static"

DEBIAN_FRONTEND=noninteractive LANG=C \
chroot "${ROOTFS_DIR}" /debootstrap/debootstrap --second-stage

# mount devices in host
mount -t proc none "${ROOTFS_DIR}/proc"
mount -t sysfs none "${ROOTFS_DIR}/sys"
mount --bind /dev "${ROOTFS_DIR}/dev"
mount --bind /dev/pts "${ROOTFS_DIR}/dev/pts"
mount --bind /tmp "${ROOTFS_DIR}/tmp"

# setup basic environment: the body lives in chroot-setup.sh, executed inside the
# chroot with MIRROR, ROOT_PASSWD and HOSTNAME taken from the environment.
LANG=C \
DEBIAN_FRONTEND=noninteractive \
MIRROR="${MIRROR}" ROOT_PASSWD="${ROOT_PASSWD}" \
HOSTNAME="${HOSTNAME}" \
chroot "${ROOTFS_DIR}" /bin/bash -s < "${CHROOT_SETUP_SRC}"

# toy benchmark programs -> /eval/toy-progs
mkdir -p "${TOY_DEST}"

# prefer clang >=16, fall back to riscv64-linux-gnu-gcc
for cc in clang-19 clang-18 clang-17 clang-16 clang riscv64-linux-gnu-gcc; do
    if command -v "$cc" >/dev/null 2>&1; then
        CROSS_CC="$cc"
        break
    fi
done

if [ -n "${CROSS_CC}" ] && [ -f "${TOY_SRC}/Makefile" ]; then
    echo ">> Cross-compiling toy programs with ${CROSS_CC} ..."

    case "${CROSS_CC}" in
    clang*)
        make -C "${TOY_SRC}" -j"$(nproc)" \
            CC="${CROSS_CC}" CXX="${CROSS_CC}++" STRIP="llvm-strip" || true
        ;;
    *)
        make -C "${TOY_SRC}" -j"$(nproc)" \
            CC="${CROSS_CC}" CXX="${CROSS_CC/cc/++}" STRIP="${CROSS_CC/gcc/strip}" || true
        ;;
    esac

    # install stripped binaries, rename (drop _O3_stripped suffix)
    for f in "${TOY_SRC}/bin/riscv64/"*_stripped.o; do
        [ -f "$f" ] || continue
        name="$(basename "$f" .o)"
        install -m755 "$f" "${TOY_DEST}/${name}"
    done
    # install unstripped copies for debugging
    for f in "${TOY_SRC}/bin/riscv64/"*.o; do
        [ -f "$f" ] || continue

        case "$(basename "$f")" in
        *_stripped.o)
            continue
            ;;
        esac

        name="$(basename "$f" .o)"
        [ -f "${TOY_DEST}/${name}_stripped" ] || install -m755 "$f" "${TOY_DEST}/${name}"
    done
else
    echo ">> No cross-compiler, installing prebuilt binaries ..."
    cp -v "${TOY_SRC}/bin/riscv64/"*_stripped.o "${TOY_DEST}/" 2>/dev/null || true
fi

echo ">> Toy programs installed:"
ls -la "${TOY_DEST}"

# 8. TEE enclave driver + cache side-channel test programs
echo ">> Building TEE enclave driver & test programs ..."
mkdir -p "${SIDECHANNEL_DEST}"

# Build kernel module (the Linux tree at ${KDIR} is optional; the build is skipped
# when it is absent).
if command -v "${GCC_CROSS}" >/dev/null 2>&1 && [ -d "${KDIR}" ]; then
    make -C "${KDIR}" M="${TEE_DRV_SRC}" ARCH=riscv \
        CROSS_COMPILE="${GCC_CROSS/gcc/}" modules 2>&1 | tail -3
    cp -v "${TEE_DRV_SRC}/tee_enclave_drv.ko" "${ROOTFS_DIR}/eval/"
else
    echo ">> SKIP driver build: gcc=${GCC_CROSS} kdir=${KDIR}"
fi

# Build via Makefile (single source of truth for program list),
# then copy all resulting binaries + payloads at once.
# require to build musl payload (hello_payload / victim_cache / attacker_cache):
# Otherwise, Makefile under /eval will execute as expected.
if command -v "${GCC_CROSS}" >/dev/null 2>&1; then
    make -C "${SIDECHANNEL_SRC}" -j"$(nproc)" CROSS_CC="${GCC_CROSS}" all musl
    install -m755 "${SIDECHANNEL_SRC}"/bin/* "${SIDECHANNEL_DEST}/"
    cp -v "${SIDECHANNEL_SRC}/tee_enclave.h" "${SIDECHANNEL_DEST}/"
    cp -v "${SIDECHANNEL_SRC}/eval.mk" "${SIDECHANNEL_DEST}/Makefile"
else
    echo ">> SKIP test programs: ${GCC_CROSS} not found"
fi

# 8b. Enclave payloads from bsp/eval-suites/fn_apps, loaded at runtime by
# tee_ecall_regress. Depends on cargo + riscv64gc-unknown-linux-musl + the
# vendor/musl submodule. Installed as /eval/fn_apps rather than under a suite
# directory: tee_ecall_regress scans every file in the payload directory, so
# that directory must hold payloads only.
#
# ensure root can compile rust code when lacking of rust environment
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    INVOKER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
fi
if [ -z "${CARGO_BIN}" ] && [ -n "${INVOKER_HOME}" ] && [ -x "${INVOKER_HOME}/.cargo/bin/cargo" ]; then
    CARGO_BIN="${INVOKER_HOME}/.cargo/bin/cargo"
fi

# Run cargo with the invoker's HOME: root's HOME holds no rustup toolchain.
# Shared by fn_apps, the enclave modules and the module signer.
if [ -n "${INVOKER_HOME}" ]; then
    CARGO_ENV=(env HOME="${INVOKER_HOME}" RUSTUP_HOME="${INVOKER_HOME}/.rustup" \
        CARGO_HOME="${INVOKER_HOME}/.cargo")
fi

if [ -n "${CARGO_BIN}" ]; then
    echo ">> Building fn_apps enclave payloads (cargo=${CARGO_BIN}) ..."
    if "${CARGO_ENV[@]}" make -C "${FNAPP_SRC}" CARGO="${CARGO_BIN}" all 2>&1 | tail -8; then
        mkdir -p "${FNAPP_DEST}"
        install -m755 "${FNAPP_SRC}"/bin/* "${FNAPP_DEST}/"
        # dir for testcases
		mkdir -p "${FNAPP_DEST}/test"
        install -m644 "${FNAPP_SRC}"/chibicc/test/inp_src.c "${FNAPP_DEST}/test/inp_src.c"
        echo ">> fn_apps payloads installed"
    else
        echo ">> WARN: fn_apps build failed; skipping enclave payloads"
    fi
else
    echo ">> SKIP fn_apps: cargo not found"
fi

if [ -f "${LANGLANDS_SYSROOT}" ]; then
    echo ">> Building Langlands payloads ..."
    if make -C "${FNAPP_SRC}" langlands 2>&1 | tail -4; then
        mkdir -p "${FNAPP_DEST}"
        # make can succeed without producing either payload; regress.sh scans the
        # payload directory, so a missing one silently leaves the summary incomplete.
        for f in Lfunc modular_form; do
            if [ ! -f "${FNAPP_SRC}/bin/${f}" ]; then
                echo ">> ERROR: Langlands build produced no ${FNAPP_SRC}/bin/${f}" >&2
                exit 1
            fi
        done
        install -m755 "${FNAPP_SRC}/bin/Lfunc" "${FNAPP_SRC}/bin/modular_form" \
            "${FNAPP_DEST}/"
        echo ">> Langlands payloads installed"
    else
        echo ">> WARN: Langlands build failed; skipping"
    fi
else
    echo ">> SKIP Langlands: run bsp/eval-suites/fn_apps/Langlands/build-deps.sh first"
fi

# 8c. Enclave module images (bsp/sittim/modules). The host hands a module to the
# enclave while it runs, so images are installed apart from the payloads: every
# image sits in /modules, and the tools name them relative to that directory. The
# make target `dist` writes that flattened copy, and `mod-tbl` writes the host-side
# module table from it -- the loader built in 8d includes that table, so both
# targets belong to this step.
if [ -n "${CARGO_BIN}" ]; then
    echo ">> Building enclave modules (cargo=${CARGO_BIN}) ..."
    "${CARGO_ENV[@]}" make -C "${MODULE_SRC}" CARGO="${CARGO_BIN}" dist mod-tbl
    mkdir -p "${MODULE_DEST}"
    install -m644 "${MODULE_SRC}"/dist/* "${MODULE_DEST}/"
    echo ">> Enclave modules installed:"
    ls -la "${MODULE_DEST}"
    # This script runs as root while both trees belong to the invoker: the module build
    # writes target/, build/ and dist/ into them, and the signer writes its own target/.
    # An artifact left owned by root cannot be replaced by a later rebuild run as the
    # invoker: the dist target starts with "rm -rf dist", so a root-owned dist stops it
    # at its first command, and the same holds for every file under target/.
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
        chown -R "${SUDO_USER}:${SUDO_USER}" "${MODULE_SRC}" "${MODULE_SIGN_SRC}"
        echo ">> ownership of module source trees returned to ${SUDO_USER}"
    fi
else
    echo ">> SKIP enclave modules: cargo not found"
fi

# 8d. Application loader: the smallest host program that drives the load path on its own.
if command -v "${GCC_CROSS}" >/dev/null 2>&1; then
    make -C "${EXT_APP_SRC}" CROSS_CC="${GCC_CROSS}" all
    mkdir -p "${EXT_APP_DEST}"
    install -m755 "${EXT_APP_SRC}/bin/app-loader" "${EXT_APP_DEST}/"
    cp -v "${EXT_APP_SRC}/eval.mk" "${EXT_APP_DEST}/Makefile"
else
    echo ">> SKIP application loader: ${GCC_CROSS} not found"
fi

# 8e. Headless regression entry — installed from regress.sh, which sits next to
# this script; the headless test boots with init=/eval/regress.sh to auto-run the
# ecall regression (insmod driver + tee_ecall_regress + tee_concurrent), and its
# [regress] ... markers are asserted from UART.
install -m755 "${REGRESS_SRC}" "${ROOTFS_DIR}/eval/regress.sh"

echo ">> Cache side-channel components:"
ls -la "${SIDECHANNEL_DEST}"

# TEE enclave lifecycle batch tests

mkdir -p "${BASIC_DEST}"

if command -v "${GCC_CROSS}" >/dev/null 2>&1; then
    make -C "${BASIC_SRC}" -j"$(nproc)" CROSS_CC="${GCC_CROSS}" all
    install -m755 "${BASIC_SRC}"/bin/* "${BASIC_DEST}/"
    cp -v "${BASIC_SRC}/tee_enclave.h" "${BASIC_DEST}/"
    cp -v "${BASIC_SRC}/eval.mk" "${BASIC_DEST}/Makefile"
else
    echo ">> SKIP basic tests: ${GCC_CROSS} not found"
fi

echo ">> Basic test components:"
ls -la "${BASIC_DEST}"

# Top-level /eval/Makefile, delegates to subdirectories
install -D -m 0644 "${EVAL_MK_SRC}" "${ROOTFS_DIR}/eval/Makefile"

echo ">> /eval/Makefile created"

# cleanup host binary and devices
rm -f "${ROOTFS_DIR}/usr/bin/qemu-riscv64-static"
cleanup_mount

# cpio for initramfs
pushd "${ROOTFS_DIR}" >/dev/null
find . -print0 | cpio --null -ov --format=newc | gzip -9 > "../${CPIO_OUT}"
popd
echo ">> initramfs: ${CPIO_OUT}"

# ext4 file-system used in block device
dd if=/dev/zero of="${EXT4_IMG_FILE}" bs=1M count="${EXT4_IMG_SIZE_MB}" status=none
mkfs.ext4 -F "${EXT4_IMG_FILE}"

mkdir -p mnt-tmp
mount -o loop "${EXT4_IMG_FILE}" ./mnt-tmp
cp -r "${ROOTFS_DIR}"/* ./mnt-tmp/
umount ./mnt-tmp
rmdir mnt-tmp

# set proper privilege via chown
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
	chown "${SUDO_USER}:${SUDO_USER}" "${EXT4_IMG_FILE}" "${CPIO_OUT}"
	echo ">> ownership of output files returned to ${SUDO_USER}"
fi

echo "well done..."
