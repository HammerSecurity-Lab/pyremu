#!/bin/bash
# setup basic environment inside the chroot
# ---- replace the deb sources
# ---- update host sources
# ---- zsh will be set as default shell
# ---- install oh-my-zsh
# ---- plugins ----
# RUNZSH=no   zsh
# CHSH=no     shell
# Gitee for Chinese Networking Environment:
#   OH_MY_ZSH_URL=https://gitee.com/mirrors/oh-my-zsh/raw/master/tools/install.sh
#   ZSH_PLUGIN_PREFIX=https://gitee.com/mirrors
#
# local-build.sh feeds this file to the guest bash over stdin and passes MIRROR,
# ROOT_PASSWD and HOSTNAME through its environment; the guest shell expands them.

: "${MIRROR:?}" "${ROOT_PASSWD:?}" "${HOSTNAME:?}"

cat > /etc/apt/sources.list <<SRC
deb ${MIRROR} trixie main contrib non-free non-free-firmware
deb ${MIRROR} trixie-updates main contrib non-free non-free-firmware
deb ${MIRROR}-security trixie-security main contrib non-free non-free-firmware
SRC

apt update -y
apt install -y dialog libterm-readline-perl-perl systemd systemd-sysv \
	gcc build-essential flex bison vim python3 libc6 zsh git curl wget \
		clang llvm lld kmod
apt clean
rm -rf /var/cache/apt/archives/*

echo "root:${ROOT_PASSWD}" | chpasswd

echo "${HOSTNAME}" > /etc/hostname
cat > /etc/hosts <<HOST
127.0.0.1   localhost ${HOSTNAME}
::1         localhost
HOST

cat > /etc/fstab <<'FS'
proc    /proc   proc    defaults    0 0
sysfs   /sys    sysfs   defaults    0 0
devtmpfs /dev  devtmpfs defaults    0 0
tmpfs   /tmp    tmpfs   size=64M    0 0
tmpfs   /var/run tmpfs  defaults    0 0
FS

chsh -s /bin/zsh root

OH_MY_ZSH_URL="${OH_MY_ZSH_URL:-https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh}"
ZSH_PLUGIN_PREFIX="${ZSH_PLUGIN_PREFIX:-https://github.com}"
ZSH_CUSTOM="/root/.oh-my-zsh/custom"

curl -fsSL "${OH_MY_ZSH_URL}" | RUNZSH=no CHSH=no sh

git clone --depth=1 \
	"${ZSH_PLUGIN_PREFIX}/zsh-users/zsh-autosuggestions" \
	"${ZSH_CUSTOM}/plugins/zsh-autosuggestions"
git clone --depth=1 \
	"${ZSH_PLUGIN_PREFIX}/zsh-users/zsh-syntax-highlighting" \
	"${ZSH_CUSTOM}/plugins/zsh-syntax-highlighting"

if [ ! -f /root/.oh-my-zsh/templates/zshrc.zsh-template ]; then
	mkdir -p /root/.oh-my-zsh/templates
	echo "export ZSH=\"/root/.oh-my-zsh\"" > /root/.oh-my-zsh/templates/zshrc.zsh-template
	echo "ZSH_THEME=\"gentoo\"" >> /root/.oh-my-zsh/templates/zshrc.zsh-template
	echo "plugins=(git)" >> /root/.oh-my-zsh/templates/zshrc.zsh-template
	echo "source \$ZSH/oh-my-zsh.sh" >> /root/.oh-my-zsh/templates/zshrc.zsh-template
fi
cp /root/.oh-my-zsh/templates/zshrc.zsh-template /root/.zshrc

sed -i "s/^plugins=(git)$/plugins=(git zsh-autosuggestions zsh-syntax-highlighting)/" \
	/root/.zshrc || true

sed -i "s/^ZSH_THEME=\".*\"$/ZSH_THEME=\"gentoo\"/" /root/.zshrc || true
