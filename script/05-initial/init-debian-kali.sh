#/usr/bin/env zsh

if [ "$(id -u)" -ne 0 ]; then
	echo "\033[0;31mrerun "$0" with sudo\033[0m"
	exit 1
fi

export all_proxy="http://192.168.9.2:7890"

# init zsh
curl -fLo $HOME/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/.zshrc
curl -fLo /root/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/.zshrc

# ssh
mkdir -p $HOME/.ssh
curl -fLo $HOME/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/authorized_keys
chmod 700 -R $HOME/.ssh

mkdir -p /root/.ssh
curl -fLo /root/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/authorized_keys
chmod 700 -R /root/.ssh

curl -fLo /etc/ssh/sshd_config https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/sshd_config
systemctl start ssh && systemctl enable ssh

# software
cat << EOF > /etc/apt/sources.list
deb https://mirrors.ustc.edu.cn/kali kali-rolling main non-free non-free-firmware contrib
deb-src https://mirrors.ustc.edu.cn/kali kali-rolling main non-free non-free-firmware contrib
EOF

apt update
apt install -y \
    ack antlr3 aria2 asciidoc autoconf automake autopoint \
	binutils bison build-essential bzip2 \
	ccache cmake cpio curl \
	device-tree-compiler \
	fastjar flex \
	gawk gettext gcc-multilib g++-multilib gperf \
	haveged help2man \
	intltool \
	libc6-dev-i386 libelf-dev libglib2.0-dev libgmp3-dev libltdl-dev libmpc-dev libpython3-dev \
	libmpfr-dev libncurses5-dev libncursesw5-dev libreadline-dev libssl-dev libtool lrzsz \
    module-assistant mkisofs msmtp \
	ninja-build \
	p7zip p7zip-full \
	patch pkgconf python2.7 python3-pip \
    software-properties-common zlib1g-dev

if [[ -f "/usr/lib/python3.12/EXTERNALLY-MANAGED" ]]; then
	mv /usr/lib/python3.12/EXTERNALLY-MANAGED /usr/lib/python3.12/EXTERNALLY-MANAGED.backup
fi

apt install -y \
	locales curl net-tools openvpn rsync proxychains4 \
	gnupg2 binutils file fd-find xxd btop rename tmux \
	scons squashfs-tools subversion swig texinfo uglifyjs upx-ucl unzip git \
	qemu-user-static qemu-system qemu-utils bridge-utils \
	python3-pip python3-venv python3-shodan \
	fzf ripgrep vim \
	docker.io docker-compose \
	nmap hydra john

curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs npm && \
npm install -g npm@latest --registry=https://registry.npmmirror.com && \
npm install cnpm -g --registry=https://registry.npmmirror.com && \
cnpm install -g pm2

apt purge needrestart -y
apt autoremove -y

ln -s /usr/bin/fdfind /usr/bin/fd
ln -s /usr/bin/python3 /usr/bin/python
ln -s /usr/bin/pip3 /usr/bin/pip

usermod -aG docker wkyuu

# python
cat << EOF > /etc/pip.conf
[global]
index-url = https://mirrors.ustc.edu.cn/pypi/simple
[install]
trusted-host = https://mirrors.ustc.edu.cn
EOF

sudo -u wkyuu pip install \
	argparse cryptography scapy netifaces wsgidav shodan datetime colorama ipython getpass4 pwntools
	
# git
git config --global user.email wkyuu@majo.im
git config --global user.name shiguma
git config --global credential.helper store
git config --global init.defaultbranch main
git config --global core.editor vim

git config -l

# vim
curl -fLo /tmp/tmp/unix-install-vim.sh https://raw.githubusercontent.com/shi9uma/vim/main/diy/unix-install-vim.sh
chmod +x /tmp/tmp/unix-install-vim.sh
/tmp/tmp/unix-install-vim.sh

# dir
USER="wkyuu"

HOME_DIR_PATH="/home"
APP_DIR_PATH="$HOME_DIR_PATH/app"
GAME_DIR_PATH="$HOME_DIR_PATH/game"
REPO_DIR_PATH="$HOME_DIR_PATH/repo"
SERVER_DIR_PATH="$HOME_DIR_PATH/server"

mkdir -p $APP_DIR_PATH $GAME_DIR_PATH $REPO_DIR_PATH $SERVER_DIR_PATH

## app
mkdir -p \
	$APP_DIR_PATH/carbonyl \
	$APP_DIR_PATH/clash \
	$APP_DIR_PATH/frp \
	$APP_DIR_PATH/java

## game
mkdir -p \
	$GAME_DIR_PATH/genshin \
	$GAME_DIR_PATH/minecraft \
	$GAME_DIR_PATH/steam

## server
mkdir -p \
	$SERVER_DIR_PATH/01-ddns-go \
	$SERVER_DIR_PATH/02-alist \
	$SERVER_DIR_PATH/03-qbittorrent \
	$SERVER_DIR_PATH/04-synctv \
	$SERVER_DIR_PATH/05-filebrowser \
	$SERVER_DIR_PATH/06-transfer \
	$SERVER_DIR_PATH/07-hedgedoc \
	$SERVER_DIR_PATH/08-outline \
	$SERVER_DIR_PATH/09-reference \
	$SERVER_DIR_PATH/10-cyberchef \
	$SERVER_DIR_PATH/11-gtfobins \
	$SERVER_DIR_PATH/12-hastebin
	
chown -R $USER:$USER $HOME_DIR_PATH