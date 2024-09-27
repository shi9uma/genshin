# qiling

repo：https://github.com/qilingframework/qiling.git

## install

参照 [qiling setup guide](https://docs.qiling.io/en/latest/install/) 安装 qiling 框架：

```shell
#/usr/bin/env zsh

apt update
apt install -y \
    ack antlr3 aria2 asciidoc autoconf automake autopoint binutils bison build-essential \
    bzip2 ccache cmake cpio curl device-tree-compiler fastjar flex gawk gettext gcc-multilib g++-multilib \
    git gperf haveged help2man intltool libc6-dev-i386 libelf-dev libglib2.0-dev libgmp3-dev libltdl-dev \
    libmpc-dev libmpfr-dev libncurses5-dev libncursesw5-dev libreadline-dev libssl-dev libtool lrzsz \
    mkisofs msmtp nano ninja-build p7zip p7zip-full patch pkgconf python2.7 python3 python3-pip libpython3-dev qemu-utils \
    rsync scons squashfs-tools subversion swig texinfo uglifyjs upx-ucl unzip vim wget xmlto xxd zlib1g-dev

mv /usr/lib/python3.12/EXTERNALLY-MANAGED /usr/lib/python3.12/EXTERNALLY-MANAGED.backup
pip install qiling
```

**注意：**pip 安装 qiling 框架时与 ipython 的依赖有冲突，可能面临二选一

## refer

1.   https://github.com/qilingframework/qiling
2.   https://www.iotsec-zone.com/article/391
3.   https://www.shielder.com/blog/2021/07/qilinglab-release/