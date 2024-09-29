# qiling

repo：https://github.com/qilingframework/qiling.git

## intro

1. feature

   1. cross platform、multi core
   2. sandbox emulate
   3. high level api
   4. python framework，easy to custom self script，就是可以利用这个框架来高度自定义地去分析固件，比如看运行时各种参数、内存，hook 中间运行时
   5. support gdbserver，gdb、ida、r2

2. can

   ```python
   
   def custom_puts():
       pass
   
   ql = Qiling( qemu_arg, qemu_rootfs)
   
   ql.set_api('puts', custom_puts)
   
   
   
   ```

   

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

**注意：**pip 安装 qiling 框架时与 ipython 的依赖有冲突，可能面临二选一，解决方法是使用 venv 来管理 qiling：`python -m venv venv-qiling`

## refer

1.   https://github.com/qilingframework/qiling
2.   https://www.iotsec-zone.com/article/391
3.   https://www.shielder.com/blog/2021/07/qilinglab-release/
4.   https://www.bilibili.com/video/BV13T4y1N7M5
5.   