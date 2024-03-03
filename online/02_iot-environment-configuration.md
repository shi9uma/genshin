# Environment Configuration

>   简要配置一下固件分析环境

个人使用的是 Kali in wsl2，属于是残疾版，很多常用的命令都没有自带，除此之外还需要配置网络，相关安装配置可以参考我的另一篇文章 [app | windows-terminal](https://www.tataramoriko.com/index.php/wkyuu/36.html) 中的 wsl 小标题下的内容

## qemu

debian 系使用 apt 安装：`apt-get install qemu-user-static qemu-system uml-utilities`



## binwalk

1.   包管理器安装（推荐）：`sudo apt-get install binwalk`
2.   或者源码安装：
     1.   `git clone https://github.com/ReFirmLabs/binwalk.git`
     2.   `cd binwalk`
     3.   `sudo ./deps.sh`
     4.   `sudo python ./setup.py install`
3.   其他依赖：`sudo apt install unsquashfs sasquatch`

## firmadyne

### installation

1.   安装必要依赖：`sudo apt-get install busybox-static fakeroot git dmsetup kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux vlan`
2.   递归获取源码：`git clone --recursive https://github.com/firmadyne/firmadyne.git`
3.   确保安装了 binwalk
4.   安装和配置数据库
     1.   `sudo apt-get install postgresql`
     2.   （可选）wsl 下安装后不会自动开启 postgresql 程序，需要手动开启：`systemctl start postgresql.service`，嫌烦的话还可以将其加入开机自启：`systemctl enable postgresql.service`
     3.   创建用户 firmadyne：`sudo -u postgres createuser -P firmadyne`，要求输入密码时，**密码输入同名** `firmadyne`
     4.   创建 db：`sudo -u postgres createdb -O firmadyne firmware`
     5.   db 建表：`sudo -u postgres psql -d firmware < ./firmadyne/database/schema`
5.   下载预编译好的 binary：`cd ./firmadyne`，`./download.sh`，注意该 shell 脚本中的 wget 默认不会使用代理，需要手动进入 download.sh 中，找到 `wget -N --continue -P./binaries/ $s`，修改成 `wget -e https_proxy=http://x.x.x.x:7890 -N --continue -P./binaries/ $s`

### usage

1.   初次使用之前需要手动配置 `./firmadyne.config` 文件中的 `FIRMWARE_DIR` 变量，将其去注释并修改成根目录位置
1.   

## references

1.   配置固件分析环境（1），[一步一步PWN路由器之环境搭建](https://xz.aliyun.com/t/1508)
2.   配置固件分析环境（2），[路由器固件模拟环境搭建](https://xz.aliyun.com/t/5697)
3.   配置固件分析环境（3），[固件模拟调试环境搭建](http://zeroisone.cc/2018/03/20/固件模拟调试环境搭建)