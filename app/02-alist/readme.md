# alist

repo：https://github.com/alist-org/alist.git

1. 创建文件夹 `mkdir -p /home/server/02-alist/storage/qbittorrent /home/server/02-alist/storage/local /home/server/02-alist/data`，
2. 挂载 nas 存储
   1. `sudo apt install cifs-utils`
   2. `sudo mount -t cifs //192.168.9.4/torrent/qbittorrent /home/server/02-alist/storage/qbittorrent -o username=user,password=xxxxx,uid=user,gid=user`
   3. `sudo mount -t cifs //192.168.9.4/storage/local /home/server/02-alist/storage/local -o username=user,password=xxxxx,uid=user,gid=user`
3. `sudo docker-compose -p 02-alist -f /home/server/02-alist/alist.yml up -d` 启动后，在 log 里看默认账密 `admin / xxxxxx`
4. 在访问页面输入账密登陆后，配置 alist
   1. 语言改中文
   1. `个人资料`，修改默认账密
   3. `存储`，添加驱动：
      1. 本机存储，挂载路径 `local`，根文件夹路径 `/opt/alist/storage/local`
      2. 本机存储，挂载路径 `qbittorrent`，根文件夹路径 `/opt/alist/storage/qbittorrent`