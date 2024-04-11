# misc scripts

1.   快速重命名，`python interact_rename.py -h` 看具体
     1.   `alias rename = "python interact_rename.py"`
     2.   `rename foobar -x x1.txt x2.ini`，排除文件（除了指定要排除的文件，还内置一套常见不该操作的文件名）
     3.   `rename -w 3 -t img fast`，对当前目录下所有 img 类型的文件执行快速重命名，prefix 从 001 开始
     4.   `rename -w 3 -m add --start_num 5 prefix`，对当前目录下所有可识别的文件进行 **添加** 指定 width 长度的前缀的重命名，并且指定开始的数字为 005
     5.   `rename -w 3 -m remove prefix`，对当前目录下所有可识别的文件进行 **去掉** 指定 width 长度的前缀的重命名
     6.   `rename interact`，交互式重命名
     7.   `rename -o '-' -n '_' replace`，将全部文件名中的 `-` 改成 `_`
     8.   `rename show`，预览所有被添加到处理队列的文件名
     9.   `rename -w 3 sort`，快速地对当前目录下所有可识别的文件进行排序并添加 width 为 3 的前缀
     10.   `rename test`，测试用，使用 `touch` 生成一些可能的文件名
2.   模拟 `ls -alh`，`alias python ls_alh.py`