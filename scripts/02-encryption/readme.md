1. 缺什么 package 补什么
2. `./password_generator.sh --length 32 --seed your_key`，这个指令一开始的预期是根据日期、平台等指定 key 来生成固定密码
3. `python password_generator.py --length 32 --seed your_key --salt salt.txt`
    1. 增强版 `--salt`：用 seed 生成一个针对于特定机器码的伪 salt 文件，即使用 `--seed` 和 `--salt` 多因素来创建 password
    2. 后续如果要得出相同的 password 需要再指定该 salt 文件，丢了就是丢了
4. `ez_encrypt.py`
    1. `python ./ez_encrypt.py -h` 查看帮助
    2. 默认使用 prompt 输入 key，也可以手动指定：`-k path/to/keyfile`
    3. `salt` 盐文件和输入的 key 与 uuid 有关，指定 `-s` 选项后需要提供一个盐路径，如果不存在会自动生成
    4. 指定 `-d` 会在加密后提示是否删除源文件
    5. 示例
        1.   **注意，操作之前，如果不主动指定 output，会自动覆盖掉解密后的同名文件，如果密码错了该文件会丢失**
        2.   对单个文件进行加密：`python ./ez_encrypt.py -i plain/ez_encrypt.md -s salt enc`
        3.   对单个文件进行解密：`python ./ez_encrypt.py -i plain/ez_encrypt.md.enc -s salt dec`
        4.   对目录下文件进行加密，并递归处理：`python ./ez_encrypt.py -i path/to/enc_dir -r -s salt enc`
        5.   对目录下文件进行解密，并递归处理：`python ./ez_encrypt.py -i path/to/enc_dir -r -s salt dec`
    6. tmp
        1. `ez_encrypt -i file --key ~/.ez_encrypt_key --salt ~/.ez_encrypt_salt enc`
        2. `ez_encrypt -d file.enc --key ~/.ez_encrypt_key --salt ~/.ez_encrypt_salt dec`