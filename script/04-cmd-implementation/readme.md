# misc scripts

1.   initial

     1.   `mkdir -p $HOME/.genshin/script/`



## interact_rename

快速重命名，`python 03-interact-rename.py -h` 看具体

```powershell
PS C:\Users\wkyuu\Desktop\mods> rename -h
usage: interact_rename.py [-h] [-w WIDTH] [-t TYPE] [-m MODE] [--start_num START_NUM] [-x EXCLUDE [EXCLUDE ...]]
                          [-o OLD] [-n NEW] [-d]
                          foobar

用于在当前文件夹下进行批量重命名; e.g.: rename foobar -x x1.txt x2.ini | rename -w 3 -t img fast | rename
-w 3 -m add prefix | rename interact | rename -o '-' -n '_' replace | rename show
| rename -w 3 sort | rename test

positional arguments:
  foobar                fast 执行快速重命名 | prefix 执行前缀操作式重命名 | interact 执行交互式重命名 |
                        replace 快速修改文件名中的指定字符 | show 列出程序预处理文件队列 | sort
                        预览添加前缀并排序的文件队列 | test 生成测试文件

optional arguments:
  -h, --help            show this help message and exit
  -w WIDTH, --width WIDTH
                        指定重命名前缀或快速重命名时, index 格式长度, 默认 3
  -t TYPE, --type TYPE  指定快速重命名时要处理的类型, 默认 img, 可选 img 或 video
  -m MODE, --mode MODE  指定快速添加前缀重命名时的模式, 默认 add, 可选 add 或 remove
  --start_num START_NUM
                        指定快速添加前缀重命名时的起始数字, 默认 1
  -x EXCLUDE [EXCLUDE ...], --exclude EXCLUDE [EXCLUDE ...]
                        指定要排除的文件名, 如果有多个需要多次指定, 且必须写在 foobar 后面
  -o OLD, --old OLD     要替换的旧字符
  -n NEW, --new NEW     要替换成的新字符
  -d, --directory       是否处理文件夹, 添加即处理
```

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

### 脚本使用方法

1.   `rename -w 3 -m add prefix`，为当前目录下所有文件添加一个 *xxx_* 数字前缀，默认从 1 开始，还可以指定 `--num 5` 从 5 开始

     ```powershell
     PS C:\Users\wkyuu\Desktop\mods> rename -w 3 -m add prefix
     | 【a-prefix】：ApothicAttributes-1.20.1-1.3.1.jar => 001_【a-prefix】：ApothicAttributes-1.20.1-1.3.1.jar
     | 【a-prefix】：Bookshelf-Forge-1.20.1-20.1.10.jar => 002_【a-prefix】：Bookshelf-Forge-1.20.1-20.1.10.jar
     | 【a-prefix】：BotanyPots-Forge-1.20.1-13.0.29.jar => 003_【a-prefix】：BotanyPots-Forge-1.20.1-13.0.29.jar
     | 【a-prefix】：CerbonsAPI-Forge-1.20.1-1.1.0.jar => 004_【a-prefix】：CerbonsAPI-Forge-1.20.1-1.1.0.jar
     | 【a-prefix】：CorgiLib-forge-1.20.1-4.0.1.1.jar => 005_【a-prefix】：CorgiLib-forge-1.20.1-4.0.1.1.jar
     | 【a-prefix】：CreativeCore_FORGE_v2.11.24_mc1.20.1.jar => 006_【a-prefix】：CreativeCore_FORGE_v2.11.24_mc1.20.1.jar
     | 【a-prefix】：EdivadLib-1.20.1-2.0.1.jar => 007_【a-prefix】：EdivadLib-1.20.1-2.0.1.jar
     | 【a-prefix】：LibX-1.20.1-5.0.12.jar => 008_【a-prefix】：LibX-1.20.1-5.0.12.jar
     | 【a-prefix】：Patchouli-1.20.1-84-FORGE.jar => 009_【a-prefix】：Patchouli-1.20.1-84-FORGE.jar
     | 【a-prefix】：Placebo-1.20.1-8.6.1.jar => 010_【a-prefix】：Placebo-1.20.1-8.6.1.jar
     | ...
     ```

     1.   `-w 3`，width，表示 xxx 的宽度，2 就是 xx

     2.   `-m`，mode，表示模式；如果改成 `-m remove`，就是自动识别上面的数字前缀并删除

          ```powershell
          PS C:\Users\wkyuu\Desktop\mods> rename -w 3 -m remove prefix
          | 001_【a-prefix】：ApothicAttributes-1.20.1-1.3.1.jar => 【a-prefix】：ApothicAttributes-1.20.1-1.3.1.jar
          | 002_【a-prefix】：Bookshelf-Forge-1.20.1-20.1.10.jar => 【a-prefix】：Bookshelf-Forge-1.20.1-20.1.10.jar
          | 003_【a-prefix】：BotanyPots-Forge-1.20.1-13.0.29.jar => 【a-prefix】：BotanyPots-Forge-1.20.1-13.0.29.jar
          | 004_【a-prefix】：CerbonsAPI-Forge-1.20.1-1.1.0.jar => 【a-prefix】：CerbonsAPI-Forge-1.20.1-1.1.0.jar
          | 005_【a-prefix】：CorgiLib-forge-1.20.1-4.0.1.1.jar => 【a-prefix】：CorgiLib-forge-1.20.1-4.0.1.1.jar
          | 006_【a-prefix】：CreativeCore_FORGE_v2.11.24_mc1.20.1.jar => 【a-prefix】：CreativeCore_FORGE_v2.11.24_mc1.20.1.jar
          | 007_【a-prefix】：EdivadLib-1.20.1-2.0.1.jar => 【a-prefix】：EdivadLib-1.20.1-2.0.1.jar
          | ...
          ```

2.   `rename -o '-' -n '_' replace`，将当前目录下所有文件名中的 `-` 修改成 `_`，`-o` 就是 old，`-n` 就是 new

3.   `rename foobar -x 'file1' 'file2'` 指定 `-x` 可以排除哪些不想处理的文件名

4.   `rename -d foobar`，默认不处理文件夹名字，指定 `-d` 可以处理文件夹

### 使用示例

比如从 pcl 下载了以下文件

```powershell
resourcefullib-forge-1.20.1-2.1.24.jar
[3D皮肤层] skinlayers3d-forge-1.6.2-mc1.20.1.jar
[alex的生物请务必把复刻怪的生成凋成0避免影响平衡] alexsmobs-1.22.8.jar
```

假设 `resourcefullib` 是 `alexsmobs` 的前置，`skinlayers3d` 是不影响玩法的增强型辅助 mod，`alexsmobs` 是影响玩法的 mod，则可以为他们修改成以下文件名

```powershell
[a-prefix] resourcefullib-forge-1.20.1-2.1.24.jar
[b-extention-3D皮肤层] skinlayers3d-forge-1.6.2-mc1.20.1.jar
[c-mod-alex的生物请务必把复刻怪的生成凋成0避免影响平衡] alexsmobs-1.22.8.jar
```

其中的 a、b、c 只是为了在后续使用快速命名时，能先被处理（即处理后数字更前，跟排序时看第一个字符一个意思），得到以下目录

```powershell
PS C:\Users\wkyuu\Desktop\mods> fd
[a-prefix] ApothicAttributes-1.20.1-1.3.1.jar
[a-prefix] Searchables-forge-1.20.1-1.0.2.jar
[a-prefix] architectury-9.2.14-forge.jar
[a-prefix] resourcefulconfig-forge-1.20.1-2.1.2.jar
[a-prefix] resourcefullib-forge-1.20.1-2.1.24.jar
[a-prefix] supermartijn642configlib-1.1.8a-fabric-mc1.20.jar
[b-extention-3D皮肤层] skinlayers3d-forge-1.6.2-mc1.20.1.jar
[b-extention-fps优化] betterfpsdist-1.20.1-4.3.jar
[b-extention-自动汉化更新] I18nUpdateMod-3.5.3-all.jar
[b-extention-自动爬坡] stepitup-2.0.1-1.20.1-forge.jar
[c-mod-alex的生物请务必把复刻怪的生成凋成0避免影响平衡] alexsmobs-1.22.8.jar
[c-mod-紫晶钻-diamethysts] diamethysts-1.9.2-1.20.1.jar
[c-mod-自动钓鱼Forge版] forgeautofish-6.0.0-1.20.1.jar
[c-mod-自然群系指南针] NaturesCompass-1.20.1-1.11.2-forge.jar
```

为了避免歧义，想要去掉其中的空格

```powershell
PS C:\Users\wkyuu\Desktop\mods> rename -o '] ' -n ']' replace
| [a-prefix] ApothicAttributes-1.20.1-1.3.1.jar => [a-prefix]ApothicAttributes-1.20.1-1.3.1.jar
| [a-prefix] Searchables-forge-1.20.1-1.0.2.jar => [a-prefix]Searchables-forge-1.20.1-1.0.2.jar
| [a-prefix] architectury-9.2.14-forge.jar => [a-prefix]architectury-9.2.14-forge.jar
| [a-prefix] resourcefulconfig-forge-1.20.1-2.1.2.jar => [a-prefix]resourcefulconfig-forge-1.20.1-2.1.2.jar
| [a-prefix] resourcefullib-forge-1.20.1-2.1.24.jar => [a-prefix]resourcefullib-forge-1.20.1-2.1.24.jar
| [a-prefix] supermartijn642configlib-1.1.8a-fabric-mc1.20.jar => [a-prefix]supermartijn642configlib-1.1.8a-fabric-mc1.20.jar
| [b-extention-3D皮肤层] skinlayers3d-forge-1.6.2-mc1.20.1.jar => [b-extention-3D皮肤层]skinlayers3d-forge-1.6.2-mc1.20.1.jar
| [b-extention-fps优化] betterfpsdist-1.20.1-4.3.jar => [b-extention-fps优化]betterfpsdist-1.20.1-4.3.jar
| [b-extention-自动汉化更新] I18nUpdateMod-3.5.3-all.jar => [b-extention-自动汉化更新]I18nUpdateMod-3.5.3-all.jar
| [b-extention-自动爬坡] stepitup-2.0.1-1.20.1-forge.jar => [b-extention-自动爬坡]stepitup-2.0.1-1.20.1-forge.jar
| [c-mod-alex的生物请务必把复刻怪的生成凋成0避免影响平衡] alexsmobs-1.22.8.jar => [c-mod-alex的生物请务必把复刻怪的生成 凋成0避免影响平衡]alexsmobs-1.22.8.jar
| [c-mod-紫晶钻-diamethysts] diamethysts-1.9.2-1.20.1.jar => [c-mod-紫晶钻-diamethysts]diamethysts-1.9.2-1.20.1.jar
| [c-mod-自动钓鱼Forge版] forgeautofish-6.0.0-1.20.1.jar => [c-mod-自动钓鱼Forge版]forgeautofish-6.0.0-1.20.1.jar
| [c-mod-自然群系指南针] NaturesCompass-1.20.1-1.11.2-forge.jar => [c-mod-自然群系指南针]NaturesCompass-1.20.1-1.11.2-forge.jar
```

最后排序

```powershell
PS C:\Users\wkyuu\Desktop\mods> rename -w 2 -m add prefix
| [a-prefix]ApothicAttributes-1.20.1-1.3.1.jar => 01_[a-prefix]ApothicAttributes-1.20.1-1.3.1.jar
| [a-prefix]Searchables-forge-1.20.1-1.0.2.jar => 02_[a-prefix]Searchables-forge-1.20.1-1.0.2.jar
| [a-prefix]architectury-9.2.14-forge.jar => 03_[a-prefix]architectury-9.2.14-forge.jar
| [a-prefix]resourcefulconfig-forge-1.20.1-2.1.2.jar => 04_[a-prefix]resourcefulconfig-forge-1.20.1-2.1.2.jar
| [a-prefix]resourcefullib-forge-1.20.1-2.1.24.jar => 05_[a-prefix]resourcefullib-forge-1.20.1-2.1.24.jar
| [a-prefix]supermartijn642configlib-1.1.8a-fabric-mc1.20.jar => 06_[a-prefix]supermartijn642configlib-1.1.8a-fabric-mc1.20.jar
| [b-extention-3D皮肤层]skinlayers3d-forge-1.6.2-mc1.20.1.jar => 07_[b-extention-3D皮肤层]skinlayers3d-forge-1.6.2-mc1.20.1.jar
| [b-extention-fps优化]betterfpsdist-1.20.1-4.3.jar => 08_[b-extention-fps优化]betterfpsdist-1.20.1-4.3.jar
| [b-extention-自动汉化更新]I18nUpdateMod-3.5.3-all.jar => 09_[b-extention-自动汉化更新]I18nUpdateMod-3.5.3-all.jar
| [b-extention-自动爬坡]stepitup-2.0.1-1.20.1-forge.jar => 10_[b-extention-自动爬坡]stepitup-2.0.1-1.20.1-forge.jar
| [c-mod-alex的生物请务必把复刻怪的生成凋成0避免影响平衡]alexsmobs-1.22.8.jar => 11_[c-mod-alex的生物请务必把复刻怪的生 成凋成0避免影响平衡]alexsmobs-1.22.8.jar
| [c-mod-紫晶钻-diamethysts]diamethysts-1.9.2-1.20.1.jar => 12_[c-mod-紫晶钻-diamethysts]diamethysts-1.9.2-1.20.1.jar
| [c-mod-自动钓鱼Forge版]forgeautofish-6.0.0-1.20.1.jar => 13_[c-mod-自动钓鱼Forge版]forgeautofish-6.0.0-1.20.1.jar
| [c-mod-自然群系指南针]NaturesCompass-1.20.1-1.11.2-forge.jar => 14_[c-mod-自然群系指南针]NaturesCompass-1.20.1-1.11.2-forge.jar
```

（可选）如果新增 mod 想要重新排序，先去掉排序

```powershell
PS C:\Users\wkyuu\Desktop\mods> rename -w 2 -m remove prefix
| 01_[a-prefix]ApothicAttributes-1.20.1-1.3.1.jar => [a-prefix]ApothicAttributes-1.20.1-1.3.1.jar
| 02_[a-prefix]Searchables-forge-1.20.1-1.0.2.jar => [a-prefix]Searchables-forge-1.20.1-1.0.2.jar
| 03_[a-prefix]architectury-9.2.14-forge.jar => [a-prefix]architectury-9.2.14-forge.jar
| 04_[a-prefix]resourcefulconfig-forge-1.20.1-2.1.2.jar => [a-prefix]resourcefulconfig-forge-1.20.1-2.1.2.jar
| 05_[a-prefix]resourcefullib-forge-1.20.1-2.1.24.jar => [a-prefix]resourcefullib-forge-1.20.1-2.1.24.jar
| 06_[a-prefix]supermartijn642configlib-1.1.8a-fabric-mc1.20.jar => [a-prefix]supermartijn642configlib-1.1.8a-fabric-mc1.20.jar
| 07_[b-extention-3D皮肤层]skinlayers3d-forge-1.6.2-mc1.20.1.jar => [b-extention-3D皮肤层]skinlayers3d-forge-1.6.2-mc1.20.1.jar
| 08_[b-extention-fps优化]betterfpsdist-1.20.1-4.3.jar => [b-extention-fps优化]betterfpsdist-1.20.1-4.3.jar
| 09_[b-extention-自动汉化更新]I18nUpdateMod-3.5.3-all.jar => [b-extention-自动汉化更新]I18nUpdateMod-3.5.3-all.jar
| 10_[b-extention-自动爬坡]stepitup-2.0.1-1.20.1-forge.jar => [b-extention-自动爬坡]stepitup-2.0.1-1.20.1-forge.jar
| 11_[c-mod-alex的生物请务必把复刻怪的生成凋成0避免影响平衡]alexsmobs-1.22.8.jar => [c-mod-alex的生物请务必把复刻怪的生 成凋成0避免影响平衡]alexsmobs-1.22.8.jar
| 12_[c-mod-紫晶钻-diamethysts]diamethysts-1.9.2-1.20.1.jar => [c-mod-紫晶钻-diamethysts]diamethysts-1.9.2-1.20.1.jar
| 13_[c-mod-自动钓鱼Forge版]forgeautofish-6.0.0-1.20.1.jar => [c-mod-自动钓鱼Forge版]forgeautofish-6.0.0-1.20.1.jar
| 14_[c-mod-自然群系指南针]NaturesCompass-1.20.1-1.11.2-forge.jar => [c-mod-自然群系指南针]NaturesCompass-1.20.1-1.11.2-forge.jar
```

增改删后再重新 `rename -w 2 -m add prefix` 确保美观可控

## list

模拟 `ls -alh`，`alias alh="python ls_alh.py"`

## lcd

存储 cd list，`alias lcd="python cd.py"`，可以直接复制使用

1.   `lcd -h`

2.   `lcd -a .`，添加一个路径记录

3.   `lcd -l`，列出所有路径记录；`lcd -l -n 3`，列出第 3 条记录，主要是配合以下 bash function

     ```bash
     lcd() {
         if [[ ! -f "$HOME/.genshin/misc/lcd.py" ]]; then
             curl -fLo $HOME/.genshin/misc/lcd.py --create-dirs https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/04_misc/lcd.py
         fi
         if [[ "$1" == "cd" && ! -z "$2" ]]; then
             target_dir=$(python $HOME/.genshin/misc/lcd.py -pn "$2" | awk '{print $3}')
             cd "$target_dir"
         elif [[ "$1" == "l" ]]; then
             python $HOME/.genshin/misc/lcd.py -l
         elif [[ "$1" == "d" && ! -z "$2" ]]; then
             python $HOME/.genshin/misc/lcd.py -d -n "$2"
         else
             python $HOME/.genshin/misc/lcd.py "$@"
         fi
     }
     ```

     `lcd l`、`lcd cd 2`、`lcd d 2`、`lcd $args`

4.   `lcd -d /tmp/tmp`，删除路径记录；`lcd -d /tmp/tmp -n 3`，删除第三条记录，此时指定的 `/tmp/tmp` 无效