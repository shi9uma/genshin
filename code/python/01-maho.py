# -*- coding: utf-8 -*-

# ============================== cli 传参 ============================== #
import argparse
ap = argparse.ArgumentParser()
ap.add_argument('-d', '--dir', nargs='?', default='./', type=str, help='参数(简写), 参数(全称), 参数个数 0 或 1, 默认值, 类型, 帮助内容')
ap.add_argument('-v', '--verbose', action='store_true', help='参数(简写), 参数(全称), 行为(添加则转变为 ture), 帮助')
ap.add_argument('foobar', help='必要的参数')
args = vars(ap.parse_args())

args['dir'] # 取值


# ============================== misc ============================== #
def exec(cmd: str, print_output=False):
    '''
    直接传入命令行字符串，执行命令行并返回输出
    ```python
    exec('ls -l')
    exec('ls -l', print_output=True)
    ```
    '''
    assert type(cmd) == str, 'wrong cmd'
    import subprocess
    output = subprocess.check_output(cmd, shell=True)
    if print_output: print(output)

def debug(*args):
    '''
    打印传入的参数值，并显示其在源码的文件和行号
    '''
    import inspect
    frame = inspect.currentframe().f_back
    info = inspect.getframeinfo(frame)
    print(f"{color(clean_path(info.filename), 3)}: {color(info.lineno, 4)} {color('|', 7)}", end = ' ')
    for x in args:
        print(f"{color(x, 2)}", end = ' ' if x[-1] != ' ' else '')
    print('')

def color(text: str = '', color: int = 2) -> str:
    '''
    返回对应的控制台 ANSI 颜色; 
    ```python
    color_table = {
        0: '无色', 
        1: '黑色加粗',
        2: '红色加粗',
        3: '绿色加粗',
        4: '黄色加粗',
        5: '蓝色加粗',
        6: '紫色加粗',
        7: '青色加粗',
        8: '白色加粗',
    }
    ```
    '''
    color_table = {
        0: '{}',                    # 无色
        1: '\033[1;30m{}\033[0m',   # 黑色加粗
        2: '\033[1;31m{}\033[0m',   # 红色加粗
        3: '\033[1;32m{}\033[0m',   # 绿色加粗
        4: '\033[1;33m{}\033[0m',   # 黄色加粗
        5: '\033[1;34m{}\033[0m',   # 蓝色加粗
        6: '\033[1;35m{}\033[0m',   # 紫色加粗
        7: '\033[1;36m{}\033[0m',   # 青色加粗
        8: '\033[1;37m{}\033[0m',   # 白色加粗
    }
    return color_table[color].format(text)

# ============================== path ============================== #
def clean_path(path: str) -> str:
    '''
    清理反斜杠
    '''
    return path.replace('\\', '/').lower()

def get_dirname(path: str) -> str:
    '''
    返回路径的目录名
    '''
    import os
    return clean_path(os.path.dirname(path))

def get_fullpath(path: str) -> str:
    '''
    返回路径的绝对路径
    '''
    import os
    return clean_path(os.path.abspath(path))

def get_workdir() -> str:
    '''
    返回根工作目录
    '''
    return get_fullpath(get_dirname(get_dirname(__file__)))

def xpath(root_path: str, *args: str) -> str:
    '''
    将所有传入的参数按顺序组合成路径
    '''
    import os
    for path in args:
        if type(path) != str:
            if type(path) == int: path = str(path)
            else: continue
        path = path.replace('\\', '').replace('/', '')
        root_path = os.path.join(root_path, path)
    return clean_path(root_path)

# ============================== split line ============================== #
SWITCH = {
    1: '-',
    2: '=',
    3: '✩',
}


def fgx(text='分割线', type=1, length='50', isPrint=True):
    text = ' ' + text + ' '
    # print("{:=^60s}".format('分割线'))
    fmt = "\033[1;33m {:type^lengths} \033[0m".replace('length', length)

    if type not in SWITCH.keys():
        type = 1
    fmt = fmt.replace('type', SWITCH.get(type))

    if isPrint:
        print(fmt.format(text))
        return None
    else:
        return fmt.format(text)

# ============================== reg test ============================== #
'''
计算正则表达式的测试代码
在线版: https://regexr-cn.com/
'''

import re


REG = r'([0-9]+)'
MSG = r'18; 6; 77; 1; 1; 61; 0; 0'

print(' re.compile 方法 ')
'''
完全匹配
'''
pattern = re.compile(REG)
alist = pattern.findall(MSG)
print(alist)

print(' re.match 方法 ')
'''
单次匹配
re.match 尝试从字符串的起始位置匹配一个模式
如果不是起始位置匹配成功的话
match() 就返回 none
'''
pattern = re.match(REG, MSG)
print(pattern.groups())
print(pattern.group(0))


print(' re.search 方法 ')
'''
单次匹配
re.search 扫描整个字符串并返回第一个成功的匹配。
'''
pattern = re.search(REG, MSG)
print(pattern.groups())
print(pattern.group(0))