# -*- coding: utf-8 -*-

# ============================== cli 传参 ============================== #
import argparse
ap = argparse.ArgumentParser()
ap.add_argument('-d', '--dir', nargs='?', default='./', type=str, help='参数(简写), 参数(全称), 参数个数 0 或 1, 默认值, 类型, 帮助内容')
ap.add_argument('-v', '--verbose', action='store_true', help='参数(简写), 参数(全称), 行为(添加则转变为 ture), 帮助')
ap.add_argument('foobar', help='必要的参数')
args = vars(ap.parse_args())

args['dir'] # 取值


# ============================== color ============================== #
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