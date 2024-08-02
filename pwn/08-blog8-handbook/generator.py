# -*- coding: utf-8 -*-
'''
用于生成找函数的式子

python -c "from pwn import *;elf = ELF('filename', checksec = False);print(hex(elf.sym['func']))"

'''

import os
import argparse
import pwn
from pwn import *

# 参数化
ap = argparse.ArgumentParser()
ap.add_argument('foobar', help='[必要] 目标文件的文件名')
ap.add_argument('-f', '--function', help='指定查找什么函数')
ap.add_argument('-s', '--str', help='指定查找什么字符串')
args = vars(ap.parse_args())
fileName = args['foobar']


def fgx(text='分割线', type=1, length='50', isPrint=True):

    text = ' ' + text + ' '
    SWITCH = {
        1: '-',
        2: '=',
        3: '✩',
    }
    # print("{:=^60s}".format('分割线'))
    fmt = "\033[1;34m{:type^lengths}\033[0m".replace('length', length)

    if type not in SWITCH.keys():
        type = 1
    fmt = fmt.replace('type', SWITCH.get(type))

    if isPrint:
        print(fmt.format(text))
        return None
    else:
        return fmt.format(text)


if not os.path.exists(fileName):
    fgx('文件无法访问')
    exit(1)

p32 = pwn.p32
p64 = pwn.p64
u32 = pwn.u32
u64 = pwn.u64

elf = ELF(fileName, checksec=False)

FUNCTIONS = [
    'main',
    'puts',
    'write',
    'read',
    'exit'
]


def searchFunction(functionName, elf = elf):
    plt = elf.sym[functionName]
    got = elf.got[functionName]
    _plt = int(hex(plt), 16)
    _got = int(hex(got), 16)
    str = 'Function Name: {}\n'
    str += '.plt => addr: {}, p32: {}, p64: {}\n'
    str += '.got => addr: {}, p32: {}, p64: {}\n'
    print(str.format(functionName, hex(plt), p32(
        _plt), p64(_plt), hex(got), p32(_got), p64(_got)))

fgx('{}'.format(fileName))
if args['function']:
    try:
        searchFunction(args['function'])
    except:
        print('function name: \033[1;33m{}\033[0m 检索无结果'.format(args['function']))
else:
    for function in FUNCTIONS:
        try:
            searchFunction(function)
        except:
            continue
