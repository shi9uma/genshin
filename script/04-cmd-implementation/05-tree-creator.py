# -*- coding: utf-8 -*-

import json
import argparse

ap = argparse.ArgumentParser(description = '传入 json 文件，生成树形结构')
ap.add_argument('-f', '--filepath', help = 'json 文件路径')
ap.add_argument('-e', '--example', action = 'store_true', help = '显示示例')
args = vars(ap.parse_args())

banner = '''传入如下 json 文件:
    {
        "root": [
            {
                "diy": [
                    "readme.md",
                    "unix-install-vim.sh",
                    "windows-vimrc"
                ]
            },
            "README.md",
            {
                "tutorials": [
                    "ch00_read_this_first.md",
                    "ch01_starting_vim.md",
                    "ch24_vim_runtime.md",
                    {
                        "images": [
                            "diffing-apples.png",
                            "fugitive-git.png",
                            "session-layout.png"
                        ]
                    },
                    "LICENSE",
                    "readme.md"
                ]
            },
            {
                "write": [
                    "often.md",
                    "readme.md",
                    "tcpdump.py",
                    "test.md"
                ]
            }
        ]
    }

生成如下树形结构:
    root
    ├── diy
    │   ├── readme.md
    │   ├── unix-install-vim.sh
    │   └── windows-vimrc
    ├── README.md
    ├── tutorials
    │   ├── ch00_read_this_first.md
    │   ├── ch01_starting_vim.md
    │   ├── ch24_vim_runtime.md
    │   ├── images
    │   │   ├── diffing-apples.png
    │   │   ├── fugitive-git.png
    │   │   └── session-layout.png
    │   ├── LICENSE
    │   └── readme.md
    └── write
        ├── often.md
        ├── readme.md
        ├── tcpdump.py
        └── test.md

'''

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

def print_tree(data, indent="", is_last=True):
    '''
    递归打印树结构
    '''

    if isinstance(data, dict):
        for idx, (key, value) in enumerate(data.items()):
            connector = "└── " if is_last and idx == len(data) - 1 else "├── "
            print(f"{indent}{connector}{key}")
            next_indent = indent + ("    " if is_last and idx == len(data) - 1 else "│   ")
            print_tree(value, next_indent, is_last=(idx == len(data) - 1))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            print_tree(item, indent, is_last=(idx == len(data) - 1))
    else:
        connector = "└── " if is_last else "├── "
        print(f"{indent}{connector}{data}")


def json_to_tree(json_data):
    '''
    处理根节点并打印目录树
    '''

    root_key = list(json_data.keys())[0]
    print(root_key)
    print_tree(json_data[root_key], indent="")


if args['example']:
    print(color(banner, 3))
    exit()

assert args['filepath'], 'lack of json file path'

with open(args['filepath'], 'r') as f:
    json_data = json.load(f)
    json_to_tree(json_data)