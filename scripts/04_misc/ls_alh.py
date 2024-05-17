# -*- coding: utf-8 -*-

import os
import ctypes
from datetime import datetime
from colorama import Fore, Style
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-d', '--dir', nargs='?', default='.', type=str, help='默认列出当前目录下文件，如果指定了 --dir 则根据具体路径来')
ap.add_argument('-a', '--all', action='store_true', help='列出所有文件，包括隐藏')
args = vars(ap.parse_args())

def human_readable_size(size, decimal_places=2):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"

def is_hidden(filepath):
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
        assert attrs != -1
        result = bool(attrs & 2)
    except (AttributeError, AssertionError):
        result = False
    return result

def ls_alh(path=".", show_all=False):
    with os.scandir(path) as entries:
        name_width = 40  # Name 列的宽度
        mode_width = 10  # Mode 列的宽度
        size_width = 15  # Size 列的宽度
        last_mod_width = 20  # Last Modified 列的宽度

        header_format = f"{Fore.GREEN}{{:<{name_width}}} {{:<{mode_width}}} {{:<{size_width}}} {{:<{last_mod_width}}}{Style.RESET_ALL}"
        row_format = f"{{:<{name_width}}} {{:<{mode_width}}} {{:<{size_width}}} {{:<{last_mod_width}}}"

        print(header_format.format('Name', 'Mode', 'Size', 'Last Modified'))

        entries = sorted(entries, key=lambda entry: entry.is_dir(), reverse=True)
        for entry in entries:
            info = entry.stat()
            mode = 'd' if entry.is_dir() else '-'
            mode += 'r' if os.access(entry, os.R_OK) else '-'
            mode += 'w' if os.access(entry, os.W_OK) else '-'
            mode += 'x' if os.access(entry, os.X_OK) else '-'
            size = human_readable_size(info.st_size) if not entry.is_dir() else ''
            last_mod = datetime.fromtimestamp(info.st_mtime).strftime('%Y/%m/%d %H:%M:%S')
            
            if is_hidden(entry.path):
                entry_name = f"{entry.name} [hide]"
                if show_all:
                    print(Fore.RED + row_format.format(entry_name, mode, size, last_mod) + Style.RESET_ALL)
            elif entry.is_dir():
                print(Fore.YELLOW + row_format.format(entry.name, mode, size, last_mod) + Style.RESET_ALL)
            else:
                print(Fore.BLUE + row_format.format(entry.name, mode, size, last_mod) + Style.RESET_ALL)

if __name__ == "__main__":
    ls_alh(args['dir'], args['all'])
