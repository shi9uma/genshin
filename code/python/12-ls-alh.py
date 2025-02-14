# -*- coding: utf-8 -*-

import os
import ctypes
from datetime import datetime
from colorama import Fore, Style
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-d', '--dir', nargs='?', default='.', type=str, help='默认列出当前目录下文件，如果指定了 --dir 则根据具体路径来')
ap.add_argument('-a', '--all', action='store_true', help='列出所有文件，包括隐藏')
ap.add_argument('-s', '--sort', choices=['name', 'size', 'time'], default='name', help='排序方式：按名称、大小或修改时间')
args = vars(ap.parse_args())

def human_readable_size(size, decimal_places=2):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024.0 or unit == 'TB':
            break
        size /= 1024.0
    return f"{size:>{decimal_places + 4}.{decimal_places}f} {unit}"

def is_hidden(filepath):
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
        assert attrs != -1
        result = bool(attrs & 2)
    except (AttributeError, AssertionError):
        result = False
    return result

def get_terminal_size():
    try:
        from shutil import get_terminal_size
        columns, _ = get_terminal_size()
        return columns
    except:
        return 80

def format_entry_simple(entry, show_hidden=False):
    if is_hidden(entry.path):
        if not show_hidden:
            return None
        return f"{Fore.RED}{entry.name} [hide]{Style.RESET_ALL}"
    elif entry.is_dir():
        return f"{Fore.YELLOW}{entry.name}{Style.RESET_ALL}"
    else:
        return f"{Fore.BLUE}{entry.name}{Style.RESET_ALL}"

def ls_alh(path=".", show_all=False, sort_by='name'):
    try:
        with os.scandir(path) as entries:
            entries = list(entries)
            # 统计变量
            total_files = 0
            total_dirs = 0
            total_size = 0
            hidden_count = 0

            # 排序逻辑
            entries = sorted(entries, key=lambda entry: entry.is_dir(), reverse=True)
            if sort_by == 'name':
                entries = sorted(entries, key=lambda entry: entry.name.lower())
            elif sort_by == 'size':
                entries = sorted(entries, key=lambda entry: entry.stat().st_size, reverse=True)
            elif sort_by == 'time':
                entries = sorted(entries, key=lambda entry: entry.stat().st_mtime, reverse=True)

            mode_width = 5
            size_width = 10
            last_mod_width = 20
            name_width = 40

            header_format = f"{Fore.GREEN}{{:<{mode_width}}} {{:<{size_width}}} {{:<{last_mod_width}}} {{:<{name_width}}}{Style.RESET_ALL}"
            row_format = f"{{:<{mode_width}}} {{:<{size_width}}} {{:<{last_mod_width}}} {{:<{name_width}}}"

            print(header_format.format('Mode', 'Size', 'Last Modified', 'Name'))

            for entry in entries:
                if is_hidden(entry.path):
                    hidden_count += 1
                    if not show_all:
                        continue

                info = entry.stat()
                if entry.is_dir():
                    total_dirs += 1
                else:
                    total_files += 1
                    total_size += info.st_size

                mode = 'd' if entry.is_dir() else '-'
                mode += 'r' if os.access(entry, os.R_OK) else '-'
                mode += 'w' if os.access(entry, os.W_OK) else '-'
                mode += 'x' if os.access(entry, os.X_OK) else '-'
                size = human_readable_size(info.st_size) if not entry.is_dir() else ''
                last_mod = datetime.fromtimestamp(info.st_mtime).strftime('%Y/%m/%d %H:%M:%S')
                
                if is_hidden(entry.path):
                    entry_name = f"{entry.name} [hide]"
                    print(Fore.RED + row_format.format(mode, size, last_mod, entry_name) + Style.RESET_ALL)
                elif entry.is_dir():
                    print(Fore.YELLOW + row_format.format(mode, size, last_mod, entry.name) + Style.RESET_ALL)
                else:
                    print(Fore.BLUE + row_format.format(mode, size, last_mod, entry.name) + Style.RESET_ALL)

            # 打印统计信息
            stats = [
                (f"{Fore.CYAN}Dirs:{Style.RESET_ALL}", total_dirs),
                (f"{Fore.BLUE}Files:{Style.RESET_ALL}", total_files),
                (f"{Fore.RED}Hidden:{Style.RESET_ALL}", hidden_count),
                (f"{Fore.GREEN}Total Size:{Style.RESET_ALL}", human_readable_size(total_size))
            ]
            print("\n" + " | ".join(f"{label} {value}" for label, value in stats))

    except PermissionError:
        print(f"{Fore.RED}错误：没有权限访问目录 {path}{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.RED}错误：目录 {path} 不存在{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}发生错误：{str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    ls_alh(args['dir'], args['all'], args['sort'])
