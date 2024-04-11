# -*- codingL utf-8 -*-

import os
import ctypes
from datetime import datetime
from colorama import Fore, Style

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

def ls_alh(path="."):
    with os.scandir(path) as entries:
        print(f"{Fore.GREEN}{'Name':<25} {'Mode':<10} {'Size':<10} {'Last Modified'}{Style.RESET_ALL}")
        for entry in entries:
            info = entry.stat()
            # 确定模式（目录或文件）
            mode = 'd' if entry.is_dir() else '-'
            mode += 'r' if os.access(entry, os.R_OK) else '-'
            mode += 'w' if os.access(entry, os.W_OK) else '-'
            mode += 'x' if os.access(entry, os.X_OK) else '-'
            # 以易于阅读的格式显示大小（针对文件）
            size = human_readable_size(info.st_size) if not entry.is_dir() else ''
            # 最后修改时间
            last_mod = datetime.fromtimestamp(info.st_mtime).strftime('%Y/%m/%d %H:%M:%S')
            # 检查是否为隐藏文件或文件夹
            if is_hidden(entry.path):
                entry_name = f"{entry.name} [hide]"
                print(f"{Fore.YELLOW}{entry_name:<25} {mode:<10} {size:<10} {last_mod}{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}{entry.name:<25} {mode:<10} {size:<10} {last_mod}{Style.RESET_ALL}")

if __name__ == "__main__":
    ls_alh()

# 针对 windows 下没有 ls -alh 很难受, 使用 python 模拟之