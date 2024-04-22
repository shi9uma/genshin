# -*- coding: utf-8 -*-

import argparse
import json
import os

if os.environ.get('USERPROFILE') != None:
    config_file = os.environ.get('USERPROFILE').replace('\\', '/') + '/.cd_path'
elif os.environ.get('HOME') != None:
    config_file = os.environ.get('HOME') + '/.cd_path'
else:
    config_file = os.path.dirname(os.path.abspath(__file__)) + '/.cd_path'

flag_color = 1
path_color = 2


def color(text: str = '', color: int = 1) -> str:
    '''
    返回对应的控制台 ANSI 颜色
    '''
    color_table = {
        0: '\033[1;30m{}\033[0m',   # 黑色加粗
        1: '\033[1;31m{}\033[0m',   # 红色加粗
        2: '\033[1;32m{}\033[0m',   # 绿色加粗
        3: '\033[1;33m{}\033[0m',   # 黄色加粗
        4: '\033[1;34m{}\033[0m',   # 蓝色加粗
        5: '\033[1;35m{}\033[0m',   # 紫色加粗
        6: '\033[1;36m{}\033[0m',   # 青色加粗
        7: '\033[1;37m{}\033[0m',   # 白色加粗
    }
    text = clean_path(text)
    return color_table[color].format(text)


def clean_path(path: str):
    return path.replace('\\', '/').strip()


def load_paths() -> list:
    if not os.path.exists(config_file):
        with open(config_file, 'w') as file:
            json.dump([], file, indent=4)
    with open(config_file, 'r') as file:
        paths = json.load(file)
    return paths


def save_paths(paths):
    with open(config_file, 'w') as file:
        json.dump(paths, file, indent=4)


def show_config():
    print(f"{color('|', flag_color)} config file: {color(config_file, path_color)}")


def add_path(path):
    current_dir = os.getcwd()
    path = os.path.join(current_dir, path)
    path = os.path.abspath(path)
    paths = load_paths()
    if path in paths:
        print(f"{color('|', flag_color)} path [{color(path, path_color)}] already exists.")
    else:
        path = clean_path(path)
        paths.append(path)
        save_paths(paths)
        print(f"{color('|', flag_color)} path [{color(path, path_color)}] added.")


def delete_path(path):
    paths = load_paths()
    if path in paths:
        paths.remove(path)
        save_paths(paths)
        print(f"{color('|', flag_color)} path [{color(path, path_color)}] deleted.")
    else:
        print(f"{color('|', flag_color)} path [{color(path, path_color)}] doesn't exist.")


def list_paths():
    paths = load_paths()
    if paths:
        for path in paths:
            abs_path = os.path.abspath(path)
            print(f"{color('|', flag_color)} {color(abs_path, path_color)}")
    elif paths == []:
        print(f"{color('|', flag_color)} no stored paths.")
    else:
        print(f"{color('|', flag_color)} config file: {color(config_file, path_color)} doesn't exist. use -a to add one path and auto generate config file.")


def main():
    parser = argparse.ArgumentParser(
        description=f"store your path; {color('-a [path]', 1)}、{color('-d [path]', 1)}、{color('-l', 1)}")
    parser.add_argument("-a", "--add", nargs='?',
                        const=os.getcwd(), type=str, help="store your path, default '.'")
    parser.add_argument("-d", "--delete", nargs='?',
                        const=os.getcwd(), type=str, help="delete a path from storage, default '.'")
    parser.add_argument("-l", "--list", action='store_true', help="list all stored paths")
    parser.add_argument("-c", "--config", action='store_true', help="show config file path")
    args = vars(parser.parse_args())

    if any(args.values()):
        if args['add']:
            add_path(args['add'])
        elif args['delete']:
            delete_path(args['delete'])
        elif args['list']:
            list_paths()
        elif args['config']:
            show_config()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
