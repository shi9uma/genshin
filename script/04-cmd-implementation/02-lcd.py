# -*- coding: utf-8 -*-

import argparse
import json
import os

cd_path_name = '.lcd-path'
if os.environ.get('USERPROFILE') != None:
    windows_user_home = os.environ.get("USERPROFILE").replace("\\", "/")
    config_file = f'{windows_user_home}/{cd_path_name}'
elif os.environ.get('HOME') != None:
    config_file = f'{os.environ.get("HOME")}/{cd_path_name}'
else:
    config_file = f'{os.path.dirname(os.path.abspath(__file__))}/{cd_path_name}'

flag_color = 2


def color(text: str = '', color: int = 2) -> str:
    '''
    返回对应的控制台 ANSI 颜色
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
    text = clean_path(text)
    return color_table[color].format(text)


def clean_path(path: str):
    return path.replace('\\', '/').strip()


def load_path() -> list:
    if not os.path.exists(config_file):
        with open(config_file, 'w') as file:
            json.dump([], file, indent=4)
    with open(config_file, 'r') as file:
        path = json.load(file)
    return path


def save_path(path):
    with open(config_file, 'w') as file:
        json.dump(path, file, indent=4)


def show_config(path_color):
    import json
    print(f"{color('|', flag_color)} config file: {color(config_file, path_color)}")
    with open(config_file, mode='r', encoding='utf-8') as file:
        print(json.dumps(json.load(file), indent=4, ensure_ascii=False))


def add_path(path, path_color):
    current_dir = os.getcwd()
    path = os.path.join(current_dir, path)
    path = os.path.abspath(path)
    path = clean_path(path)
    path_list = load_path()
    if path in path_list:
        print(
            f"{color('|', flag_color)} path [{color(path, path_color)}] already exists.")
    else:
        path = clean_path(path)
        path_list.append(path)
        save_path(path_list)
        print(
            f"{color('|', flag_color)} path [{color(path, path_color)}] added.")


def delete_path(path, path_color, num=0):
    path_list = load_path()

    if num != 0:
        if num > len(path_list):
            print(
                f"{color('|', flag_color)} path number [{color(str(num), 4)}] out of range.")
            return
        count = 1
        for _path in path_list:
            if count == num:
                path = _path
                break
            count += 1

    if path in path_list:
        path_list.remove(path)
        save_path(path_list)
        print(
            f"{color('|', flag_color)} path [{color(path, path_color)}] deleted.")
    else:
        print(
            f"{color('|', flag_color)} path [{color(path, path_color)}] doesn't exist.")


def list_path(path_color, num):
    path_list = load_path()
    if path_list:
        if num != 0:
            if num > len(path_list):
                print(
                    f"{color('|', flag_color)} path number [{color(str(num), 4)}] out of range.")
                return
            count = 1
            for path in path_list:
                if count == num:
                    abs_path = os.path.abspath(path)
                    print(f"{color(abs_path, path_color)}")
                    return
                count += 1
        count = 1
        for path in path_list:
            abs_path = os.path.abspath(path)
            print(
                f"{color('|', flag_color)} [{color(str(count), 4)}] {color(abs_path, path_color)}")
            count += 1
    elif path_list == []:
        print(f"{color('|', flag_color)} no stored path.")
    else:
        print(f"{color('|', flag_color)} config file: {color(config_file, path_color)} doesn't exist. use -a to add one path and auto generate config file.")


def main():
    parser = argparse.ArgumentParser(
        description=f"store your path; {color('-a [path]', flag_color)}、{color('-d [path]', flag_color)}、{color('-l', flag_color)}")
    parser.add_argument("-a", "--add", nargs='?',
                        const=os.getcwd(), type=str, help="store your path, default '.'")
    parser.add_argument("-d", "--delete", nargs='?',
                        const=os.getcwd(), type=str, help="delete a path from storage, default '.', if you specify a number, it will delete the path by number.")
    parser.add_argument("-n", "--num", type=int, default=0,
                        help="specify the number of path to operate.")
    parser.add_argument("-l", "--list", action='store_true',
                        help="list all stored path.")
    parser.add_argument("-c", "--config", action='store_true',
                        help="show config file path.")
    parser.add_argument("-p", "--plain", action='store_true',
                        help="dont show color in output.")
    args = vars(parser.parse_args())

    path_color = 0 if args['plain'] else 3

    if any(args.values()):
        if args['add']:
            add_path(args['add'], path_color)
        elif args['delete']:
            delete_path(args['delete'], path_color, args['num'])
        elif args['list'] or args['num']:
            list_path(path_color, args['num'])
        elif args['config']:
            show_config(path_color)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
