# -*- coding: utf-8 -*-

import os
import argparse
import re

# data
work_dir = os.getcwd()

video_file_ext_list = (
    '.mp4', '.flv', '.wmv', '.avi', '.webm', '3gp', '.mpg', '.mov', '.rm', '.rmvb', '.mkv'
)

image_file_ext_list = (
    '.jpg', '.png', '.jpeg', '.bmp'
)

ignore_file_list = [
    'desktop.ini', 'Thumbs.db', '._.DS_Store', '.DS_Store', '._.localized', '.localized', '._', '.git', '.gitignore', '.gitattributes', '.vscode', '__pycache__'
]

ex_ignore_file_list = [
    'rename.py', 'tools.py', 'interact-rename.py'
]

# test file list; use `tree -L 1`
test_filelist = '''
|-- 07fb14fe76fdb56d727419558dbd24d1.jpg
|-- 0905a026f284804c008dfa9c614fe840.jpg
|-- 0cdcf5efe5129a7cc314c80e6705dc8e.jpg
|-- 61-111-106393714_p0.jpg
|-- 110978512_p0.png
|-- 1150BDAF40C2E5F3B5E75952DB81525E.jpg
|-- 5FEF561475DD4AE1F4F570B233EC3096.jpg
|-- 5a8279e190b11769ab06ad50ece263bd.jpg
|-- 5f2feaf62596df85282ea1389a2c35b1.jpg
|-- f5e3d3806e0b6939c2fcdc0170e55521-1231-sadsa-safhgasjghf.jpg
`-- {98CA9747-AB19-7815-BBC0-2D6D01A9A2AD}.jpg
'''


def color(text) -> str:
    return '\033[1;33m{}\033[0m'.format(text)


def fgx(text=False, _fgx='='):
    _fgx = _fgx * 10
    print('\033[1;34m{}\033[0m {} \033[1;34m{}\033[0m'.format(
        _fgx, text if text else '分割线', _fgx))


def is_ignore(file_item, ignore_file_list: list) -> bool:
    for file_name in ignore_file_list:
        if file_name == file_item:
            return True
    return False


def show_files(file_list):
    fgx('工作目录文件列表如下')
    [print('{}{}'.format(color('|'), file_name)) for file_name in file_list]
    print('')

# main function


def fast_rename(directory, type, width=3):
    assert type in ['img', 'video'], 'type error, \'img\' or \'video\''

    files = [filename for filename in os.listdir(directory) if filename.lower(
    ).endswith(video_file_ext_list if type == 'video' else image_file_ext_list)]
    files.sort()
    for index, filename in enumerate(files):
        new_filename = '{}{}'.format(
            str(index + 1).zfill(width), '.mp4' if type == 'video' else '.png')
        if new_filename == filename:
            continue
        src = os.path.join(directory, filename)
        dst = os.path.join(directory, new_filename)
        os.rename(src, dst)
        print('{} {} => {}'.format(color('|'), filename, color(new_filename)))


def prefix_rename(file_list, width=3, mode='add', start_num=1):
    assert width > 0, 'width 必须大于 0'
    assert mode in ['add', 'remove'], 'mode error, \'add\' or \'remove\''
    assert start_num > 0, 'start_num 必须大于 0'

    if mode == 'add':
        for index, filename in enumerate(file_list):
            index += 1
            if start_num != 1:
                index += start_num - 1
            new_filename = '{}-{}'.format(str(index).zfill(width), filename)
            src = os.path.join(work_dir, filename)
            dst = os.path.join(work_dir, new_filename)
            os.rename(src, dst)
            print('{} {} => {}'.format(color('|'),
                  filename, color(new_filename)))
    elif mode == 'remove':
        for filename in file_list:
            new_filename = re.sub(
                r'^\d{{{},}}-(.*)$'.format(width), r'\1', filename)
            src = os.path.join(work_dir, filename)
            dst = os.path.join(work_dir, new_filename)
            os.rename(src, dst)
            print('{} {} => {}'.format(color('|'),
                  filename, color(new_filename)))


def interact_rename(file_list):
    # banner
    banner = '''
交互式批量重命名, 输入基本名字样式, 搭配正则匹配, 仅修改相应项目
例如有文件列表: ['24建筑美学基础15.pdf', '24建筑美学基础12.pdf', '建筑美学基础11.pdf']
想要批量修改成统一格式: ['2024_建筑美学基础-11.pdf', '2024_建筑美学基础-12.pdf', '2024_建筑美学基础-15.pdf']
则输入基本名字样式: \033[1;33m2024_建筑美学基础->\033[0m
注意: 1. 使用 > 符号来表示想要自定义内容的位置; 2. 不需要填写后缀名, 修改成的文件与源文件的后缀相同
    '''
    print(banner)
    fgx('^_^')

    # 设定 base_name
    base_name = True
    while (base_name):
        base_name = input('基本名字样式: ')
        check_base_name = base_name.replace('>', color('自定义'))
        print('基本名字样式为: {}'.format(check_base_name))
        if input('确认吗?(输入 {} 重新自定义, 输入其他(回车等)则确认): '.format(color('[F]'))) != 'f':
            break
    fgx('已确认基本名字样式为: {}'.format(check_base_name))
    print('')

    # 开始修改名字
    for old_file_path in file_list:
        while (True):
            _, file_ext = os.path.splitext(old_file_path)
            if file_ext == '':
                break
            print('正在将 {} 修改成 {}{}'.format(
                color(old_file_path), check_base_name, file_ext))

            temp_file_name = list(base_name)
            new_name = []
            count = 1
            for reg_index in range(len(temp_file_name)):
                if temp_file_name[reg_index] == '>':
                    new_name.append(input('自定义 {} => '.format(color(count))))
                    count += 1
                else:
                    new_name.append(temp_file_name[reg_index])
            new_name = ''.join(new_name)
            new_name = '{}{}'.format(new_name, file_ext)
            print('新的文件名为: {}'.format(color(new_name)))
            flag = input('输入 {} 重新修改, 输入 {} 跳过当前文件, 输入其他(回车等)则确认该修改'.format(
                color('[F]'), color('[S]')))
            if flag == 'F':
                continue
            elif flag == 'S':
                fgx('文件 {} 未修改, 跳过...'.format(color(old_file_path)), '=')
                print('')
                break
            else:
                os.rename(old_file_path, os.path.join(work_dir, new_name))
                fgx('{} => {}'.format(color(old_file_path), color(new_name)), '=')
                print('')
                break


def replace_file_name(file_list, old, new):
    assert old is not None and new is not None, 'old 和 new 不能为空'
    for file_name in file_list:
        new_filename = file_name.replace(old, new)
        if new_filename == file_name:
            continue
        src = os.path.join(work_dir, file_name)
        dst = os.path.join(work_dir, new_filename)
        os.rename(src, dst)
        print('{} {} => {}'.format(color('|'), file_name, color(new_filename)))


def sort_file(file_list, width=3):
    assert width > 0, 'width 必须大于 0'
    change_list = []  # [ [index, src, dst], []... ]
    for index, file_name in enumerate(file_list):
        new_filename = '{}-{}'.format(str(index + 1).zfill(width), file_name)
        src = os.path.join(work_dir, file_name)
        dst = os.path.join(work_dir, new_filename)
        change_list.append([index, src, dst])
        print('{} {} => {}'.format(color('|'), file_name, color(new_filename)))

    if input('是否确认以上修改?(输入 {} 以确认, 输入其他(回车等)则退出): '.format(color('[Y]'))) == 'Y':
        for index, src, dst in change_list:
            os.rename(src, dst)
        fgx('已确认以上修改', '=')
    else:
        fgx('已取消以上修改', '=')


def make_test_file(workdir):
    def touch(path):
        with open(path, 'a'):
            pass

    def mkdir(path):
        os.makedirs(path, exist_ok=True)

    if os.path.basename(workdir) == 'tests_dir':
        directory = workdir
    else:
        directory = os.path.join(workdir, 'tests_dir')
    if not os.path.exists(directory):
        mkdir(directory)

    filename_list = [filename for filename in test_filelist.replace(
        '|-- ', '').replace('`-- ', '').split('\n') if filename != '']
    for filename in filename_list:
        touch(os.path.join(directory, filename))

    if len(filename_list) == len(os.listdir(directory)):
        print('已创建 {} 个测试文件, 目录 {}'.format(
            len(filename_list), color(directory)))
    else:
        print('创建测试文件失败, 目录 {}'.format(color(directory)))


# ================================ main =================================
ap = argparse.ArgumentParser(description='用于在当前文件夹下进行批量重命名; e.g.: {} | {} | {} | {} | {} | {} | {} | {}'.format(color('rename foobar -x x1.txt x2.ini'), color('rename -w 3 -t img fast'), color(
    'rename -w 3 -m add prefix'), color('rename interact'), color('rename -o \'-\' -n \'_\' replace'), color('rename show'), color('rename -w 3 sort'), color('rename test')))
ap.add_argument('foobar', help='{} 执行快速重命名 | {} 执行前缀操作式重命名 | {} 执行交互式重命名 | {} 快速修改文件名中的指定字符 | {} 列出程序预处理文件队列 | {} 预览添加前缀并排序的文件队列 | {} 生成测试文件'.format(
    color('fast'), color('prefix'), color('interact'), color('replace'), color('show'), color('sort'), color('test')))
ap.add_argument('-w', '--width', type=int, default=3,
                help='指定重命名前缀或快速重命名时, index 格式长度, 默认 3')
ap.add_argument('-t', '--type', type=str, default='img',
                help='指定快速重命名时要处理的类型, 默认 img, 可选 {} 或 {}'.format(color('img'), color('video')))
ap.add_argument('-m', '--mode', type=str, default='add',
                help='指定快速添加前缀重命名时的模式, 默认 add, 可选 {} 或 {}'.format(color('add'), color('remove')))
ap.add_argument('--start_num', type=int, default=1,
                help='指定快速添加前缀重命名时的起始数字, 默认 1')
ap.add_argument('-x', '--exclude', nargs='+',
                default=[], help='指定要排除的文件名, 必须写在 foobar 后面; {}'.format(color('e.g: rename foobar -x dont_1 dont_2 dont_3')))
ap.add_argument('-o', '--old', type=str, help='要替换的旧字符')
ap.add_argument('-n', '--new', type=str, default='', help='要替换成的新字符')
ap.add_argument('-d', '--directory', action='store_true',
                help='是否处理文件夹, 添加即处理')
args = vars(ap.parse_args())

# ignore some files
if args['directory']:
    assert input('{}'.format(color(
        '注意, 指定了 --directory 选项, 这会包含文件夹, 是否继续? y / [n] '))) == 'y', '{}'.format('已取消操作')

ignore_file_list = ignore_file_list + ex_ignore_file_list + args['exclude']

temp_file_list = [
    filename
    for filename in os.listdir(work_dir)
    if os.path.isfile(os.path.join(work_dir, filename)) or (args['directory'] and os.path.isdir(os.path.join(work_dir, filename)))
]
temp_file_list.sort()

file_list = []
for file_item in temp_file_list:
    if is_ignore(file_item, ignore_file_list):
        continue
    file_list.append(file_item)

if any(args.values()):
    if args['foobar'] == 'fast':        # 快速重命名
        fast_rename(work_dir, args['type'], args['width'])
    elif args['foobar'] == 'prefix':    # 前缀操作式重命名
        prefix_rename(file_list, args['width'], args['mode'], args['start_num'])
    elif args['foobar'] == 'interact':  # 交互式重命名
        show_files(file_list)
        interact_rename(file_list)
    elif args['foobar'] == 'replace':   # 替换文件名中字符
        replace_file_name(file_list, args['old'], args['new'])
    elif args['foobar'] == 'show':      # 列出将要操作文件目录列表
        show_files(file_list)
    elif args['foobar'] == 'sort':      # 排序，等待确认
        sort_file(file_list, args['width'])
    elif args['foobar'] == 'test':      # 生成测试文件
        make_test_file(work_dir)
    else:
        fgx('参数错误', '=')
else:
    ap.print_help()
