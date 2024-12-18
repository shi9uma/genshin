# -*- coding: utf-8 -*-

import os
import sys
import hashlib
import base64
import argparse
import subprocess
from time import time


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
    return color_table[color].format(text)


def get_system_uuid() -> str:
    try:
        if sys.platform == "win32":
            cmd = 'wmic csproduct get UUID'
            uuid = subprocess.check_output(cmd).decode().split('\n')[1].strip()
        elif sys.platform == "linux":
            cmd = 'cat /proc/sys/kernel/random/uuid'
            uuid = subprocess.check_output(cmd, shell=True).decode().strip()
        else:
            raise Exception("Unsupported OS")
        return uuid
    except Exception as e:
        print(f"Error obtaining system UUID: {e}")
        exit()


def get_salt(uuid: str, key: str, salt_file='salt') -> str:
    if os.path.exists(salt_file):
        with open(salt_file, 'r') as file:
            salt = file.read()
            if salt != '':
                return salt

    salt_sha256_obj = hashlib.sha256(uuid.encode())
    salt_sha256_obj.update(key.encode())
    salt = salt_sha256_obj.hexdigest()[:16]

    with open(salt_file, 'w') as file:
        file.write(salt)
    return salt

def check_length(src_length: int, generated_password: str) -> int:
    this_length = len(generated_password)
    return src_length - this_length if this_length < src_length else 0
    

def generate_password(seed: str, length: int, salt_file: str, char_set: str = None, is_recursive: bool = False) -> str:
    if salt_file is not None:
        system_uuid = get_system_uuid()
        salt = get_salt(system_uuid, seed, salt_file)
        salt = base64.b64encode(salt.encode()).decode('utf-8')
    else:
        salt = seed

    hash_bytes = hashlib.sha256(seed.encode()).digest()
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        hash_bytes,
        salt.encode(),  # 如果没有 salt，则直接使用自身作为 salt
        10000
    )
    base64_bytes = base64.b64encode(hash_bytes)
    
    if char_set:
        password = ''.join(filter(lambda x: x in char_set, base64_bytes.decode()))
    else:
        password = ''.join(filter(lambda x: x.isalnum() or x in '-#.', base64_bytes.decode()))  # default raw password
    
    # handle situation which first generated length not enough
    if is_recursive:
        return password[:length]
    else:
        length_to_add = check_length(length, password)
        while length_to_add != 0:
            password += generate_password(password, length_to_add, salt_file, char_set, True)
            length_to_add = check_length(length, password)

    return password[:length]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-k', '--key', type=str,
                    help='Seed for password generation')
    ap.add_argument('-l', '--length', default=15,
                    type=int, help='Password length')
    ap.add_argument('-s', '--salt', type=str, default=None,
                    help='指定一个含有 salt 的文件路径, 没有则自动创建并写入随机字符')
    ap.add_argument('--char', type=str, default=None,
                    help='指定密码生成的字符集, 例如 --char "abcdefg123"')
    args = vars(ap.parse_args())

    if args['key'] is None:
        tmp_seed = str(time())
        print('Using random seed based on time.time(): {}'.format(color(tmp_seed, 3)))
    else:
        tmp_seed = args['key']

    password = generate_password(tmp_seed, args['length'], args['salt'], args['char'])
    print('Generated password of length {}: {}'.format(
        color(str(len(password)), 3),
        color(password, 4)
    ))


if __name__ == "__main__":
    main()
