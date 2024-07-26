# -*- coding: utf-8 -*-

import argparse
import os
import sys
import subprocess
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass


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


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def pad_salt(salt: bytes, desired_length: int = 16) -> bytes:
    if len(salt) < desired_length:
        salt += b'\x00' * (desired_length - len(salt))
    elif len(salt) > desired_length:
        salt = salt[:desired_length]
    return salt


def encrypt_file(input_path: str, output_path: str, password: str, salt: bytes):
    salt = pad_salt(salt)
    key = derive_key(password, salt)
    initialization_vector = salt[:16]
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(initialization_vector),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as f:
        data = f.read()

    # aes 字节填充
    padding_length = 16 - len(data) % 16
    data += bytes([padding_length] * padding_length)

    cipher_text = encryptor.update(data) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + cipher_text)


def decrypt_file(input_path: str, output_path: str, password: str, salt: bytes = None):
    with open(input_path, 'rb') as f:
        salt_read = f.read(16)
        cipher_text = f.read()

    salt_read = pad_salt(salt_read)
    key = derive_key(password, salt_read)
    initialization_vector = salt_read[:16]
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(initialization_vector),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    data = decryptor.update(cipher_text) + decryptor.finalize()

    # 清除 aes 字节填充
    padding_length = data[-1]
    data = data[:-padding_length]

    with open(output_path, 'wb') as f:
        f.write(data)


def process_directory(directory: str, func, output_dir: str, password: str, recursive: bool, salt: bytes):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    for root, dirs, files in os.walk(directory):
        for file in files:
            input_path = os.path.join(root, file)
            rel_path = os.path.relpath(input_path, directory)
            output_path = os.path.join(output_dir, rel_path)
            func(input_path, output_path, password, salt)
        if not recursive:
            break


def get_system_uuid() -> str:
    try:
        if sys.platform == "win32":
            cmd = 'wmic csproduct get UUID'
            uuid = subprocess.check_output(cmd).decode().split('\n')[1].strip()
        elif sys.platform == "linux":
            cmd = 'cat /proc/sys/kernel/random/uuid'
            uuid = subprocess.check_output(cmd, shell=True).decode().strip()
        elif sys.platform == "Darwin":
            cmd = "system_profiler SPHardwareDataType | awk '/UUID/ { print $3; }'"
            uuid = subprocess.check_output(cmd, shell=True).decode().strip()
        else:
            raise Exception("Unsupported OS")
        return uuid
    except Exception as e:
        print(f"Error obtaining system UUID: {e}")
        exit()


def get_salt(key: str, salt_file='salt', is_use_salt=False) -> str:
    if os.path.exists(salt_file) and is_use_salt:
        with open(salt_file, 'rb') as file:
            salt = file.read()
            if salt != b'':
                return salt

    uuid = get_system_uuid() if is_use_salt else key
    salt_sha256_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
    salt_sha256_obj.update(uuid.encode())
    salt_sha256_obj.update(key.encode())
    salt = salt_sha256_obj.finalize()

    if is_use_salt:
        with open(salt_file, 'wb') as file:
            file.write(salt[:16])
    return salt


def main():
    parser = argparse.ArgumentParser(description='End of Life')
    parser.add_argument('foobar', choices=['enc', 'dec'], help='选择模式：加密或解密')
    parser.add_argument('-i', '--input', required=True, help='指定输入文件或目录路径')
    parser.add_argument('-o', '--output', help='指定输出文件或目录路径')
    parser.add_argument('-r', '--recursive',
                        action='store_true', help='是否递归处理目录')
    parser.add_argument('-d', '--delete', action='store_true', help='加密后删除源文件')
    parser.add_argument(
        '-s', '--salt', help='指定一个盐文件，如果添加该选项但路径文件为空，则根据 key 和 uuid 生成盐，并存储到指定路径')
    parser.add_argument('-k', '--key', help='指定一个密钥文件，或字符（不推荐直接暴露在命令行）')
    args = vars(parser.parse_args())

    # assert
    assert os.path.exists(args['input']), '{}'.format(color('输入文件或目录无效'), 3)

    # 检查 key 是否被指定，并取值
    if args['key'] is None:
        password = getpass(color('请输入密钥：', 3))
    else:
        if os.path.exists(args['key']):
            with open(args['key'], 'r') as f:
                password = f.read().strip()
        else:
            password = args['key']

    if args['salt'] is not None:
        salt = get_salt(password, args['salt'], is_use_salt=True)
    else:
        salt = get_salt(password, is_use_salt=False)

    if os.path.isdir(args['input']):
        if args['output'] is None:
            if args['foobar'] == 'enc':
                args['output'] = args['input'] + \
                    ('_enc' if not args['input'].endswith('_enc') else '')
            elif args['foobar'] == 'dec':
                if args['output'].endswith('_enc'):
                    temp_dir = args['output'][:-4]
                    if os.path.exists(temp_dir):
                        args['output'] = temp_dir + '_dec'
        process_directory(
            args['input'],
            encrypt_file if args['foobar'] == 'enc' else decrypt_file,
            args['output'],
            password,
            args['recursive'],
            salt
        )
    else:
        if args['output'] is None:
            args['output'] = args['input'] + \
                '.enc' if args['foobar'] == 'enc' else args['input'].rstrip(
                    '.enc')
        if args['foobar'] == 'enc':
            encrypt_file(args['input'], args['output'], password, salt)
        else:
            decrypt_file(args['input'], args['output'], password, salt)

    if args['delete'] and args['foobar'] == 'enc':
        assert input('是否删除源文件？(y/n)') == 'y', '{}'.format(color('已取消删除', 3))
        if os.path.isdir(args['input']):
            for root, dirs, files in os.walk(args['input'], topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
        else:
            os.remove(args['input'])


if __name__ == '__main__':
    main()
