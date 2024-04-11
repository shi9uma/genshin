# -*- coding: utf-8 -*-

import os
import hashlib
import base64
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-k', '--key', type=str, help='seed')
ap.add_argument('-l', '--length', default=15, type=int, help='key length')
ap.add_argument('-s', '--salt', type=str, default=None, help='指定一个含有 salt 的文件路径, 没有则自动创建并写入随机字符')
args = vars(ap.parse_args())

def get_salt(seed, salt_file='salt'):
    if os.path.exists(salt_file):
        with open(salt_file, 'r') as file:
            salt = file.read()
            if salt != '':
                return salt
    salt = generate_password_with_salt(seed = seed, length = 20, no_print = True)
    with open(salt_file, 'w') as file:
        file.write(salt)

    return salt

def generate_password_with_salt(seed: str, length=15, salt_file=None, no_print = False):
    
    hash_bytes = hashlib.sha256(seed.encode()).digest()
    if salt_file is not None:
        salt = get_salt(seed, salt_file)
        hash_bytes = hashlib.pbkdf2_hmac('sha256', hash_bytes, salt.encode(), 100000)
    base64_bytes = base64.b64encode(hash_bytes)
    password = ''.join(filter(lambda x: x.isalnum() or x in '-#.', base64_bytes.decode()))[:length]
    
    if no_print: return password
    print('Generated password of length {}: {}'.format(len(password), password))

if __name__ == "__main__":
    if args['key'] is None:
        from time import time
        tmp_seed = str(time())
        print('use random seed base on time.time(): {}'.format(tmp_seed))
    else: tmp_seed = args['key']
    generate_password_with_salt(tmp_seed, args['length'], args['salt'])