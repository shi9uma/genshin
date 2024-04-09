# -*- coding: utf-8 -*-

import hashlib
import base64
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-k', '--key', type=str, help='seed')
ap.add_argument('-l', '--length', default=15, type=int, help='key length')
args = vars(ap.parse_args())

def generate_password(seed: str=None, length=15):
    hash_bytes = hashlib.sha256(seed.encode()).digest()
    base64_bytes = base64.b64encode(hash_bytes)
    password = ''.join(filter(lambda x: x.isalnum() or x in '-#.', base64_bytes.decode()))[:length]
    print('generate new password of {} length: {}'.format(length, password))

if __name__ == "__main__":
    if args['key'] is None:
        from time import time
        tmp_seed = str(time())
        print('use random seed base on time.time(): {}'.format(tmp_seed))
    else: tmp_seed = args['key']
    generate_password(tmp_seed, args['length'])