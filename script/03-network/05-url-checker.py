# -*- coding: utf-8 -*-

import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
import re

def is_valid_url(url):
    return re.match(r'^http[s]://\d+\.\d+\.\d+\.\d+/', url) is not None

def check_url(url, timeout):
    try:
        response = requests.get(url, timeout=timeout)
        return url, response.status_code, len(response.content)
    except requests.RequestException as e:
        return url, str(e), 0

def main():
    parser = argparse.ArgumentParser(description='check url')
    parser.add_argument('--path', required=True, help='result 文件的路径')
    parser.add_argument('--code', type=int, default=200, help='用于筛选状态码等于 code 的 URL')
    parser.add_argument('--timeout', type=int, default=5, help='超时时间')
    parser.add_argument('--length', type=int, default=0, help='用于筛选返回内容长度大于等于 length 的 URL')
    parser.add_argument('--thread', type=int, default=4, help='线程数')
    
    args = parser.parse_args()
    
    with open(args.path, 'r') as file:
        urls = [line.strip() for line in file if is_valid_url(line.strip())]
    
    with ThreadPoolExecutor(max_workers=args.thread) as executor:
        futures = [executor.submit(check_url, url, args.timeout) for url in urls]
        
        for future in futures:
            url, status, length = future.result()
            if isinstance(status, int):
                if (args.code is None or status == args.code) and (args.length is None or length >= args.length):
                    print(f'{url} - Status Code: {status} - Length: {length}')
            else:
                print(f'{url} - Error: {status}')

if __name__ == '__main__':
    main()