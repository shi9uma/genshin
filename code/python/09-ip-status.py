# -*- coding: utf-8 -*-
# 感谢 https://ip-api.com 提供的接口

import subprocess
import json
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-i', '--ip', default='', type=str, help='指定 ip 来查询')
ap.add_argument('-2', '--ip2location', action='store_true', help='展示 ip2location 查询结果')
ap.add_argument('-q', '--qqwry', action='store_true', help='展示 cz 查询结果')
ap.add_argument('-g', '--geoip2', action='store_true', help='展示 geoip2 查询结果')
ap.add_argument('-a', '--all', action='store_true', help='展示所有查询结果')
ap.add_argument('-c', '--cmd', action='store_true', help='展示 curl 原生指令')
args = vars(ap.parse_args())

BASE_URL = "https://ip-api.com"
TITLE_COLOR = 7
SUB_TITLE_COLOR = 2
CONTENT_COLOR = 3

class IPRSSClient:
    def __init__(self, args):
        self.ip = ''
        self.args = args

    def execute_curl(self, url):
        result = subprocess.run(
            ['curl', '-s', url], capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            raise Exception(
                f"Failed to execute curl for {url}, Error: {result.stderr}")

    def get_ip_with_location(self):
        '''
        获取公网 IP 地址 + 详细区域
        '''
        url = f"{BASE_URL}/json"
        if args['ip'] != '':
            self.ip = args['ip']
            url += f"/{self.ip}"
        response = self.execute_curl(url)
        response_json = json.loads(response)
        if response_json.get('status', '') == 'success':
            data = response_json
        else:
            raise Exception(
                f"Failed to get public ip address, Error: {response_json.get('msg', '')}")
        print(color("IP with Location:", TITLE_COLOR))
        print(
            '{}: {}; {}: {} {} {}'.format(
                color('ip', SUB_TITLE_COLOR),
                color(data['query'], CONTENT_COLOR),
                color('location', SUB_TITLE_COLOR),
                color(data['country'], CONTENT_COLOR),
                color(data['regionName'], CONTENT_COLOR),
                color(data['city'], CONTENT_COLOR),
                color(data['lat'], CONTENT_COLOR),
                color(data['lon'], CONTENT_COLOR)
            )
        )
        self.ip = data['ip']

    def query_ip_with_ip2location(self):
        '''
        在 cz 数据库中查询 IP 地址对应信息
        '''
        if check_arg(args, 'ip2location') == None:
            return
        url = f"{BASE_URL}/api/ip-query?source=ip2location&ip={self.ip}"
        response = self.execute_curl(url)
        qqwry_result = json.loads(response)
        print(color("ip2location Result:", TITLE_COLOR))
        format_dict(qqwry_result, exclude_keys=['code', 'msg'])

    def query_ip_with_qqwry(self):
        '''
        在 cz 数据库中查询 IP 地址对应信息
        '''
        if check_arg(args, 'qqwry') == None:
            return
        url = f"{BASE_URL}/api/ip-query?source=qqwry&ip={self.ip}"
        response = self.execute_curl(url)
        qqwry_result = json.loads(response)
        print(color("QQWry Result:", TITLE_COLOR))
        format_dict(qqwry_result, exclude_keys=['code', 'msg'])

    def query_ip_with_geoip2(self):
        '''
        在 geoip2 数据库中查询 IP 地址对应信息
        '''
        if check_arg(args, 'geoip2') == None:
            return
        url = f"{BASE_URL}/api/ip-query?source=geoip2&ip={self.ip}"
        response = self.execute_curl(url)
        geoip2_result = json.loads(response)
        print(color("GeoIP2 Result:", TITLE_COLOR))
        format_dict(geoip2_result)


def format_dict(data: dict, indent=0, exclude_keys=None):
    if exclude_keys is None:
        exclude_keys = ["code", "msg"]

    for key, value in data.items():
        if key in exclude_keys:
            continue
        if isinstance(value, dict):
            print(' ' * indent + f"{color(key, CONTENT_COLOR)}:")
            format_dict(value, indent + 4, exclude_keys)
        else:
            print(
                ' ' * indent + f"{color(key, SUB_TITLE_COLOR)}: {color(value, CONTENT_COLOR)}")


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
    return color_table[color].format(text)


def check_arg(args, type) -> str:
    try:
        if args[type]:
            return args[type]
    except BaseException as e:
        return None


def cmd():
    print(color('curl cmd:', TITLE_COLOR))
    print(color(f'{" " * SUB_TITLE_COLOR}curl {BASE_URL}/json?ip=', CONTENT_COLOR))
    print(color(f'{" " * SUB_TITLE_COLOR}curl {BASE_URL}/api/ip-query?source=qqwry&ip=', CONTENT_COLOR))
    print(color(f'{" " * SUB_TITLE_COLOR}curl {BASE_URL}/api/ip-query?source=geoip2&ip=', CONTENT_COLOR))


def check_ip_and_return_str(ip: str) -> str:
    '''
    检查 ip 地址是否合法, 最终只返回一个 ip 地址
    '''
    import re

    assert re.search(r'\d+\.\d+\.\d+\.\d+', ip), "no IP address found."
    return re.search(r'\d+\.\d+\.\d+\.\d+', ip).group()


if __name__ == "__main__":

    if args['ip']:
        args['ip'] = check_ip_and_return_str(args['ip'])

    if args['cmd']:
        cmd()
        exit()

    if args['all']:
        args = {
            'ip': args['ip'] if args['ip'] else '',
            'ip2location': True,
            'qqwry': True,
            'geoip2': True
        }

    client = IPRSSClient(args)

    client.get_ip_with_location()
    client.query_ip_with_ip2location()
    client.query_ip_with_qqwry()
    client.query_ip_with_geoip2()
