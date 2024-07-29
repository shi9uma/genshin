# -*- coding: utf-8 -*-
# 感谢 https://ip.rss.ink 提供的接口

import subprocess
import json
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-i', '--ip', default='', type=str, help='指定 ip 来查询')
ap.add_argument('-l', '--location', action='store_true', help='展示 location')
ap.add_argument('-q', '--qqwry', action='store_true', help='展示 cz 查询结果')
ap.add_argument('-2', '--ip2location', action='store_true', help='展示 ip2location 查询结果')
ap.add_argument('-g', '--geoip2', action='store_true', help='展示 geoip2 查询结果')
ap.add_argument('-a', '--all', action='store_true', help='展示所有查询结果')
ap.add_argument('-c', '--cmds', action='store_true', help='展示 curl 原生指令')
args = vars(ap.parse_args())

class IPRSSClient:
    def __init__(self, args) -> None:
        self.ip = ''
        self.args = args
        self.BASE_URL = "https://ip.rss.ink"

    def execute_curl(self, url):
        result = subprocess.run(['curl', '-s', url], capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            raise Exception(f"Failed to execute curl for {url}, Error: {result.stderr}")

    # def get_public_ip(self):
    #     '''
    #     获取本机公网 IP 地址
    #     '''
    #     if args['ip'] != '':
    #         self.ip = args['ip']
    #     else:
    #         url = f"{self.BASE_URL}"
    #         self.ip = self.execute_curl(url)

    def get_public_ip_v2(self):
        '''
        获取本机公网 IP 地址 + 区域
        '''
        url = f"{self.BASE_URL}/text"
        if args['ip'] != '':
            self.ip = args['ip']
            url += f"?ip={self.ip}"
        ip, location = self.execute_curl(url).split(',')
        print(color("IP with Location:", 7))
        print(f"{color('ip', 2)}: {color(ip, 3)}; {color('location', 2)}: {color(location, 3)}")
        self.ip = ip

    def get_ip_with_location(self):
        '''
        获取本机公网 IP 地址 + 详细区域
        '''
        if check_args(args, 'location') == None:
            return
        url = f"{self.BASE_URL}/json?ip={self.ip}"
        response = self.execute_curl(url)
        ip_with_location_json = json.loads(response)
        print(color("IP with Location Detail:", 7))
        format_dict(ip_with_location_json)

    def query_ip_with_qqwry(self):
        '''
        在 cz 数据库中查询 IP 地址对应信息
        '''
        if check_args(args, 'qqwry') == None:
            return
        url = f"{self.BASE_URL}/v1/qqwry?ip={self.ip}"
        response = self.execute_curl(url)
        qqwry_result = json.loads(response)
        print(color("QQWry Result:", 7))
        format_dict(qqwry_result, exclude_keys=['code', 'msg'])

    def query_ip_with_ip2location(self):
        '''
        在 ip2location 数据库中查询 IP 地址对应信息
        '''
        if check_args(args, 'ip2location') == None:
            return
        url = f"{self.BASE_URL}/v1/ip2location?ip={self.ip}"
        response = self.execute_curl(url)
        ip2location_result = json.loads(response)
        print(color("IP2Location Result:", 7))
        format_dict(ip2location_result)

    def query_ip_with_geoip2(self):
        '''
        在 geoip2 数据库中查询 IP 地址对应信息
        '''
        if check_args(args, 'geoip2') == None:
            return
        url = f"{self.BASE_URL}/v1/geoip2?ip={self.ip}"
        response = self.execute_curl(url)
        geoip2_result = json.loads(response)
        print(color("GeoIP2 Result:", 7))
        format_dict(geoip2_result)

def format_dict(data: dict, indent=0, exclude_keys=None):
    if exclude_keys is None:
        exclude_keys = ["code", "msg"]

    for key, value in data.items():
        if key in exclude_keys:
            continue
        if isinstance(value, dict):
            print(' ' * indent + f"{color(key, 4)}:")
            format_dict(value, indent + 4, exclude_keys)
        else:
            print(' ' * indent + f"{color(key, 2)}: {color(value, 3)}")

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

def check_args(args, type) -> str:
    try:
        if args[type]:
            return args[type]
    except BaseException as e:
        return None
    
def cmds():
    BASE_URL = "https://ip.rss.ink"
    print(color('curl cmds:', 7))
    print(color(f'{" " * 2}curl {BASE_URL}', 3))
    print(color(f'{" " * 2}curl {BASE_URL}/text', 3))
    print(color(f'{" " * 2}curl {BASE_URL}/json?ip=', 3))
    print(color(f'{" " * 2}curl {BASE_URL}/v1/qqwry?ip=', 3))
    print(color(f'{" " * 2}curl {BASE_URL}/v1/ip2location?ip=', 3))
    print(color(f'{" " * 2}curl {BASE_URL}/v1/geoip2?ip=', 3))

if __name__ == "__main__":
    
    if args['cmds']:
        cmds()
        exit()

    if args['all']:
        args = {
            'ip': args['ip'] if args['ip'] else '',
            'location': True,
            'qqwrt': True,
            'ip2location': True,
            'geoip2': True
        }
    
    client = IPRSSClient(args)

    try:

        # client.get_public_ip()
        client.get_public_ip_v2()
        client.get_ip_with_location()
        client.query_ip_with_qqwry()
        client.query_ip_with_ip2location()
        client.query_ip_with_geoip2()

    except Exception as e:
        print(f"Error: {str(e)}")
