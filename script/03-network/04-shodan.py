# -*- coding: utf-8 -*-

import shodan
import os
import json

api_storage_name = '.shodan'
if os.environ.get('USERPROFILE') != None:
    api_storage_path = f'{os.environ.get("USERPROFILE").replace("\\", "/")}/{api_storage_name}'
elif os.environ.get('HOME') != None:
    api_storage_path = f'{os.environ.get("HOME")}/{api_storage_name}'
else:
    api_storage_path = f'{os.path.dirname(os.path.abspath(__file__))}/{api_storage_name}'

class shodan_client:
    def __init__(self):
        self.api_storage_path = api_storage_path
        self.api_key = self.check_api_key()
    
    def init_api_key(self):
        
        pass

    def check_api_key(self) -> str:
        
        api_json = json.loads(open(self.api_storage_path, 'r').read())
        return api_json['api_key']

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