# -*- coding: utf-8 -*-

import shodan
import os

api_storage_name = '.shodan'
if os.environ.get('USERPROFILE') != None:
    api_storage_path = f'{os.environ.get("USERPROFILE").replace("\\", "/")}/{api_storage_name}'
elif os.environ.get('HOME') != None:
    api_storage_path = f'{os.environ.get("HOME")}/{api_storage_name}'
else:
    api_storage_path = f'{os.path.dirname(os.path.abspath(__file__))}/{api_storage_name}'

def check_api():
    pass