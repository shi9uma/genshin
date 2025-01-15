# -*- coding: utf-8 -*-
# 感谢 https://ip-api.com 提供的接口

import subprocess
import json
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("-i", "--ip", default="", type=str, help="指定 ip 来查询")
ap.add_argument("-c", "--cmd", action="store_true", help="展示 curl 原生指令")
args = vars(ap.parse_args())

BASE_URL = "http://ip-api.com"
TITLE_COLOR = 7
SUB_TITLE_COLOR = 2
CONTENT_COLOR = 3


class IPRSSClient:
    def __init__(self, args):
        self.ip = ""
        self.args = args

    def execute_curl(self, url):
        result = subprocess.run(
            ["curl", "-s", url], capture_output=True, text=True, encoding="utf-8"
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            raise Exception(f"Failed to execute curl for {url}, Error: {result.stderr}")

    def get_ip_with_location(self):
        """
        获取公网 IP 地址 + 详细区域
        """
        url = f"{BASE_URL}/json"
        if args["ip"] != "":
            self.ip = args["ip"]
            url += f"/{self.ip}"
        response = self.execute_curl(url)
        response_json = json.loads(response)
        if response_json.get("status", "") == "success":
            data = response_json
        else:
            raise Exception(
                f"Failed to get public ip address, Error: {response_json.get('msg', '')}"
            )
        print(color("IP with Location:", TITLE_COLOR))
        self.ip = data["query"]
        format_data = {
            **{
                "ip": data["query"],
            },
            **data,
        }
        format_dict(format_data, indent=2)


def format_dict(data: dict, indent=0, exclude_keys=None):
    if exclude_keys is None:
        exclude_keys = ["status", "query"]

    for key, value in data.items():
        if key in exclude_keys:
            continue
        if isinstance(value, dict):
            print(" " * indent + f"{color(key, CONTENT_COLOR)}:")
            format_dict(value, indent + 4, exclude_keys)
        else:
            print(
                " " * indent
                + f"{color(key, SUB_TITLE_COLOR)}: {color(value, CONTENT_COLOR)}"
            )


def color(text: str = "", color: int = 2) -> str:
    """
    返回对应的控制台 ANSI 颜色
    """
    color_table = {
        0: "{}",  # 无色
        1: "\033[1;30m{}\033[0m",  # 黑色加粗
        2: "\033[1;31m{}\033[0m",  # 红色加粗
        3: "\033[1;32m{}\033[0m",  # 绿色加粗
        4: "\033[1;33m{}\033[0m",  # 黄色加粗
        5: "\033[1;34m{}\033[0m",  # 蓝色加粗
        6: "\033[1;35m{}\033[0m",  # 紫色加粗
        7: "\033[1;36m{}\033[0m",  # 青色加粗
        8: "\033[1;37m{}\033[0m",  # 白色加粗
    }
    return color_table[color].format(text)


def check_arg(args, type) -> str:
    try:
        if args[type]:
            return args[type]
    except BaseException:
        return None


def cmd():
    print(color("curl cmd:", TITLE_COLOR))
    print(color(f"{' ' * SUB_TITLE_COLOR}curl {BASE_URL}/json/<ip>", CONTENT_COLOR))


def check_ip_and_return_str(ip: str) -> str:
    """
    检查 ip 地址是否合法, 最终只返回一个 ip 地址
    """
    import re

    assert re.search(r"\d+\.\d+\.\d+\.\d+", ip), "no IP address found."
    return re.search(r"\d+\.\d+\.\d+\.\d+", ip).group()


if __name__ == "__main__":
    if args["ip"]:
        args["ip"] = check_ip_and_return_str(args["ip"])

    if args["cmd"]:
        cmd()
        exit()

    if args["all"]:
        args = {"ip": args["ip"] if args["ip"] else ""}

    client = IPRSSClient(args)

    client.get_ip_with_location()
