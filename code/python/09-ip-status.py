# -*- coding: utf-8 -*-
# 感谢 https://ip-api.com 提供的接口

import subprocess
import json
import argparse

class Config:
    BASE_URL = "http://ip-api.com"
    COLORS = {
        "TITLE": 7,
        "SUB_TITLE": 2,
        "CONTENT": 3,
    }
    EXCLUDE_KEYS = ["status", "query"]

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

class ColoredArgumentParser(argparse.ArgumentParser):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if action.nargs == 0:
                parts.extend(map(lambda x: color(x, Config.COLORS["SUB_TITLE"]), action.option_strings))
            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append(color(f'{option_string} {args_string}', Config.COLORS["SUB_TITLE"]))
            return ', '.join(parts)

    def format_help(self):
        formatter = self._get_formatter()
        formatter.add_text(self.description)
        formatter.add_usage(self.usage, self._actions,
                          self._mutually_exclusive_groups)
        formatter.add_text(color("\n可选参数:", Config.COLORS["TITLE"]))
        
        for action_group in self._action_groups:
            formatter.start_section(action_group.title)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()
            
        formatter.add_text(self.epilog)
        return formatter.format_help()

ap = ColoredArgumentParser(
    description=color('IP地址查询工具 - 基于 ip-api.com 接口', Config.COLORS["TITLE"]),
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=f'''
{color("示例:", Config.COLORS["SUB_TITLE"])}
  {color("%(prog)s", Config.COLORS["CONTENT"])}                     # 查询本机公网IP信息
  {color("%(prog)s -i 8.8.8.8", Config.COLORS["CONTENT"])}         # 查询指定IP信息
  {color("%(prog)s -c", Config.COLORS["CONTENT"])}                 # 显示curl命令
  {color("%(prog)s -f json", Config.COLORS["CONTENT"])}           # 以JSON格式输出
  
{color("输出信息包含:", Config.COLORS["SUB_TITLE"])}
  {color("- IP地址", Config.COLORS["CONTENT"])}
  {color("- 国家/地区", Config.COLORS["CONTENT"])}
  {color("- 城市", Config.COLORS["CONTENT"])}
  {color("- ISP提供商", Config.COLORS["CONTENT"])}
  {color("- 地理位置(经纬度)", Config.COLORS["CONTENT"])}
  {color("- 时区", Config.COLORS["CONTENT"])}
''')

ap.add_argument("-i", "--ip", 
    default="", 
    type=str,
    metavar=color("IP", Config.COLORS["CONTENT"]),
    help=color("指定要查询的IP地址", Config.COLORS["CONTENT"])
)
ap.add_argument("-c", "--cmd", 
    action="store_true",
    help=color("显示对应的curl命令", Config.COLORS["CONTENT"])
)
ap.add_argument("-f", "--format",
    choices=['text', 'json', 'csv'],
    default='text',
    help=color("指定输出格式(默认: text)", Config.COLORS["CONTENT"])
)
ap.add_argument("-t", "--timeout",
    type=int,
    default=5,
    metavar=color("SECONDS", Config.COLORS["CONTENT"]),
    help=color("设置请求超时时间(默认: 5秒)", Config.COLORS["CONTENT"])
)
args = vars(ap.parse_args())

class IPRSSClient:
    def __init__(self, args):
        self.ip = ""
        self.args = args

    def execute_curl(self, url):
        try:
            result = subprocess.run(
                ["curl", "-s", "--connect-timeout", "5", "-m", "10", url],
                capture_output=True,
                text=True,
                encoding="utf-8"
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                raise Exception(f"请求失败: {result.stderr}")
        except Exception as e:
            print(color(f"执行curl命令时出错: {str(e)}", 2))
            exit(1)

    def get_ip_with_location(self):
        """
        获取公网 IP 地址 + 详细区域
        """
        url = f"{Config.BASE_URL}/json"
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
        print(color("IP with Location:", Config.COLORS["TITLE"]))
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
        exclude_keys = Config.EXCLUDE_KEYS

    for key, value in data.items():
        if key in exclude_keys:
            continue
        if isinstance(value, dict):
            print(" " * indent + f"{color(key, Config.COLORS['CONTENT'])}:")
            format_dict(value, indent + 4, exclude_keys)
        else:
            print(
                " " * indent
                + f"{color(key, Config.COLORS['SUB_TITLE'])}: {color(value, Config.COLORS['CONTENT'])}"
            )


def check_arg(args, type) -> str:
    try:
        if args[type]:
            return args[type]
    except BaseException:
        return None


def cmd():
    print(color("curl cmd:", Config.COLORS["TITLE"]))
    print(color(f"{' ' * Config.COLORS['SUB_TITLE']}curl {Config.BASE_URL}/json/<ip>", Config.COLORS["CONTENT"]))


def check_ip_and_return_str(ip: str) -> str:
    """
    检查IP地址是否合法并提取有效IP地址
    
    Args:
        ip (str): 输入的IP地址字符串
        
    Returns:
        str: 提取出的有效IP地址
        
    Raises:
        AssertionError: 当未找到有效IP地址时抛出
    """
    import re
    assert re.search(r"\d+\.\d+\.\d+\.\d+", ip), "未找到有效的IP地址"
    return re.search(r"\d+\.\d+\.\d+\.\d+", ip).group()


if __name__ == "__main__":
    if args["ip"]:
        args["ip"] = check_ip_and_return_str(args["ip"])

    if args["cmd"]:
        cmd()
        exit()

    args = {"ip": args["ip"] if args["ip"] else ""}

    client = IPRSSClient(args)

    client.get_ip_with_location()
