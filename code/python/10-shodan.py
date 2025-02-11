# -*- coding: utf-8 -*-
# need pip install shodan rich

import os
import sys
import json
import argparse
import shodan
from datetime import datetime, timezone, timedelta
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
import threading
import time
import hashlib
import re

# 全局变量定义
shodan_dir_name = '.shodan'
shodan_dir_path = os.path.expanduser(f'~/{shodan_dir_name}')
shodan_config_name = 'config.json'
shodan_config_path = os.path.join(shodan_dir_path, shodan_config_name)
shodan_result_dir = os.path.join(shodan_dir_path, 'result')

# 全局变量
is_searching = False

def color(text: str = '', color: int = 2) -> str:
    """返回对应的控制台 ANSI 颜色"""
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

def show_loading_animation():
    """显示加载动画"""
    animation = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    global is_searching
    start_time = time.time()
    while is_searching:
        elapsed = time.time() - start_time
        sys.stdout.write(f"\r{color(f'{animation[i]} Searching... ({elapsed:.1f}s)', 6)}")
        sys.stdout.flush()
        time.sleep(0.1)
        i = (i + 1) % len(animation)
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()

class ShodanClient:
    def __init__(self):
        self.api_key = None
        self.client = None
        self.load_config()
    
    def load_config(self):
        """加载配置文件,优先使用自定义配置,如果不存在则尝试加载 shodan cli 的配置"""
        # 首先尝试加载自定义配置
        if os.path.exists(shodan_config_path):
            try:
                with open(shodan_config_path, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key')
                    if self.api_key:
                        self.client = shodan.Shodan(self.api_key)
                        return
            except Exception as e:
                print(color(f"Error loading config: {str(e)}", 2))
        
        # 如果自定义配置不存在或无效,尝试加载 shodan cli 配置
        shodan_cli_config = os.path.expanduser('~/.config/shodan/api_key')
        if os.path.exists(shodan_cli_config):
            try:
                with open(shodan_cli_config, 'r') as f:
                    self.api_key = f.read().strip()
                    if self.api_key:
                        self.client = shodan.Shodan(self.api_key)
                        # 将 shodan cli 的配置同步到自定义配置
                        self.sync_from_cli_config()
                        print(color("Using API key from Shodan CLI config", 7))
            except Exception as e:
                print(color(f"Error loading Shodan CLI config: {str(e)}", 2))
    
    def sync_from_cli_config(self):
        """将 shodan cli 的配置同步到自定义配置文件"""
        try:
            os.makedirs(shodan_dir_path, exist_ok=True)
            config = {'api_key': self.api_key}
            with open(shodan_config_path, 'w') as f:
                json.dump(config, f, indent=4)
            print(color(f"Synced API key to: {shodan_config_path}", 7))
        except Exception as e:
            print(color(f"Error syncing config: {str(e)}", 2))
    
    def init_api_key(self, api_key):
        """初始化 API key"""
        try:
            # 测试 API key 是否有效
            test_client = shodan.Shodan(api_key)
            test_client.info()
            
            # 确保目录存在
            os.makedirs(shodan_dir_path, exist_ok=True)
            
            # 保存配置
            config = {'api_key': api_key}
            with open(shodan_config_path, 'w') as f:
                json.dump(config, f, indent=4)
            
            print(color("API key successfully initialized!", 3))
            print(color(f"Config saved to: {shodan_config_path}", 7))
            
            self.api_key = api_key
            self.client = test_client
            
        except Exception as e:
            print(color("Error initializing API key:", 2))
            print(color(str(e), 2))
            sys.exit(1)
    
    def _get_cache_filename(self, query):
        """生成缓存文件名"""
        # 规范化查询字符串，处理引号内的空格
        def normalize_query(q):
            # 保护引号内的内容
            protected = []
            def protect(match):
                protected.append(match.group(0))
                return f"__PROTECTED_{len(protected)-1}__"
            
            # 保护双引号和单引号中的内容
            q = re.sub(r'"[^"]*"', protect, q)
            q = re.sub(r"'[^']*'", protect, q)
            
            # 规范化空格
            q = q.replace(' ', '_')
            
            # 还原被保护的内容
            for i, p in enumerate(protected):
                q = q.replace(f"__PROTECTED_{i}__", p.strip('"\''))
            
            return q
        
        # 规范化查询字符串
        normalized_query = normalize_query(query)
        # 使用规范化后的查询生成哈希
        query_hash = hashlib.md5(normalized_query.encode()).hexdigest()[:12]
        return os.path.join(shodan_result_dir, f"result_{query_hash}.json")
    
    def _update_search_index(self, query, cache_file, results):
        """更新搜索索引"""
        index_file = os.path.join(shodan_dir_path, 'search-result.json')
        try:
            # 读取现有索引
            index_data = {}
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    index_data = json.load(f)
            
            if 'searches' not in index_data:
                index_data['searches'] = []
            
            # 检查是否已存在相同查询
            for search in index_data['searches']:
                if search['query'] == query:
                    # 更新现有记录
                    search.update({
                        'last_updated': datetime.now().isoformat(),
                        'total_results': results.get('total', 0),
                        'matches_count': len(results.get('matches', [])),
                    })
                    break
            else:
                # 如果不存在相同查询，添加新记录
                search_record = {
                    'query': query,
                    'created_at': datetime.now().isoformat(),
                    'last_updated': datetime.now().isoformat(),
                    'result_file': os.path.basename(cache_file),
                    'total_results': results.get('total', 0),
                    'matches_count': len(results.get('matches', [])),
                }
                index_data['searches'].insert(0, search_record)
            
            # 写入索引文件
            with open(index_file, 'w') as f:
                json.dump(index_data, f, indent=2)
                
        except Exception as e:
            print(color(f"Warning: Failed to update search index: {str(e)}", 4))
    
    def search(self, query, no_cache=False, delete_cache=False):
        """执行搜索并保存结果"""
        if not self.client:
            print(color("Error: API key not configured. Use 'init' command first.", 2))
            return None
        
        global is_searching
        results = None
        
        try:
            # 检查缓存
            cache_file = self._get_cache_filename(query)
            
            # 如果指定了删除缓存且缓存存在,则删除
            if delete_cache and os.path.exists(cache_file):
                try:
                    os.remove(cache_file)
                    print(color("Deleted existing cache.", 7))
                except Exception as e:
                    print(color(f"Error deleting cache: {str(e)}", 2))
            
            # 如果不使用缓存,直接执行搜索
            if no_cache:
                is_searching = True
                loading_thread = threading.Thread(target=show_loading_animation)
                loading_thread.daemon = True
                loading_thread.start()
                results = self._do_search(query)
                is_searching = False
                loading_thread.join()
            else:
                # 检查缓存
                if os.path.exists(cache_file):
                    try:
                        with open(cache_file, 'r') as f:
                            results = json.load(f)
                            print(color("Using cached results...", 7))
                    except Exception:
                        print(color("Cache corrupted, performing new search...", 4))
                        is_searching = True
                        loading_thread = threading.Thread(target=show_loading_animation)
                        loading_thread.daemon = True
                        loading_thread.start()
                        results = self._do_search(query)
                        is_searching = False
                        loading_thread.join()
                else:
                    is_searching = True
                    loading_thread = threading.Thread(target=show_loading_animation)
                    loading_thread.daemon = True
                    loading_thread.start()
                    results = self._do_search(query)
                    is_searching = False
                    loading_thread.join()
                
                # 保存缓存(除非指定了不使用缓存)
                if results and not no_cache:
                    try:
                        os.makedirs(shodan_result_dir, exist_ok=True)
                        cache_file = self._get_cache_filename(query)
                        
                        # 保存搜索结果
                        with open(cache_file, 'w') as f:
                            json.dump(results, f, indent=2)
                        
                        # 更新索引
                        self._update_search_index(query, cache_file, results)
                        
                    except Exception as e:
                        print(color(f"Error saving cache: {str(e)}", 2))
            
            return results
            
        except Exception as e:
            is_searching = False
            print(color(f"\nError during search: {str(e)}", 2))
            return None
    
    def _do_search(self, query):
        """执行实际的搜索操作"""
        try:
            response = self.client.search(query)
            if not response or 'matches' not in response:
                print(color("No results found or invalid response", 2))
                return None
            return response
        except Exception as e:
            print(color("Search error:", 2))
            print(color(str(e), 2))
            return None
    
    def show_info(self):
        """显示 Shodan 信息和配置"""
        if not self.client:
            print(color("Error: API key not configured. Use 'init' command first.", 2))
            return
        
        try:
            info = self.client.info()
            if not info:
                print(color("Error: Could not retrieve Shodan info", 2))
                return
            
            console = Console()
            
            # 显示 API 信息
            api_table = Table(
                title="Shodan API Information",
                box=box.ROUNDED,
                header_style="bold cyan",
                border_style="cyan"
            )
            
            api_table.add_column("Property", style="bold green")
            api_table.add_column("Value", style="yellow")
            
            for key, value in info.items():
                api_table.add_row(str(key), str(value))
            
            console.print()
            console.print(api_table)
            
            # 显示配置信息
            config_table = Table(
                title="Configuration",
                box=box.ROUNDED,
                header_style="bold cyan",
                border_style="cyan"
            )
            
            config_table.add_column("Item", style="bold green")
            config_table.add_column("Value", style="yellow")
            
            config_table.add_row("Config Directory", shodan_dir_path)
            config_table.add_row("Config File", shodan_config_path)
            config_table.add_row("Results Directory", shodan_result_dir)
            
            console.print()
            console.print(config_table)
            console.print()
            
        except Exception as e:
            print(color("Error getting info:", 2))
            print(color(str(e), 2))
            return

def main():
    script_name = os.path.basename(sys.argv[0])
    
    examples = f'''
{color("Examples:", 3)}
  {color("# Initialize API key", 7)}
  {script_name} init YOUR_API_KEY

  {color("# Search for specific terms", 7)}
  {script_name} search "apache country:cn"
  {script_name} search "nginx port:443" --no-cache
  {script_name} search 'http.favicon.hash:"-620522584" country:"cn"' --delete-cache

  {color("# Show API information and config", 7)}
  {script_name} info

{color("Notes:", 3)}
  {color("- Will automatically use API key from ~/.config/shodan/api_key if available", 7)}
  {color("- Custom config is stored in ~/.shodan/config.json", 7)}
  {color("- Search results are cached in ~/.shodan/result/", 7)}
  {color("- Use --no-cache to skip cache, --delete-cache to refresh cache", 7)}
  {color("- For complex searches, enclose the entire query in quotes", 7)}
'''
    
    parser = argparse.ArgumentParser(
        description=color('Shodan CLI Tool', 4),
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # init command
    init_parser = subparsers.add_parser('init', help='Initialize API key')
    init_parser.add_argument('api_key', help='Shodan API key')
    
    # search command
    search_parser = subparsers.add_parser('search', 
        help='Search Shodan',
        description=color('Search Shodan for specific terms', 4),
        epilog=f'''
{color("Examples:", 3)}
  {color("# Basic search", 7)}
  {script_name} search "apache country:cn"
  
  {color("# Search with quotes", 7)}
  {script_name} search 'http.html:"hello world"'
  {script_name} search 'http.favicon.hash:"-620522584"'
  
  {color("# Cache control", 7)}
  {script_name} search "nginx port:443" --no-cache
  {script_name} search "apache" --delete-cache
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    search_parser.add_argument('query', nargs='+', help='Search query (use quotes for complex queries)')
    search_parser.add_argument('--no-cache', action='store_true', help='Do not use or save cache')
    search_parser.add_argument('--delete-cache', action='store_true', help='Delete and refresh cache')
    
    # info command
    subparsers.add_parser('info', help='Show Shodan API information and config')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    client = ShodanClient()
    
    if args.command == 'init':
        client.init_api_key(args.api_key)
    
    elif args.command == 'search':
        query = ' '.join(args.query)
        results = client.search(query, no_cache=args.no_cache, delete_cache=args.delete_cache)
        
        # 更严格的结果检查
        if not results:
            print(color("No results found", 2))
            return
        
        matches = results.get('matches', [])
        if not matches:
            print(color("No matches found", 2))
            return
            
        console = Console()
        
        # 显示查询字符串
        console.print()
        console.print(f"Query: [cyan]{query}[/cyan]")
        console.print()
        
        # 显示搜索结果摘要
        total = results.get('total', 0)
        
        # 分开显示总数和获取数
        console.print(f"Total Results: [green]{total}[/green]")
        console.print(f"Matches Retrieved: [cyan]{len(matches)}[/cyan]")
        console.print()
        
        # 显示匹配项
        results_table = Table(
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="cyan",
            show_lines=True
        )
        
        # 设置列
        results_table.add_column("IP", style="bold green", width=15)
        results_table.add_column("Port", style="yellow", width=6)
        results_table.add_column("URL", style="cyan", width=30)
        results_table.add_column("Organization", style="blue", width=25)
        results_table.add_column("Location (纬度 Latitude, 经度 Longitude)", style="magenta", width=40)
        results_table.add_column("Timestamp (UTC+8)", style="green", width=19)
        
        try:
            for match in matches[:10]:
                if not isinstance(match, dict):
                    continue
                
                # 安全地获取数据
                def safe_get(data, key, default='N/A'):
                    """安全地获取字典值"""
                    try:
                        value = data.get(key)
                        return str(value) if value is not None else default
                    except:
                        return default
                
                def truncate(text, width):
                    """截断文本，添加省略号"""
                    if len(text) > width:
                        return text[:width-3] + "..."
                    return text
                
                # IP、Port、URL 保持完整
                ip = safe_get(match, 'ip_str')
                port = safe_get(match, 'port')
                protocol = 'https' if port in ['443', '8443'] else 'http'
                url = f"{protocol}://{ip}:{port}"
                
                # Organization 可以截断
                org = safe_get(match, 'org')
                if org != 'N/A':
                    org = truncate(org, 22)  # 预留一些边距空间
                
                # 获取位置信息
                location_data = match.get('location', {})
                country = safe_get(location_data, 'country_name')
                city = safe_get(location_data, 'city')
                if city != 'N/A':
                    city = truncate(city, 15)  # 城市名称过长时截断
                longitude = safe_get(location_data, 'longitude')
                latitude = safe_get(location_data, 'latitude')
                location = f"{country}, {city}\n({latitude}°N, {longitude}°E)"
                
                # 时间戳处理保持不变
                timestamp = match.get('timestamp')
                if timestamp:
                    try:
                        ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        ts = ts.astimezone(timezone(timedelta(hours=8)))
                        timestamp = ts.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        timestamp = 'N/A'
                else:
                    timestamp = 'N/A'
                
                results_table.add_row(
                    ip,
                    port,
                    url,
                    org,
                    location,
                    timestamp
                )
            
            console.print(results_table)
            console.print()
            
            if len(matches) > 10:
                console.print(f"[grey]Showing 10 of {len(matches)} matches. Full results saved to cache.[/grey]")
                console.print()
            
        except Exception as e:
            print(color(f"Error displaying results: {str(e)}", 2))
            return
    
    elif args.command == 'info':
        try:
            client.show_info()
        except Exception as e:
            print(color(f"Error displaying info: {str(e)}", 2))
            return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(color("\nOperation cancelled by user", 2))
        sys.exit(0)
    except Exception as e:
        print(color(f"\nError: {str(e)}", 2))
        sys.exit(1)