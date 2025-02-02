# -*- coding: utf-8 -*-
# need pip install ollama rich readchar

import os
import sys
import argparse
import json
import signal
import time
import threading
import socket
from ollama import Client
import pprint
import readchar
from rich.console import Console
from rich.table import Table
from rich.prompt import IntPrompt
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

def quiet_import():
    try:
        import argparse
        import json
        import signal
        import time
        import threading
        import socket
        from ollama import Client
        import pprint
        import readchar
        from rich.console import Console
        from rich.table import Table
        from rich.prompt import IntPrompt
        from rich.markdown import Markdown
        from rich import box
        return True
    except KeyboardInterrupt:
        print("\n\nctrl + c catched, exit.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

quiet_import()

should_exit = False
is_generating = False
ollama_dir_name = ".ollama"
ollama_dir_path = os.path.expanduser(f"~/{ollama_dir_name}")
ollama_config_name = "config.json"
ollama_config_path = os.path.join(ollama_dir_path, ollama_config_name)

split_line_char = "─"
split_line_length = 30

def signal_handler(signum, frame):
    global should_exit
    should_exit = True
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_ollama_config_path():
    """获取默认配置文件路径"""
    return ollama_config_path

def load_config(config_path):
    """加载配置文件，如果指定路径不存在则尝试加载默认配置"""
    config = {}
    
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    
    # 确保 .ollama 文件夹存在
    if not os.path.exists(ollama_dir_path):
        try:
            os.makedirs(ollama_dir_path)
        except Exception as e:
            print(color(f"\nError creating directory {ollama_dir_path}: {str(e)}", 2))
            return config
    
    default_config = get_ollama_config_path()
    if os.path.exists(default_config):
        with open(default_config, 'r') as f:
            return json.load(f)
    
    return config

def color(text: str = '', color: int = 2) -> str:
    '''
    返回对应的控制台 ANSI 颜色; 
    ```python
    color_table = {
        0: '无色', 
        1: '黑色加粗',
        2: '红色加粗',
        3: '绿色加粗',
        4: '黄色加粗',
        5: '蓝色加粗',
        6: '紫色加粗',
        7: '青色加粗',
        8: '白色加粗',
    }
    ```
    '''
    color_table = {
        0: '{}',
        1: '\033[1;30m{}\033[0m',
        2: '\033[1;31m{}\033[0m',
        3: '\033[1;32m{}\033[0m',
        4: '\033[1;33m{}\033[0m',
        5: '\033[1;34m{}\033[0m',
        6: '\033[1;35m{}\033[0m',
        7: '\033[1;36m{}\033[0m',
        8: '\033[1;37m{}\033[0m',
    }
    return color_table[color].format(text)

def show_loading_animation():
    """显示加载动画"""
    animation = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    global is_generating
    start_time = time.time()  # 记录开始时间
    while is_generating:
        if should_exit:
            break
        elapsed = time.time() - start_time  # 计算已过时间
        sys.stdout.write(color(f"\r{animation[i]} Generating response... ({elapsed:.1f}s)", 6))
        sys.stdout.flush()
        time.sleep(0.1)
        i = (i + 1) % len(animation)
    sys.stdout.write("\r" + " " * 50 + "\r")  # Clear status bar (increased width)
    sys.stdout.flush()

def format_size(size_bytes):
    """智能转换文件大小单位"""
    for unit in ['MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"

class OllamaClient:
    def __init__(self, ip, port, ssl=False):
        self.ip = ip
        self.port = port
        protocol = "https" if ssl else "http"
        self.host = f"{protocol}://{self.ip}:{self.port}"
        try:
            self.client = Client(host=self.host)
        except Exception as e:
            print(color("\nConnection Error:", 2))
            print(color(f"Failed to connect to Ollama service at {self.host}", 2))
            print(color(f"Reason: {str(e)}", 2))
            print(color("\nPossible solutions:", 3))
            print(color("1. Check if Ollama service is running", 7))
            print(color("2. Verify IP address and port", 7))
            print(color("3. Check network connectivity", 7))
            sys.exit(1)
    
    def _get_models(self):
        """获取原始模型列表数据"""
        try:
            response = self.client.list()
            return json.loads(response.model_dump_json())['models']
        except Exception as e:
            print(color("\nAPI Error:", 2))
            print(color("Failed to get model list", 2))
            print(color(f"Reason: {str(e)}", 2))
            return []
    
    def list_models(self):
        """获取模型列表对象"""
        return self._get_models()
    
    def get_available_models(self):
        """获取可用模型名称列表"""
        return [model['model'] for model in self._get_models()]
    
    def show_model_list(self):
        """显示模型列表"""
        models = self._get_models()
        if not models:
            print(color("\nNo models available.", 2))
            return
        
        print(color("Available models:", 3))
        for model in models:
            param_size = model.get('details', {}).get('parameter_size', 'N/A')
            size_mb = model.get('size', 0) / (1024 * 1024)  # 转换为 MB
            formatted_size = format_size(size_mb)
            print(color(f"- {model['model']} ({param_size} params, {formatted_size})", 7))
    
    def show_model_selection(self, current_model=None):
        """显示模型选择界面"""
        try:
            models = self._get_models()
            if not models:
                print(color("\nNo models available.", 2))
                return None
            
            console = Console()
            
            # 创建表格
            table = Table(
                title="Available Models",
                box=box.ROUNDED,
                header_style="bold cyan",
                border_style="cyan",
                title_style="bold cyan",
                show_lines=True
            )
            
            # 添加列
            table.add_column("#", style="dim")
            table.add_column("Model", style="bold")
            table.add_column("Parameters", style="green")
            table.add_column("Size", style="blue")
            
            # 添加数据行
            for idx, model in enumerate(models, 1):
                param_size = model.get('details', {}).get('parameter_size', 'N/A')
                size_mb = model.get('size', 0) / (1024 * 1024)
                formatted_size = format_size(size_mb)
                
                # 添加到表格
                table.add_row(
                    str(idx),
                    model['model'],
                    param_size,
                    formatted_size
                )
            
            # 显示表格
            console.print()
            console.print(table)
            console.print()
            
            # 添加提示
            console.print(Panel(
                "[cyan]Enter number to select (1-{}) or 0 to quit[/cyan]".format(len(models)),
                border_style="cyan",
                box=box.ROUNDED
            ))
            
            # 使用 IntPrompt 进行选择
            try:
                choice = IntPrompt.ask(
                    "\nSelect model",
                    console=console,
                    default=1
                )
                
                if choice == 0:
                    return None
                elif 1 <= choice <= len(models):
                    return models[choice-1]['model']
                else:
                    console.print("[red]Invalid selection.[/red]")
                    return None
                
            except KeyboardInterrupt:
                return None
            
        except Exception as e:
            print(color(f"\nError displaying model selection: {str(e)}", 2))
            print(color("\nAvailable models:", 3))
            self.show_model_list()  # 如果 rich 界面失败，回退到简单列表显示
            return None
    
    def generate(self, model, prompt):
        try:
            return self.client.generate(model, prompt)
        except Exception as e:
            error_msg = str(e)
            if "502" in error_msg:
                print(color("\nServer Error (502):", 2))
                print(color("The Ollama server is not responding properly", 2))
                print(color("\nPossible solutions:", 3))
                print(color("1. Check if the model is properly loaded", 7))
                print(color("2. Restart the Ollama service", 7))
                print(color("3. Try again in a few moments", 7))
            else:
                print(color("\nGeneration Error:", 2))
                print(color("Failed to generate response", 2))
                print(color(f"Reason: {error_msg}", 2))
            raise
    
    def print_response(self, content):
        """使用 rich markdown 渲染回复内容"""
        console = Console()
        try:
            # 尝试作为 markdown 渲染
            md = Markdown(content)
            console.print(md)
        except Exception:
            # 如果渲染失败，回退到普通文本显示
            print(content)
    
    def chat(self, model, messages):
        try:
            return self.client.chat(model=model, messages=messages)
        except Exception as e:
            error_msg = str(e)
            if "502" in error_msg:
                print(color("\nServer Error (502):", 2))
                print(color("The Ollama server is not responding properly", 2))
                print(color("\nPossible solutions:", 3))
                print(color("1. Check if the model is properly loaded", 7))
                print(color("2. Restart the Ollama service", 7))
                print(color("3. Try again in a few moments", 7))
            else:
                print(color("\nChat Error:", 2))
                print(color("Failed to get response", 2))
                print(color(f"Reason: {error_msg}", 2))
            raise
    
    def status(self):
        return self.client.ps()
    
    def generate_config_file(self, config_path):
        default_config = {
            "ip": "127.0.0.1",
            "port": "11434",
            "model": "llama3.2:1b",
            "ssl": False,
            "pre_prompt": "1. Answer in Chinese\n2. Be concise and efficient"
        }
        
        # 如果是默认配置路径，确保目录存在
        if config_path == ollama_config_path:
            try:
                if not os.path.exists(ollama_dir_path):
                    os.makedirs(ollama_dir_path)
            except Exception as e:
                print(color(f"\nError creating directory {ollama_dir_path}: {str(e)}", 2))
                return
        
        # 确保目标文件的目录存在
        config_dir = os.path.dirname(config_path)
        if config_dir and not os.path.exists(config_dir):
            try:
                os.makedirs(config_dir)
            except Exception as e:
                print(color(f"\nError creating directory {config_dir}: {str(e)}", 2))
                return
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    existing_config = json.load(f)
                    default_config.update(existing_config)
            except json.JSONDecodeError:
                print(color(f"Warning: Existing config file '{config_path}' is invalid, using default values", 4))
        
        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=4)
            print(color(f"Config file generated at: {config_path}", 3))
            print(color("\nConfig contents:", 7))
            print(json.dumps(default_config, indent=4))
        except Exception as e:
            print(color(f"Error generating config file: {str(e)}", 2))

def check_required_params(args, config):
    """检查必要参数是否完整"""
    errors = []
    suggestions = []
    
    if not args['model'] and not config.get('model'):
        errors.append("No model specified")
        suggestions.append("Use -m/--model to specify a model or set it in config file")
    
    if not args['config']:
        if not args['ip'] and not config.get('ip'):
            errors.append("No server IP specified")
            suggestions.append("Use -i/--ip to specify server IP or use a config file (-c)")
        if not args['port'] and not config.get('port'):
            errors.append("No server port specified")
            suggestions.append("Use -p/--port to specify server port or use a config file (-c)")
    
    if errors:
        default_config = get_ollama_config_path()
        print(color("\nConfiguration Error:", 2))
        for error in errors:
            print(color(f"- {error}", 2))
        
        print(color("\nSuggestions:", 3))
        for suggestion in suggestions:
            print(color(f"- {suggestion}", 7))
        
        print(color("\nYou can:", 3))
        print(color("1. Create default config file (recommended):", 7))
        print(color(f"   {os.path.basename(sys.argv[0])} --new-config {default_config}", 8))
        print(color("2. Use existing config file:", 7))
        print(color(f"   {os.path.basename(sys.argv[0])} -c config.json", 8))
        print(color("3. Specify all parameters manually:", 7))
        print(color(f"   {os.path.basename(sys.argv[0])} -i 127.0.0.1 -p 11434 -m llama3.2:1b", 8))
        sys.exit(1)

def get_user_input(prompt_text):
    """获取用户输入，支持退格键等编辑功能"""
    print(prompt_text, end='', flush=True)
    buffer = []
    while True:
        char = readchar.readchar()
        if char == '\r' or char == '\n':  # Enter 键
            print()  # 换行
            return ''.join(buffer)
        elif char == '\x03':  # Ctrl+C
            raise KeyboardInterrupt
        elif char == '\x7f' or char == '\x08':  # 退格键
            if buffer:
                buffer.pop()
                print('\b \b', end='', flush=True)  # 删除一个字符
        elif char.isprintable():  # 可打印字符
            buffer.append(char)
            print(char, end='', flush=True)

def show_current_config(args, config):
    """显示当前配置信息"""
    console = Console()
    
    # 合并命令行参数和配置文件
    current_config = {
        'ip': args['ip'] or config.get('ip', '127.0.0.1'),
        'port': args['port'] or config.get('port', '11434'),
        'model': args['model'] or config.get('model', ''),
        'ssl': args['ssl'] or config.get('ssl', False),
        'pre_prompt': args['pre_prompt'] or config.get('pre_prompt', '')
    }
    
    # 创建表格
    table = Table(
        title="Current Configuration",
        box=box.ROUNDED,
        header_style="bold cyan",
        border_style="cyan",
        title_style="bold cyan"
    )
    
    table.add_column("Parameter", style="bold green")
    table.add_column("Value", style="yellow")
    table.add_column("Source", style="blue")
    
    # 添加配置信息到表格
    for key, value in current_config.items():
        source = "Command Line" if args.get(key) else "Config File" if key in config else "Default"
        # 处理 pre_prompt 的多行显示
        if key == 'pre_prompt' and value:
            value = value.replace('\n', '\\n')
        table.add_row(key, str(value), source)
    
    # 添加配置文件路径信息
    if args['config']:
        table.add_row("Config File", args['config'], "Command Line")
    elif os.path.exists(ollama_config_path):
        table.add_row("Config File", ollama_config_path, "Default")
    
    console.print()
    console.print(table)
    console.print()

def main():
    global is_generating
    
    socket.setdefaulttimeout(5)
    script_name = os.path.basename(sys.argv[0])
    
    # 检查默认配置文件
    default_config = {}
    if os.path.exists(ollama_config_path):
        try:
            with open(ollama_config_path, 'r') as f:
                default_config = json.load(f)
        except json.JSONDecodeError:
            print(color(f"\nWarning: Default config file '{ollama_config_path}' is invalid", 4))
    
    examples = f'''
{color("Required:", 2)}
  - Model name (-m or in config)
  - Either specify server details (-i, -p) or use a config file (-c)
  - Default config file {ollama_config_path} will be used if exists

{color("Config File Format:", 3)}
  {{
    "ip": "127.0.0.1",
    "port": "11434",
    "model": "llama3.2:1b",
    "ssl": false,
    "pre_prompt": "1. Answer in Chinese\\n2. Be concise"
  }}

{color("Examples:", 3)}
  {color("# Start chat with local server", 7)}
  {script_name} -m llama3.2:1b

  {color("# Use config file (recommended)", 7)}
  {script_name} -c config.json

  {color("# Connect to remote server", 7)}
  {script_name} -i 127.0.0.1 -p 11434 -m llama3.2:1b

  {color("# List available models", 7)}
  {script_name} -l

  {color("# Show server status", 7)}
  {script_name} --status

  {color("# Generate new config file", 7)}
  {script_name} --new-config config.json

  {color("# Use custom pre-prompt", 7)}
  {script_name} -m llama3.2:1b --pre-prompt "1. Answer in Chinese\\n2. Be concise"

  {color("# Use SSL connection", 7)}
  {script_name} -s -i api.example.com -p 443 -m llama3.2:1b

  {color("# Generate single response and exit", 7)}
  {script_name} -c config.json --exit "What is Python?"
  {script_name} -i 127.0.0.1 -p 11434 -m llama3.2:1b --exit "What is Python?"
'''
    
    class ColoredHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def __init__(self, prog, indent_increment=2, max_help_position=24, width=None):
            super().__init__(prog, indent_increment, max_help_position, width)
        
        def format_help(self):
            help_text = super().format_help()
            help_text = help_text.replace('usage:', color('usage:', 3))
            help_text = help_text.replace('options:', color('options:', 3))
            help_text = help_text.replace('Ollama CLI Tool', color('Ollama CLI Tool', 4))
            return help_text
    
    ap = argparse.ArgumentParser(
        description=color('Ollama CLI Tool', 4),
        formatter_class=ColoredHelpFormatter,
        epilog=examples
    )
    ap.add_argument('-c', '--config', type=str, help='Path to config file (JSON)')
    ap.add_argument('--new-config', type=str, help='Generate new config file at specified path')
    ap.add_argument('-s', '--ssl', action='store_true', help='Use SSL connection')
    ap.add_argument('-m', '--model', type=str, help='Model name (e.g., llama3.2:1b)')
    ap.add_argument('-i', '--ip', type=str, help='API IP address (default: 127.0.0.1)')
    ap.add_argument('-p', '--port', type=str, default='11434', help='API port number (default: 11434)')
    ap.add_argument('-l', '--list', action='store_true', help='List available models')
    ap.add_argument('--status', action='store_true', help='Show Ollama status')
    ap.add_argument('--pre-prompt', type=str, help='Set pre-prompt instructions for the model (e.g., "1. Answer in Chinese\\n2. Be concise")')
    ap.add_argument('-e', '--exit', type=str, help='Generate single response and exit')
    ap.add_argument('--show-config', action='store_true', help='Show current configuration')
    
    args = vars(ap.parse_args())
    
    if args['new_config']:
        client = OllamaClient('127.0.0.1', '11434')
        client.generate_config_file(args['new_config'])
        return
    
    config = {}
    if args['config']:
        config = load_config(args['config'])
        if not config:
            print(color(f"\nError: Config file '{args['config']}' not found or empty", 2))
            if os.path.exists(ollama_config_path):
                print(color(f"\nUsing default config file: {ollama_config_path}", 3))
                config = default_config
            else:
                print(color("\nYou can:", 3))
                print(color("1. Generate a new config file:", 7))
                print(color(f"  {script_name} --new-config {args['config']}", 8))
                print(color("2. Create default config file:", 7))
                print(color(f"  {script_name} --new-config {ollama_config_path}", 8))
            return
    else:
        # 如果没有指定配置文件，使用默认配置
        config = default_config
    
    # 在检查参数之前添加显示配置的处理
    if args['show_config']:
        show_current_config(args, config)
        return
    
    # 只在需要完整配置的命令时检查参数
    if not args['list'] and not args['status'] and not args['new_config'] and not args['show_config']:
        check_required_params(args, config)
    
    try:
        client = OllamaClient(args['ip'], args['port'], args['ssl'])
    except KeyboardInterrupt:
        sys.exit(0)
    
    if args['list']:
        try:
            client.show_model_list()
        except KeyboardInterrupt:
            sys.exit(0)
        return
    
    if args['status']:
        try:
            status = client.status()
            print(color("Ollama Status:", 3))
            pprint.pprint(status)
        except KeyboardInterrupt:
            sys.exit(0)
        return
    
    if not args['model']:
        args['model'] = client.show_model_selection()
        if not args['model']:
            return
    
    available_models = client.get_available_models()
    if args['model'] not in available_models:
        print(color(f"\nError: Model '{args['model']}' is not available", 2))
        print(color("\nPlease select a model:", 3))
        args['model'] = client.show_model_selection(args['model'])
        if not args['model']:
            return
    
    if args['exit']:
        try:
            is_generating = True
            start_time = time.time()
            loading_thread = threading.Thread(target=show_loading_animation)
            loading_thread.daemon = True
            loading_thread.start()
            
            messages = []
            if args['pre_prompt']:
                messages.append({
                    "role": "system",
                    "content": args['pre_prompt']
                })
            messages.append({
                "role": "user",
                "content": args['exit']
            })
            
            try:
                response = client.chat(args['model'], messages)
                is_generating = False
                loading_thread.join()
                
                assistant_message = response.message
                messages.append({"role": "assistant", "content": assistant_message['content']})
                elapsed = time.time() - start_time  # 获取总思考时间
                print(f"{color(args['model'], 6)} {color(f'[Responded in {elapsed:.1f}s]:', 8)}")  # 使用不同颜色
                client.print_response(assistant_message['content'])
                print(color(split_line_char * split_line_length, 8))  # 添加底部分隔线
            except Exception:
                is_generating = False
                loading_thread.join()
                sys.exit(1)
            return
        except Exception:
            is_generating = False
            if loading_thread.is_alive():
                loading_thread.join()
            sys.exit(1)
        
    print(color(f"Starting chat with model: {args['model']}", 3))
    print(color("Press Ctrl+C to exit", 7))
    
    messages = []
    # Add pre-prompt if specified
    if args['pre_prompt']:
        messages.append({
            "role": "system",
            "content": args['pre_prompt']
        })
    
    try:
        while True:
            if should_exit:
                break
                
            user_input = get_user_input(color("\nYou: ", 4))
            if not user_input.strip():
                continue
            
            print(color(split_line_char * split_line_length, 8))  # 添加顶部分隔线
            messages.append({"role": "user", "content": user_input})
            try:
                is_generating = True
                start_time = time.time()  # 记录开始时间
                loading_thread = threading.Thread(target=show_loading_animation)
                loading_thread.daemon = True
                loading_thread.start()
                
                response = client.chat(args['model'], messages)
                is_generating = False
                loading_thread.join()
                
                assistant_message = response.message
                messages.append({"role": "assistant", "content": assistant_message['content']})
                elapsed = time.time() - start_time  # 获取总思考时间
                print(f"\n{color(args['model'], 6)} {color(f'[Responded in {elapsed:.1f}s]:', 8)}", end="")  # 使用不同颜色
                client.print_response(assistant_message['content'])
                print(color(split_line_char * split_line_length, 8))  # 添加底部分隔线
            except Exception as e:
                is_generating = False
                if loading_thread.is_alive():
                    loading_thread.join()
                print(color(f"\nError: {str(e)}", 2))
                if should_exit:
                    break
                messages.pop()
                
    except EOFError:
        pass  # Handle EOFError, exit silently
    finally:
        if should_exit:
            print(color("\nchat ended, exit.", 3))
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)  # Exit silently
    except Exception as e:
        print(color(f"\nError: {str(e)}", 2))
        sys.exit(1)