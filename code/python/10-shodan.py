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

# Global variable definitions
shodan_dir_name = '.shodan'
shodan_dir_path = os.path.expanduser(f'~/{shodan_dir_name}')
shodan_config_name = 'config.json'
shodan_config_path = os.path.join(shodan_dir_path, shodan_config_name)
shodan_result_dir = os.path.join(shodan_dir_path, 'result')

# Global variables
is_searching = False

def color(text: str = '', color: int = 2) -> str:
    """Return corresponding ANSI color for console output"""
    color_table = {
        0: '{}',                    # No color
        1: '\033[1;30m{}\033[0m',   # Black bold
        2: '\033[1;31m{}\033[0m',   # Red bold
        3: '\033[1;32m{}\033[0m',   # Green bold
        4: '\033[1;33m{}\033[0m',   # Yellow bold
        5: '\033[1;34m{}\033[0m',   # Blue bold
        6: '\033[1;35m{}\033[0m',   # Purple bold
        7: '\033[1;36m{}\033[0m',   # Cyan bold
        8: '\033[1;37m{}\033[0m',   # White bold
    }
    return color_table[color].format(text)

def show_loading_animation():
    """Display loading animation"""
    animation = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    global is_searching
    start_time = time.time()
    while is_searching:
        elapsed = time.time() - start_time
        sys.stdout.write(f"\r{color(f'{animation[i]} Pending... ({elapsed:.1f}s)', 6)}")
        sys.stdout.flush()
        time.sleep(0.1)
        i = (i + 1) % len(animation)
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()

class ShodanClient:
    def __init__(self):
        self.api_key = None
        self.client = None
        self.is_paid = False  # Default value
        self.load_config()
    
    def load_config(self):
        """Load config file, prioritize custom config, fallback to shodan cli config if not exists"""
        # First try to load custom config
        if os.path.exists(shodan_config_path):
            try:
                with open(shodan_config_path, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key')
                    self.is_paid = config.get('is_paid', False)  # Load is_paid status from config file
                    if self.api_key:
                        self.client = shodan.Shodan(self.api_key)
                        return
            except Exception as e:
                print(color(f"Error loading config: {str(e)}", 2))
        
        # If custom config doesn't exist or is invalid, try loading shodan cli config
        shodan_cli_config = os.path.expanduser('~/.config/shodan/api_key')
        if os.path.exists(shodan_cli_config):
            try:
                with open(shodan_cli_config, 'r') as f:
                    self.api_key = f.read().strip()
                    if self.api_key:
                        self.client = shodan.Shodan(self.api_key)
                        # Sync shodan cli config to custom config
                        self.sync_from_cli_config()
                        print(color("Using API key from Shodan CLI config", 7))
            except Exception as e:
                print(color(f"Error loading Shodan CLI config: {str(e)}", 2))
    
    def sync_from_cli_config(self):
        """Sync shodan cli config to custom config file"""
        try:
            # Test API key and get plan info
            test_client = shodan.Shodan(self.api_key)
            info = test_client.info()
            is_paid = info.get('plan', '').lower() != 'dev' and info.get('unlocked', False)
            
            os.makedirs(shodan_dir_path, exist_ok=True)
            config = {
                'api_key': self.api_key,
                'is_paid': is_paid,
                'plan': info.get('plan', 'unknown')
            }
            with open(shodan_config_path, 'w') as f:
                json.dump(config, f, indent=4)
            print(color(f"Synced API key to: {shodan_config_path}", 7))
            print(color(f"Plan type: {info.get('plan', 'unknown')} ({'Paid' if is_paid else 'Free'})", 7))
            
            # Update instance attributes
            self.is_paid = is_paid
            
        except Exception as e:
            print(color(f"Error syncing config: {str(e)}", 2))
    
    def init_api_key(self, api_key):
        """Initialize API key"""
        try:
            # Test if API key is valid
            test_client = shodan.Shodan(api_key)
            info = test_client.info()
            
            # Check if this is a paid plan
            is_paid = info.get('plan', '').lower() != 'dev' and info.get('unlocked', False)
            
            # Ensure directory exists
            os.makedirs(shodan_dir_path, exist_ok=True)
            
            # Save configuration
            config = {
                'api_key': api_key,
                'is_paid': is_paid,  # Save paid status
                'plan': info.get('plan', 'unknown')
            }
            with open(shodan_config_path, 'w') as f:
                json.dump(config, f, indent=4)
            
            print(color("API key successfully initialized!", 3))
            print(color(f"Config saved to: {shodan_config_path}", 7))
            print(color(f"Plan type: {info.get('plan', 'unknown')} ({'Paid' if is_paid else 'Free'})", 7))
            
            self.api_key = api_key
            self.client = test_client
            self.is_paid = is_paid  # Update instance attribute
            
        except Exception as e:
            print(color("Error initializing API key:", 2))
            print(color(str(e), 2))
            sys.exit(1)
    
    def _get_cache_filename(self, query, page=1):
        """Generate cache filename based on query and page number"""
        # Normalize query string, handle spaces within quotes
        def normalize_query(q):
            # Protect quoted content
            protected = []
            def protect(match):
                protected.append(match.group(0))
                return f"__PROTECTED_{len(protected)-1}__"
            
            # Protect content in double and single quotes
            q = re.sub(r'"[^"]*"', protect, q)
            q = re.sub(r"'[^']*'", protect, q)
            
            # Normalize spaces
            q = q.replace(' ', '_')
            
            # Restore protected content
            for i, p in enumerate(protected):
                q = q.replace(f"__PROTECTED_{i}__", p.strip('"\''))
            
            return q
        
        # Normalize query string and include page number
        normalized_query = normalize_query(query)
        # Generate hash from normalized query and page number
        query_hash = hashlib.md5(f"{normalized_query}_page{page}".encode()).hexdigest()[:12]
        return os.path.join(shodan_result_dir, f"result_{query_hash}.json")
    
    def _update_search_index(self, query, cache_file, results, page=1):
        """Update search index"""
        index_file = os.path.join(shodan_dir_path, 'search-result.json')
        try:
            # Read existing index
            index_data = {}
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    index_data = json.load(f)
            
            if 'searches' not in index_data:
                index_data['searches'] = []
            
            # Clean up records of non-existent cache files
            index_data['searches'] = [
                search for search in index_data['searches']
                if os.path.exists(os.path.join(shodan_result_dir, search.get('result_file', '')))
            ]
            
            # Check if query and page combination already exists
            search_key = f"{query}_page{page}"
            for search in index_data['searches']:
                if search.get('search_key') == search_key:
                    # Update existing record
                    search.update({
                        'last_updated': datetime.now().isoformat(),
                        'total_results': results.get('total', 0),
                        'matches_count': len(results.get('matches', [])),
                    })
                    break
            else:
                # If query doesn't exist, add new record
                search_record = {
                    'query': query,
                    'search_key': search_key,
                    'page': page,
                    'created_at': datetime.now().isoformat(),
                    'last_updated': datetime.now().isoformat(),
                    'result_file': os.path.basename(cache_file),
                    'total_results': results.get('total', 0),
                    'matches_count': len(results.get('matches', [])),
                }
                index_data['searches'].insert(0, search_record)
            
            # Write index file
            with open(index_file, 'w') as f:
                json.dump(index_data, f, indent=2)
                
        except Exception as e:
            print(color(f"Warning: Failed to update search index: {str(e)}", 4))
    
    def search(self, query, page=1, no_cache=False, delete_cache=False):
        """Execute search and handle caching"""
        if not self.client:
            print(color("Error: API key not configured. Use 'init' command first.", 2))
            return None
        
        # Check paid API access for pagination
        if page > 1 and not self.is_paid:
            print(color("Warning: Free API can only access the first page of results (max 100)", 4))
            page = 1
        
        global is_searching
        results = None
        
        try:
            # Check cache - now includes page number
            cache_file = self._get_cache_filename(query, page)
            
            # If delete_cache is specified and cache exists, delete it
            if delete_cache and os.path.exists(cache_file):
                try:
                    os.remove(cache_file)
                    print(color("Deleted existing cache.", 7))
                except Exception as e:
                    print(color(f"Error deleting cache: {str(e)}", 2))
            
            # Check if we need to perform a new search
            need_new_search = no_cache or delete_cache or not os.path.exists(cache_file)
            
            # For pages > 1, also check if previous page exists
            if page > 1 and not need_new_search:
                prev_cache_file = self._get_cache_filename(query, page-1)
                if not os.path.exists(prev_cache_file):
                    print(color(f"Previous page {page-1} not found, performing new search...", 7))
                    need_new_search = True
            
            if need_new_search:
                # Print search information first
                offset = (page - 1) * 100
                print(f"\nSearching with query: {color(query, 7)}, page: {color(str(page), 7)}, offset: {color(str(offset), 7)}")
                print()  # Add empty line
                
                # Start loading animation
                is_searching = True
                loading_thread = threading.Thread(target=show_loading_animation)
                loading_thread.daemon = True
                loading_thread.start()
                
                results = self._do_search(query, page)
                is_searching = False
                loading_thread.join()
                
                # Save results if search was successful
                if results and not no_cache:
                    try:
                        os.makedirs(shodan_result_dir, exist_ok=True)
                        with open(cache_file, 'w') as f:
                            json.dump(results, f, indent=2)
                        self._update_search_index(query, cache_file, results, page)
                    except Exception as e:
                        print(color(f"Error saving cache: {str(e)}", 2))
            else:
                # Use cached results
                try:
                    with open(cache_file, 'r') as f:
                        results = json.load(f)
                        print(color("Using cached results...", 7), end='')
                except Exception as e:
                    print(color(f"Error reading cache: {str(e)}", 2))
                    # If cache read fails, perform new search
                    is_searching = True
                    loading_thread = threading.Thread(target=show_loading_animation)
                    loading_thread.daemon = True
                    loading_thread.start()
                    results = self._do_search(query, page)
                    is_searching = False
                    loading_thread.join()
            
            return results
            
        except Exception as e:
            is_searching = False
            print(color(f"\nError during search: {str(e)}", 2))
            return None
    
    def _do_search(self, query, page=1):
        """Execute actual search operation against Shodan API"""
        try:
            try:
                # Use page parameter for pagination
                response = self.client.search(query, page=page)
            except shodan.APIError as e:
                if "Search cursor timed out" in str(e):
                    print(color("\nError: Search cursor timed out.", 2))
                    print(color("Note: Shodan API may timeout when accessing higher page numbers directly.", 4))
                    print(color("Suggestion: Start from page 1 or try a lower page number.", 4))
                    return None
                else:
                    raise e
            
            if not response or 'matches' not in response:
                print(color("No results found or invalid response", 2))
                return None
            
            print(color(f"Got {len(response.get('matches', []))} results", 7))
            return response
            
        except Exception as e:
            print(color("Search error:", 2))
            print(color(str(e), 2))
            return None
    
    def show_info(self):
        """Display Shodan API information and configuration"""
        if not self.client:
            print(color("Error: API key not configured. Use 'init' command first.", 2))
            return
        
        try:
            info = self.client.info()
            if not info:
                print(color("Error: Could not retrieve Shodan info", 2))
                return
            
            console = Console()
            
            # Display API information
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
            
            # Display configuration information
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
            config_table.add_row("Search Index File", os.path.join(shodan_dir_path, 'search-result.json'))
            
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
  
  {color("# Pagination (Paid API only)", 7)}
  {script_name} search "nginx" --page 2
  {script_name} search "apache country:cn" --page 3

  {color("# Limit results", 7)}
  {script_name} search "nginx" --limit 10
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    search_parser.add_argument('query', nargs='+', help='Search query (use quotes for complex queries)')
    search_parser.add_argument('--page', type=int, default=1, help='Page number (Paid API only, default: 1)')
    search_parser.add_argument('--no-cache', action='store_true', help='Do not use or save cache')
    search_parser.add_argument('--delete-cache', action='store_true', help='Delete and refresh cache')
    search_parser.add_argument('--limit', type=int, help='Limit the number of results to display')
    
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
        results = client.search(query, page=args.page, no_cache=args.no_cache, delete_cache=args.delete_cache)
        
        # Strict result validation
        if not results:
            print(color("No results found", 2))
            return
        
        matches = results.get('matches', [])
        if not matches:
            print(color("No matches found", 2))
            return
        
        # Apply limit if specified
        total_matches = len(matches)
        if args.limit and args.limit > 0:
            matches = matches[:args.limit]
            
        console = Console()
        console.print()
        
        # Get total results count
        total = results.get('total', 0)
        console.print()
        
        # Setup results table
        results_table = Table(
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="cyan",
            show_lines=True,
            padding=(0, 1)  # Reduce padding to save space
        )
        
        # Set up columns - IP, Port, URL and Location with no width limit for full display
        results_table.add_column("IP", style="bold green", no_wrap=True)
        results_table.add_column("Port", style="yellow", no_wrap=True)
        results_table.add_column("URL", style="cyan", no_wrap=True)
        results_table.add_column("Organization", style="blue", width=30)
        results_table.add_column("Location", style="magenta", no_wrap=True)
        results_table.add_column("Timestamp (UTC+8)", style="green", width=19)

        try:
            for match in matches:
                if not isinstance(match, dict):
                    continue
                
                # Safely get data
                def safe_get(data, key, default='N/A'):
                    """Safely get dictionary value"""
                    try:
                        value = data.get(key)
                        return str(value) if value is not None else default
                    except:
                        return default
                
                def truncate(text, width):
                    """Truncate text and add ellipsis"""
                    if len(text) > width:
                        return text[:width-3] + "..."
                    return text
                
                # IP, Port, URL full display, no truncation
                ip = safe_get(match, 'ip_str')
                port = safe_get(match, 'port')
                protocol = 'https' if port in ['443', '8443'] else 'http'
                url = f"{protocol}://{ip}:{port}"
                
                # Organization truncation length adjustment
                org = safe_get(match, 'org')
                if org != 'N/A':
                    org = truncate(org, 27)  # Adjusted to 27, leaving some margin space
                
                # Location information full display, no truncation
                location_data = match.get('location', {})
                country = safe_get(location_data, 'country_name')
                city = safe_get(location_data, 'city')
                longitude = safe_get(location_data, 'longitude')
                latitude = safe_get(location_data, 'latitude')
                location = f"{country}, {city}\n({latitude}°N, {longitude}°E)"
                
                # Process timestamp
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
            
            # Display query information and statistics after the table
            console.print(f"Query: [cyan]{query}[/cyan]")
            if args.page > 1:
                console.print(f"Page: [yellow]{args.page}[/yellow]")
            
            if args.limit and args.limit > 0:
                console.print(f"[grey]Total Results: {total} | Retrieved: {total_matches} | Displayed: {len(matches)} (limited by --limit)[/grey]")
            else:
                console.print(f"[grey]Total Results: {total} | Matches Retrieved: {total_matches}[/grey]")
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