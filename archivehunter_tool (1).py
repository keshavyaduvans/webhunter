#!/usr/bin/env python3
"""
ArchiveHunter - Advanced Automated Recon & Bug Hunting Tool
Author: Your Name
Version: 2.0.0
Description: Production-grade reconnaissance tool with real integrations
WARNING: Use only on authorized targets with proper permission
"""

import argparse
import json
import subprocess
import sys
import os
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin, unquote
from collections import defaultdict
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading
from queue import Queue

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    MAGENTA = '\033[35m'

class ArchiveHunter:
    def __init__(self, target, output_dir="output", threads=10):
        self.target = target
        self.domain = self.extract_domain(target)
        self.output_dir = output_dir
        self.threads = threads
        self.results = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "subdomains": [],
            "archived_urls": [],
            "parameters": {},
            "vulnerabilities": defaultdict(list),
            "interesting_endpoints": [],
            "score": 0,
            "statistics": {}
        }
        self.setup_output_dir()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def extract_domain(self, url):
        """Extract domain from URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    
    def setup_output_dir(self):
        """Create output directory structure"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_dir = os.path.join(self.output_dir, f"{self.domain}_{timestamp}")
        os.makedirs(self.scan_dir, exist_ok=True)
        print(f"{Colors.GREEN}[+] Output directory: {self.scan_dir}{Colors.END}")
    
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     █████╗ ██████╗  ██████╗██╗  ██╗██╗██╗   ██╗███████╗  ║
║    ██╔══██╗██╔══██╗██╔════╝██║  ██║██║██║   ██║██╔════╝  ║
║    ███████║██████╔╝██║     ███████║██║██║   ██║█████╗    ║
║    ██╔══██║██╔══██╗██║     ██╔══██║██║╚██╗ ██╔╝██╔══╝    ║
║    ██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████╔╝ ███████╗  ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝  ║
║                                                           ║
║         HUNTER v2.0 - Advanced Recon & Bug Hunting        ║
║           Wayback | GF Patterns | ParamSpider            ║
║                 Responsible Disclosure                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
        print(f"{Colors.YELLOW}[!] Target: {self.target}{Colors.END}")
        print(f"{Colors.YELLOW}[!] Threads: {self.threads}{Colors.END}")
        print(f"{Colors.YELLOW}[!] Use only on authorized targets!{Colors.END}\n")
    
    def check_tool_installed(self, tool_name):
        """Check if external tool is installed"""
        try:
            subprocess.run([tool_name, '-h'], 
                         capture_output=True, 
                         timeout=5)
            return True
        except:
            return False
    
    def run_command(self, cmd, description, timeout=300):
        """Execute shell command and return output"""
        print(f"{Colors.BLUE}[*] {description}...{Colors.END}")
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[-] Command timed out{Colors.END}")
            return ""
        except Exception as e:
            print(f"{Colors.RED}[-] Error: {str(e)}{Colors.END}")
            return ""
    
    def subdomain_discovery(self):
        """Advanced subdomain discovery using multiple tools"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.HEADER}[PHASE 1] Advanced Subdomain Discovery{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        subdomains = set()
        
        # Method 1: Subfinder
        if self.check_tool_installed('subfinder'):
            print(f"{Colors.CYAN}[*] Running Subfinder...{Colors.END}")
            cmd = f"subfinder -d {self.domain} -silent -all"
            output = self.run_command(cmd, "Subfinder scanning", 120)
            if output:
                subs = [line.strip() for line in output.split('\n') if line.strip()]
                subdomains.update(subs)
                print(f"{Colors.GREEN}[+] Subfinder found {len(subs)} subdomains{Colors.END}")
        else:
            print(f"{Colors.YELLOW}[!] Subfinder not installed, skipping...{Colors.END}")
        
        # Method 2: crt.sh (Certificate Transparency)
        print(f"{Colors.CYAN}[*] Checking Certificate Transparency logs...{Colors.END}")
        crt_subs = self.crtsh_search(self.domain)
        subdomains.update(crt_subs)
        print(f"{Colors.GREEN}[+] crt.sh found {len(crt_subs)} subdomains{Colors.END}")
        
        # Method 3: HackerTarget API
        print(f"{Colors.CYAN}[*] Querying HackerTarget API...{Colors.END}")
        ht_subs = self.hackertarget_search(self.domain)
        subdomains.update(ht_subs)
        print(f"{Colors.GREEN}[+] HackerTarget found {len(ht_subs)} subdomains{Colors.END}")
        
        # Add main domain
        subdomains.add(self.domain)
        subdomains.add(f"www.{self.domain}")
        
        self.results["subdomains"] = sorted(list(subdomains))
        print(f"\n{Colors.GREEN}[+] Total unique subdomains: {len(subdomains)}{Colors.END}")
        
        # Save to file
        subdomain_file = os.path.join(self.scan_dir, "subdomains.txt")
        with open(subdomain_file, 'w') as f:
            f.write('\n'.join(sorted(subdomains)))
        
        return list(subdomains)
    
    def crtsh_search(self, domain):
        """Query crt.sh for subdomains"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle wildcards and newlines
                        names = name.split('\n')
                        for n in names:
                            n = n.strip().replace('*.', '')
                            if n and domain in n:
                                subdomains.add(n)
        except Exception as e:
            print(f"{Colors.RED}[-] crt.sh error: {str(e)}{Colors.END}")
        return subdomains
    
    def hackertarget_search(self, domain):
        """Query HackerTarget API for subdomains"""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and domain in subdomain:
                            subdomains.add(subdomain)
        except Exception as e:
            print(f"{Colors.RED}[-] HackerTarget error: {str(e)}{Colors.END}")
        return subdomains
    
    def wayback_urls_advanced(self, domains):
        """Advanced Wayback Machine URL extraction with filtering"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.HEADER}[PHASE 2] Advanced Wayback URL Discovery{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        all_urls = set()
        
        # Limit domains to prevent timeout
        domains_to_scan = domains[:20] if len(domains) > 20 else domains
        
        print(f"{Colors.CYAN}[*] Scanning {len(domains_to_scan)} domains from Wayback Machine...{Colors.END}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.fetch_wayback_urls, domain): domain 
                      for domain in domains_to_scan}
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    urls = future.result()
                    all_urls.update(urls)
                    print(f"{Colors.GREEN}[+] {domain}: {len(urls)} URLs{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}[-] Error for {domain}: {str(e)}{Colors.END}")
        
        # Filter and clean URLs
        all_urls = self.filter_urls(all_urls)
        
        self.results["archived_urls"] = sorted(list(all_urls))
        print(f"\n{Colors.GREEN}[+] Total unique archived URLs: {len(all_urls)}{Colors.END}")
        
        # Save URLs
        urls_file = os.path.join(self.scan_dir, "archived_urls.txt")
        with open(urls_file, 'w') as f:
            f.write('\n'.join(sorted(all_urls)))
        
        return list(all_urls)
    
    def fetch_wayback_urls(self, domain):
        """Fetch URLs from Wayback Machine for a single domain"""
        urls = set()
        try:
            # Wayback CDX API
            api_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=10000"
            response = self.session.get(api_url, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if entry and len(entry) > 0:
                        url = entry[0]
                        if url.startswith('http'):
                            urls.add(url)
        except Exception as e:
            pass
        
        return urls
    
    def filter_urls(self, urls):
        """Filter out unwanted URLs"""
        filtered = set()
        # Extensions to exclude
        exclude_ext = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg', 
                       '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf']
        
        for url in urls:
            # Skip static files
            if any(url.lower().endswith(ext) for ext in exclude_ext):
                continue
            # Skip very long URLs
            if len(url) > 500:
                continue
            filtered.add(url)
        
        return filtered
    
    def parameter_discovery_advanced(self, urls):
        """Advanced parameter discovery using multiple techniques"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.HEADER}[PHASE 3] Advanced Parameter Discovery{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        param_dict = defaultdict(set)
        
        # Method 1: Extract from URLs
        print(f"{Colors.CYAN}[*] Extracting parameters from URLs...{Colors.END}")
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                param_dict[param].add(url)
        
        print(f"{Colors.GREEN}[+] Extracted {len(param_dict)} parameters from URLs{Colors.END}")
        
        # Method 2: Common parameter wordlist (Arjun-style)
        print(f"{Colors.CYAN}[*] Adding common parameters from wordlist...{Colors.END}")
        common_params = self.load_parameter_wordlist()
        
        for param in common_params:
            if param not in param_dict:
                param_dict[param] = set()
        
        print(f"{Colors.GREEN}[+] Total parameters: {len(param_dict)}{Colors.END}")
        
        # Method 3: ParamSpider-style JavaScript analysis
        print(f"{Colors.CYAN}[*] Analyzing JavaScript files for hidden parameters...{Colors.END}")
        js_params = self.extract_params_from_js(urls)
        
        for param, url in js_params:
            param_dict[param].add(url)
        
        print(f"{Colors.GREEN}[+] Found {len(js_params)} parameters in JavaScript{Colors.END}")
        
        # Convert sets to lists for JSON
        self.results["parameters"] = {k: list(v) if v else [f"https://{self.domain}"] 
                                     for k, v in param_dict.items()}
        
        # Save parameters
        params_file = os.path.join(self.scan_dir, "parameters.json")
        with open(params_file, 'w') as f:
            json.dump(self.results["parameters"], f, indent=2)
        
        # Save unique parameters list
        unique_params_file = os.path.join(self.scan_dir, "unique_parameters.txt")
        with open(unique_params_file, 'w') as f:
            f.write('\n'.join(sorted(param_dict.keys())))
        
        return param_dict
    
    def load_parameter_wordlist(self):
        """Load common parameter names (Arjun-style wordlist)"""
        # Comprehensive parameter wordlist
        params = [
            # Common
            'id', 'user', 'page', 'search', 'query', 'q', 'keyword', 'key',
            'email', 'password', 'token', 'api_key', 'apikey', 'access_token',
            # Redirect/SSRF
            'url', 'redirect', 'next', 'return', 'callback', 'continue', 'dest',
            'destination', 'goto', 'out', 'view', 'to', 'redir', 'target',
            # File/LFI
            'file', 'path', 'folder', 'doc', 'document', 'page', 'include',
            'template', 'dir', 'load', 'download', 'upload',
            # API/SSRF
            'api', 'endpoint', 'service', 'host', 'proxy', 'fetch', 'uri',
            'domain', 'server', 'ip', 'port',
            # SQLi
            'cat', 'category', 'type', 'sort', 'order', 'filter', 'name',
            'username', 'userid', 'uid', 'pid', 'gid',
            # XSS
            'message', 'comment', 'text', 'title', 'description', 'content',
            'data', 'output', 'value', 'input', 'field',
            # Other
            'action', 'cmd', 'exec', 'command', 'debug', 'test', 'mode',
            'admin', 'config', 'settings', 'lang', 'language', 'locale',
            'code', 'error', 'ref', 'referrer', 'source', 'src'
        ]
        return params
    
    def extract_params_from_js(self, urls):
        """Extract parameters from JavaScript files"""
        js_params = []
        js_urls = [url for url in urls if url.endswith('.js')][:50]  # Limit to 50 JS files
        
        # Common JS parameter patterns
        patterns = [
            r'[\'"]([\w_-]+)[\'"]:\s*[\'"]?\w+[\'"]?',  # Object keys
            r'\.get\([\'"](\w+)[\'"]\)',  # .get() calls
            r'params\[[\'"]([\w_-]+)[\'"]\]',  # params[] access
            r'\?(\w+)=',  # Query parameters
        ]
        
        for js_url in js_urls[:20]:  # Further limit to prevent timeout
            try:
                response = self.session.get(js_url, timeout=10)
                if response.status_code == 200:
                    content = response.text
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if len(match) > 2 and len(match) < 50:
                                js_params.append((match, js_url))
            except:
                continue
        
        return js_params
    
    def gf_pattern_analysis(self, urls):
        """GF-style pattern analysis for vulnerability detection"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.HEADER}[PHASE 4] GF Pattern Analysis{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        # Advanced GF patterns
        gf_patterns = {
            "XSS": {
                "patterns": [
                    r'search=', r'query=', r'q=', r'keyword=', r's=',
                    r'message=', r'comment=', r'text=', r'name=',
                    r'callback=', r'jsonp=', r'data=', r'output='
                ],
                "severity": "High"
            },
            "SSRF": {
                "patterns": [
                    r'url=', r'uri=', r'redirect=', r'proxy=', r'fetch=',
                    r'api=', r'endpoint=', r'host=', r'domain=',
                    r'server=', r'target=', r'destination='
                ],
                "severity": "Critical"
            },
            "Open Redirect": {
                "patterns": [
                    r'redirect=', r'return=', r'next=', r'callback=',
                    r'continue=', r'dest=', r'destination=', r'goto=',
                    r'out=', r'view=', r'to=', r'redir='
                ],
                "severity": "Medium"
            },
            "SQL Injection": {
                "patterns": [
                    r'id=\d+', r'user=', r'page=\d+', r'category=',
                    r'cat=', r'filter=', r'sort=', r'order=',
                    r'type=', r'pid=', r'uid='
                ],
                "severity": "Critical"
            },
            "LFI/RFI": {
                "patterns": [
                    r'file=', r'path=', r'folder=', r'doc=',
                    r'document=', r'page=', r'include=', r'template=',
                    r'dir=', r'load='
                ],
                "severity": "High"
            },
            "XXE": {
                "patterns": [
                    r'xml=', r'feed=', r'import=', r'upload=',
                    r'data=.*\.xml'
                ],
                "severity": "High"
            },
            "IDOR": {
                "patterns": [
                    r'id=', r'user=', r'userid=', r'uid=', r'gid=',
                    r'profile=', r'account=', r'doc='
                ],
                "severity": "Medium"
            },
            "API Endpoints": {
                "patterns": [
                    r'/api/', r'/v\d+/', r'/rest/', r'/graphql',
                    r'\.json', r'/swagger', r'/openapi'
                ],
                "severity": "Info"
            }
        }
        
        for vuln_type, config in gf_patterns.items():
            print(f"{Colors.BLUE}[*] Checking for {vuln_type} ({config['severity']})...{Colors.END}")
            matches = []
            
            for url in urls:
                for pattern in config["patterns"]:
                    if re.search(pattern, url, re.IGNORECASE):
                        matches.append({
                            "url": url,
                            "pattern": pattern,
                            "severity": config["severity"]
                        })
                        break
            
            if matches:
                self.results["vulnerabilities"][vuln_type] = matches
                print(f"{Colors.YELLOW}[!] Found {len(matches)} potential {vuln_type} endpoints{Colors.END}")
        
        # Save vulnerabilities
        vuln_file = os.path.join(self.scan_dir, "vulnerabilities.json")
        with open(vuln_file, 'w') as f:
            json.dump(dict(self.results["vulnerabilities"]), f, indent=2)
        
        # Create GF-style output files
        for vuln_type, matches in self.results["vulnerabilities"].items():
            filename = vuln_type.lower().replace(' ', '_').replace('/', '_')
            gf_file = os.path.join(self.scan_dir, f"gf_{filename}.txt")
            with open(gf_file, 'w') as f:
                for match in matches:
                    f.write(f"{match['url']}\n")
        
        return self.results["vulnerabilities"]
    
    def find_interesting_endpoints(self, urls):
        """Find interesting endpoints (admin panels, APIs, configs)"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.HEADER}[PHASE 5] Interesting Endpoint Discovery{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        interesting_patterns = {
            "Admin Panels": [r'/admin', r'/administrator', r'/wp-admin', r'/cpanel', r'/dashboard'],
            "Config Files": [r'\.env', r'config\.', r'\.git', r'\.svn', r'web\.config'],
            "API Endpoints": [r'/api/', r'/v\d+/', r'/rest/', r'/graphql', r'/swagger'],
            "Backup Files": [r'\.bak', r'\.backup', r'\.old', r'\.zip', r'\.tar'],
            "Debug/Test": [r'/debug', r'/test', r'/dev', r'/staging', r'phpinfo'],
            "Upload Forms": [r'/upload', r'/uploader', r'/file', r'/media'],
            "Login Forms": [r'/login', r'/signin', r'/auth', r'/session']
        }
        
        for category, patterns in interesting_patterns.items():
            print(f"{Colors.BLUE}[*] Searching for {category}...{Colors.END}")
            matches = []
            
            for url in urls:
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        matches.append(url)
                        break
            
            if matches:
                self.results["interesting_endpoints"].append({
                    "category": category,
                    "count": len(matches),
                    "urls": matches[:20]  # Limit to 20 per category
                })
                print(f"{Colors.YELLOW}[!] Found {len(matches)} {category}{Colors.END}")
        
        # Save interesting endpoints
        interesting_file = os.path.join(self.scan_dir, "interesting_endpoints.json")
        with open(interesting_file, 'w') as f:
            json.dump(self.results["interesting_endpoints"], f, indent=2)
    
    def calculate_advanced_score(self):
        """Calculate advanced security score"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.HEADER}[PHASE 6] Advanced Scoring & Statistics{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        score = 0
        stats = {}
        
        # Subdomain scoring
        subdomain_count = len(self.results["subdomains"])
        score += subdomain_count * 2
        stats["subdomains"] = subdomain_count
        
        # URL scoring
        url_count = len(self.results["archived_urls"])
        score += min(url_count, 1000) * 1  # Cap at 1000 for scoring
        stats["archived_urls"] = url_count
        
        # Parameter scoring
        param_count = len(self.results["parameters"])
        score += param_count * 3
        stats["parameters"] = param_count
        
        # Vulnerability scoring with severity weighting
        severity_weights = {"Critical": 20, "High": 15, "Medium": 10, "Info": 2}
        vuln_score = 0
        vuln_breakdown = {}
        
        for vuln_type, matches in self.results["vulnerabilities"].items():
            count = len(matches)
            severity = matches[0]["severity"] if matches else "Medium"
            weight = severity_weights.get(severity, 10)
            vuln_score += count * weight
            vuln_breakdown[vuln_type] = {"count": count, "severity": severity}
        
        score += vuln_score
        stats["vulnerabilities"] = vuln_breakdown
        
        # Interesting endpoints scoring
        interesting_count = sum(e["count"] for e in self.results["interesting_endpoints"])
        score += interesting_count * 5
        stats["interesting_endpoints"] = interesting_count
        
        self.results["score"] = score
        self.results["statistics"] = stats
        
        # Print statistics
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}SCAN STATISTICS{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.GREEN}Security Score: {score}{Colors.END}")
        print(f"{Colors.GREEN}Subdomains: {subdomain_count}{Colors.END}")
        print(f"{Colors.GREEN}Archived URLs: {url_count}{Colors.END}")
        print(f"{Colors.GREEN}Parameters: {param_count}{Colors.END}")
        print(f"{Colors.GREEN}Interesting Endpoints: {interesting_count}{Colors.END}")
        print(f"\n{Colors.YELLOW}Vulnerability Breakdown:{Colors.END}")
        for vuln_type, data in vuln_breakdown.items():
            print(f"  {Colors.YELLOW}{vuln_type}: {data['count']} ({data['severity']}){Colors.END}")
        
        return score
    
    def generate_comprehensive_report(self):
        """Generate comprehensive reports"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.HEADER}[PHASE 7] Comprehensive Report Generation{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        # JSON Report
        json_report = os.path.join(self.scan_dir, "report.json")
        with open(json_report, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"{Colors.GREEN}[+] JSON report: {json_report}{Colors.END}")
        
        # HTML Report
        html_report = os.path.join(self.scan_dir, "report.html")
        html_content = self.generate_advanced_html_report()
        with open(html_report, 'w') as f:
            f.write(html_content)
        print(f"{Colors.GREEN}[+] HTML report: {html_report}{Colors.END}")
        
        # Markdown Report
        md_report = os.path.join(self.scan_dir, "report.md")
        md_content = self.generate_markdown_report()
        with open(md_report, 'w') as f:
            f.write(md_content)
        print(f"{Colors.GREEN}[+] Markdown report: {md_report}{Colors.END}")
        
        # Summary Report
        summary_file = os.path.join(self.scan_dir, "SUMMARY.txt")
        with open(summary_file, 'w') as f:
            f.write(f"╔{'═'*58}╗\n")
            f.write(f"║{' '*15}ARCHIVEHUNTER SCAN SUMMARY{' '*15}║\n")
            f.write(f"╚{'═'*58}╝\n\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Time: {self.results['scan_time']}\n")
            f.write(f"Security Score: {self.results['score']}\n\n")
            f.write(f"{'─'*60}\n")
            f.write(f"FINDINGS OVERVIEW\n")
            f.write(f"{'─'*60}\n\n")
            f.write(f"Subdomains Discovered: {len(self.results['subdomains'])}\n")
            f.write(f"Archived URLs Found: {len(self.results['archived_urls'])}\n")
            f.write(f"Parameters Identified: {len(self.results['parameters'])}\n")
            f.write(f"Interesting Endpoints: {sum(e['count'] for e in self.results['interesting_endpoints'])}\n\n")
            
            if self.results['vulnerabilities']:
                f.write(f"{'─'*60}\n")
                f.write(f"POTENTIAL VULNERABILITIES\n")
                f.write(f"{'─'*60}\n\n")
                for vuln_type, matches in self.results['vulnerabilities'].items():
                    f.write(f"  [{matches[0]['severity']}] {vuln_type}: {len(matches)} endpoints\n")
            
            f.write(f"\n{'─'*60}\n")
            f.write(f"All detailed results saved in:\n")
            f.write(f"  {self.scan_dir}\n")
            f.write(f"{'─'*60}\n")
        
        print(f"{Colors.GREEN}[+] Summary: {summary_file}{Colors.END}")
    
    def generate_advanced_html_report(self):
        """Generate advanced HTML report with charts and styling"""
        vuln_rows = ""
        total_vulns = 0
        
        for vuln_type, matches in self.results["vulnerabilities"].items():
            severity = matches[0]["severity"] if matches else "Medium"
            severity_color = {
                "Critical": "#e74c3c",
                "High": "#e67e22",
                "Medium": "#f39c12",
                "Info": "#3498db"
            }.get(severity, "#95a5a6")
            
            vuln_rows += f"""
            <tr>
                <td>{vuln_type}</td>
                <td><span class="badge" style="background-color: {severity_color}">{severity}</span></td>
                <td>{len(matches)}</td>
                <td><a href="gf_{vuln_type.lower().replace(' ', '_').replace('/', '_')}.txt" target="_blank">View URLs</a></td>
            </tr>
            """
            total_vulns += len(matches)
        
        interesting_rows = ""
        for endpoint in self.results["interesting_endpoints"]:
            interesting_rows += f"""
            <tr>
                <td>{endpoint['category']}</td>
                <td>{endpoint['count']}</td>
                <td>{', '.join(endpoint['urls'][:3])}...</td>
            </tr>
            """
        
        param_rows = ""
        for i, (param, urls) in enumerate(list(self.results["parameters"].items())[:20]):
            param_rows += f"""
            <tr>
                <td>{i+1}</td>
                <td><code>{param}</code></td>
                <td>{len(urls) if isinstance(urls, list) else 1}</td>
            </tr>
            """
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArchiveHunter Report - {self.domain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #2c3e50;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .score-section {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .score {{
            font-size: 72px;
            font-weight: bold;
            text-shadow: 3px 3px 6px rgba(0,0,0,0.3);
            margin: 20px 0;
        }}
        
        .score-label {{
            font-size: 24px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.2);
        }}
        
        .stat-card .number {{
            font-size: 48px;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }}
        
        .stat-card .label {{
            font-size: 16px;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 50px;
        }}
        
        h2 {{
            color: #2c3e50;
            font-size: 28px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 14px;
            letter-spacing: 1px;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 12px;
            text-transform: uppercase;
        }}
        
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin: 30px 0;
            border-radius: 4px;
        }}
        
        .warning h3 {{
            color: #856404;
            margin-bottom: 10px;
        }}
        
        .warning p {{
            color: #856404;
            line-height: 1.6;
        }}
        
        code {{
            background: #f8f9fa;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #e74c3c;
        }}
        
        a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }}
        
        a:hover {{
            text-decoration: underline;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .footer p {{
            opacity: 0.8;
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ArchiveHunter Security Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Scan Date:</strong> {self.results['scan_time']}</p>
        </div>
        
        <div class="score-section">
            <div class="score-label">Security Assessment Score</div>
            <div class="score">{self.results['score']}</div>
            <p>Higher scores indicate larger attack surface and more potential findings</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Subdomains</div>
                <div class="number">{len(self.results['subdomains'])}</div>
            </div>
            <div class="stat-card">
                <div class="label">Archived URLs</div>
                <div class="number">{len(self.results['archived_urls'])}</div>
            </div>
            <div class="stat-card">
                <div class="label">Parameters</div>
                <div class="number">{len(self.results['parameters'])}</div>
            </div>
            <div class="stat-card">
                <div class="label">Potential Vulnerabilities</div>
                <div class="number">{total_vulns}</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>🔴 Vulnerability Patterns Detected (GF Analysis)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Vulnerability Type</th>
                            <th>Severity</th>
                            <th>Count</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vuln_rows if vuln_rows else '<tr><td colspan="4" style="text-align: center;">No vulnerabilities detected</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🎯 Interesting Endpoints Discovered</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Count</th>
                            <th>Sample URLs</th>
                        </tr>
                    </thead>
                    <tbody>
                        {interesting_rows if interesting_rows else '<tr><td colspan="3" style="text-align: center;">No interesting endpoints found</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>📋 Top Parameters (Sample)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Parameter Name</th>
                            <th>Occurrences</th>
                        </tr>
                    </thead>
                    <tbody>
                        {param_rows if param_rows else '<tr><td colspan="3" style="text-align: center;">No parameters found</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="warning">
                <h3>⚠️ Important Disclaimer</h3>
                <p>
                    This report contains <strong>POTENTIAL</strong> vulnerabilities based on pattern matching and 
                    automated analysis. All findings must be <strong>manually verified</strong> before reporting.
                    <br><br>
                    <strong>Only perform security testing on systems you have explicit authorization to test.</strong>
                    Follow responsible disclosure practices and comply with bug bounty program rules.
                    <br><br>
                    ArchiveHunter is a reconnaissance tool designed for authorized security assessments only.
                    Unauthorized testing is illegal and unethical.
                </p>
            </div>
            
            <div class="section">
                <h2>📁 Report Files Generated</h2>
                <ul style="line-height: 2; font-size: 16px;">
                    <li><code>report.json</code> - Complete scan data in JSON format</li>
                    <li><code>report.html</code> - This visual report</li>
                    <li><code>report.md</code> - Markdown formatted report</li>
                    <li><code>subdomains.txt</code> - All discovered subdomains</li>
                    <li><code>archived_urls.txt</code> - All archived URLs</li>
                    <li><code>parameters.json</code> - Parameter dictionary</li>
                    <li><code>vulnerabilities.json</code> - Vulnerability patterns</li>
                    <li><code>gf_*.txt</code> - GF-style output files by vulnerability type</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>ArchiveHunter v2.0</strong></p>
            <p>Advanced Recon & Bug Hunting Tool</p>
            <p>Use Responsibly | Authorized Testing Only</p>
        </div>
    </div>
</body>
</html>
        """
        return html
    
    def generate_markdown_report(self):
        """Generate markdown report for GitHub/documentation"""
        md = f"""# ArchiveHunter Security Report

## Target Information
- **Target:** {self.target}
- **Scan Date:** {self.results['scan_time']}
- **Security Score:** {self.results['score']}

---

## Executive Summary

### Statistics Overview
| Metric | Count |
|--------|-------|
| Subdomains | {len(self.results['subdomains'])} |
| Archived URLs | {len(self.results['archived_urls'])} |
| Parameters | {len(self.results['parameters'])} |
| Potential Vulnerabilities | {sum(len(v) for v in self.results['vulnerabilities'].values())} |

---

## Vulnerability Breakdown

"""
        
        for vuln_type, matches in self.results['vulnerabilities'].items():
            severity = matches[0]['severity'] if matches else 'Medium'
            md += f"### {vuln_type} ({severity})\n"
            md += f"- **Count:** {len(matches)}\n"
            md += f"- **Sample URLs:**\n"
            for match in matches[:5]:
                md += f"  - `{match['url']}`\n"
            md += "\n"
        
        md += """---

## Interesting Endpoints

"""
        for endpoint in self.results['interesting_endpoints']:
            md += f"### {endpoint['category']}\n"
            md += f"- **Count:** {endpoint['count']}\n"
            md += "- **Sample URLs:**\n"
            for url in endpoint['urls'][:5]:
                md += f"  - `{url}`\n"
            md += "\n"
        
        md += """---

## Disclaimer

⚠️ **WARNING:** This report contains potential vulnerabilities based on automated pattern matching.

- All findings must be manually verified
- Only test systems with explicit authorization
- Follow responsible disclosure practices
- Comply with bug bounty program rules

---

*Generated by ArchiveHunter v2.0*
"""
        return md
    
    def run_scan(self):
        """Execute complete advanced scanning pipeline"""
        self.print_banner()
        
        start_time = time.time()
        
        try:
            # Phase 1: Advanced Subdomain Discovery
            subdomains = self.subdomain_discovery()
            
            # Phase 2: Advanced Wayback URLs
            urls = self.wayback_urls_advanced(subdomains)
            
            # Phase 3: Advanced Parameter Discovery
            parameters = self.parameter_discovery_advanced(urls)
            
            # Phase 4: GF Pattern Analysis
            vulnerabilities = self.gf_pattern_analysis(urls)
            
            # Phase 5: Interesting Endpoints
            self.find_interesting_endpoints(urls)
            
            # Phase 6: Advanced Scoring
            score = self.calculate_advanced_score()
            
            # Phase 7: Comprehensive Report Generation
            self.generate_comprehensive_report()
            
            # Completion
            elapsed = time.time() - start_time
            print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}{Colors.BOLD}[✓] SCAN COMPLETED SUCCESSFULLY!{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}[✓] Time elapsed: {elapsed:.2f} seconds{Colors.END}")
            print(f"{Colors.GREEN}[✓] Results saved to: {self.scan_dir}{Colors.END}")
            print(f"{Colors.GREEN}[✓] Open report.html for detailed visual report{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}\n")
            
            # Final summary
            print(f"{Colors.CYAN}{Colors.BOLD}QUICK SUMMARY:{Colors.END}")
            print(f"{Colors.CYAN}→ Subdomains: {len(self.results['subdomains'])}{Colors.END}")
            print(f"{Colors.CYAN}→ URLs: {len(self.results['archived_urls'])}{Colors.END}")
            print(f"{Colors.CYAN}→ Parameters: {len(self.results['parameters'])}{Colors.END}")
            print(f"{Colors.CYAN}→ Vulnerabilities: {sum(len(v) for v in self.results['vulnerabilities'].values())}{Colors.END}")
            print(f"{Colors.CYAN}→ Score: {self.results['score']}{Colors.END}\n")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.END}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error during scan: {str(e)}{Colors.END}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


def print_tool_requirements():
    """Print tool installation guide"""
    print(f"{Colors.CYAN}{Colors.BOLD}Optional External Tools:{Colors.END}")
    print(f"{Colors.CYAN}For enhanced functionality, install these tools:{Colors.END}\n")
    print(f"{Colors.YELLOW}1. Subfinder (Subdomain Discovery):{Colors.END}")
    print(f"   GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n")
    print(f"{Colors.YELLOW}2. GF (Pattern Matching) - Optional:{Colors.END}")
    print(f"   go install github.com/tomnomnom/gf@latest\n")
    print(f"{Colors.YELLOW}3. Python Requirements:{Colors.END}")
    print(f"   pip install requests\n")
    print(f"{Colors.GREEN}Note: ArchiveHunter works without these tools using built-in alternatives!{Colors.END}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ArchiveHunter v2.0 - Advanced Automated Recon & Bug Hunting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python archivehunter.py -t example.com
  python archivehunter.py -t https://example.com -o results -T 20
  python archivehunter.py --check-tools
  
Features:
  ✓ Advanced Wayback Machine URL extraction
  ✓ GF-style vulnerability pattern detection
  ✓ Arjun-style parameter discovery
  ✓ ParamSpider-inspired JavaScript analysis
  ✓ Subfinder integration for subdomain discovery
  ✓ Certificate Transparency log checking
  ✓ Multi-threaded scanning
  ✓ Comprehensive HTML/JSON/Markdown reports
  
WARNING: Use only on authorized targets with proper permission!
        """
    )
    
    parser.add_argument('-t', '--target', help='Target domain or URL')
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: output)')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--check-tools', action='store_true', help='Check tool requirements')
    
    args = parser.parse_args()
    
    if args.check_tools:
        print_tool_requirements()
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Initialize and run scanner
    scanner = ArchiveHunter(args.target, args.output, args.threads)
    scanner.run_scan()


if __name__ == "__main__":
    main()