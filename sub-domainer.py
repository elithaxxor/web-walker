import threading
import requests
import time
import os
import re
import random
import json
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init
from tqdm import tqdm
import validators

# Initialize colorama
init()

class SubdomainScanner:
    def __init__(self, domain, filename=None, subdomains_list=None, timeout=20):
        """
        Initialize the SubdomainScanner with the target domain and subdomain source.
        
        Args:
            domain (str): Target domain to scan
            filename (str, optional): Path to file containing subdomains to check
            subdomains_list (list, optional): List of subdomains to check instead of a file
            timeout (int): Request timeout in seconds
        """
        self.domain = domain
        self.filename = filename
        self.subdomains_list = subdomains_list
        self.timeout = timeout
        self.subdomains_found = []
        self.subdomains_lock = threading.Lock()
        
        # Colors
        self.R = "\033[91m"  # Red
        self.Y = "\033[93m"  # Yellow
        self.G = "\033[92m"  # Green
        self.C = "\033[96m"  # Cyan
        self.W = "\033[0m"   # White/Reset
        
        # Default settings
        self.max_threads = 10
        self.batch_size = 50
        self.proxies = None
        self.verbose = 1  # 0: quiet, 1: normal, 2: verbose
        self.output_file = None
        self.custom_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.verify_ssl = True
        self.rate_limit_delay = 0  # Seconds between requests
        self.total_subdomains = 0
        self.progress_bar = None
        self.protocols = ["https", "http"]  # Try HTTPS first, then HTTP if it fails
    
    def set_max_threads(self, max_threads):
        """Set the maximum number of concurrent threads"""
        self.max_threads = max_threads
        return self
    
    def set_batch_size(self, batch_size):
        """Set the batch size for processing subdomains"""
        self.batch_size = batch_size
        return self
    
    def set_proxies(self, proxies):
        """
        Set proxies for requests.
        
        Args:
            proxies (dict): Proxy configuration, e.g., {'http': 'http://proxy.example.com:8080', 'https': 'https://proxy.example.com:8080'}
        """
        self.proxies = proxies
        return self
    
    def set_verbose(self, level):
        """Set verbosity level (0: quiet, 1: normal, 2: verbose)"""
        self.verbose = level
        return self
    
    def set_output_file(self, filename):
        """Set output file to save results"""
        self.output_file = filename
        return self
    
    def set_custom_headers(self, headers):
        """Set custom HTTP headers for requests"""
        self.custom_headers.update(headers)
        return self
    
    def set_verify_ssl(self, verify):
        """Set whether to verify SSL certificates"""
        self.verify_ssl = verify
        return self
    
    def set_rate_limit(self, delay):
        """Set delay between requests in seconds"""
        self.rate_limit_delay = delay
        return self
    
    def validate_subdomain(self, subdomain):
        """Validate subdomain format"""
        if not subdomain or len(subdomain) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', subdomain):
            return False
        return True
    
    def check_subdomain(self, subdomain):
        """
        Check if a subdomain exists by sending HTTP/HTTPS requests.
        
        Args:
            subdomain (str): Subdomain to check
        """
        if not self.validate_subdomain(subdomain):
            if self.verbose >= 2:
                print(f"{self.R}Invalid subdomain format: {subdomain}{self.W}")
            return
        
        # Apply rate limiting
        if self.rate_limit_delay > 0:
            time.sleep(self.rate_limit_delay)
        
        # Try each protocol (HTTPS first, then HTTP if it fails)
        for protocol in self.protocols:
            subdomain_url = f"{protocol}://{subdomain}.{self.domain}"
            
            try:
                response = requests.get(
                    subdomain_url, 
                    timeout=self.timeout, 
                    headers=self.custom_headers,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                
                status_code = response.status_code
                
                # Consider redirects as valid findings too
                if status_code == 200 or status_code == 301 or status_code == 302:
                    with self.subdomains_lock:
                        self.subdomains_found.append({
                            'url': subdomain_url,
                            'status_code': status_code,
                            'server': response.headers.get('Server', 'Unknown'),
                            'title': self._extract_title(response.text)
                        })
                        
                        if self.verbose >= 1:
                            print(f"{Fore.GREEN}Subdomain Found [+]: {subdomain_url} (Status: {status_code}){Fore.RESET}")
                    
                    # We found it with this protocol, no need to try the next one
                    break
                    
                elif self.verbose >= 2:
                    print(f"{Fore.YELLOW}Subdomain Responded: {subdomain_url} (Status: {status_code}){Fore.RESET}")
                
            except requests.exceptions.RequestException as e:
                if self.verbose >= 2:
                    print(f"{Fore.RED}Error checking {subdomain_url}: {str(e)[:100]}...{Fore.RESET}")
                
                # Only try the next protocol if this one failed
                continue
    
    def _extract_title(self, html):
        """Extract the title from HTML content"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return "No Title"
    
    def load_subdomains(self):
        """Load subdomains from file or list"""
        if self.subdomains_list is not None:
            return self.subdomains_list
        
        if self.filename is None:
            raise ValueError("Either filename or subdomains_list must be provided")
        
        if not os.path.exists(self.filename):
            raise FileNotFoundError(f"Subdomain file not found: {self.filename}")
        
        with open(self.filename, "r") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    
    def process_batch(self, batch):
        """Process a batch of subdomains"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.check_subdomain, batch)
    
    def scan(self):
        """
        Scan subdomains in batches.
        
        Returns:
            dict: Results of the scan
        """
        subdomains = self.load_subdomains()
        self.total_subdomains = len(subdomains)
        
        if self.verbose >= 1:
            print(f"{self.Y}Starting subdomain scan for {self.domain} with {self.total_subdomains} subdomains...{self.W}")
            print(f"{self.Y}Using {self.max_threads} threads and batch size of {self.batch_size}{self.W}")
        
        start_time = time.time()
        
        # Process in batches
        batches = [subdomains[i:i + self.batch_size] for i in range(0, len(subdomains), self.batch_size)]
        
        # Create progress bar if verbose
        if self.verbose >= 1:
            self.progress_bar = tqdm(total=len(batches), desc="Scanning batches", unit="batch")
        
        for batch in batches:
            self.process_batch(batch)
            if self.progress_bar:
                self.progress_bar.update(1)
        
        if self.progress_bar:
            self.progress_bar.close()
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        return {
            "subdomains_scanned": self.total_subdomains,
            "subdomains_found": self.subdomains_found,
            "elapsed_time": elapsed_time
        }
    
    def print_results(self, results):
        """Print scan results"""
        if self.verbose == 0:
            return
        
        print("\n" + "="*60)
        print(f"{self.G}[+] {self.C}Scan Results for {self.domain}{self.W}")
        print("="*60)
        print(f"{self.G}[+] {self.C}Total Subdomains Scanned:{self.W} {results['subdomains_scanned']}")
        print(f"{self.G}[+] {self.C}Total Subdomains Found:{self.W} {len(results['subdomains_found'])}")
        print(f"{self.G}[+] {self.C}Time taken:{self.W} {results['elapsed_time']:.2f} seconds")
        
        if results['subdomains_found']:
            print("\nSubdomains Found:\n" + "-"*60)
            for i, data in enumerate(results['subdomains_found'], 1):
                print(f"{i}. {data['url']} (Status: {data['status_code']}, Server: {data['server']})")
                if self.verbose >= 2:
                    print(f"   Title: {data['title']}")
    
    def save_results(self, results):
        """Save results to file"""
        if not self.output_file:
            return
        
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Determine file format based on extension
        _, ext = os.path.splitext(self.output_file)
        
        if ext.lower() == '.json':
            # Save as JSON
            with open(self.output_file, 'w') as f:
                json.dump({
                    'domain': self.domain,
                    'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'subdomains_scanned': results['subdomains_scanned'],
                    'subdomains_found': results['subdomains_found'],
                    'elapsed_time': results['elapsed_time']
                }, f, indent=4)
        else:
            # Save as plain text
            with open(self.output_file, 'w') as f:
                f.write(f"Subdomain Scan Results for {self.domain}\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Subdomains Scanned: {results['subdomains_scanned']}\n")
                f.write(f"Total Subdomains Found: {len(results['subdomains_found'])}\n")
                f.write(f"Time taken: {results['elapsed_time']:.2f} seconds\n\n")
                
                if results['subdomains_found']:
                    f.write("Subdomains Found:\n")
                    for i, data in enumerate(results['subdomains_found'], 1):
                        f.write(f"{i}. {data['url']} (Status: {data['status_code']}, Server: {data['server']})\n")
        
        if self.verbose >= 1:
            print(f"\n{self.G}[+] {self.C}Results saved to:{self.W} {self.output_file}")
    
    def run(self):
        """Run the complete scan process and return results"""
        results = self.scan()
        self.print_results(results)
        self.save_results(results)
        return results


# Example usage:
"""
# Basic usage:
scanner = SubdomainScanner("example.com", "subdomains.txt")
scanner.run()

# Advanced usage with all options:
scanner = SubdomainScanner("example.com", "subdomains.txt")
scanner.set_max_threads(20) \
    .set_batch_size(100) \
    .set_verbose(2) \
    .set_output_file("results.json") \
    .set_custom_headers({'User-Agent': 'Custom User Agent'}) \
    .set_verify_ssl(False) \
    .set_rate_limit(0.5) \
    .set_proxies({
        'http': 'http://user:pass@proxy.example.com:8080',
        'https': 'https://user:pass@proxy.example.com:8080'
    }) \
    .run()
"""
