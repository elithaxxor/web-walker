import os
import re
import json
import csv
import threading
import requests
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from tqdm import tqdm
import validators
from bs4 import BeautifulSoup

# Initialize colorama for colored output
init()

# Constants
MAX_SUBDOMAIN_LENGTH = 63  # Maximum length of a subdomain per RFC 1035
DEFAULT_VALID_STATUS_CODES = {200, 301, 302}  # Default HTTP status codes for "found" subdomains
DEFAULT_PROTOCOLS = ["https", "http"]  # Default protocols to try

class SubdomainScanner:
    def __init__(self, domain, filename=None, subdomains_list=None, timeout=20, 
                 valid_status_codes=None, protocols=None):
        if not validators.domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        self.domain = domain
        self.filename = filename
        self.subdomains_list = subdomains_list
        self.timeout = timeout
        self.subdomains_found = []
        self.subdomains_lock = threading.Lock()

        # Colors for output
        self.R = "\033[91m"  # Red
        self.Y = "\033[93m"  # Yellow
        self.G = "\033[92m"  # Green
        self.C = "\033[96m"  # Cyan
        self.W = "\033[0m"   # White/Reset

        # Default settings
        self.max_threads = 10
        self.batch_size = 50
        self.proxies = None  # For security, use environment variables for credentials
        self.verbose = 1  # 0: quiet, 1: normal, 2: verbose
        self.output_file = None
        self.custom_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.verify_ssl = True
        self.rate_limit_delay = 0  # Seconds between requests
        self.total_subdomains = 0
        self.progress_bar = None
        self.semaphore = None  # For rate limiting across threads

        # Extensibility: Allow custom status codes and protocols
        self.valid_status_codes = valid_status_codes if valid_status_codes is not None else DEFAULT_VALID_STATUS_CODES
        self.protocols = protocols if protocols is not None else DEFAULT_PROTOCOLS

    def set_max_threads(self, max_threads):
        """Set the maximum number of concurrent threads."""
        self.max_threads = max_threads
        return self

    def set_batch_size(self, batch_size):
        """Set the batch size for processing subdomains."""
        self.batch_size = batch_size
        return self

    def set_proxies(self, proxies=None):
        """
        Set proxies for requests. If proxies are not provided, attempt to retrieve from environment variables.
        """
        if proxies is None:
            # Attempt to build proxies from environment variables
            proxy_user = os.environ.get('HTTPS_PROXY_USER')
            proxy_pass = os.environ.get('HTTPS_PROXY_PASS')
            proxy_host = os.environ.get('HTTPS_PROXY_HOST')
            proxy_port = os.environ.get('HTTPS_PROXY_PORT')
            if proxy_host and proxy_port:
                # Construct proxy URL if all required variables are present
                proxy_url = f"https://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}" if proxy_user and proxy_pass else f"https://{proxy_host}:{proxy_port}"
                self.proxies = {'https': proxy_url}
            else:
                self.proxies = None
        else:
            self.proxies = proxies
        return self

    def set_verbose(self, level):
        """Set verbosity level (0: quiet, 1: normal, 2: verbose)."""
        self.verbose = level
        return self

    def set_output_file(self, filename):
        """Set output file to save results (supports .json and .csv)."""
        self.output_file = filename
        return self

    def set_custom_headers(self, headers):
        """Set custom HTTP headers for requests."""
        self.custom_headers.update(headers)
        return self

    def set_verify_ssl(self, verify):
        """Set whether to verify SSL certificates."""
        self.verify_ssl = verify
        return self

    def set_rate_limit(self, delay):
        """Set delay between requests in seconds and initialize semaphore if needed."""
        self.rate_limit_delay = delay
        if delay > 0:
            self.semaphore = threading.Semaphore(self.max_threads)
        return self

    def validate_subdomain(self, subdomain):
        """
        Validate subdomain format per RFC 1035.
        """
        if not subdomain or len(subdomain) > MAX_SUBDOMAIN_LENGTH:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', subdomain):
            return False
        return True

    def _try_protocols(self, subdomain):
        """Try different protocols for the subdomain and return the first successful response."""
        for protocol in self.protocols:
            url = f"{protocol}://{subdomain}.{self.domain}"
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    headers=self.custom_headers,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                if response.status_code in self.valid_status_codes:
                    return response
            except requests.exceptions.Timeout:
                if self.verbose >= 2:
                    print(f"{self.R}Timeout for {url}{self.W}")
            except requests.exceptions.ConnectionError:
                if self.verbose >= 2:
                    print(f"{self.R}Connection error for {url}{self.W}")
            except requests.exceptions.RequestException as e:
                if self.verbose >= 2:
                    print(f"{self.R}Request exception for {url}: {str(e)}{self.W}")
        return None

    def check_subdomain(self, subdomain):
        """Check if a subdomain exists by sending HTTP/HTTPS requests."""
        if not self.validate_subdomain(subdomain):
            if self.verbose >= 2:
                print(f"{self.R}Invalid subdomain format: {subdomain}{self.W}")
            return

        # Rate limiting with semaphore
        if self.semaphore:
            with self.semaphore:
                time.sleep(self.rate_limit_delay)

        response = self._try_protocols(subdomain)
        if response:
            with self.subdomains_lock:
                self.subdomains_found.append({
                    'url': response.url,
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'title': self._extract_title(response.text)
                })
                if self.verbose >= 1:
                    print(f"{Fore.GREEN}Subdomain Found [+]: {response.url} (Status: {response.status_code}){Fore.RESET}")
        elif self.verbose >= 2:
            print(f"{Fore.YELLOW}No response from {subdomain}.{self.domain}{Fore.RESET}")

    def _extract_title(self, html):
        """Extract the title from HTML content using BeautifulSoup."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            return soup.title.string.strip() if soup.title else "No Title"
        except Exception:
            return "No Title"

    def load_subdomains(self):
        """Load and filter subdomains from file or list."""
        if self.subdomains_list is not None:
            subdomains = self.subdomains_list
        elif self.filename is not None:
            if not os.path.exists(self.filename):
                raise FileNotFoundError(f"Subdomain file not found: {self.filename}")
            with open(self.filename, "r") as file:
                subdomains = [line.strip() for line in file.readlines() if line.strip()]
        else:
            raise ValueError("Either filename or subdomains_list must be provided")

        # Filter invalid subdomains
        valid_subdomains = [sub for sub in subdomains if self.validate_subdomain(sub)]
        if self.verbose >= 1 and len(valid_subdomains) < len(subdomains):
            print(f"{self.Y}Filtered out {len(subdomains) - len(valid_subdomains)} invalid subdomains{self.W}")
        return valid_subdomains

    def scan(self):
        """Scan subdomains using threading and return results."""
        subdomains = self.load_subdomains()
        self.total_subdomains = len(subdomains)

        if self.verbose >= 1:
            print(f"{self.Y}Starting subdomain scan for {self.domain} with {self.total_subdomains} subdomains...{self.W}")
            print(f"{self.Y}Using {self.max_threads} threads{self.W}")

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in subdomains}
            if self.verbose >= 1:
                self.progress_bar = tqdm(total=self.total_subdomains, desc="Scanning subdomains", unit="sub")
            for future in as_completed(futures):
                future.result()  # Wait for completion
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
        """Print scan results based on verbosity level."""
        if self.verbose >= 1:
            print(f"\n{self.C}Scan completed in {results['elapsed_time']:.2f} seconds{self.W}")
            print(f"{self.G}Subdomains scanned: {results['subdomains_scanned']}{self.W}")
            print(f"{self.G}Subdomains found: {len(results['subdomains_found'])}{self.W}")
            for subdomain in results['subdomains_found']:
                print(f"{self.G}{subdomain['url']} (Status: {subdomain['status_code']}, Title: {subdomain['title']}){self.W}")

    def save_results(self, results):
        """Save results to a file in JSON or CSV format if output_file is set."""
        if self.output_file:
            if self.output_file.endswith('.csv'):
                # Save as CSV
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Status Code', 'Server', 'Title'])
                    for subdomain in results['subdomains_found']:
                        writer.writerow([subdomain['url'], subdomain['status_code'], subdomain['server'], subdomain['title']])
            else:
                # Save as JSON
                with open(self.output_file, 'w') as f:
                    json.dump(results, f, indent=4)
            if self.verbose >= 1:
                print(f"{self.Y}Results saved to {self.output_file}{self.W}")

    def run(self):
        """Run the complete scan process and return results."""
        results = self.scan()
        self.print_results(results)
        self.save_results(results)
        return results

def main():
    parser = argparse.ArgumentParser(description="Subdomain Scanner")
    parser.add_argument("domain", nargs='?', help="Target domain to scan (e.g., 'example.com')")
    parser.add_argument("-f", "--file", help="Path to file containing subdomains")
    parser.add_argument("-l", "--list", nargs='+', help="List of subdomains")
    parser.add_argument("-t", "--timeout", type=int, default=20, help="Request timeout in seconds")
    parser.add_argument("-s", "--status-codes", nargs='+', type=int, help="HTTP status codes considered as 'found'")
    parser.add_argument("-p", "--protocols", nargs='+', help="Protocols to try (e.g., 'https http')")
    parser.add_argument("-m", "--max-threads", type=int, default=10, help="Maximum number of concurrent threads")
    parser.add_argument("-b", "--batch-size", type=int, default=50, help="Batch size for processing subdomains")
    parser.add_argument("-P", "--proxies", help="Proxy settings to use")
    parser.add_argument("-v", "--verbose", type=int, choices=[0, 1, 2], default=1, help="Verbosity level (0: quiet, 1: normal, 2: verbose)")
    parser.add_argument("-o", "--output", help="Output file to save results (supports .json and .csv)")
    parser.add_argument("-H", "--headers", nargs='+', help="Custom HTTP headers for requests")
    parser.add_argument("-V", "--verify-ssl", action='store_true', help="Verify SSL certificates")
    parser.add_argument("-r", "--rate-limit", type=float, default=0, help="Delay between requests in seconds")

    args = parser.parse_args()

    if not args.domain:
        print("No command-line arguments provided. Enter details through the menu.")

        domain = input("Enter the target domain to scan (e.g., 'example.com'): ")
        file = input("Enter the path to file containing subdomains (leave empty if not using a file): ")
        subdomains_list = input("Enter the list of subdomains (comma-separated, leave empty if using a file): ").split(',')
        timeout = int(input("Enter request timeout in seconds (default is 20): ") or 20)
        status_codes = input("Enter HTTP status codes considered as 'found' (comma-separated, leave empty for defaults): ").split(',')
        protocols = input("Enter protocols to try (space-separated, e.g., 'https http', leave empty for defaults): ").split()
        max_threads = int(input("Enter the maximum number of concurrent threads (default is 10): ") or 10)
        batch_size = int(input("Enter the batch size for processing subdomains (default is 50): ") or 50)
        proxies = input("Enter proxy settings to use (leave empty if not using proxies): ")
        verbose = int(input("Enter verbosity level (0: quiet, 1: normal, 2: verbose, default is 1): ") or 1)
        output = input("Enter the output file to save results (supports .json and .csv, leave empty if not saving): ")
        headers = input("Enter custom HTTP headers for requests (comma-separated key:value pairs, leave empty if not using): ").split(',')
        verify_ssl = input("Verify SSL certificates? (y/n, default is n): ").lower() == 'y'
        rate_limit = float(input("Enter delay between requests in seconds (default is 0): ") or 0)

        status_codes = [int(code) for code in status_codes] if status_codes else None
        headers = {header.split(':')[0].strip(): header.split(':')[1].strip() for header in headers} if headers else {}

        scanner = SubdomainScanner(
            domain,
            filename=file or None,
            subdomains_list=subdomains_list if subdomains_list != [''] else None,
            timeout=timeout,
            valid_status_codes=set(status_codes) if status_codes else None,
            protocols=protocols if protocols else None
        )

        scanner.set_max_threads(max_threads) \
               .set_batch_size(batch_size) \
               .set_proxies(proxies or None) \
               .set_verbose(verbose) \
               .set_output_file(output or None) \
               .set_rate_limit(rate_limit)

        if headers:
            scanner.set_custom_headers(headers)

        if verify_ssl:
            scanner.set_verify_ssl(verify_ssl)

        results = scanner.run()
    else:
        scanner = SubdomainScanner(
            args.domain,
            filename=args.file,
            subdomains_list=args.list,
            timeout=args.timeout,
            valid_status_codes=set(args.status_codes) if args.status_codes else None,
            protocols=args.protocols
        )

        scanner.set_max_threads(args.max_threads) \
               .set_batch_size(args.batch_size) \
               .set_proxies(args.proxies) \
               .set_verbose(args.verbose) \
               .set_output_file(args.output) \
               .set_rate_limit(args.rate_limit)

        if args.headers:
            headers = dict(header.split(':') for header in args.headers)
            scanner.set_custom_headers(headers)

        if args.verify_ssl:
            scanner.set_verify_ssl(args.verify_ssl)

        results = scanner.run()

if __name__ == "__main__":
    main()
