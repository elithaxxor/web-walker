import threading, requests, time, os, json, csv
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init
from tqdm import tqdm
import validators
from bs4 import BeautifulSoup
from jinja2 import Template
from collections import Counter
from datetime import datetime

# Initialize colorama for colored output
init()

class SubdomainScanner:
    # HTML report template with placeholders for dynamic data
    REPORT_TEMPLATE = """
    <html>
    <head>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
    table {
      border-collapse: collapse;
      width: 100%;
    }
    th, td {
      border: 1px solid #ddd;
      padding: 8px;
      text-align: left;
    }
    th {
      background-color: #f2f2f2;
    }
    </style>
    </head>
    <body>
    <h1>Subdomain Scan Report for {{ domain }}</h1>
    <p>Scan completed on {{ scan_date }}</p>
    <h2>Summary</h2>
    <p>Total subdomains scanned: {{ total_scanned }}</p>
    <p>Subdomains found: {{ total_found }}</p>
    {% if total_found > 0 %}
    <h2>Charts</h2>
    <p>Distribution of HTTP Status Codes</p>
    <canvas id="statusChart" width="400" height="200"></canvas>
    <p>Distribution of Server Types</p>
    <canvas id="serverChart" width="400" height="200"></canvas>
    <h2>Details</h2>
    <table>
    <thead>
    <tr><th>URL</th><th>Status Code</th><th>Server</th><th>Title</th></tr>
    </thead>
    <tbody>
    {% for subdomain in subdomains_found %}
    <tr>
    <td>{{ subdomain.url }}</td>
    <td>{{ subdomain.status_code }}</td>
    <td>{{ subdomain.server }}</td>
    <td>{{ subdomain.title }}</td>
    </tr>
    {% endfor %}
    </tbody>
    </table>
    <script>
    var statusLabels = {{ status_labels | tojson }};
    var statusData = {{ status_data | tojson }};
    var serverLabels = {{ server_labels | tojson }};
    var serverData = {{ server_data | tojson }};
    new Chart(document.getElementById('statusChart'), {
      type: 'pie',
      data: {
        labels: statusLabels,
        datasets: [{
          data: statusData,
          backgroundColor: ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56']
        }]
      }
    });
    new Chart(document.getElementById('serverChart'), {
      type: 'bar',
      data: {
        labels: serverLabels,
        datasets: [{
          label: 'Server Types',
          data: serverData,
          backgroundColor: '#36a2eb'
        }]
      }
    });
    </script>
    {% else %}
    <p>No subdomains were found during the scan.</p>
    {% endif %}
    </body>
    </html>
    """

    def __init__(self, domain, filename=None, timeout=20, valid_status_codes=None, protocols=None):
        if not validators.domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        self.domain = domain
        self.filename = filename
        self.timeout = timeout
        self.subdomains_found = []
        self.subdomains_lock = threading.Lock()
        self.R = "\033[91m"  # Red
        self.Y = "\033[93m"  # Yellow
        self.G = "\033[92m"  # Green
        self.W = "\033[0m"   # Reset
        self.max_threads = 10
        self.verbose = 1
        self.output_file = None
        self.report_file = None  # New attribute for HTML report
        self.valid_status_codes = valid_status_codes or {200, 301, 302}
        self.protocols = protocols or ["https", "http"]

    def set_report_file(self, filename):
        """Set the output file path for the HTML report."""
        self.report_file = filename
        return self

    def generate_report(self, results, report_file):
        """Generate an HTML report with scan results, charts, and explanations."""
        # Prepare report data
        domain = self.domain
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_scanned = results['subdomains_scanned']
        subdomains_found = results['subdomains_found']
        total_found = len(subdomains_found)

        # Prepare chart data if subdomains are found
        if total_found > 0:
            status_counter = Counter(subdomain['status_code'] for subdomain in subdomains_found)
            status_labels = list(status_counter.keys())
            status_data = list(status_counter.values())
            server_counter = Counter(subdomain['server'] for subdomain in subdomains_found)
            server_labels = list(server_counter.keys())
            server_data = list(server_counter.values())
        else:
            status_labels = []
            status_data = []
            server_labels = []
            server_data = []

        # Render the HTML template
        template = Template(self.REPORT_TEMPLATE)
        html = template.render(
            domain=domain,
            scan_date=scan_date,
            total_scanned=total_scanned,
            total_found=total_found,
            subdomains_found=subdomains_found,
            status_labels=status_labels,
            status_data=status_data,
            server_labels=server_labels,
            server_data=server_data
        )

        # Write to file
        with open(report_file, 'w') as f:
            f.write(html)

        if self.verbose >= 1:
            print(f"{self.Y}Report generated: {report_file}{self.W}")

    def run(self):
        """Execute the scan and generate the report if specified."""
        # Placeholder for existing scan logic
        results = {
            'subdomains_scanned': 100,  # Example value; replace with actual scan logic
            'subdomains_found': [
                {'url': 'sub1.example.com', 'status_code': 200, 'server': 'Apache', 'title': 'Home'},
                {'url': 'sub2.example.com', 'status_code': 301, 'server': 'Nginx', 'title': 'Redirect'}
            ],
            'elapsed_time': 10.5
        }
        # Existing save_results logic assumed here
        if hasattr(self, 'save_results'):
            self.save_results(results)
        # Generate report if requested
        if self.report_file:
            self.generate_report(results, self.report_file)
        return results

# Example usage
if __name__ == "__main__":
    scanner = SubdomainScanner("example.com", filename="subdomains.txt")
    scanner.set_report_file("report.html")
    scanner.run()
