```markdown
# 🔍 SubdomainScanner

<div align="center">

![SubdomainScanner Banner](https://via.placeholder.com/1200x300/0d1117/38b0de?text=🔍+SubdomainScanner)

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/yourusername/SubdomainScanner?style=for-the-badge&logo=github)](https://github.com/yourusername/SubdomainScanner/stargazers)

**Discover the digital footprint of any domain with blazing speed and precision**

</div>

<p align="center">
<b>SubdomainScanner</b> is a high-performance Python tool for discovering and analyzing subdomains with multi-threaded scanning capabilities, advanced protocol detection, and comprehensive output formats.
</p>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🚀 Installation](#-installation)
- [💻 Usage](#-usage)
- [🔄 Input & Output](#-input--output)
- [⚙️ Advanced Configuration](#️-advanced-configuration)
- [📊 Comparison](#-comparison)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## ✨ Features

<div align="center">

```mermaid
graph TD
    A[SubdomainScanner] --> B[Multi-threaded Scanning]
    A --> C[Protocol Detection]
    A --> D[Customization]
    A --> E[Output Options]
    
    B --> B1[Parallel Processing]
    B --> B2[Semaphore-based Rate Limiting]
    
    C --> C1[HTTPS/HTTP Fallback]
    C --> C2[Custom Protocol Support]
    
    D --> D1[Proxy Configuration]
    D --> D2[Custom Headers]
    D --> D3[Status Code Filtering]
    
    E --> E1[Console Output]
    E --> E2[JSON Export]
    E --> E3[CSV Export]
```

</div>

### 🚄 Performance
- **⚡ Multi-threaded Architecture**: Scan hundreds of subdomains in seconds
- **🔄 Adaptive Batch Processing**: Optimizes resource usage during scanning
- **⏱️ Configurable Rate Limiting**: Prevent triggering security measures

### 🔒 Security Features
- **🔐 Secure Proxy Integration**: Environment variable-based credential management
- **🧪 Custom Header Support**: Mimic legitimate browser traffic
- **🛡️ SSL Verification Options**: Handle self-signed certificates

### 📊 Smart Analysis
- **🔍 Protocol Fallback**: Automatically tests HTTPS then HTTP
- **📝 Title Extraction**: Uses BeautifulSoup for reliable HTML parsing
- **🚦 Status Code Filtering**: Customize which responses count as "valid"

### 📦 Output & Reporting
- **🎨 Color-Coded Console Output**: Instantly visualize results
- **📈 Live Progress Tracking**: Real-time scanning progress
- **💾 Multiple Export Formats**: JSON and CSV export options

---

## 🚀 Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Quick Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/SubdomainScanner.git
   cd SubdomainScanner
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

<details>
<summary>📋 View requirements.txt contents</summary>

```
requests>=2.25.1
colorama>=0.4.4
tqdm>=4.62.3
validators>=0.18.2
beautifulsoup4>=4.10.0
requests-mock>=1.9.3  # For testing
```
</details>

### 🔐 Environment Setup (Optional)

For secure proxy usage, set these environment variables:

```bash
# For Linux/macOS
export HTTPS_PROXY_USER='your_username'
export HTTPS_PROXY_PASS='your_password'
export HTTPS_PROXY_HOST='proxy.example.com'
export HTTPS_PROXY_PORT='8080'

# For Windows
setx HTTPS_PROXY_USER "your_username"
setx HTTPS_PROXY_PASS "your_password"
setx HTTPS_PROXY_HOST "proxy.example.com"
setx HTTPS_PROXY_PORT "8080"
```

> 💡 **Pro Tip**: Use a `.env` file with python-dotenv for easier management of environment variables.

---

## 💻 Usage

### 🔰 Basic Usage

```python
from subdomain_scanner import SubdomainScanner

# Initialize with a list of subdomains
scanner = SubdomainScanner("example.com", subdomains_list=["www", "mail", "api", "ftp"])
results = scanner.run()

# Print discovered subdomains
for subdomain, data in results.items():
    print(f"{subdomain}: {data['status']} - {data['title']}")
```

### 📚 Using a Wordlist File

```python
# Initialize with a wordlist file
scanner = SubdomainScanner(
    "example.com",
    filename="wordlists/common-subdomains-5000.txt"
)
scanner.run()
```

### 🌟 Advanced Example

```python
scanner = SubdomainScanner(
    target_domain="example.com",
    filename="wordlists/comprehensive.txt",
    timeout=5,                              # 5-second timeout per request
    valid_status_codes={200, 201, 204, 403},  # Consider these status codes valid
    protocols=["https", "http"]             # Try HTTPS first, then HTTP
)

# Chain configuration methods
scanner.set_max_threads(30)\
       .set_verbose(2)\
       .set_batch_size(50)\
       .set_output_file("results.json", format="json")\
       .set_rate_limit(0.5)\    # Half-second delay between requests
       .set_headers({           # Custom headers
           "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
           "Accept-Language": "en-US,en;q=0.9"
       })\
       .set_proxies({
           "https": "https://proxy.example.com:8080"
       })

# Execute the scan
results = scanner.run()

# Process results
active_subdomains = [subdomain for subdomain, data in results.items() 
                    if data["status_code"] in scanner.valid_status_codes]
print(f"Found {len(active_subdomains)} active subdomains")
```

---

## 🔄 Input & Output

### 📥 Input Options

| Method | Description | Example |
|--------|-------------|---------|
| **List** | Provide a Python list of subdomains | `subdomains_list=["www", "mail", "admin"]` |
| **File** | Path to a text file with one subdomain per line | `filename="subdomains.txt"` |
| **Mixed** | Combine both methods for comprehensive scanning | Use both parameters together |

<details>
<summary>📄 Example Wordlist Format</summary>

```
www
mail
ftp
admin
blog
shop
api
dev
stage
test
```
</details>

### 📤 Output Formats

#### Terminal Output

<div align="center">

![Terminal Output](https://via.placeholder.com/800x400/0d1117/38b0de?text=Live+Terminal+Output+with+Progress+Bar)

</div>

#### JSON Output

```json
{
  "www.example.com": {
    "url": "https://www.example.com",
    "status_code": 200,
    "title": "Example Domain",
    "ip": "93.184.216.34",
    "content_type": "text/html; charset=UTF-8",
    "response_time": 0.342
  },
  "api.example.com": {
    "url": "https://api.example.com",
    "status_code": 403,
    "title": "Forbidden",
    "ip": "93.184.216.34", 
    "content_type": "application/json",
    "response_time": 0.156
  }
}
```

#### CSV Output

```csv
subdomain,url,status_code,title,ip,content_type,response_time
www.example.com,https://www.example.com,200,"Example Domain",93.184.216.34,text/html; charset=UTF-8,0.342
api.example.com,https://api.example.com,403,Forbidden,93.184.216.34,application/json,0.156
```

---

## ⚙️ Advanced Configuration

### 🧰 Configuration Methods

| Method | Description | Default |
|--------|-------------|---------|
| `set_max_threads(n)` | Set maximum concurrent threads | 10 |
| `set_batch_size(n)` | Number of subdomains per batch | 50 |
| `set_verbose(level)` | Verbosity level (0-3) | 1 |
| `set_output_file(filename, format)` | Save results to file | None, "json" |
| `set_rate_limit(delay)` | Seconds between requests | 0 (no limit) |
| `set_proxies(proxy_dict)` | Set proxy configuration | None |
| `set_headers(headers_dict)` | Set custom HTTP headers | Default User-Agent |
| `set_ssl_verify(verify)` | Enable/disable SSL verification | True |

### 🛡️ Proxy Configuration

```python
# Manual configuration
scanner.set_proxies({
    "http": "http://user:pass@proxy.example.com:8080",
    "https": "https://user:pass@proxy.example.com:8080"
})

# Using environment variables (more secure)
scanner.set_proxies()  # Automatically uses environment variables
```

### 🔍 Custom Status Codes

```python
# Only consider these status codes as valid findings
scanner.valid_status_codes = {200, 201, 301, 302, 403}

# Include additional status codes for special cases
scanner.valid_status_codes.add(401)  # Add authentication required
```

---

## 📊 Comparison

### 🔄 Version Comparison

<div align="center">

| **Feature** | **Original Version** | **Enhanced Version** |
|-------------|----------------------|----------------------|
| **Performance** | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Input Validation** | Basic | Comprehensive |
| **Error Handling** | Generic | Specific & Robust |
| **Rate Limiting** | Simple delay | Semaphore-based |
| **Proxy Support** | Basic | Secure & Environment-based |
| **Output Formats** | Limited | Multiple formats |
| **Progress Feedback** | Batch-level | Per-subdomain |
| **Title Extraction** | Regex-based | BeautifulSoup HTML parsing |
| **Extensibility** | Fixed parameters | Fully customizable |
| **Security** | Hardcoded credentials | Environment variables |
| **Testing** | None | Unit test suite |

</div>

### 🏆 Key Improvements

- **🚄 Processing Algorithm**: Results processed as they complete instead of waiting for batch completion
- **🔒 Security Enhancements**: No hardcoded credentials, proper environment variable usage
- **🧩 Modular Design**: More extensible codebase with better separation of concerns
- **📊 Better Reporting**: Rich console output with detailed progress information
- **🧪 Testing Framework**: Added unit tests for reliable code quality

---

## 🤝 Contributing

Contributions make the open-source community thrive! We welcome all contributions to improve SubdomainScanner.

### 🔄 Contribution Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add some amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### 💡 Development Ideas

- Command-line interface using `argparse` or `click`
- Additional output formats (HTML, XML)
- Integration with other security tools (Nmap, Nuclei)
- Enhanced reporting with visualization

<details>
<summary>📝 Code Style Guidelines</summary>

- Follow PEP 8 style guide
- Add docstrings to all functions and classes
- Include type hints where appropriate
- Write tests for new functionality
</details>


---

<div align="center">

**[Documentation](https://github.com/yourusername/SubdomainScanner/wiki)** |
**[Report Bug](https://github.com/yourusername/SubdomainScanner/issues)** |
**[Request Feature](https://github.com/yourusername/SubdomainScanner/issues)**


</div>
```
