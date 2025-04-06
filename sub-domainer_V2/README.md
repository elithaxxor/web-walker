---
# SubdomainScanner

**SubdomainScanner** is a Python tool designed to efficiently scan and enumerate subdomains of a target domain. It supports multi-threading for faster execution, customizable configurations (e.g., proxies, headers, rate limiting), and detailed output options (e.g., JSON, CSV). This project is ideal for security researchers, penetration testers, and web administrators looking to identify active subdomains.

---

## Features

- **Multi-threaded Scanning**: Leverage concurrent threads to speed up subdomain enumeration.
- **Protocol Fallback**: Automatically tries HTTPS and HTTP protocols for each subdomain.
- **Customizable Configuration**:
  - Set maximum threads, batch sizes, and rate limits.
  - Use proxies with credentials securely retrieved from environment variables.
  - Define custom HTTP headers and SSL verification settings.
- **Input Validation**: Ensures the target domain and subdomains are valid before scanning.
- **Detailed Output**:
  - Console output with color-coded results and a progress bar.
  - Save results to JSON or CSV files.
- **Extensibility**: Supports custom HTTP status codes and protocols.
- **Error Handling**: Gracefully manages timeouts, connection errors, and invalid inputs.
- **Unit Tests**: Includes a basic test suite for verifying core functionality.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/SubdomainScanner.git
   cd SubdomainScanner
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   The `requirements.txt` should include:
   ```
   requests
   colorama
   tqdm
   validators
   beautifulsoup4
   requests-mock  # For testing
   ```

3. **Set environment variables (optional)**:
   - For proxy credentials:
     ```bash
     export HTTPS_PROXY_USER='your_username'
     export HTTPS_PROXY_PASS='your_password'
     export HTTPS_PROXY_HOST='proxy.example.com'
     export HTTPS_PROXY_PORT='8080'
     ```

---

## Usage

### Basic Usage
Scan subdomains using a list:
```python
from subdomain_scanner import SubdomainScanner

scanner = SubdomainScanner("example.com", subdomains_list=["www", "mail", "ftp"])
scanner.run()
```

### Advanced Usage
Customize the scan with additional options:
```python
scanner = SubdomainScanner(
    "example.com",
    filename="subdomains.txt",
    timeout=10,
    valid_status_codes={200, 403},
    protocols=["https"]
)
scanner.set_max_threads(20)\
       .set_verbose(2)\
       .set_output_file("results.json")\
       .set_rate_limit(0.5)\
       .set_proxies()  # Uses environment variables if not provided
results = scanner.run()
```

### Command-Line Interface (CLI)
While the current version is a Python class, you can extend it to a CLI tool using libraries like `argparse` for easier usage.

---

## Differences from the Original Version

The new version of `SubdomainScanner` includes several enhancements and improvements over the original implementation. Below is a comparison table highlighting the key differences:

| **Feature**                 | **Original Version**                           | **New Version**                                      |
|-----------------------------|------------------------------------------------|------------------------------------------------------|
| **Input Validation**        | Basic validation for subdomains                | Enhanced validation for both domain and subdomains   |
| **Error Handling**          | Generic exception handling                     | Specific handling for timeouts, connection errors    |
| **Performance**             | Batch-based processing                         | Processes results as they complete for faster feedback |
| **Rate Limiting**           | Simple delay per request                       | Semaphore-based rate limiting across threads         |
| **Proxy Support**           | Hardcoded or manually set proxies              | Retrieves proxy credentials from environment variables |
| **Output Formats**          | Only JSON or plain text                        | Supports JSON and CSV formats                        |
| **Progress Feedback**       | Batch-level progress bar                       | Granular progress bar per subdomain                  |
| **Title Extraction**        | Regex-based title extraction                   | Uses `BeautifulSoup` for reliable HTML parsing       |
| **Extensibility**           | Fixed status codes and protocols               | Customizable status codes and protocols              |
| **Security**                | No specific security measures                  | Avoids hardcoded credentials; uses environment variables |
| **Testing**                 | No tests provided                              | Includes a basic unit test suite                     |

These improvements make the new version more robust, efficient, and secure, while also providing a better user experience and greater flexibility for advanced use cases.

---

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
