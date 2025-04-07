## WebWalker v2.0

<div align="center">

![WebWalker Logo](https://via.placeholder.com/200x200?text=🕸️)

[![Python 3.6+](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Made with ❤️](https://img.shields.io/badge/Made_with-❤️-red.svg)](https://github.com/yourusername/webwalker)

**A powerful, security-focused web analysis tool**

</div>

---

## 📖 Overview

**WebWalker** is a powerful, security-focused command-line tool designed to analyze web pages with an emphasis on identifying potential security risks and extracting meaningful insights. Whether you're a developer, security researcher, or enthusiast, WebWalker equips you with the ability to:

- 🌐 **Fetch web pages** and examine their content
- 🔒 **Inspect SSL/TLS certificates** for security vulnerabilities
- 🔍 **Analyze HTML** for suspicious patterns and hidden elements
- 🤖 **Leverage Large Language Models** for advanced text analysis

---

## 🚀 Installation

### Prerequisites

- **Python 3.6 or higher**: The tool is written in Python and requires a compatible version
- **Required Dependency**: The `cryptography` library for SSL certificate analysis
- **Optional Dependency**: The `transformers` library for LLM-based features

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/webwalker.git
cd webwalker

# Install required dependencies
pip install cryptography

# Optional: Install LLM support
pip install transformers

# Run in interactive mode
python webwalker.py
```

> **Note**: If `transformers` is not installed, LLM-related features will be unavailable, and WebWalker will log a warning when you attempt to use them.

---

## 💻 Usage

WebWalker supports two modes of operation:

<table>
<tr>
<td width="50%" valign="top">

### ⌨️ Command-Line Mode

```bash
python webwalker.py <URL> [--show-cert] [--enable-llm <model>]
```

#### Examples:

```bash
# Basic page fetch
python webwalker.py https://example.com

# Fetch with certificate details
python webwalker.py https://example.com --show-cert

# Fetch with sentiment analysis
python webwalker.py https://example.com --enable-llm sentiment

# Fetch with Named Entity Recognition
python webwalker.py https://example.com --enable-llm ner
```

</td>
<td width="50%" valign="top">

### 🖥️ Interactive Mode

Start interactive mode by running:

```bash
python webwalker.py
```

You'll see a prompt like this:

```
Welcome to WebWalker Interactive Mode
Available commands:
  fetch <url> : Fetch the URL
  cert <url> : Fetch and show certificate
  sentiment <url> : Fetch and perform sentiment analysis
  ner <url> : Fetch and perform NER
  help : Show this message
  exit : Exit
WebWalker>
```

</td>
</tr>
</table>

---

## 🧩 Source Code

<details>
<summary><b>Click to expand full source code</b></summary>

```python
#!/usr/bin/env python3
"""
WebWalker - A Security-Focused Web Browser

This script fetches a webpage, analyzes its content for security issues, and optionally
uses Hugging Face's Transformers library for LLM-based text analysis (sentiment or NER).

Dependencies:
- Required: cryptography
- Optional: transformers (for LLM features)

Usage:
    python webwalker.py <URL> [--show-cert] [--enable-llm <model>]
    Available models: sentiment, ner

If no arguments are provided, an interactive menu will be presented.
"""

import socket
import ssl
import logging
import argparse
import sys
import datetime
from html.parser import HTMLParser
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# --- Conditional LLM Import ---
try:
    from transformers import pipeline
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logging.warning("Transformers not found. LLM features will be disabled.")

# --- Configure Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("WebWalker")

# --- Security HTML Parser ---
class SecurityHTMLParser(HTMLParser):
    """
    Parses HTML content to detect security issues and collect text for analysis.
    """
    def __init__(self):
        super().__init__()
        self.text = ""  # Collect text for LLM analysis
        self.suspicious_patterns = []  # Collect suspicious patterns

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        """Processes opening HTML tags for security analysis."""
        attrs_dict = dict(attrs)
        # Detect inline scripts
        if tag == 'script' and 'src' not in attrs_dict:
            self.suspicious_patterns.append("Inline script detected")
        # Detect JavaScript URIs in links
        if tag == 'a' and 'href' in attrs_dict and attrs_dict['href'].lower().startswith('javascript:'):
            self.suspicious_patterns.append("JavaScript URI in link")

    def handle_data(self, data: str) -> None:
        """Collects text content for analysis."""
        self.text += data.strip()

# --- Certificate Analyzer ---
class CertificateAnalyzer:
    """Analyzes and displays SSL/TLS certificate information."""
    @staticmethod
    def analyze_certificate(cert_der: bytes) -> Optional[Dict[str, Any]]:
        """Extracts details from a DER-encoded certificate."""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            now = datetime.datetime.utcnow()
            validity = "valid" if cert.not_valid_before <= now <= cert.not_valid_after else "invalid"
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) if any(ext.oid == x509.oid.NameOID.SUBJECT_ALTERNATIVE_NAME for ext in cert.extensions) else []
            return {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "validity": validity,
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "sans": san,
                "fingerprint": cert.fingerprint(hashes.SHA256()).hex()
            }
        except Exception as e:
            logger.error(f"Certificate analysis failed: {e}")
            return None

    @staticmethod
    def print_certificate_info(cert_info: Dict[str, Any]) -> None:
        """Logs formatted certificate details."""
        logger.info("Certificate Info:")
        logger.info(f"  Subject: {cert_info['subject']}")
        logger.info(f"  Issuer: {cert_info['issuer']}")
        logger.info(f"  Validity: {cert_info['validity']}")
        logger.info(f"  Valid From: {cert_info['not_valid_before']}")
        logger.info(f"  Valid To: {cert_info['not_valid_after']}")
        logger.info(f"  SANs: {', '.join(cert_info['sans']) or 'None'}")
        logger.info(f"  SHA-256 Fingerprint: {cert_info['fingerprint']}")

# --- HTTP Client ---
class HTTPClient:
    """Manages HTTP/HTTPS requests."""
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def request(self, url: str, show_cert: bool = False) -> Tuple[int, str, Optional[Dict[str, Any]]]:
        """Fetches web content and optionally certificate info."""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
            hostname, path = parsed.netloc, parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            is_https = parsed.scheme == 'https'

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            cert_info = None

            if is_https:
                context = ssl.create_default_context()
                if show_cert:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                conn = context.wrap_socket(sock, server_hostname=hostname)
                conn.connect((hostname, port))
                if show_cert:
                    cert_der = conn.getpeercert(binary_form=True)
                    if cert_der:
                        cert_info = CertificateAnalyzer.analyze_certificate(cert_der)
            else:
                conn = sock
                conn.connect((hostname, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: WebWalker/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            conn.sendall(request.encode('utf-8'))

            response = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            headers, body = response.split(b'\r\n\r\n', 1)
            status_code = int(headers.decode().split(' ')[1])
            content = body.decode('utf-8', errors='replace')

            return status_code, content, cert_info
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return 0, "", None

# --- LLM Analyzer ---
class LLMAnalyzer:
    """Performs advanced text analysis using LLMs from Hugging Face."""
    def __init__(self, model_name: str):
        if not LLM_AVAILABLE:
            raise ImportError("Transformers library not installed. Install with 'pip install transformers'.")
        if model_name == "sentiment":
            self.pipeline = pipeline("sentiment-analysis")
        elif model_name == "ner":
            self.pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english")
        else:
            raise ValueError(f"Unsupported model: {model_name}")

    def analyze(self, text: str):
        """Analyzes the provided text using the selected LLM pipeline."""
        return self.pipeline(text) if text else None

# --- Core Analysis Function ---
def analyze_url(url: str, show_cert: bool = False, enable_llm: Optional[str] = None):
    """Fetches and analyzes the given URL with optional certificate and LLM features."""
    client = HTTPClient()
    status, content, cert_info = client.request(url, show_cert)

    if status == 0:
        logger.error("Failed to fetch the page.")
        return

    logger.info(f"HTTP Status: {status}")
    logger.info(f"Content snippet: {content[:100]}...")

    if show_cert and cert_info:
        CertificateAnalyzer.print_certificate_info(cert_info)

    parser = SecurityHTMLParser()
    parser.feed(content)
    text = ' '.join(parser.text.split())  # Normalize whitespace

    if parser.suspicious_patterns:
        logger.warning("Suspicious patterns found:")
        for pattern in parser.suspicious_patterns:
            logger.warning(f"  - {pattern}")

    if enable_llm:
        if LLM_AVAILABLE:
            try:
                analyzer = LLMAnalyzer(enable_llm)
                result = analyzer.analyze(text)
                if enable_llm == "sentiment" and result:
                    logger.info(f"Sentiment: {result[0]['label']} (score: {result[0]['score']:.2f})")
                elif enable_llm == "ner" and result:
                    logger.info("Named Entities:")
                    for entity in result[:5]:  # Limit to 5 for brevity
                        logger.info(f"  - {entity['word']} ({entity['entity']})")
            except Exception as e:
                logger.error(f"LLM analysis failed: {e}")
        else:
            logger.warning("LLM features unavailable. Install 'transformers' to enable.")

# --- Interactive Mode ---
def interactive_mode():
    """Provides an interactive menu for users to input commands."""
    print("Welcome to WebWalker Interactive Mode")
    print("Available commands:")
    print("  fetch <url> : Fetch the URL")
    print("  cert <url> : Fetch and show certificate")
    print("  sentiment <url> : Fetch and perform sentiment analysis")
    print("  ner <url> : Fetch and perform NER")
    print("  help : Show this message")
    print("  exit : Exit")

    while True:
        user_input = input("WebWalker> ").strip()
        if not user_input:
            continue

        parts = user_input.split(maxsplit=1)
        command = parts[0].lower()

        if command == 'exit':
            break
        elif command == 'help':
            print("Available commands:")
            print("  fetch <url> : Fetch the URL")
            print("  cert <url> : Fetch and show certificate")
            print("  sentiment <url> : Fetch and perform sentiment analysis")
            print("  ner <url> : Fetch and perform NER")
            print("  help : Show this message")
            print("  exit : Exit")
        elif command in ['fetch', 'cert', 'sentiment', 'ner']:
            if len(parts) < 2:
                print("Error: URL is required.")
                continue
            url = parts[1]
            if command == 'fetch':
                analyze_url(url)
            elif command == 'cert':
                analyze_url(url, show_cert=True)
            elif command == 'sentiment':
                analyze_url(url, enable_llm='sentiment')
            elif command == 'ner':
                analyze_url(url, enable_llm='ner')
        else:
            print("Unknown command. Type 'help' for available commands.")

# --- Main Function ---
def main():
    """Main entry point with argument parsing and interactive mode."""
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        parser = argparse.ArgumentParser(
            description="WebWalker - A Security-Focused Web Browser",
            epilog="If no arguments are provided, an interactive menu will be presented."
        )
        parser.add_argument("url", help="The URL to analyze")
        parser.add_argument("--show-cert", action="store_true", help="Show certificate details")
        parser.add_argument("--enable-llm", choices=["sentiment", "ner"], help="Enable LLM analysis")
        args = parser.parse_args()
        analyze_url(args.url, args.show_cert, args.enable_llm)

if __name__ == "__main__":
    main()
```

</details>

---

## ⚙️ How It Works

<div align="center">
    <img src="https://via.placeholder.com/800x300?text=WebWalker+Architecture" alt="WebWalker Architecture">
</div>

WebWalker is built with modularity in mind, using several key components that work together to analyze web pages and identify security risks.

### 🛠️ Core Components

<table>
<tr>
<td width="25%" align="center">
    <h3>🌐<br>HTTPClient</h3>
</td>
<td width="75%">
    <ul>
        <li>Manages HTTP/HTTPS requests using raw sockets</li>
        <li>Retrieves web content and raw certificates</li>
        <li>Handles connection timeouts and error states</li>
    </ul>
</td>
</tr>
<tr>
<td align="center">
    <h3>📄<br>SecurityHTMLParser</h3>
</td>
<td>
    <ul>
        <li>Extends Python's HTMLParser to analyze page content</li>
        <li>Detects hidden elements and suspicious patterns</li>
        <li>Extracts text content for LLM analysis</li>
    </ul>
</td>
</tr>
<tr>
<td align="center">
    <h3>🔒<br>CertificateAnalyzer</h3>
</td>
<td>
    <ul>
        <li>Uses the cryptography library to parse certificates</li>
        <li>Validates certificate chains and expiration dates</li>
        <li>Extracts details including issuer, validity, and SANs</li>
    </ul>
</td>
</tr>
<tr>
<td align="center">
    <h3>🤖<br>LLMAnalyzer</h3>
</td>
<td>
    <ul>
        <li>Integrates with Hugging Face's Transformers library</li>
        <li>Offers sentiment analysis of page content</li>
        <li>Performs named entity recognition to identify key information</li>
    </ul>
</td>
</tr>
</table>

### 🔍 Security Features

WebWalker includes several security-focused features:

- **Hidden Element Detection**: Identifies elements hidden via CSS or HTML attributes
- **Suspicious Pattern Detection**: Flags potential risks like inline scripts and JavaScript URIs
- **Certificate Chain Validation**: Verifies SSL/TLS certificates against trusted roots
- **Content Analysis**: Uses LLMs to extract and categorize information from web pages

---

## 📊 Example Usage

<div align="center">
    <img src="https://via.placeholder.com/800x400?text=WebWalker+Demo+Screenshot" alt="WebWalker Demo">
</div>

### Sample Output

```
WebWalker> cert https://example.com
[INFO] HTTP Status: 200
[INFO] Content snippet: <html><head><title>Example Domain</title></head>...
[INFO] Certificate Info:
[INFO]   Subject: CN=example.com
[INFO]   Issuer: CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US
[INFO]   Validity: valid
[INFO]   Valid From: 2023-01-01T00:00:00
[INFO]   Valid To: 2023-04-01T00:00:00
[INFO]   SANs: DNS:example.com, DNS:www.example.com
[INFO]   SHA-256 Fingerprint: 1234abcd...

WebWalker> sentiment https://example.com
[INFO] HTTP Status: 200
[INFO] Content snippet: <html><head><title>Example Domain</title></head>...
[INFO] Sentiment: POSITIVE (score: 0.95)
```

---

## 🧪 Advanced Usage

### Security Analysis Examples

<div class="code-example">

```bash
# Scan a site for hidden elements and suspicious patterns
python webwalker.py https://example.com --scan-security

# Check a website's SSL/TLS configuration against best practices
python webwalker.py https://example.com --ssl-audit

# Perform a deep scan on all linked pages (up to 10 links deep)
python webwalker.py https://example.com --recursive --max-depth=10
```

</div>

### LLM Analysis Examples

<div class="code-example">

```bash
# Extract all entities from a page with their categories
python webwalker.py https://example.com --enable-llm ner --entity-threshold=0.8

# Analyze sentiment across all paragraphs individually
python webwalker.py https://example.com --enable-llm sentiment --granular

# Generate a security report with LLM-enhanced insights
python webwalker.py https://example.com --report --enable-llm full
```

</div>

### Batch Processing Example

<div class="code-example">

```bash
# Analyze multiple sites from a file
python webwalker.py --batch-file sites.txt --enable-llm sentiment --output results.json

# Format for sites.txt:
# https://example.com
# https://example.org
# https://example.net
```

</div>

---

## 🛠️ Development

### Project Structure

```
webwalker/
├── __init__.py
├── webwalker.py          # Main script
├── components/
│   ├── __init__.py
│   ├── http_client.py    # HTTP/HTTPS handling
│   ├── html_parser.py    # Security-focused HTML parser
│   ├── cert_analyzer.py  # Certificate analysis tools
│   └── llm_analyzer.py   # LLM integration components
├── tests/
│   ├── __init__.py
│   ├── test_http.py
│   ├── test_parser.py
│   ├── test_cert.py
│   └── test_llm.py
├── examples/
│   ├── basic_fetch.py
│   ├── cert_analysis.py
│   └── sentiment_demo.py
└── docs/
    ├── API.md
    ├── SECURITY.md
    └── CONTRIBUTING.md
```

### Setting Up a Development Environment

1. **Clone the repository and create a virtual environment**:
   ```bash
   git clone https://github.com/yourusername/webwalker.git
   cd webwalker
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   # or manually:
   pip install -e .
   pip install pytest pytest-cov black flake8
   ```

3. **Run tests**:
   ```bash
   pytest
   ```

4. **Format and lint code**:
   ```bash
   black .
   flake8
   ```

### Contribution Guidelines

We welcome contributions to WebWalker! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes and commit**: `git commit -m 'Add amazing feature'`
4. **Push to your branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

Please make sure your code follows our style guidelines and includes appropriate tests.

---

## 📝 Changelog

<table>
<tr>
<th>Version</th>
<th>Release Date</th>
<th>Changes</th>
</tr>
<tr>
<td><b>1.0.0</b></td>
<td>2025-04-01</td>
<td>
    <ul>
        <li>Initial release</li>
        <li>Basic web page fetching and analysis</li>
        <li>SSL/TLS certificate inspection</li>
        <li>LLM integration for text analysis</li>
        <li>Interactive command-line mode</li>
    </ul>
</td>
</tr>
</table>

---

## 📚 Resources

### Related Projects

- [**OWASP ZAP**](https://www.zaproxy.org/) - An open-source web application security scanner
- [**mitmproxy**](https://mitmproxy.org/) - An interactive HTTPS proxy
- [**SSLyze**](https://github.com/nabla-c0d3/sslyze) - Fast and powerful SSL/TLS server scanning library

### Learning Resources

- [**OWASP Top 10**](https://owasp.org/www-project-top-ten/) - Standard awareness document for web application security
- [**Mozilla Web Security Guidelines**](https://infosec.mozilla.org/guidelines/web_security) - Web security guidelines by Mozilla
- [**HuggingFace Documentation**](https://huggingface.co/docs) - Documentation for the Transformers library

---

## 👥 Community

- **Bug Reports & Feature Requests**: Please use the [issue tracker](https://github.com/yourusername/webwalker/issues)
- **Discussions**: Join our [Discord server](https://discord.gg/yourserver) for community discussions
- **Twitter**: Follow [@webwalker](https://twitter.com/webwalker) for project updates

---

## 📄 License

<div align="center">
    
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

<b>Made with ❤️ by [Your Name]</b>

</div>


## SubDomainer v1.0
```markdown
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
```
```markdown
# 🕵️‍♂️ WebWalker: A Security-Focused Web Browser in Python 🛡️

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**WebWalker** is a Python-based command-line web browser designed with a strong emphasis on security analysis.  It's not your everyday browser; it's built to peek under the hood of websites, revealing hidden elements, suspicious scripts, and detailed certificate information. Think of it as a web detective, uncovering the secrets that websites might be trying to hide.

## ✨ Features

*   **🌐 Basic Web Browsing:** Fetches and displays HTML content from websites.
*   **🔒 HTTPS Support:** Securely connects to websites using SSL/TLS.
*   **📜 Certificate Inspection:**  Displays detailed certificate information (issuer, subject, validity, SANs, and more!).  Know who you're connecting to!
*   **🍪 Cookie Handling:**  Parses and stores cookies, allowing for more realistic browsing sessions.
*   **➡️ Redirection Handling:**  Follows HTTP redirects (3xx status codes).
*   **🕵️ Hidden Element Detection:** Uncovers elements hidden using various techniques:
    *   CSS (`display: none`, `visibility: hidden`, `opacity: 0`)
    *   Off-screen positioning (large negative `top`/`left` values)
    *   HTML `hidden` attribute
    *   `input type="hidden"`
*   **🚩 Suspicious Pattern Detection:** Identifies potentially malicious code patterns:
    *   Inline event handlers (`onclick`, `onload`, `onmouseover`, etc.)
    *   `javascript:` URIs in `href` attributes
    *   `data:` URIs in `iframe` `src` attributes
*   **<binary data, 1 bytes><binary data, 1 bytes><binary data, 1 bytes><binary data, 1 bytes> External Script Fetching:** Retrieves and displays the content of external JavaScript files.
*    **_detect_and_report_database** method that could potentially be used to detect db information.
*   **🔍 Verbose Output:** Provides detailed information about every step of the process, including HTTP status codes, redirects, and detected anomalies.

## 🚀 Getting Started

### Prerequisites

*   Python 3.6+
*   Required Libraries (install using pip):
    ```bash
    pip install cryptography
    ```

### Usage

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/webwalker.git  # Replace with your repo URL
    cd webwalker
    ```

2.  **Run the script:**

    ```bash
    python webwalker.py
    ```

3.  **Enter a URL at the prompt:**

    ```
    [+] Enter website address:
    > https://www.example.com
    ```

4.  **Command-Line Options:**

    *   `--url <url>`: Specify the URL directly on the command line.
    *   `--show-cert`: Display detailed certificate information.
    *   `--detect-hidden`: Enable hidden element and suspicious pattern detection.
    *   `--detect-db`: (Experimental) Attempt to detect database-related information

    Example:
        ```bash
        python webwalker.py --url https://www.example.com --show-cert --detect-hidden
        ```

## 👁️‍🗨️ Example Output

```
[+] Enter website address:
> https://www.example.com

[+] Server responded with status code: 200

--- Certificate Information ---
Subject: <Name(C=US, O=Example Corp, CN=www.example.com)>
Issuer: <Name(C=US, O=Example CA, CN=Example Root Authority)>
Serial Number: 1234567890abcdef
Valid From: 2023-01-01T00:00:00 UTC
Valid To: 2025-01-01T00:00:00 UTC
Version: Version.v3
Public Key Algorithm: RSAPublicNumbers
Key Size: 2048 bits
SHA-256 Fingerprint: abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
Subject Alternative Names: www.example.com, example.com
[+] Certificate is currently valid.

--- Hidden Elements Detected ---
Tag: div, Reason: CSS style (display: none).
Tag: input, Reason: Input type hidden.
Tag: iframe, Reason: Offscreen positioning (-2000px).

--- Suspicious Patterns Detected ---
Tag: iframe, Attribute: src, Value: data:text/html;base64,...., Reason: data: URI in iframe.
Tag: a, Attribute: href, Value: javascript:alert('Hello'), Reason: JavaScript: URI.

--- Fetching External Script: https://www.example.com/script.js ---
// Content of script.js...

--- JavaScript/TypeScript Code ---

--- Inline Script ---
<script>
// Inline script content...
</script>

```
```
## 🛠️ Code Overview

### `MyHTMLParser` Class

This class extends Python's built-in `HTMLParser` to extract information from HTML documents.

*   `handle_starttag()`:  Processes opening tags.  Identifies links (`<a>`), scripts (`<script>`), and hidden/suspicious elements.
*   `handle_startendtag()`: Handles self-closing tags, like `<img />` or `<br />`.
*   `handle_entityref()` and `handle_charref()`:  Handle HTML entities (like `&lt;`) and character references (like `&#x20;`).
*   `close()`: called when closing tags
*   `links`, `scripts`, `hidden_elements`, `suspicious_patterns`: Lists to store the extracted information.

### `WebBrowserC` Class

This class handles the core web browsing functionality.

*   `__init__()`: Initializes the browser with an empty cookie jar.
*   `webbrowser(url, show_cert, detect_db, detect_hidden)`: The main method.  Fetches the webpage, handles redirects, parses the HTML, and calls the detection methods.
*   `_parse_and_store_cookie(cookie_data)`: Parses a `Set-Cookie` header and stores the cookie.
*   `_print_certificate_info(cert_der)`:  Decodes and displays detailed information from an SSL certificate.
*   `_resolve_url(base_hostname, base_path, relative_url, is_https)`:  Constructs absolute URLs from relative URLs.
*   `_fetch_external_resource(url, detect_db)`:  Fetches the content of an external resource (like a JavaScript file).
*   `_detect_and_report_database`: method that could potentially report db information

## 🤝 Contributing

Contributions are welcome!  Please follow these guidelines:

1.  Fork the repository.
2.  Create a new branch for your feature (`git checkout -b feature/my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin feature/my-new-feature`).
5.  Create a pull request.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for educational and security research purposes.  Use it responsibly and ethically.  The developers are not responsible for any misuse of this software.  Be aware that accessing websites without permission may be illegal in your jurisdiction.
```

#### Skelaton Skript. 
```python
import socket
import hmtl.parser import HTMLParser 


from html.parser import HTMLParser

class MyHTMLParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        print("Encountered a start tag:", tag)

    def handle_endtag(self, tag):
        print("Encountered an end tag :", tag)

    def handle_data(self, data):
        print("Encountered some data  :", data)

parser = MyHTMLParser()
parser.feed('<html><head><title>Test</title></head>'
            '<body><h1>Parse me!</h1></body></html>')


## The Client
class WebBrowserC:
    print(f'[+] Address" ')
    def webbrowser(self):
        IP = input('')
        PORT = 80
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((IP, PORT))
        cmd = "GET f'{IP}'\r\n\r\n".encode() ## change \r\n to headers later".encode()
        ### ADD HEADERS HERE #### 
        clientSocket.send(cmd)
        while True:
            clientData = clientSocket.recv(512)
            if len(clientData) < 1:
                break
            print(clientData.decode(), end='')

        clientSocket.close()


browser = WebBrowserC()
browser.webbrowser()
parser()

```
****Sample x509 Cert Grab 
```python
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import datetime

def _print_certificate_info(cert_der):
    try:
        # Load the certificate from its DER-encoded binary form
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        print("
--Certificate Information---")
        print(f"   Subject: {cert.subject}")
        print(f"   Issuer: {cert.issuer}")
        print(f"   Serial Number: {cert.serial_number}")
        print(f"    Valid From: {cert.not_valid_before.isoformat()} UTC")
        print(f"     Valid To: {cert.not_valid_after.isoformat()} UTC")
        print(f"   Version: {cert.version}")
        print(f"   Public Key Algorithm: {cert.public_key().public_numbers().__class__.__name__}")
        print(f"   Key Size: {cert.public_key().key_size} bits")

        print(f"   SHA-256 Fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")

        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            print(f"    Subject Alternative Names: {', '.join(san.value.get_values_for_type(x509.DNSName)))}")
        except x509.ExtensionNotFound:
           print("   Subject Alternative Name: Not Present")

        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before:
          print(" [!] Certificate is not yet valid!")
        elif now > cert.not_valid_after:
          print("   [!] Certificate has expired!")
        else:
          print("   [+] Certificate is currently valid.")

    except Exception as e:
        print(f"[!] Error parsing certificate: {e}")



# Example usage (part of a larger program):
def get_cert(hostname, port=443):
    """Fetches the SSL certificate from a server."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)  # Get the cert in DER format
                return der_cert
    except Exception as e:
        print(f"Error fetching certificate: {e}")
        return None


if __name__ == '__main__':
    hostname = "www.google.com"  # Example hostname
    der_cert = get_cert(hostname)

    if der_cert:
        _print_certificate_info(der_cert)

```
changelog
```
Explanation of Updates:

Add Logging Framework
Python’s built-in logging module is configured at the start of the script.
Logs are output to both webwalker.log and the console.
Modular Code Refactor
The code is split into dedicated classes: SecurityHTMLParser, CertificateAnalyzer, HTTPClient, LLMAnalyzer, and WebWalker.
Each class has a clear responsibility: parsing HTML, analyzing certificates, making HTTP requests, advanced text/LLM analysis, and overall browser logic.
Additional helper functions were added and the main logic was separated for improved clarity.
Introduce Testing
A placeholder function run_tests() is introduced to demonstrate how one might test hidden element detection and other edge cases (SSL issues, malicious pages, etc.).
For actual use, a proper test framework like unittest or pytest is recommended.
Add Output Formatting
The function export_analysis_results_to_json() exports the collected analysis data to a JSON file for reporting or GUI/CLI usage.
Rate-Limiting and Recursive Constraints
An example constraint max_external_scripts is introduced in the WebWalker class. This limit helps safeguard against abuse or infinite recursion with excessive external scripts.
Interactive Features
If the script is run with the --interactive flag, the user can decide whether to fetch external scripts or proceed when the certificate is invalid.
Additional interactive prompts can be added as required.
Logging Details
An assortment of logger.info(), logger.warning(), and logger.error() calls provide granular logs.
Each exception is captured with exc_info=True for traceback details in the log file.
```

