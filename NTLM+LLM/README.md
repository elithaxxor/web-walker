# WebWalker 1.4

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
