## SubDomainer v1.0
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
Key improvements and explanations in this README:

*   **Engaging Title and Intro:**  Uses emojis and a clear, concise description to immediately grab the reader's attention.  The "web detective" analogy is helpful.
*   **Shields.io Badge:** Adds a professional touch with a license badge.
*   **Features Section:**  Clearly lists the capabilities of the tool, using bullet points and descriptive language.  Highlights the security-focused features.
*   **Getting Started:**  Provides clear instructions for installation and basic usage.  Includes examples for using command-line options.
*   **Example Output:**  Shows the kind of output a user can expect, demonstrating the tool's capabilities in action.  This is *crucially* important for understanding what the tool does.
*   **Code Overview:** Explains the main classes and methods, making it easier for contributors to understand the codebase.
*   **Contributing:**  Provides standard guidelines for contributing to the project.
*   **License:**  Clearly states the license under which the project is released.
*   **Disclaimer:**  Important for ethical and legal reasons.  Emphasizes responsible use.
*   **Markdown Formatting:** Uses headings, bullet points, code blocks, and bold text to make the README well-organized and easy to read.
*    **Removed reference to non-existant file.** The changelog was removed because the readme should just be for the current state of the code.

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

