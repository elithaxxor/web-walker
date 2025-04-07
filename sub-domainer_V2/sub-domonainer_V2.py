#!/usr/bin/env python3
"""
WebWalker - A Security-Focused Web Analysis Tool

This script fetches a webpage, analyzes its content for security issues, inspects SSL certificates,
and optionally uses Hugging Face's Transformers for LLM-based text analysis (sentiment or NER).

Dependencies:
- Required: cryptography
- Optional: transformers (for LLM features)

Usage:
    python webwalker.py <URL> [--show-cert] [--enable-llm <model>]
    Available models: sentiment, ner

If no arguments are provided, an interactive menu will be presented.
"""

# --- Imports and Dependencies ---
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

try:
    from transformers import pipeline
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logging.warning("Transformers library not found. LLM features will be disabled.")

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("WebWalker")

# --- HTTP Client Class ---
class HTTPClient:
    """Handles HTTP/HTTPS requests and optionally retrieves SSL certificates."""
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def request(self, url: str, show_cert: bool = False) -> Tuple[int, str, Optional[Dict[str, Any]]]:
        """Fetches a webpage and its SSL certificate if requested."""
        try:
            # Parse URL, default to HTTPS if scheme is omitted
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
            hostname = parsed.netloc
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            is_https = parsed.scheme == 'https'

            # Set up socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            cert_info = None

            # Handle HTTPS connection
            if is_https:
                context = ssl.create_default_context()
                if show_cert:
                    # Disable hostname verification to get cert even if invalid
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                conn = context.wrap_socket(sock, server_hostname=hostname)
                conn.connect((hostname, port))
                if show_cert:
                    cert_der = conn.getpeercert(binary_form=True)
                    if cert_der:
                        cert_info = {"raw": cert_der}
            else:
                conn = sock
                conn.connect((hostname, port))

            # Send HTTP GET request
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: WebWalker/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            conn.sendall(request.encode('utf-8'))

            # Receive response
            response = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            # Parse response
            headers, body = response.split(b'\r\n\r\n', 1)
            status_code = int(headers.decode('utf-8', errors='replace').split(' ')[1])
            content = body.decode('utf-8', errors='replace')

            return status_code, content, cert_info
        except Exception as e:
            logger.error(f"Request to {url} failed: {e}")
            return 0, "", None

# --- Security HTML Parser Class ---
class SecurityHTMLParser(HTMLParser):
    """Parses HTML to extract text and detect suspicious patterns."""
    def __init__(self):
        super().__init__()
        self.text = ""  # Accumulated text content
        self.suspicious_patterns = []  # List of detected security issues

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        """Checks for suspicious HTML patterns in tags."""
        attrs_dict = dict(attrs)
        if tag == 'script' and 'src' not in attrs_dict:
            self.suspicious_patterns.append("Inline script detected")
        if tag == 'a' and 'href' in attrs_dict and attrs_dict['href'].lower().startswith('javascript:'):
            self.suspicious_patterns.append("JavaScript URI in link")

    def handle_data(self, data: str) -> None:
        """Collects text data from the HTML."""
        self.text += data.strip()

# --- Certificate Analyzer Class ---
class CertificateAnalyzer:
    """Analyzes and displays SSL certificate details."""
    @staticmethod
    def analyze_certificate(cert_der: bytes) -> Optional[Dict[str, Any]]:
        """Extracts details from a DER-encoded SSL certificate."""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            now = datetime.datetime.utcnow()
            validity = "valid" if cert.not_valid_before <= now <= cert.not_valid_after else "invalid"
            # Check for SAN extension
            san = []
            for ext in cert.extensions:
                if ext.oid == x509.oid.NameOID.SUBJECT_ALTERNATIVE_NAME:
                    san = ext.value.get_values_for_type(x509.DNSName)
                    break
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
        """Logs certificate details in a readable format."""
        logger.info("Certificate Info:")
        logger.info(f"  Subject: {cert_info['subject']}")
        logger.info(f"  Issuer: {cert_info['issuer']}")
        logger.info(f"  Validity: {cert_info['validity']}")
        logger.info(f"  Valid From: {cert_info['not_valid_before']}")
        logger.info(f"  Valid To: {cert_info['not_valid_after']}")
        logger.info(f"  SANs: {', '.join(cert_info['sans']) or 'None'}")
        logger.info(f"  SHA-256 Fingerprint: {cert_info['fingerprint']}")

# --- LLM Analyzer Class ---
class LLMAnalyzer:
    """Handles integration with Hugging Face's Transformers for text analysis."""
    def __init__(self, model_name: str):
        if not LLM_AVAILABLE:
            raise ImportError("Transformers library not installed. Install with 'pip install transformers'.")
        if model_name == "sentiment":
            self.pipeline = pipeline("sentiment-analysis")
        elif model_name == "ner":
            self.pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english")
        else:
            raise ValueError(f"Unsupported model: {model_name}")

    def analyze(self, text: str) -> Any:
        """Analyzes text using the specified LLM pipeline."""
        return self.pipeline(text) if text else None

# --- Core Analysis Function ---
def analyze_url(url: str, show_cert: bool = False, enable_llm: Optional[str] = None) -> None:
    """Fetches and analyzes a URL, including certificate and LLM analysis if requested."""
    client = HTTPClient()
    status, content, cert_info = client.request(url, show_cert)

    if status == 0:
        logger.error("Failed to fetch the page.")
        return

    logger.info(f"HTTP Status: {status}")
    logger.info(f"Content snippet: {content[:100]}...")

    # Analyze SSL certificate if requested
    if show_cert and cert_info:
        cert_details = CertificateAnalyzer.analyze_certificate(cert_info['raw'])
        if cert_details:
            CertificateAnalyzer.print_certificate_info(cert_details)

    # Parse HTML for security issues and text extraction
    parser = SecurityHTMLParser()
    parser.feed(content)
    text = ' '.join(parser.text.split())  # Normalize whitespace

    if parser.suspicious_patterns:
        logger.warning("Suspicious patterns found:")
        for pattern in parser.suspicious_patterns:
            logger.warning(f"  - {pattern}")

    # Perform LLM analysis if enabled
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

# --- Interactive Mode Function ---
def interactive_mode() -> None:
    """Provides a menu-driven interface for interacting with WebWalker."""
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
            print("Goodbye.")
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
def main() -> None:
    """Entry point of the script, handling both CLI and interactive modes."""
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        parser = argparse.ArgumentParser(
            description="WebWalker - A Security-Focused Web Analysis Tool",
            epilog="If no arguments are provided, an interactive menu will be presented."
        )
        parser.add_argument("url", help="The URL to analyze")
        parser.add_argument("--show-cert", action="store_true", help="Show SSL certificate details")
        parser.add_argument("--enable-llm", choices=["sentiment", "ner"], help="Enable LLM analysis")
        args = parser.parse_args()
        analyze_url(args.url, args.show_cert, args.enable_llm)

if __name__ == "__main__":
    main()
