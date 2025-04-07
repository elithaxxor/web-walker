#!/usr/bin/env python3
"""
WebWalker - A Security-Focused Web Browser

This script implements a command-line web browser with enhanced security analysis
features, including certificate inspection, hidden element detection, suspicious
pattern detection, and optional integration with Large Language Models (LLMs)
for advanced text analysis (sentiment analysis and named entity recognition).

Dependencies:
- Required: cryptography
- Optional: transformers (for LLM features)

Usage:
    python webwalker.py <URL> [--show-cert] [--enable-llm]
"""

import socket
import ssl
import logging
import argparse
import datetime
import re
from html.parser import HTMLParser
from urllib.parse import urlparse, ParseResult
from typing import List, Dict, Tuple, Optional, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# --- Conditional LLM Imports ---
try:
    from transformers import pipeline
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logging.warning("Transformers not found. LLM features will be disabled.")

# --- Configure Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("webwalker.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WebWalker")

# --- Security HTML Parser ---
class SecurityHTMLParser(HTMLParser):
    """
    Parses HTML content to detect security issues and collect text for analysis.
    """
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[Dict[str, str]] = []
        self.hidden_elements: List[Dict[str, Any]] = []
        self.suspicious_patterns: List[Dict[str, Any]] = []
        self.current_script: Optional[Dict[str, str]] = None
        self.text: str = ""  # Collect non-script text for LLM analysis

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        """Processes opening HTML tags for security analysis."""
        try:
            attrs_dict = dict(attrs)
            # Extract links
            if tag == 'a' and 'href' in attrs_dict:
                self.links.append(attrs_dict['href'])
            # Process scripts
            if tag == 'script':
                script_info = {"type": "inline", "content": ""}
                if 'src' in attrs_dict:
                    script_info["type"] = "external"
                    script_info["src"] = attrs_dict['src']
                self.scripts.append(script_info)
                self.current_script = script_info
            # Detect hidden elements
            if self._is_hidden_element(tag, attrs_dict):
                self.hidden_elements.append({
                    'tag': tag,
                    'attrs': attrs_dict,
                    'reason': self._get_hidden_reason(tag, attrs_dict)
                })
            # Detect suspicious patterns
            self._check_suspicious_patterns(tag, attrs_dict)
        except Exception as e:
            logger.error(f"Error in handle_starttag: {str(e)}", exc_info=True)

    def handle_endtag(self, tag: str) -> None:
        """Resets current script tracking on script tag closure."""
        if tag == 'script':
            self.current_script = None

    def handle_data(self, data: str) -> None:
        """Collects text content, separating script content from body text."""
        try:
            if self.current_script and self.current_script["type"] == "inline":
                self.current_script["content"] += data
            else:
                self.text += data
        except Exception as e:
            logger.error(f"Error in handle_data: {str(e)}", exc_info=True)

    def _is_hidden_element(self, tag: str, attrs: Dict[str, str]) -> bool:
        """Checks if an element is hidden based on attributes or styles."""
        if 'style' in attrs:
            style = attrs['style'].lower()
            if any(prop in style for prop in ['display: none', 'visibility: hidden', 'opacity: 0']):
                return True
            for pos in ['top', 'left', 'right', 'bottom']:
                match = re.search(rf'{pos}:\s*(-?\d+)(px|em|rem|%)', style)
                if match and int(match.group(1)) < -500:
                    return True
        return 'hidden' in attrs or (tag == 'input' and attrs.get('type', '').lower() == 'hidden')

    def _get_hidden_reason(self, tag: str, attrs: Dict[str, str]) -> str:
        """Identifies why an element is hidden."""
        if 'style' in attrs:
            style = attrs['style'].lower()
            if 'display: none' in style: return 'display: none'
            if 'visibility: hidden' in style: return 'visibility: hidden'
            if 'opacity: 0' in style: return 'opacity: 0'
            for pos in ['top', 'left', 'right', 'bottom']:
                match = re.search(rf'{pos}:\s*(-?\d+)(px|em|rem|%)', style)
                if match and int(match.group(1)) < -500:
                    return f'offscreen ({pos}: {match.group(1)}{match.group(2)})'
        if 'hidden' in attrs: return 'hidden attribute'
        if tag == 'input' and attrs.get('type', '').lower() == 'hidden': return 'input type=hidden'
        return 'unknown'

    def _check_suspicious_patterns(self, tag: str, attrs: Dict[str, str]) -> None:
        """Detects potentially malicious patterns in HTML."""
        for attr, value in attrs.items():
            if attr.startswith('on') and value:
                self.suspicious_patterns.append({
                    'tag': tag, 'attr': attr, 'value': value, 'reason': 'Inline event handler'
                })
        if tag == 'a' and 'href' in attrs and attrs['href'].lower().startswith('javascript:'):
            self.suspicious_patterns.append({
                'tag': tag, 'attr': 'href', 'value': attrs['href'], 'reason': 'JavaScript URI'
            })

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
            logger.error(f"Certificate analysis failed: {str(e)}")
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
        self.cookies: Dict[str, str] = {}

    def request(self, url: str, show_cert: bool = False) -> Tuple[int, Dict[str, str], str, Optional[Dict[str, Any]]]:
        """Fetches web content and optionally certificate info."""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
            hostname, path = parsed.netloc, parsed.path or "/"
            if parsed.query: path += f"?{parsed.query}"
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            is_https = parsed.scheme == 'https'

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            cert_info = None

            headers = {
                "Host": hostname,
                "User-Agent": "WebWalker/1.0",
                "Accept": "*/*",
                "Connection": "close"
            }
            if self.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

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

            request = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
            conn.sendall(request.encode('utf-8'))

            response = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk: break
                response += chunk
            sock.close()

            headers_data, body = response.split(b'\r\n\r\n', 1) if b'\r\n\r\n' in response else (response, b'')
            headers_lines = headers_data.decode('utf-8', errors='ignore').split('\r\n')
            status_code = int(headers_lines[0].split(' ')[1]) if len(headers_lines[0].split(' ')) > 1 else 0

            resp_headers = {}
            for line in headers_lines[1:]:
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    resp_headers[k.lower()] = v

            charset = re.search(r'charset=([^\s;]+)', resp_headers.get('content-type', '')) or 'utf-8'
            content = body.decode(charset.group(1) if isinstance(charset, re.Match) else charset, errors='replace')

            return status_code, resp_headers, content, cert_info
        except Exception as e:
            logger.error(f"Request failed: {str(e)}")
            return 0, {}, "", None

# --- LLM Analyzer ---
class LLMAnalyzer:
    """Performs advanced text analysis using LLMs."""
    def __init__(self):
        if not LLM_AVAILABLE:
            raise ImportError("LLM features unavailable")
        self.sentiment_analyzer = pipeline("sentiment-analysis")
        self.ner_pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english")

    def analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """Returns sentiment analysis of the text."""
        return self.sentiment_analyzer(text)[0] if text else {'label': 'N/A', 'score': 0.0}

    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extracts named entities from the text."""
        return self.ner_pipeline(text) if text else []

# --- Main Execution Logic ---
def main():
    """Main entry point for WebWalker."""
    parser = argparse.ArgumentParser(description="WebWalker - Security-Focused Web Browser")
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("--show-cert", action="store_true", help="Show certificate details")
    parser.add_argument("--enable-llm", action="store_true", help="Enable LLM analysis if available")
    args = parser.parse_args()

    # Initialize HTTP client and fetch page
    client = HTTPClient()
    status, headers, content, cert_info = client.request(args.url, args.show_cert)

    if status == 0:
        logger.error("Failed to fetch page")
        return

    # Log basic response info
    logger.info(f"HTTP Status: {status}")
    logger.info("Response Headers:")
    for k, v in headers.items():
        logger.info(f"  {k}: {v}")

    # Display certificate if requested
    if args.show_cert and cert_info:
        CertificateAnalyzer.print_certificate_info(cert_info)

    # Analyze HTML content if applicable
    if 'content-type' in headers and 'text/html' in headers['content-type'].lower():
        parser = SecurityHTMLParser()
        try:
            parser.feed(content)
            logger.info(f"Links found: {len(parser.links)}")
            inline_scripts = sum(1 for s in parser.scripts if s['type'] == 'inline')
            external_scripts = len(parser.scripts) - inline_scripts
            logger.info(f"Scripts found: {len(parser.scripts)} ({inline_scripts} inline, {external_scripts} external)")

            if parser.hidden_elements:
                logger.warning(f"Hidden elements ({len(parser.hidden_elements)}):")
                for elem in parser.hidden_elements:
                    attrs = ', '.join(f"{k}={v}" for k, v in elem['attrs'].items())
                    logger.warning(f"  <{elem['tag']} {attrs}>, reason: {elem['reason']}")

            if parser.suspicious_patterns:
                logger.warning(f"Suspicious patterns ({len(parser.suspicious_patterns)}):")
                for pattern in parser.suspicious_patterns:
                    logger.warning(f"  {pattern['reason']}: <{pattern['tag']} {pattern['attr']}=\"{pattern['value']}\">")

            # Perform LLM analysis if enabled and available
            if args.enable_llm:
                if LLM_AVAILABLE:
                    try:
                        analyzer = LLMAnalyzer()
                        text = ' '.join(parser.text.split())  # Normalize whitespace
                        if text:
                            sentiment = analyzer.analyze_sentiment(text)
                            logger.info(f"Sentiment: {sentiment['label']} (score: {sentiment['score']:.2f})")
                            entities = analyzer.extract_entities(text)
                            if entities:
                                logger.info("Named Entities:")
                                for entity in entities:
                                    logger.info(f"  - {entity['word']} ({entity['entity']})")
                        else:
                            logger.info("No text content for LLM analysis")
                    except Exception as e:
                        logger.error(f"LLM analysis failed: {str(e)}")
                else:
                    logger.warning("LLM features requested but not available")
        except Exception as e:
            logger.error(f"HTML parsing failed: {str(e)}")
    else:
        logger.info("Content is not HTML; skipping analysis")

if __name__ == "__main__":
    main()
