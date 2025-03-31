#!/usr/bin/env python3
"""
WebWalker - A Security-Focused Web Browser

This script implements a command-line web browser with enhanced security analysis
features, including certificate inspection, hidden element detection, suspicious
pattern detection, and integration with NLTK and Large Language Models (LLMs)
for advanced text and code analysis.
"""

import socket
import ssl
import logging
import argparse
import datetime
import re
import json
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin, ParseResult
from typing import List, Dict, Tuple, Optional, Union, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# --- NLTK and LLM Imports (Conditional) ---
try:
    import nltk
    from nltk.tokenize import word_tokenize, sent_tokenize
    from nltk.tag import pos_tag
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification, AutoModelForTokenClassification
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logging.warning("NLTK or transformers not found. LLM features will be disabled.")

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


# --- Helper Functions ---

def summarize_text(text: str, max_length: int = 256) -> str:
    """Summarizes text to a maximum length, adding an ellipsis if truncated."""
    if len(text) > max_length:
        return text[:max_length - 3] + "..."
    return text

# --- Security HTML Parser ---

class SecurityHTMLParser(HTMLParser):
    """
    Extended HTML parser to detect hidden elements, suspicious patterns,
    extract links, and scripts.
    """
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[Dict[str, str]] = []
        self.hidden_elements: List[Dict[str, Any]] = []
        self.suspicious_patterns: List[Dict[str, Any]] = []
        self.current_script: Optional[Dict[str, str]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        """Processes opening HTML tags."""
        try:
            attrs_dict = dict(attrs)

            # Extract links
            if tag == 'a' and 'href' in attrs_dict:
                self.links.append(attrs_dict['href'])

            # Process script tags
            if tag == 'script':
                script_info = {"type": "inline", "content": "", "src": None}
                if 'src' in attrs_dict:
                    script_info["type"] = "external"
                    script_info["src"] = attrs_dict['src']
                self.scripts.append(script_info)
                self.current_script = script_info

            # Check for hidden elements
            if self._is_hidden_element(tag, attrs_dict):
                self.hidden_elements.append({
                    'tag': tag,
                    'attrs': attrs_dict,
                    'reason': self._get_hidden_reason(tag, attrs_dict)
                })

            # Check for suspicious patterns
            self._check_suspicious_patterns(tag, attrs_dict)

        except Exception as e:
            logger.error(f"Error in handle_starttag: {str(e)}", exc_info=True)

    def handle_endtag(self, tag: str) -> None:
        """Processes closing HTML tags."""
        try:
            if tag == 'script':
                self.current_script = None
        except Exception as e:
            logger.error(f"Error in handle_endtag: {str(e)}", exc_info=True)

    def handle_data(self, data: str) -> None:
        """Processes text content within tags."""
        try:
            if self.current_script and self.current_script["type"] == "inline":
                self.current_script["content"] += data
        except Exception as e:
            logger.error(f"Error in handle_data: {str(e)}", exc_info=True)

    def _is_hidden_element(self, tag: str, attrs: Dict[str, str]) -> bool:
        """Detects if an element is hidden."""
        if 'style' in attrs:
            style = attrs['style'].lower()
            if any(hidden_style in style for hidden_style in [
                'display: none', 'visibility: hidden', 'opacity: 0'
            ]):
                return True
            for pos_prop in ['top', 'left', 'right', 'bottom']:
                match = re.search(rf'{pos_prop}:\s*(-?\d+)(px|em|rem|%)', style)
                if match and int(match.group(1)) < -500:
                    return True
        if 'hidden' in attrs:
            return True
        if tag == 'input' and attrs.get('type', '').lower() == 'hidden':
            return True
        return False

    def _get_hidden_reason(self, tag: str, attrs: Dict[str, str]) -> str:
        """Determines the reason an element is hidden."""
        if 'style' in attrs:
            style = attrs['style'].lower()
            if 'display: none' in style: return 'CSS style (display: none)'
            if 'visibility: hidden' in style: return 'CSS style (visibility: hidden)'
            if 'opacity: 0' in style: return 'CSS style (opacity: 0)'
            for pos_prop in ['top', 'left', 'right', 'bottom']:
                match = re.search(rf'{pos_prop}:\s*(-?\d+)(px|em|rem|%)', style)
                if match and int(match.group(1)) < -500:
                    return f'Offscreen positioning ({pos_prop}: {match.group(1)}{match.group(2)})'
        if 'hidden' in attrs: return 'HTML hidden attribute'
        if tag == 'input' and attrs.get('type', '').lower() == 'hidden':
            return 'Input type hidden'
        return 'Unknown hiding method'

    def _check_suspicious_patterns(self, tag: str, attrs: Dict[str, str]) -> None:
        """Detects suspicious patterns in HTML elements."""
        for attr, value in attrs.items():
            if attr.startswith('on') and value:
                self.suspicious_patterns.append({
                    'tag': tag, 'attr': attr, 'value': value, 'reason': 'Inline event handler'
                })
        if tag == 'a' and 'href' in attrs and attrs['href'].lower().startswith('javascript:'):
            self.suspicious_patterns.append({
                'tag': tag, 'attr': 'href', 'value': attrs['href'], 'reason': 'JavaScript: URI'
            })
        if tag == 'iframe' and 'src' in attrs and attrs['src'].lower().startswith('data:'):
            self.suspicious_patterns.append({
                'tag': tag, 'attr': 'src', 'value': attrs['src'], 'reason': 'data: URI in iframe'
            })


# --- Certificate Analyzer ---

class CertificateAnalyzer:
    """Analyzes SSL/TLS certificates."""

    @staticmethod
    def analyze_certificate(cert_der: bytes) -> Optional[Dict[str, Any]]:
        """Analyzes a DER-encoded certificate."""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            now = datetime.datetime.utcnow()
            validity_status = "valid"
            if now < cert.not_valid_before: validity_status = "not_yet_valid"
            elif now > cert.not_valid_after: validity_status = "expired"
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []
            return {
                "subject": str(cert.subject), "issuer": str(cert.issuer),
                "serial_number": cert.serial_number,
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "version": str(cert.version),
                "public_key_algorithm": cert.public_key().__class__.__name__,
                "key_size": cert.public_key().key_size,
                "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
                "subject_alternative_names": sans, "validity_status": validity_status
            }
        except Exception as e:
            logger.error(f"Certificate analysis error: {str(e)}", exc_info=True)
            return None

    @staticmethod
    def print_certificate_info(cert_info: Dict[str, Any]) -> None:
        """Prints formatted certificate information."""
        if not cert_info:
            logger.warning("No certificate information to display")
            return
        logger.info("
--- Certificate Information ---")
        logger.info(f"   Subject: {cert_info['subject']}")
        logger.info(f"   Issuer: {cert_info['issuer']}")
        logger.info(f"   Serial Number: {cert_info['serial_number']}")
        logger.info(f"    Valid From: {cert_info['not_valid_before']} UTC")
        logger.info(f"     Valid To: {cert_info['not_valid_after']} UTC")
        logger.info(f"   Version: {cert_info['version']}")
        logger.info(f"   Public Key Algorithm: {cert_info['public_key_algorithm']}")
        logger.info(f"   Key Size: {cert_info['key_size']} bits")
        logger.info(f"   SHA-256 Fingerprint: {cert_info['fingerprint']}")
        if cert_info['subject_alternative_names']:
            logger.info(f"    Subject Alternative Names: {', '.join(cert_info['subject_alternative_names'])}")
        else:
            logger.info("   Subject Alternative Name: Not Present")
        if cert_info['validity_status'] == "not_yet_valid":
            logger.warning("   [!] Certificate is not yet valid!")
        elif cert_info['validity_status'] == "expired":
            logger.warning("   [!] Certificate has expired!")
        else:
            logger.info("   [+] Certificate is currently valid.")


# --- HTTP Client ---

class HTTPClient:
    """Handles HTTP and HTTPS connections and requests."""

    def __init__(self, timeout: int = 10):
        self.timeout: int = timeout
        self.cookies: Dict[str, str] = {}

    def request(self, url: str, show_cert: bool = False) -> Tuple[int, Dict[str, str], str, Optional[Dict[str, Any]]]:
        """Makes an HTTP/HTTPS request."""
        try:
            parsed_url: ParseResult = urlparse(url)
            if not parsed_url.scheme:
                parsed_url = urlparse(f"https://{url}")
            hostname: str = parsed_url.netloc
            path: str = parsed_url.path or "/"
            if parsed_url.query:
                path += f"?{parsed_url.query}"
            port: int = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            is_https: bool = parsed_url.scheme == 'https'

            headers: Dict[str, str] = {
                "Host": hostname, "User-Agent": "WebWalker/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "close"
            }
            if self.cookies:
                headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())

            sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            cert_info: Optional[Dict[str, Any]] = None

            try:
                if is_https:
                    context: ssl.SSLContext = ssl.create_default_context()
                    if show_cert:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    conn: ssl.SSLSocket = context.wrap_socket(sock, server_hostname=hostname)
                    conn.connect((hostname, port))
                    if show_cert:
                        cert_der: bytes = conn.getpeercert(binary_form=True)
                        if cert_der:
                            cert_info = CertificateAnalyzer.analyze_certificate(cert_der)
                else:
                    conn: socket.socket = sock
                    conn.connect((hostname, port))

                request_str: str = f"GET {path} HTTP/1.1\r
"
                for header, value in headers.items():
                    request_str += f"{header}: {value}\r
"
                request_str += "\r
"
                conn.sendall(request_str.encode('utf-8'))

                response: bytes = b""
                while True:
                    chunk: bytes = conn.recv(4096)
                    if not chunk: break
                    response += chunk
            finally:
                sock.close()

            if b'\r
\r
' in response:
                headers_data, body = response.split(b'\r
\r
', 1)
            else:
                headers_data, body = response, b''

            headers_lines: List[str] = headers_data.decode('utf-8', errors='ignore').split('\r
')
            status_line: str = headers_lines[0]
            status_parts: List[str] = status_line.split(' ', 2)
            status_code: int = int(status_parts[1]) if len(status_parts) >= 2 else 0

            headers: Dict[str,str] = {}
            for line in headers_lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value
                    if key.lower() == 'set-cookie':
                        self._parse_cookie(value)

            charset: str = 'utf-8'
            if 'content-type' in headers:
                content_type: str = headers['content-type'].lower()
                charset_match: Optional[re.Match] = re.search(r'charset=([^\s;]+)', content_type)
                if charset_match:
                    charset = charset_match.group(1)
            try:
                content: str = body.decode(charset, errors='replace')
            except (UnicodeDecodeError, LookupError):
                content = body.decode('utf-8', errors='replace')

            return status_code, headers, content, cert_info

        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
            logger.error(f"Connection error for {url}: {str(e)}")
            return 0, {}, "", None
        except Exception as e:
            logger.exception(f"Request error for {url}: {str(e)}")
            return 0, {}, "", None

    def _parse_cookie(self, cookie_header: str) -> None:
        """Parses and stores cookies."""
        try:
            cookie_parts: str = cookie_header.split(';')[0].strip()
            if '=' in cookie_parts:
                name, value = cookie_parts.split('=', 1)
                self.cookies[name] = value
        except Exception as e:
            logger.error(f"Error parsing cookie: {str(e)}")

# --- LLM Analyzer ---

class LLMAnalyzer:
    """Handles interactions with Large Language Models for content analysis."""

    def __init__(self):
        self.sentiment_analyzer = None
        self.zero_shot_classifier = None
        self.ner_pipeline = None
        self.text_classification_pipeline = None

        if LLM_AVAILABLE:
          try:
              # Sentiment analysis pipeline (example)
              self.sentiment_analyzer = pipeline("sentiment-analysis")

              # Zero-shot classification (for more flexible categorization)
              self.zero_shot_classifier = pipeline("zero-shot-classification")

              # Named Entity Recognition (NER)
              self.ner_model_name = "dbmdz/bert-large-cased-finetuned-conll03-english" #Example model
              self.ner_tokenizer = Auto
