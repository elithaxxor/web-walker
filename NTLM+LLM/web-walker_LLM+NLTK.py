#!/usr/bin/env python3
"""
WebWalker - A Simple Web Analysis Tool

This script fetches a webpage and performs analysis, with optional SSL certificate display
and LLM-based text analysis (sentiment or NER).

Usage:
    python webwalker.py [URL] [--show-cert] [--enable-llm <model>]
    Available models: sentiment, ner

If no arguments are provided, an interactive menu will be presented.
"""

import socket
import ssl
import logging
import argparse
import sys
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict, Any

# --- Conditional LLM Import ---
try:
    from transformers import pipeline
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

# --- Configure Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("WebWalker")

# --- HTTP Client Class ---
class HTTPClient:
    """Handles HTTP/HTTPS requests."""
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def request(self, url: str, show_cert: bool = False) -> Tuple[int, str, Optional[Dict[str, Any]]]:
        """Fetches a webpage and optionally retrieves certificate info."""
        try:
            parsed_url = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
            hostname = parsed_url.netloc
            path = parsed_url.path or '/'
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            is_https = parsed_url.scheme == 'https'

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
                    cert = conn.getpeercert(binary_form=True)
                    cert_info = {"raw": cert.hex()}  # Simplified for example
            else:
                conn = sock
                conn.connect((hostname, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            conn.sendall(request.encode('utf-8'))

            response = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            headers, body = response.split(b'\r\n\r\n', 1)
            status_line = headers.decode('utf-8').split('\r\n')[0]
            status_code = int(status_line.split(' ')[1])
            content = body.decode('utf-8', errors='replace')

            return status_code, content, cert_info

        except Exception as e:
            logger.error(f"Request failed: {e}")
            return 0, "", None

# --- LLM Analyzer Class ---
class LLMAnalyzer:
    """Handles LLM-based text analysis."""
    def __init__(self, model_name: str):
        if not LLM_AVAILABLE:
            raise ImportError("Transformers library not installed.")
        if model_name == "sentiment":
            self.pipeline = pipeline("sentiment-analysis")
        elif model_name == "ner":
            self.pipeline = pipeline("ner")
        else:
            raise ValueError(f"Unsupported model: {model_name}")

    def analyze(self, text: str) -> Any:
        """Analyzes text using the selected LLM pipeline."""
        if text:
            return self.pipeline(text)
        return None

# --- Core Analysis Function ---
def analyze_url(url: str, show_cert: bool = False, enable_llm: Optional[str] = None):
    """Fetches and analyzes the given URL with optional features."""
    client = HTTPClient()
    status, content, cert_info = client.request(url, show_cert)

    if status == 0:
        logger.error("Failed to fetch the page.")
        return

    logger.info(f"HTTP Status: {status}")
    logger.info(f"Content snippet: {content[:100]}...")

    if show_cert and cert_info:
        logger.info("Certificate Info:")
        logger.info(f"  Raw Certificate (hex): {cert_info['raw'][:50]}...")

    if enable_llm:
        if LLM_AVAILABLE:
            try:
                analyzer = LLMAnalyzer(enable_llm)
                result = analyzer.analyze(content)
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
        # No arguments, enter interactive mode
        interactive_mode()
    else:
        # Arguments provided, parse and execute
        parser = argparse.ArgumentParser(
            description="WebWalker - A Simple Web Analysis Tool",
            epilog="If no arguments are provided, an interactive menu will be presented."
        )
        parser.add_argument("url", help="The URL to fetch and analyze")
        parser.add_argument(
            "--show-cert",
            action="store_true",
            help="Display SSL certificate information (HTTPS only)"
        )
        parser.add_argument(
            "--enable-llm",
            choices=["sentiment", "ner"],
            help="Enable LLM analysis with the specified model (requires transformers)"
        )
        args = parser.parse_args()
        analyze_url(args.url, args.show_cert, args.enable_llm)

if __name__ == "__main__":
    main()
