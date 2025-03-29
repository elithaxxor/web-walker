import requests
import socket
import ssl
from html.parser import HTMLParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import re
import logging
import datetime
import argparse

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Constants ---
CONNECTION_TIMEOUT = 5
MAX_REDIRECTS = 5

class HTTPError(Exception):
    """Custom exception for HTTP errors."""
    pass

class ConnectionError(Exception):
    """Custom exception for connection errors."""
    pass

class MyHTMLParser(HTMLParser):
    """
    Custom HTML parser to extract links, scripts, hidden elements, and suspicious patterns.
    """
    def __init__(self):
        """
        Initializes the MyHTMLParser with empty lists to store extracted data.
        """
        super().__init__()
        self.links = []  # List to store extracted links (href attributes).
        self.scripts = []  # List to store extracted script tags (both inline and external).
        self.hidden_elements = []  # List to store elements hidden by CSS or HTML attributes.
        self.suspicious_patterns = []  # List to store potentially suspicious code patterns.

    def handle_starttag(self, tag, attrs):
        """
        Handles the start of an HTML tag.

        Args:
            tag (str): The name of the tag (e.g., 'a', 'div', 'script').
            attrs (list): A list of (attribute, value) tuples for the tag.
        """
        try:
            if tag == 'a':
                self._handle_a_tag(attrs)
            elif tag == 'script':
                self._handle_script_tag(attrs)
            elif tag in ('div', 'input', 'iframe', 'img', 'form', 'span', 'p', 'a'):
                self._check_hidden_elements(tag, attrs)

            self._check_suspicious_patterns(tag, attrs)
        except Exception as e:
            logger.error(f"Error in handle_starttag: {e}")

    def _handle_a_tag(self, attrs):
        """Extracts href attributes from <a> tags."""
        for attr, value in attrs:
            if attr == 'href':
                self.links.append(value)

    def _handle_script_tag(self, attrs):
        """Extracts script tags, distinguishing between external and inline scripts."""
        src = next((value for attr, value in attrs if attr == 'src'), None)
        if src:
            self.scripts.append({"type": "external", "src": src, "content": None})
        else:
            self.scripts.append({"type": "inline", "src": None, "content": ""})

    def _check_hidden_elements(self, tag, attrs):
        """Checks for hidden elements using various techniques."""
        style = next((value.lower() for attr, value in attrs if attr == 'style'), None)
        hidden_attr = any(attr == 'hidden' or (attr == 'type' and value.lower() == 'hidden') for attr, value in attrs)

        if hidden_attr:
            self.hidden_elements.append({"tag": tag, "attrs": attrs, "reason": "hidden attribute"})
        elif style:
            if "display: none" in style or "visibility: hidden" in style or "opacity: 0" in style:
                self.hidden_elements.append({"tag": tag, "attrs": attrs, "reason": "CSS style"})
            elif re.search(r'(position:\s*absolute|fixed);\s*(top|left):\s*(-?\d+)px', style):
                match = re.search(r'(position:\s*absolute|fixed);\s*(top|left):\s*(-?\d+)px', style)
                if match:
                    offset = int(match.group(3))
                    if abs(offset) > 1000:
                        self.hidden_elements.append({"tag": tag, "attrs": attrs, "reason": f"Offscreen positioning ({offset}px)"})

    def _check_suspicious_patterns(self, tag, attrs):
        """Checks for suspicious patterns in tag attributes."""
        event_attrs = ('onload', 'onerror', 'onmouseover', 'onclick', 'onmousedown', 'onmouseup', 'onmousemove', 'onkeypress', 'onkeydown', 'onkeyup')
        for attr, value in attrs:
            if attr in event_attrs:
                self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "Inline event handler"})
            elif attr == 'href' and value.startswith('javascript:'):
                self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "javascript: URI"})
            elif attr == 'src' and tag == 'iframe' and value.startswith('data:'):
                self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "data: URI in iframe"})

    def handle_startendtag(self, tag, attrs):
        """Handles self-closing tags."""
        try:
            if tag == 'script':
                self._handle_script_tag(attrs)
            self.handle_starttag(tag, attrs)
        except Exception as e:
            logger.error(f"Error in handle_startendtag: {e}")

    def handle_entityref(self, name):
        """Handles HTML entity references."""
        try:
            char = {'lt': '<', 'gt': '>', 'amp': '&', 'quot': '"', 'apos': "'"}.get(name, f'&{name};')
            if self.scripts and self.scripts[-1]['type'] == 'inline' and 'content' in self.scripts[-1]:
                self.scripts[-1]['content'] += char
        except Exception as e:
            logger.error(f"Error in handle_entityref: {e}")

    def handle_charref(self, name):
        """Handles HTML character references."""
        try:
            char = chr(int(name[1:], 16)) if name.startswith('x') else chr(int(name))
        except ValueError:
            char = f'&#{name};'
        if self.scripts and self.scripts[-1]['type'] == 'inline' and 'content' in self.scripts[-1]:
            self.scripts[-1]['content'] += char

    def close(self):
        """Called when the parser is finished."""
        try:
            super().close()
        except Exception as e:
            logger.error(f"Error in close: {e}")

class WebPageFetcher:
    """Handles fetching and processing web pages."""

    def __init__(self):
        self.cookies = {}

    def fetch_page(self, url, show_cert=False, detect_db=False, detect_hidden=False, redirect_count=0):
        """Fetches a web page and handles redirects."""
        if redirect_count >= MAX_REDIRECTS:
            logger.error(f"Maximum redirects ({MAX_REDIRECTS}) exceeded.")
            raise HTTPError("Too many redirects")

        is_https, hostname, path = self._parse_url(url)
        port = 443 if is_https else 80

        try:
            with socket.create_connection((hostname, port), timeout=CONNECTION_TIMEOUT) as sock:
                if is_https:
                    context = ssl.create_default_context()
                    if show_cert:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=hostname) as conn:
                        if show_cert:
                            self._print_certificate_info(conn.getpeercert(binary_form=True))
                        response = self._send_request(conn, hostname, path)
                else:
                    response = self._send_request(sock, hostname, path)

                status_code, response_headers, content_type, body = self._process_response(response)

                if 300 <= status_code < 400:
                    location = response_headers.get("location")
                    if location:
                        logger.info(f"Redirecting to: {location}")
                        return self.fetch_page(location, show_cert, detect_db, detect_hidden, redirect_count + 1)
                    else:
                        raise HTTPError("Redirect without location header")
                elif status_code >= 400:
                    raise HTTPError(f"Server responded with error: {status_code}")

                return status_code, response_headers, content_type, body, hostname, path, is_https

        except socket.timeout:
            raise ConnectionError("Connection timed out.")
        except ssl.SSLError as e:
            raise ConnectionError(f"SSL Error: {e}")
        except Exception as e:
            raise ConnectionError(f"Error fetching page: {e}")

    def _parse_url(self, url):
        """Parses the URL to determine protocol, hostname, and path."""
        if url.startswith("http://"):
            is_https = False
            hostname = url[7:].split("/")[0]
            path = "/" + url[7:].split("/", 1)[1] if "/" in url[7:] else "/"
        elif url.startswith("https://"):
            is_https = True
            hostname = url[8:].split("/")[0]
            path = "/" + url[8:].split("/", 1)[1] if "/" in url[8:] else "/"
        else:
            is_https = True
            hostname = url.split("/")[0]
            path = "/" + url.split("/", 1)[1] if "/" in url else "/"
        return is_https, hostname, path

    def _send_request(self, conn, hostname, path):
        """Sends the HTTP request and returns the raw response."""
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {hostname}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent: WebWalker/1.0",
        ]
        if self.cookies:
            cookie_string = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
            headers.append(f"Cookie: {cookie_string}")
        headers.extend(["", ""])
        request = "\r\n".join(headers).encode()
        conn.sendall(request)

        response = b""
        while True:
            chunk = conn.recv(512)
            if not chunk:
                break
            response += chunk
        return response

    def _process_response(self, response):
        """Processes the raw HTTP response."""
        try:
            response_str = response.decode(errors='ignore')
            header_part, body = response_str.split("\r\n\r\n", 1) if "\r\n\r\n" in response_str else (response_str, "")
            headers = {}
            status_line, *header_lines = header_part.split("\r\n")
            status_code = int(status_line.split()[1])
            logger.info(f"Server responded with status code: {status_code}")

            for line in header_lines:
                if ":" in line:
                    header_name, header_value = line.split(":", 1)
                    headers[header_name.strip().lower()] = header_value.strip()
                if line.lower().startswith("set-cookie:"):
                    self._parse_and_store_cookie(line.split(":", 1)[1].strip())

            content_type = headers.get("content-type", "").lower()
            return status_code, headers, content_type, body
        except (IndexError, ValueError) as e:
            raise HTTPError(f"Invalid HTTP response format: {e}")

    def _parse_and_store_cookie(self, cookie_data):
        """Parses and stores a cookie from a Set-Cookie header."""
        try:
            cookie_parts = cookie_data.split(";")
            for part in cookie_parts:
                if "=" in part:
                    name, value = part.split("=", 1)
                    self.cookies[name.strip()] = value.strip()
                    logger.debug(f"Stored cookie: {name.strip()}={value.strip()}")
        except Exception as e:
            logger.error(f"Error parsing and storing cookie: {e}")
            logger.error(f"Cookie data: {cookie_data}")
            logger.error("Make sure the cookie data is in the correct format (name=value; ...)")

    def _print_certificate_info(self, cert_der):
        """Prints detailed information about an SSL certificate."""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            logger.info(f"--- Certificate Information ---")
            logger.info(f"   Subject: {cert.subject}")
            logger.info(f"   Issuer: {cert.issuer}")
            logger.info(f"   Serial Number: {cert.serial_number}")
            logger.info(f"    Valid From: {cert.not_valid_before.isoformat()} UTC")
            logger.info(f"     Valid To: {cert.not_valid_after.isoformat()} UTC")
            logger.info(f"   Version: {cert.version}")
            logger.info(f"   Public Key Algorithm: {cert.public_key().public_numbers().__class__.__name__}")
            logger.info(f"   Key Size: {cert.public_key().key_size} bits")
            logger.info(f"   SHA-256 Fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")

            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                logger.info(f"    Subject Alternative Names: {', '.join(san.value.get_values_for_type(x509.DNSName))}")
            except x509.ExtensionNotFound:
                logger.info("   Subject Alternative Name: Not Present")

            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before:
                logger.info(" [!] Certificate is not yet valid!")
            elif now > cert.not_valid_after:
                logger.info("   [!] Certificate has expired!")
            else:
                logger.info("   [+] Certificate is currently valid.")

        except Exception as e:
            logger.error(f"[!] Error parsing certificate: {e}")

    def _detect_and_report_database(self, headers, html):
        """Attempts to detect database-related information."""
        try:
            if "x-powered-by" in headers:
                logger.info(f"Detected database: {headers['x-powered-by']}")
            if "sql" in html.lower():
                logger.info("Possible SQL database detected in HTML content")
        except Exception as e:
            logger.error(f"Error detecting database: {e}")

    def _resolve_url(self, hostname, path, link, is_https):
        """Resolves a relative URL to an absolute URL."""
        try:
            if link.startswith("http://") or link.startswith("https://"):
                return link
            elif link.startswith("/"):
                return f"https://{hostname}{link}" if is_https else f"http://{hostname}{link}"
            else:
                return f"https://{hostname}{path}/{link}" if is_https else f"http://{hostname}{path}/{link}"
        except Exception as e:
            logger.error(f"Error resolving URL: {e}")
            return None

    def _fetch_external_resource(self, url, detect_db=False, detect_hidden=False):
        """Fetches the content of an external resource."""
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Error fetching external resource: {e}")
            return None

    def get_cert(self, hostname, port=443):
        """Fetches the SSL certificate from a server."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)  # Get the cert in DER format
                    return der_cert
        except Exception as e:
            logger.error(f"Error fetching certificate: {e}")
            return None

class WebPageAnalyzer:
    """Analyzes the fetched web page content."""

    def __init__(self, fetcher: WebPageFetcher):
        self.fetcher = fetcher

    def analyze_page(self, status_code, response_headers, content_type, body, hostname, path, is_https, detect_db=False, detect_hidden=False):
        """Analyzes the fetched web page content."""
        if "text/html" in content_type:
            self._analyze_html(body, hostname, path, is_https, detect_db, detect_hidden, response_headers)
        elif "text/plain" in content_type:
            logger.info("Plain text content. Displaying raw text:")
            logger.info(body)
        elif "image" in content_type:
            logger.info("Image content detected. Cannot display.")
        elif "javascript" in content_type or "typescript" in content_type:
            logger.info("JavaScript/TypeScript Code (Direct Response):")
            logger.info(body)
        else:
            logger.info(f"Unsupported content type: {content_type}")

    def _analyze_html(self, html_content, hostname, path, is_https, detect_db, detect_hidden, response_headers):
        """Analyzes HTML content for links, scripts, hidden elements, and suspicious patterns."""
        parser = MyHTMLParser()
        try:
            parser.feed(html_content)
            if detect_db:
                self.fetcher._detect_and_report_database(response_headers, html_content)
            for script in parser.scripts:
                if script["type"] == "inline" and script["content"]:
                    parser.handle_data(script["content"])
            for link in parser.links:
                logger.info(f"Link found: {link}")
                resolved_link = self.fetcher._resolve_url(hostname, path, link, is_https)
                logger.info(f"Resolved Link: {resolved_link}")
            if detect_hidden:
                self._report_hidden_elements(parser.hidden_elements)
                self._report_suspicious_patterns(parser.suspicious_patterns)
            self._fetch_and_display_external_scripts(parser.scripts, hostname, path, is_https, detect_db, detect_hidden)
            self._display_inline_scripts(parser.scripts)
        except Exception as e:
            logger.error(f"Error analyzing HTML: {e}")
        finally:
            parser.close()

    def _report_hidden_elements(self, hidden_elements):
        """Reports hidden elements."""
        if hidden_elements:
            logger.info("Hidden Elements Detected:")
            for element in hidden_elements:
                logger.info(f"Tag: {element['tag']}, Reason: {element['reason']}")

    def _report_suspicious_patterns(self, suspicious_patterns):
        """Reports suspicious patterns."""
        if suspicious_patterns:
            logger.info("Suspicious Patterns Detected:")
            for pattern in suspicious_patterns:
                logger.info(f"Tag: {pattern['tag']}, Attribute: {pattern['attr']}, Value: {pattern['value']}, Reason: {pattern['reason']}")

    def _fetch_and_display_external_scripts(self, scripts, hostname, path, is_https, detect_db, detect_hidden):
        """Fetches and displays external scripts."""
        for script in scripts:
            if script["type"] == "external":
                script_url = self.fetcher._resolve_url(hostname, path, script["src"], is_https)
                logger.info(f"Fetching External Script: {script_url}")
                try:
                    script_content = self.fetcher._fetch_external_resource(script_url, detect_db, detect_hidden)
                    if script_content:
                        script["content"] = script_content
                        logger.info(script_content)
                    else:
                        logger.error(f"Could not retrieve external script: {script_url}")
                except Exception as e:
                    logger.error(f"Error fetching external script {script_url}: {e}")

    def _display_inline_scripts(self, scripts):
        """Displays inline scripts."""
        logger.info("JavaScript/TypeScript Code:")
        for script in scripts:
            if script["type"] == "inline" and script["content"] is not None:
                logger.info("Inline Script:")
                logger.info(script["content"])

def main():
    """Main function to run the web browser."""
    parser = argparse.ArgumentParser(description="WebWalker: A Security-Focused Web Browser")
    parser.add_argument("--url", help="The URL to browse")
    parser.add_argument("--show-cert", action="store_true", help="Display detailed certificate information")
    parser.add_argument("--detect-hidden", action="store_true", help="Enable hidden element and suspicious pattern detection")
    parser.add_argument("--detect-db", action="store_true", help="Attempt to detect database-related information")
    args = parser.parse_args()

    fetcher = WebPageFetcher()
    analyzer = WebPageAnalyzer(fetcher)

    try:
        url = args.url if args.url else input("Enter website address: ")
        status_code, response_headers, content_type, body, hostname, path, is_https = fetcher.fetch_page(url, args.show_cert, args.detect_db, args.detect_hidden)
        analyzer.analyze_page(status_code, response_headers, content_type, body, hostname, path, is_https, args.detect_db, args.detect_hidden)
    except ConnectionError as e:
        logger.error(f"Connection Error: {e}")
    except HTTPError as e:
        logger.error(f"HTTP Error: {e}")
    except KeyboardInterrupt:
        logger.info("Program interrupted by user.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

    if args.show_cert and args.url:
        der_cert = fetcher.get_cert(hostname)
        if der_cert:
            fetcher._print_certificate_info(der_cert)

if __name__ == "__main__":
    main()