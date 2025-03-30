import socket
import ssl
import logging
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from html.parser import HTMLParser
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MyHTMLParser(HTMLParser):
    """Parses HTML content to extract links, scripts, and hidden/suspicious elements."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.hidden_elements = []
        self.suspicious_patterns = []

    def handle_starttag(self, tag, attrs):
        """Handles opening tags."""
        try:
            attrs_dict = dict(attrs)

            if tag == 'a' and 'href' in attrs_dict:
                self.links.append(attrs_dict['href'])

            if tag == 'script':
                script_info = {"type": "inline", "content": None, "src": None}
                if 'src' in attrs_dict:
                    script_info["type"] = "external"
                    script_info["src"] = attrs_dict['src']
                self.scripts.append(script_info)

            # Hidden element detection
            if self._is_hidden(tag, attrs_dict):
                return  # No need to check for suspicious patterns if hidden

            # Suspicious pattern detection
            self._check_suspicious_patterns(tag, attrs_dict)

        except Exception as e:
            logging.exception(f"Error in handle_starttag: {e}")

    def handle_startendtag(self, tag, attrs):
        """Handles self-closing tags."""
        try:
            self.handle_starttag(tag, attrs)  # Treat self-closing tags like start tags
        except Exception as e:
            logging.exception(f"Error in handle_startendtag: {e}")

    def handle_data(self, data):
        """Handles text content within tags."""
        try:
            if self.scripts and self.scripts[-1]['type'] == 'inline':
                if self.scripts[-1]['content'] is None:
                    self.scripts[-1]['content'] = data
                else:
                    self.scripts[-1]['content'] += data
        except Exception as e:
            logging.exception(f"Error in handle_data: {e}")


    def _is_hidden(self, tag, attrs):
        """Checks if an element is hidden."""
        # CSS styles
        if 'style' in attrs:
            style = attrs['style'].lower()
            if 'display: none' in style or 'visibility: hidden' in style or 'opacity: 0' in style:
                self.hidden_elements.append({'tag': tag, 'attrs': attrs, 'reason': 'CSS style'})
                return True
            # Off-screen positioning (check for large negative values)
            match = re.search(r'(top|left):\s*(-?\d+)(px|em|%)', style)
            if match:
                value = int(match.group(2))
                if value < -500:  # Threshold, adjust as needed
                    self.hidden_elements.append({'tag': tag, 'attrs': attrs, 'reason': 'Offscreen positioning'})
                    return True
        # HTML hidden attribute
        if 'hidden' in attrs:
            self.hidden_elements.append({'tag': tag, 'attrs': attrs, 'reason': 'HTML hidden attribute'})
            return True
        # Input type hidden
        if tag == 'input' and 'type' in attrs and attrs['type'].lower() == 'hidden':
            self.hidden_elements.append({'tag': tag, 'attrs': attrs, 'reason': 'Input type hidden'})
            return True
        return False

    def _check_suspicious_patterns(self, tag, attrs):
        """Checks for suspicious patterns in element attributes."""
        # Inline event handlers
        for attr, value in attrs.items():
            if attr.startswith('on') and value:  # onclick, onload, etc.
                self.suspicious_patterns.append({
                    'tag': tag, 'attr': attr, 'value': value, 'reason': 'Inline event handler'
                })
            elif attr == 'href' and value.lower().startswith('javascript:'):
                self.suspicious_patterns.append({
                    'tag': tag, 'attr': attr, 'value': value, 'reason': 'JavaScript: URI'
                })
            elif tag == 'iframe' and attr == 'src' and value.lower().startswith('data:'):
                 self.suspicious_patterns.append({
                    'tag': tag, 'attr': attr, 'value': value, 'reason': 'data: URI in iframe'
                })

    def close(self):
        """Handles any final processing when parsing is complete."""
        super().close()  # Important: Call the superclass close() method
        # Additional cleanup or final checks can be added here if needed

class WebBrowser:
    """Fetches and analyzes web pages, including handling certificates, redirects, and content parsing."""

    def __init__(self):
        self.cookies = {}
        self.timeout = 5

    def fetch_page(self, url, show_cert=False, detect_hidden=False, detect_db=False):
        """Fetches a webpage, handles redirects, and parses the content."""
        try:
            is_https, hostname, path, port = self._parse_url(url)
            response_headers, html_response = self._make_request(is_https, hostname, path, port, show_cert)

            if detect_db:
                self._detect_and_report_database(response_headers, html_response)  # Call detect_db

            if 300 <= response_headers.get('status_code', 0) < 400:
                location = response_headers.get('location')
                if location:
                    new_url = self._resolve_url(hostname, path, location, is_https)
                    logging.info(f"Redirecting to: {new_url}")
                    return self.fetch_page(new_url, show_cert, detect_hidden, detect_db)  # Recursive call
                else:
                    logging.warning("Redirect status code received, but no Location header found.")
                    return None, None

            if response_headers.get('content-type') and "text/html" in response_headers['content-type'].lower():
                    parser = MyHTMLParser()
                    try:
                        parser.feed(html_response)
                    finally:
                        parser.close()  #ensure always closed


                    if detect_hidden:
                        self._report_hidden_and_suspicious(parser)

                    scripts = self._process_scripts(parser.scripts, hostname, path, is_https, detect_db, detect_hidden)
                    return response_headers, {"html": html_response, "scripts": scripts, "parser":parser} #return parser
            elif response_headers.get('content-type'):
                logging.info(f"Content type: {response_headers.get('content-type')}")
                return response_headers, {"content" : html_response.split("\r
\r
", 1)[1]} #Return the raw response.
            else:
                logging.warning("No content type header, returning the headers only")
                return response_headers, {}



        except Exception as e:
            logging.exception(f"Error fetching page: {e}")
            return {}, {}

    def _parse_url(self, url):
        """Parses a URL into its components (HTTPS status, hostname, path, port)."""
        try:
            if url.startswith("http://"):
                is_https = False
                hostname = url[7:].split("/")[0]
                path = "/" + url[7:].split("/", 1)[1] if "/" in url[7:] else "/"
            elif url.startswith("https://"):
                is_https = True
                hostname = url[8:].split("/")[0]
                path = "/" + url[8:].split("/", 1)[1] if "/" in url[8:] else "/"
            else:  # Default to HTTPS if no protocol specified
                is_https = True
                hostname = url.split("/")[0]
                path = "/" + url.split("/", 1)[1] if "/" in url else "/"

            port = 443 if is_https else 80
            return is_https, hostname, path, port
        except Exception as e:
            logging.exception(f"Error parsing URL: {e}")
            raise  # Re-raise the exception to be handled by the caller


    def _make_request(self, is_https, hostname, path, port, show_cert):
        """Makes an HTTP/HTTPS request and returns the response headers and content."""
        try:
            headers = {
                "Host": hostname,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": "MyCustomBrowser/1.0",
            }
            if self.cookies:
                cookie_string = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
                headers["Cookie"] = cookie_string

            conn = self._create_connection(is_https, hostname, port, show_cert)
            request = self._build_request(path, headers)
            conn.send(request)
            return self._get_response(conn)

        except Exception as e:
            logging.exception(f"Error during request: {e}")
            return {}, ""  # Return empty headers and content on error
        finally:
            if 'conn' in locals(): #check if the variable is defined
                conn.close()


    def _create_connection(self, is_https, hostname, port, show_cert):
        """Creates a socket connection (with or without SSL)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        if is_https:
            context = ssl.create_default_context()
            if show_cert:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(sock, server_hostname=hostname)
        else:
            conn = sock

        conn.connect((hostname, port))

        if is_https and show_cert:
            cert = conn.getpeercert(binary_form=True)
            self._print_certificate_info(cert)
        return conn

    def _build_request(self, path, headers):
        """Builds the HTTP request string."""
        request_lines = [f"GET {path} HTTP/1.1"]
        request_lines.extend(f"{name}: {value}" for name, value in headers.items())
        request_lines.extend(("", ""))  # Empty lines to terminate the headers
        return "\r
".join(request_lines).encode()

    def _get_response(self, conn):
        """Receives the HTTP response and parses headers."""
        response = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r
\r
" in response:  # Check for end of headers
                    break
            except socket.timeout:
                logging.warning("Response timed out")
                break

        headers_part, content_part = response.split(b"\r
\r
", 1)
        headers = self._parse_headers(headers_part.decode(errors='ignore'))

        try:
            status_line = headers_part.decode(errors='ignore').split("\r
")[0]
            status_code = int(status_line.split()[1])
            headers['status_code'] = status_code  # Store status code in headers
            logging.info(f"Server responded with status code: {status_code}")
        except (IndexError, ValueError) as e:
            logging.error(f"Invalid HTTP response format. {e}")
            return {}, ""

        # Decode the body *after* parsing headers and status code
        try:
            decoded_content_part = content_part.decode(errors='ignore')
        except UnicodeDecodeError as e:
            logging.error(f"Error decoding response content: {e}")
            decoded_content_part = ""  # Set content to empty string on decode error

        #Handle cookies
        for line in headers_part.decode(errors='ignore').split("\r
"):
            if line.lower().startswith("set-cookie:"):
                cookie_data = line.split(":", 1)[1].strip()
                self._parse_and_store_cookie(cookie_data)

        return headers, decoded_content_part


    def _parse_headers(self, headers_str):
        """Parses HTTP headers into a dictionary."""
        headers = {}
        for line in headers_str.split("\r
"):
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        return headers

    def _print_certificate_info(self, cert_der):
        """Prints detailed information about an SSL certificate."""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            logging.info("-- Certificate Information --")
            logging.info(f"   Subject: {cert.subject}")
            logging.info(f"   Issuer: {cert.issuer}")
            logging.info(f"   Serial Number: {cert.serial_number}")
            logging.info(f"    Valid From: {cert.not_valid_before.isoformat()} UTC")
            logging.info(f"     Valid To: {cert.not_valid_after.isoformat()} UTC")
            logging.info(f"   Version: {cert.version}")
            logging.info(f"   Public Key Algorithm: {cert.public_key().public_numbers().__class__.__name__}")  # Corrected line
            logging.info(f"   Key Size: {cert.public_key().key_size} bits")
            logging.info(f"   SHA-256 Fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")

            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                logging.info(f"    Subject Alternative Names: {', '.join(san.value.get_values_for_type(x509.DNSName)))}")
            except x509.ExtensionNotFound:
                logging.info("   Subject Alternative Name: Not Present")

            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before:
                logging.warning("Certificate is not yet valid!")
            elif now > cert.not_valid_after:
                logging.warning("Certificate has expired!")
            else:
                logging.info("Certificate is currently valid.")

        except Exception as e:
            logging.exception(f"Error parsing certificate: {e}")


    def _resolve_url(self, base_hostname, base_path, relative_url, is_https):
        """Resolves a relative URL to an absolute URL."""
        if relative_url.startswith("http://") or relative_url.startswith("https://"):
            return relative_url  # Already absolute
        if relative_url.startswith("//"):
            protocol = "https:" if is_https else "http:"
            return protocol + relative_url
        if relative_url.startswith("/"):
            protocol = "https://" if is_https else "http://"
            return f"{protocol}{base_hostname}{relative_url}"

        protocol = "https://" if is_https else "http://"
        base_url = f"{protocol}{base_hostname}{base_path}"
        if not base_url.endswith("/"):
             base_url = base_url.rsplit("/",1)[0] + "/"
        return f"{base_url}{relative_url}"

    def _fetch_external_resource(self, url, detect_db=False, detect_hidden=False):
        """Fetches an external resource (e.g., JavaScript file)."""
        try:
            logging.info(f"Fetching external resource: {url}")
            headers, content = self.fetch_page(url, show_cert=False, detect_hidden=detect_hidden, detect_db=detect_db) #call fetch page.
            if isinstance(content, dict) and 'content' in content:
                return content['content'] #extract the content
            else:
                return "" #return an empty string

        except Exception as e:
            logging.exception(f"Error fetching external resource: {e}")
            return ""

    def _report_hidden_and_suspicious(self, parser):
        """Reports detected hidden elements and suspicious patterns."""
        if parser.hidden_elements:
            logging.info("--- Hidden Elements Detected ---")
            for element in parser.hidden_elements:
                logging.info(f"  Tag: {element['tag']}, Reason: {element['reason']}")
                #logging.info(f"    Attributes
