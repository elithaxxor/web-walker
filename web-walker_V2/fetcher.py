import socket
import ssl
import logging
import asyncio
import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

CONNECTION_TIMEOUT = 5
MAX_REDIRECTS = 5

class HTTPError(Exception):
    pass

class ConnectionError(Exception):
    pass

class WebPageFetcher:
    def __init__(self):
        self.cookies = {}

    def fetch_page(self, url, show_cert=False, verify_ssl=True, redirect_count=0):
        """Fetch a webpage with SSL support and redirect handling."""
        if redirect_count >= MAX_REDIRECTS:
            logger.error(f"Maximum redirects ({MAX_REDIRECTS}) exceeded.")
            raise HTTPError("Too many redirects")

        is_https, hostname, path = self._parse_url(url)
        port = 443 if is_https else 80

        try:
            with socket.create_connection((hostname, port), timeout=CONNECTION_TIMEOUT) as sock:
                if is_https:
                    context = ssl.create_default_context()
                    if not verify_ssl:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        logger.warning("SSL verification disabled!")
                    with context.wrap_socket(sock, server_hostname=hostname) as conn:
                        if show_cert:
                            self._print_certificate_info(conn.getpeercert(binary_form=True))
                        response = self._send_request(conn, hostname, path)
                else:
                    response = self._send_request(sock, hostname, path)

                status_code, headers, content_type, body = self._process_response(response)

                if 300 <= status_code < 400:
                    location = headers.get("location")
                    if location:
                        logger.info(f"Redirecting to: {location}")
                        return self.fetch_page(location, show_cert, verify_ssl, redirect_count + 1)
                    raise HTTPError("Redirect without location header")
                elif status_code >= 400:
                    raise HTTPError(f"Server responded with error: {status_code}")

                return status_code, headers, content_type, body, hostname, path, is_https

        except socket.timeout:
            raise ConnectionError("Connection timed out.")
        except ssl.SSLError as e:
            raise ConnectionError(f"SSL Error: {e}")
        except Exception as e:
            raise ConnectionError(f"Error fetching page: {e}")

    def _parse_url(self, url):
        """Parse URL into components."""
        if url.startswith("http://"):
            return False, url[7:].split("/")[0], "/" + url[7:].split("/", 1)[1] if "/" in url[7:] else "/"
        elif url.startswith("https://"):
            return True, url[8:].split("/")[0], "/" + url[8:].split("/", 1)[1] if "/" in url[8:] else "/"
        else:
            return True, url.split("/")[0], "/" + url.split("/", 1)[1] if "/" in url else "/"

    def _send_request(self, conn, hostname, path):
        """Send an HTTP request."""
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {hostname}",
            "User-Agent: WebAnalyzer/1.0",
            "Accept: text/html",
            "", ""
        ]
        conn.sendall("\r\n".join(headers).encode())
        response = b""
        while True:
            chunk = conn.recv(512)
            if not chunk:
                break
            response += chunk
        return response

    def _process_response(self, response):
        """Process the HTTP response."""
        response_str = response.decode(errors="ignore")
        header_part, body = response_str.split("\r\n\r\n", 1) if "\r\n\r\n" in response_str else (response_str, "")
        headers = {}
        status_line, *header_lines = header_part.split("\r\n")
        status_code = int(status_line.split()[1])
        for line in header_lines:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        content_type = headers.get("content-type", "").lower()
        return status_code, headers, content_type, body

    def _print_certificate_info(self, cert_der):
        """Display SSL certificate details."""
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        logger.info(f"Certificate: Subject={cert.subject}, Issuer={cert.issuer}, Valid From={cert.not_valid_before}")

    async def fetch_external_resource(self, url, session, retries=3):
        """Asynchronously fetch an external resource."""
        for attempt in range(retries):
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    response.raise_for_status()
                    return await response.text()
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt == retries - 1:
                    raise ConnectionError(f"Failed to fetch {url} after {retries} attempts")

    def _resolve_url(self, hostname, path, link, is_https):
        """Resolve relative URLs to absolute."""
        if link.startswith("http"):
            return link
        base = f"https://{hostname}" if is_https else f"http://{hostname}"
        return f"{base}{link}" if link.startswith("/") else f"{base}{path}/{link}"

    def detect_database(self, headers, html):
        """Detect database signatures."""
        db_signatures = {
            "MySQL": ["mysql", "mysqli"],
            "PostgreSQL": ["postgres", "pgsql"],
            "SQLite": ["sqlite"]
        }
        for db, patterns in db_signatures.items():
            if any(p in html.lower() for p in patterns):
                logger.info(f"Possible {db} database detected in HTML")
        if "x-powered-by" in headers:
            logger.info(f"Server header suggests: {headers['x-powered-by']}")
