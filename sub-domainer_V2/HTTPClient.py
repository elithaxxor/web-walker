import socket
import ssl
from typing import Tuple, Optional
from urllib.parse import urlparse

class HTTPClient:
    """Handles HTTP/HTTPS requests and optionally retrieves SSL certificates."""
    def __init__(self, timeout: int = 10):
        """Initialize the HTTP client with a timeout for network operations."""
        self.timeout = timeout

    def request(self, url: str, show_cert: bool = False) -> Tuple[int, str, Optional[bytes]]:
        """Fetches a webpage and its SSL certificate if requested.
        
        Args:
            url (str): The URL to fetch (e.g., 'https://example.com').
            show_cert (bool): Whether to retrieve the SSL certificate (default: False).
        
        Returns:
            Tuple[int, str, Optional[bytes]]: HTTP status code, page content, and certificate (if requested).
        """
        # Parse the URL and set defaults
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
        hostname = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        is_https = parsed.scheme == 'https'

        # Create socket and set timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        cert_der = None

        # Handle HTTPS connections
        if is_https:
            context = ssl.create_default_context()
            if show_cert:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(sock, server_hostname=hostname)
            conn.connect((hostname, port))
            if show_cert:
                cert_der = conn.getpeercert(binary_form=True)
        else:
            conn = sock
            conn.connect((hostname, port))

        # Send HTTP GET request
        request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
        conn.sendall(request.encode('utf-8'))

        # Receive response
        response = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        # Parse response into headers and body
        headers, body = response.split(b'\r\n\r\n', 1)
        status_code = int(headers.decode('utf-8', errors='replace').split(' ')[1])
        content = body.decode('utf-8', errors='replace')

        return status_code, content, cert_der
