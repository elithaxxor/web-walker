import socket
import ssl
import logging
from typing import Tuple, Optional
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class HTTPClient:
    """Handles HTTP/HTTPS requests and optionally retrieves SSL certificates."""
    def __init__(self, timeout: int = 10):
        """Initialize the HTTP client with a timeout for network operations."""
        self.timeout = timeout
        logging.info(f"HTTPClient initialized with timeout: {timeout}")

    def request(self, url: str, show_cert: bool = False) -> Tuple[int, str, Optional[bytes]]:
        """
        Fetches a webpage and its SSL certificate if requested.
        
        Args:
            url (str): The URL to fetch (e.g., 'https://example.com').
            show_cert (bool): Whether to retrieve the SSL certificate (default: False).
        
        Returns:
            Tuple[int, str, Optional[bytes]]: HTTP status code, page content, and certificate (if requested).
        """
        logging.info(f"Requesting URL: {url} with show_cert={show_cert}")
        
        # Parse the URL and set defaults
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
        hostname = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        is_https = parsed.scheme == 'https'
        
        logging.debug(f"Parsed URL - hostname: {hostname}, path: {path}, port: {port}, is_https: {is_https}")

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
                logging.debug(f"Retrieved SSL certificate for {hostname}")
        else:
            conn = sock
            conn.connect((hostname, port))
        
        logging.info(f"Connected to {hostname}:{port}")

        # Send HTTP GET request
        request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
        conn.sendall(request.encode('utf-8'))
        logging.debug(f"Sent request: {request.strip()}")

        # Receive response
        response = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        
        logging.info(f"Received response from {hostname}")

        # Parse response into headers and body
        headers, body = response.split(b'\r\n\r\n', 1)
        status_code = int(headers.decode('utf-8', errors='replace').split(' ')[1])
        content = body.decode('utf-8', errors='replace')
        
        logging.debug(f"Response status code: {status_code}")
        logging.debug(f"Response content: {content[:100]}...")  # Log only the first 100 characters of the content

        return status_code, content, cert_der

# Example usage
if __name__ == "__main__":
    client = HTTPClient(timeout=10)
    status, content, cert = client.request("https://example.com", show_cert=True)
    print(f"[+] Status: \n {status}")
    print(f"[+] Content: \n {content[:400]}...")  # Print only the first 400 characters of the content
    if cert:
        print(f"[+] Certificate: \n {cert[:300]}...")  # Print only the first 300 bytes of the certificate
