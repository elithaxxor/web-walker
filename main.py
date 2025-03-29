import socket,ssl,requests
import ssl
from html.parser import HTMLParser
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import re,json,base64

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.hidden_elements = []
        self.suspicious_patterns = []

    def handle_starttag(self, tag, attrs):
        try:
            if tag == 'a':
                for attr, value in attrs:
                    if attr == 'href':
                        self.links.append(value)
            elif tag == 'script':
                src = None
                for attr, value in attrs:
                    if attr == 'src':
                        src = value
                        break
                if src:
                    self.scripts.append({"type": "external", "src": src, "content": None})
                else:
                    self.scripts.append({"type": "inline", "src": None, "content": ""})

            if tag in ('div', 'input', 'iframe', 'img', 'form', 'span', 'p', 'a'):
                style = None
                hidden_attr = False
                for attr, value in attrs:
                    if attr == 'style':
                        style = value.lower()
                    elif attr == 'hidden':
                        hidden_attr = True
                    elif attr == 'type' and value.lower() == 'hidden':
                        hidden_attr = True

                if hidden_attr:
                    self.hidden_elements.append({"tag": tag, "attrs": attrs, "reason": "hidden attribute"})
                elif style:
                    if "display: none" in style or "visibility: hidden" in style or "opacity: 0" in style:
                        self.hidden_elements.append({"tag": tag, "attrs": attrs, "reason": "CSS style"})
                    elif re.search(r'(position:\s*absolute|fixed);\s*(top|left):\s*-?\d+px', style):
                        match = re.search(r'(position:\s*absolute|fixed);\s*(top|left):\s*(-?\d+)px', style)
                        if match:
                            position, _, offset_str = match.groups()
                            offset = int(offset_str)
                            if abs(offset) > 1000:
                                self.hidden_elements.append({"tag": tag, "attrs": attrs, "reason": f"Offscreen positioning ({offset}px)"})

            for attr, value in attrs:
                if attr in ('onload', 'onerror', 'onmouseover', 'onclick', 'onmousedown', 'onmouseup', 'onmousemove', 'onkeypress', 'onkeydown', 'onkeyup'):
                    self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "Inline event handler"})
                if attr == 'href' and value.startswith('javascript:'):
                    self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "javascript: URI"})
                if attr == 'src' and tag == 'iframe' and value.startswith('data:'):
                    self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "data: URI in iframe"})
        except Exception as e:
            print(f"[!] Error in handle_starttag: {e}")

    def handle_endtag(self, tag):
        pass

    def handle_data(self, data):
        pass

    def handle_startendtag(self, tag, attrs):
        try:
            if tag == 'script':
                src = None
                for attr, value in attrs:
                    if attr == 'src':
                        src = value
                        break
                if src:
                    self.scripts.append({"type": "external", "src": src, "content": None})
            self.handle_starttag(tag, attrs)
        except Exception as e:
            print(f"[!] Error in handle_startendtag: {e}")

    def handle_entityref(self, name):
        try:
            char = {
                'lt': '<',
                'gt': '>',
                'amp': '&',
                'quot': '"',
                'apos': "'"
            }.get(name, f'&{name};')
            if self.scripts and self.scripts[-1]['type'] == 'inline' and 'content' in self.scripts[-1]:
                self.scripts[-1]['content'] += char
        except Exception as e:
            print(f"[!] Error in handle_entityref: {e}")

    def handle_charref(self, name):
        try:
            char = chr(int(name[1:], 16)) if name.startswith('x') else chr(int(name))
        except ValueError:
            char = f'&#{name};'
        if self.scripts and self.scripts[-1]['type'] == 'inline' and 'content' in self.scripts[-1]:
            self.scripts[-1]['content'] += char

    def close(self):
        try:
            super().close()
            for script in self.scripts:
                if script["type"] == "inline" and script["content"] is not None:
                    pass
        except Exception as e:
            print(f"[!] Error in close: {e}")

class WebBrowserC:
    def __init__(self):
        self.cookies = {}

    def webbrowser(self, url=None, show_cert=False, detect_db=False, detect_hidden=False):
        if url is None:
            print(f'[+] Enter website address: ')
            input_url = input('')
        else:
            input_url = url

        if input_url.startswith("http://"):
            is_https = False
            hostname = input_url[7:].split("/")[0]
            path = "/" + input_url[7:].split("/", 1)[1] if "/" in input_url[7:] else "/"
        elif input_url.startswith("https://"):
            is_https = True
            hostname = input_url[8:].split("/")[0]
            path = "/" + input_url[8:].split("/", 1)[1] if "/" in input_url[8:] else "/"
        else:
            is_https = True
            hostname = input_url.split("/")[0]
            path = "/" + input_url.split("/", 1)[1] if "/" in input_url else "/"

        port = 443 if is_https else 80

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

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

            headers = [
                f"GET {path} HTTP/1.1",
                f"Host: {hostname}",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent: MyCustomBrowser/1.0",
            ]
            if self.cookies:
                cookie_string = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
                headers.append(f"Cookie: {cookie_string}")
            headers.append("")
            headers.append("")

            cmd = "\r\n".join(headers).encode()
            conn.send(cmd)

            html_response = ""
            response_headers = {}
            while True:
                try:
                    clientData = conn.recv(512)
                    if not clientData:
                        break
                    chunk = clientData.decode(errors='ignore')
                    html_response += chunk

                    if "\r\n" in chunk:
                        status_line = chunk.split("\r\n")[0]
                        try:
                            status_code = int(status_line.split()[1])
                            print(f"\n[+] Server responded with status code: {status_code}\n")

                            if status_code == 200:
                                pass
                            elif 300 <= status_code < 400:
                                location_header = [line for line in chunk.split("\r\n") if line.lower().startswith("location:")]
                                if location_header:
                                    new_url = location_header[0].split(":", 1)[1].strip()
                                    print(f"[+] Redirecting to: {new_url}")
                                    conn.close()
                                    self.webbrowser(url=new_url, show_cert=show_cert, detect_db=detect_db, detect_hidden=detect_hidden)
                                    return
                            elif status_code >= 400:
                                print(f"[!] Error: {status_line}")
                                return
                        except (IndexError, ValueError) as e:
                            print(f"[!] Invalid HTTP response format. {e}")
                            return

                        for line in chunk.split("\r\n"):
                            if ":" in line:
                                header_name, header_value = line.split(":", 1)
                                response_headers[header_name.strip().lower()] = header_value.strip()

                        content_type_header = [line for line in chunk.split("\r\n") if line.lower().startswith("content-type:")]
                        if content_type_header:
                            content_type = content_type_header[0].split(":", 1)[1].strip()

                            if "text/html" in content_type.lower():
                                pass
                            elif "text/plain" in content_type.lower():
                                print("[+] Plain text content. Displaying raw text:")
                                print(html_response.split("\r\n\r\n", 1)[1])
                                return
                            elif "image" in content_type.lower():
                                print("[+] Image content detected.  Cannot display.")
                                return
                            elif "javascript" in content_type.lower() or "typescript" in content_type.lower():
                                print("\n--- JavaScript/TypeScript Code (Direct Response) ---")
                                print(html_response.split("\r\n\r\n", 1)[1])
                                return
                            else:
                                print(f"[+] Unsupported content type: {content_type}")
                                return

                        for line in chunk.split("\r\n"):
                            if line.lower().startswith("set-cookie:"):
                                cookie_data = line.split(":", 1)[1].strip()
                                self._parse_and_store_cookie(cookie_data)
                except socket.timeout:
                    print("[!] Response timed out")
                    break

            conn.close()

            if detect_db:
                self._detect_and_report_database(response_headers, html_response)

            if "\r\n\r\n" in html_response:
                html_content = html_response.split("\r\n\r\n", 1)[1]
                parser = MyHTMLParser()
                try:
                    parser.feed(html_content)
                    if parser.scripts:
                        for script in parser.scripts:
                            if script["type"] == "inline" and script["content"]:
                                parser.handle_data(script["content"])
                    for link in parser.links:
                        print(f"[+] Link found: {link}")
                        resolved_link = self._resolve_url(hostname, path, link, is_https)
                        print(f"[+] Resolved Link: {resolved_link}")
                    parser.feed(html_content)
                finally:
                    parser.close()

                if detect_hidden:
                    if parser.hidden_elements:
                        print("--- Hidden Elements Detected ---")
                        for element in parser.hidden_elements:
                            print(f"  Tag: {element['tag']}, Reason: {element['reason']}")

                    if parser.suspicious_patterns:
                        print("\n--- Suspicious Patterns Detected ---")
                        for pattern in parser.suspicious_patterns:
                            print(f"  Tag: {pattern['tag']}, Attribute: {pattern['attr']}, Value: {pattern['value']}, Reason: {pattern['reason']}")

                for script in parser.scripts:
                    if script["type"] == "external":
                        script_url = self._resolve_url(hostname, path, script["src"], is_https)
                        print(f"\n--- Fetching External Script: {script_url} ---")
                        try:
                            script_content = self._fetch_external_resource(script_url, detect_db=detect_db, detect_hidden=detect_hidden)
                            if script_content:
                                script["content"] = script_content
                                print(script_content)
                            else:
                                print(f"[!] Could not retrieve external script: {script_url}")
                        except Exception as e:
                            print(f"[!] Error fetching external script {script_url}: {e}")

                print("\n--- JavaScript/TypeScript Code ---\n")
                for script in parser.scripts:
                    if script["type"] == "inline" and script["content"] is not None:
                        print("\n--- Inline Script ---")
                        print(script["content"])

            else:
                print("No HTML content found in the response")

        except socket.timeout:
            print("[!] Connection timed out.")
        except ssl.SSLError as e:
            print(f"[!] SSL Error: {e}")
        except Exception as e:
            print(f"[!] Error in webbrowser: {e}")

    def _fetch_external_resource(self, url, detect_db=False, detect_hidden=False):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"[!] Error fetching external resource: {e}")
            return None

    def _resolve_url(self, hostname, path, link, is_https):
        try:
            if link.startswith("http://") or link.startswith("https://"):
                return link
            elif link.startswith("/"):
                return f"https://{hostname}{link}" if is_https else f"http://{hostname}{link}"
            else:
                return f"https://{hostname}{path}/{link}" if is_https else f"http://{hostname}{path}/{link}"
        except Exception as e:
            print(f"[!] Error resolving URL: {e}")
            return None

    def _print_certificate_info(self, cert):
        try:
            cert = x509.load_der_x509_certificate(cert, default_backend())
            print(f"Subject: {cert.subject}")
            print(f"Issuer: {cert.issuer}")
            print(f"Serial Number: {cert.serial_number}")
            print(f"Not Before: {cert.not_valid_before}")
            print(f"Not After: {cert.not_valid_after}")
        except Exception as e:
            print(f"[!] Error printing certificate info: {e}")

    def _detect_and_report_database(self, headers, html):
        try:
            if "x-powered-by" in headers:
                print(f"[+] Detected database: {headers['x-powered-by']}")
            if "sql" in html.lower():
                print("[+] Possible SQL database detected in HTML content")
        except Exception as e:
            print(f"[!] Error detecting database: {e}")

    def _parse_and_store_cookie(self, cookie_data):
        try:
            cookie_parts = cookie_data.split(";")
            for part in cookie_parts:
                if "=" in part:
                    name, value = part.split("=", 1)
                    self.cookies[name.strip()] = value.strip()
        except Exception as e:
            print(f"[!] Error parsing and storing cookie: {e}")