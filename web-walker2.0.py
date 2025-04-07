import asyncio
import aiohttp
import re
import os
import json
import logging
import urllib.parse
from typing import List, Dict, Set, Optional, Tuple, Any
from bs4 import BeautifulSoup
import aiofiles
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import plotly.graph_objects as go
import plotly.io as pio
from datetime import datetime
import esprima  # For JavaScript parsing


# ---- Web Analysis Base Scanner ----

class WebAnalysisScanner(BaseScanner):
    """Base class for web content analysis"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 results_dir: str = "recon_results",
                 max_depth: int = 2,
                 respect_robots: bool = True,
                 rate_limit: float = 1.0):  # requests per second
        super().__init__(target, config, None, results_dir)
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.rate_limit = rate_limit
        self.visited_urls = set()
        self.disallowed_paths = set()
        self.last_request_time = 0
        
    async def _get_headers(self) -> Dict[str, str]:
        """Get request headers including user agent"""
        return {
            "User-Agent": "Network-Recon-Framework/1.0 (Research-Scanner; +https://example.com/about/scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
    async def _check_robots_txt(self, session: aiohttp.ClientSession) -> bool:
        """Check robots.txt for scanning permissions"""
        try:
            # Get base URL
            parsed_url = urllib.parse.urlparse(self.target)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            robots_url = f"{base_url}/robots.txt"
            
            async with session.get(robots_url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse robots.txt content
                    user_agent = None
                    for line in content.split('\n'):
                        line = line.strip().lower()
                        
                        # Check for user agent line
                        if line.startswith('user-agent:'):
                            agent = line[11:].strip()
                            if agent == '*' or 'bot' in agent:
                                user_agent = agent
                        
                        # Check for disallow line
                        elif user_agent and line.startswith('disallow:'):
                            path = line[9:].strip()
                            if path:
                                self.disallowed_paths.add(path)
                    
                    # Check if our target path is allowed
                    target_path = parsed_url.path
                    for path in self.disallowed_paths:
                        if target_path.startswith(path):
                            self.logger.warning(f"Target path {target_path} is disallowed by robots.txt")
                            return False
                    
                    return True
                else:
                    # No robots.txt or can't access it, assume allowed
                    return True
        except Exception as e:
            self.logger.error(f"Error checking robots.txt: {e}")
            # Assume allowed if there's an error
            return True
    
    async def _is_allowed(self, url: str) -> bool:
        """Check if a URL is allowed to be scanned"""
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        
        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False
        
        return True
    
    async def _rate_limit_request(self) -> None:
        """Implement rate limiting for requests"""
        import time
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        sleep_time = max(0, (1.0 / self.rate_limit) - time_since_last)
        
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def _normalize_url(self, url: str, base_url: str) -> str:
        """Normalize a URL (handle relative URLs, etc.)"""
        if not url:
            return None
            
        # Skip javascript: URLs, anchors, etc.
        if url.startswith(('javascript:', '#', 'mailto:', 'tel:')):
            return None
            
        # Handle relative URLs
        if not url.startswith(('http://', 'https://')):
            return urllib.parse.urljoin(base_url, url)
            
        # Check if URL is for the same domain
        parsed_base = urllib.parse.urlparse(base_url)
        parsed_url = urllib.parse.urlparse(url)
        
        if parsed_base.netloc != parsed_url.netloc:
            return None  # Skip external domains
            
        return url


# ---- API Endpoint Scanner ----

class APIEndpointScanner(WebAnalysisScanner):
    """Scanner to identify potential API endpoints in web content"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 results_dir: str = "recon_results",
                 max_depth: int = 2,
                 respect_robots: bool = True,
                 rate_limit: float = 1.0):
        super().__init__(target, config, results_dir, max_depth, respect_robots, rate_limit)
        self.discovered_endpoints = set()
        self.potential_api_paths = set()
        self.api_patterns = [
            r'/api/\w+/?',                  # Standard API paths
            r'/v\d+/\w+/?',                 # Versioned API paths
            r'/rest/\w+/?',                 # REST API paths
            r'/graphql/?',                  # GraphQL endpoints
            r'/swagger/?',                  # Swagger documentation
            r'/openapi/?',                  # OpenAPI documentation
            r'\.json(\?|$)',                # JSON responses
            r'\.xml(\?|$)',                 # XML responses
            r'/oauth/\w+/?',                # OAuth endpoints
            r'/auth/\w+/?',                 # Auth endpoints
            r'/service/\w+/?',              # Service endpoints
            r'/data/\w+/?',                 # Data endpoints
            r'/ajax/\w+/?',                 # AJAX endpoints
            r'/rpc/\w+/?',                  # RPC endpoints
            r'/_api/\w+/?',                 # Hidden API endpoints
            r'/wp-json/\w+/?',              # WordPress REST API
            r'/api-docs/?',                 # API documentation
        ]
    
    @property
    def name(self) -> str:
        return "api_endpoint_scanner"
    
    async def scan(self) -> ScanResult:
        """Scan target website for API endpoints"""
        ToolDescription.print_tool_info(self.name)
        
        output_file = self.get_output_file()
        
        # Ensure target is a URL
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"https://{self.target}"
        
        # Create aiohttp session
        async with aiohttp.ClientSession(headers=await self._get_headers()) as session:
            # Check robots.txt if required
            if self.respect_robots and not await self._check_robots_txt(session):
                return ScanResult(
                    target=self.target,
                    scanner_name=self.name,
                    success=False,
                    message="Scanning not allowed by robots.txt"
                )
            
            # Create network graph for visualization
            graph = nx.DiGraph()
            graph.add_node(self.target, type="root")
            
            # Start crawling from the main page
            await self._crawl_page(session, self.target, 0, graph)
            
            # Check potential API paths
            await self._test_potential_api_paths(session)
            
            # Visualize the API endpoint graph
            graph_image = await self._generate_graph_image(graph)
            
            # Write results to file
            await self._write_results(output_file, graph_image)
            
            # Print summary
            self._print_summary()
            
        return ScanResult(
            target=self.target,
            scanner_name=self.name,
            success=True,
            message=f"Discovered {len(self.discovered_endpoints)} potential API endpoints",
            output_file=output_file
        )
    
    async def _crawl_page(self, session: aiohttp.ClientSession, url: str, depth: int, graph: nx.DiGraph) -> None:
        """Crawl a page and extract API endpoints"""
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        if not await self._is_allowed(url):
            return
        
        self.visited_urls.add(url)
        
        try:
            await self._rate_limit_request()
            
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                
                content_type = response.headers.get('Content-Type', '')
                if not content_type.startswith('text/html'):
                    return
                
                html_content = await response.text()
                
                # Extract API endpoints from HTML
                api_endpoints = await self._extract_api_endpoints(html_content, url)
                for endpoint in api_endpoints:
                    self.discovered_endpoints.add(endpoint)
                    graph.add_node(endpoint, type="api")
                    graph.add_edge(url, endpoint)
                
                # Extract links for further crawling
                soup = BeautifulSoup(html_content, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link.get('href')
                    normalized_url = await self._normalize_url(href, url)
                    
                    if normalized_url and normalized_url not in self.visited_urls:
                        if depth < self.max_depth:
                            graph.add_node(normalized_url, type="page")
                            graph.add_edge(url, normalized_url)
                            await self._crawl_page(session, normalized_url, depth + 1, graph)
                
                # Extract and analyze JavaScript files
                script_tags = soup.find_all('script', src=True)
                for script in script_tags:
                    script_url = await self._normalize_url(script.get('src'), url)
                    if script_url and script_url not in self.visited_urls:
                        self.visited_urls.add(script_url)
                        api_endpoints = await self._analyze_javascript(session, script_url, url)
                        
                        for endpoint in api_endpoints:
                            self.discovered_endpoints.add(endpoint)
                            graph.add_node(endpoint, type="api")
                            graph.add_edge(script_url, endpoint)
                        
                        # Add script node to graph
                        graph.add_node(script_url, type="script")
                        graph.add_edge(url, script_url)
        
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
    
    async def _extract_api_endpoints(self, html_content: str, base_url: str) -> Set[str]:
        """Extract potential API endpoints from HTML content"""
        endpoints = set()
        
        # Look for API URLs in the HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract from data attributes
        for tag in soup.find_all(attrs={"data-url": True}):
            url = tag.get('data-url')
            normalized_url = await self._normalize_url(url, base_url)
            if normalized_url:
                for pattern in self.api_patterns:
                    if re.search(pattern, normalized_url):
                        endpoints.add(normalized_url)
                        break
        
        # Extract from JavaScript inline code
        for script in soup.find_all('script'):
            if script.string:
                # Look for API URLs in JavaScript code
                js_code = script.string
                # Fetch URLs from JavaScript
                urls = re.findall(r'["\'](?:(?:https?://)|/)(?:[^"\'/\s]+/?)+["\']', js_code)
                
                for url in urls:
                    # Clean up the URL (remove quotes)
                    url = url.strip('\'"')
                    normalized_url = await self._normalize_url(url, base_url)
                    
                    if normalized_url:
                        for pattern in self.api_patterns:
                            if re.search(pattern, normalized_url):
                                endpoints.add(normalized_url)
                                # Also add to potential paths for testing
                                parsed_url = urllib.parse.urlparse(normalized_url)
                                self.potential_api_paths.add(parsed_url.path)
                                break
        
        return endpoints
    
    async def _analyze_javascript(self, session: aiohttp.ClientSession, script_url: str, base_url: str) -> Set[str]:
        """Analyze JavaScript file for API endpoints"""
        endpoints = set()
        
        try:
            await self._rate_limit_request()
            
            async with session.get(script_url, timeout=10) as response:
                if response.status != 200:
                    return endpoints
                
                js_content = await response.text()
                
                # Look for URLs in JavaScript code
                urls = re.findall(r'["\'](?:(?:https?://)|/)(?:[^"\'/\s]+/?)+["\']', js_content)
                
                for url in urls:
                    # Clean up the URL (remove quotes)
                    url = url.strip('\'"')
                    normalized_url = await self._normalize_url(url, base_url)
                    
                    if normalized_url:
                        for pattern in self.api_patterns:
                            if re.search(pattern, normalized_url):
                                endpoints.add(normalized_url)
                                # Also add to potential paths for testing
                                parsed_url = urllib.parse.urlparse(normalized_url)
                                self.potential_api_paths.add(parsed_url.path)
                                break
                
                # Advanced JavaScript parsing with esprima if available
                try:
                    ast = esprima.parseScript(js_content)
                    # Extract fetch, XHR, axios calls
                    # This would require recursive AST traversal
                    # Simplified version for demonstration
                    fetch_calls = re.findall(r'fetch\(["\']([^"\']+)["\']', js_content)
                    axios_calls = re.findall(r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']', js_content)
                    xhr_calls = re.findall(r'\.open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']', js_content)
                    
                    for url in fetch_calls + [match[1] for match in axios_calls] + xhr_calls:
                        normalized_url = await self._normalize_url(url, base_url)
                        if normalized_url:
                            endpoints.add(normalized_url)
                            # Also add to potential paths for testing
                            parsed_url = urllib.parse.urlparse(normalized_url)
                            self.potential_api_paths.add(parsed_url.path)
                
                except Exception as e:
                    self.logger.debug(f"Error parsing JavaScript with esprima: {e}")
        
        except Exception as e:
            self.logger.error(f"Error analyzing JavaScript {script_url}: {e}")
        
        return endpoints
    
    async def _test_potential_api_paths(self, session: aiohttp.ClientSession) -> None:
        """Test potential API paths with common HTTP methods"""
        parsed_url = urllib.parse.urlparse(self.target)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for path in self.potential_api_paths:
            full_url = urllib.parse.urljoin(base_url, path)
            
            # Test with different methods
            for method in ['GET']:  # Add more methods for more thorough testing
                try:
                    await self._rate_limit_request()
                    
                    if method == 'GET':
                        async with session.get(full_url, timeout=5) as response:
                            if response.status == 200:
                                content_type = response.headers.get('Content-Type', '')
                                if 'json' in content_type or 'xml' in content_type:
                                    self.discovered_endpoints.add(full_url)
                
                except Exception as e:
                    self.logger.debug(f"Error testing API path {full_url} with {method}: {e}")
    
    async def _generate_graph_image(self, graph: nx.DiGraph) -> str:
        """Generate a visualization of the API endpoint graph"""
        plt.figure(figsize=(12, 8))
        
        # Define node colors based on type
        node_colors = []
        for node in graph.nodes():
            node_type = graph.nodes[node].get('type', 'page')
            if node_type == 'root':
                node_colors.append('blue')
            elif node_type == 'page':
                node_colors.append('green')
            elif node_type == 'api':
                node_colors.append('red')
            elif node_type == 'script':
                node_colors.append('orange')
            else:
                node_colors.append('gray')
        
        # Draw the graph
        pos = nx.spring_layout(graph, k=0.3, iterations=50)
        nx.draw(graph, pos, with_labels=False, node_color=node_colors, 
                node_size=30, edge_color='gray', linewidths=0.5, 
                font_size=8, arrows=True, alpha=0.6)
        
        # Add legend
        import matplotlib.patches as mpatches
        root_patch = mpatches.Patch(color='blue', label='Root')
        page_patch = mpatches.Patch(color='green', label='Page')
        api_patch = mpatches.Patch(color='red', label='API Endpoint')
        script_patch = mpatches.Patch(color='orange', label='Script')
        plt.legend(handles=[root_patch, page_patch, api_patch, script_patch])
        
        # Save to base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=150)
        plt.close()
        
        base64_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return base64_image
    
    async def _write_results(self, output_file: str, graph_image: str) -> None:
        """Write discovered endpoints to file"""
        result = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "discovered_endpoints": list(self.discovered_endpoints),
            "crawled_pages": len(self.visited_urls),
            "api_endpoint_count": len(self.discovered_endpoints),
            "graph_image": graph_image
        }
        
        async with aiofiles.open(output_file, "w") as f:
            await f.write(json.dumps(result, indent=2))
    
    def _print_summary(self) -> None:
        """Print a summary of the scan results"""
        print("\nAPI Endpoint Discovery Results:")
        print("-" * 50)
        print(f"Target: {self.target}")
        print(f"Pages Crawled: {len(self.visited_urls)}")
        print(f"API Endpoints Discovered: {len(self.discovered_endpoints)}")
        
        if len(self.discovered_endpoints) > 0:
            print("\nTop API Endpoints:")
            for endpoint in list(self.discovered_endpoints)[:5]:  # Show top 5
                print(f"  - {endpoint}")
            
            if len(self.discovered_endpoints) > 5:
                print(f"  ... and {len(self.discovered_endpoints) - 5} more")
        
        print("-" * 50 + "\n")


# ---- Script Analyzer ----

class ScriptAnalyzer(WebAnalysisScanner):
    """Scanner to download and analyze JavaScript files"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 results_dir: str = "recon_results",
                 max_depth: int = 2,
                 respect_robots: bool = True,
                 rate_limit: float = 1.0,
                 download_scripts: bool = True):
        super().__init__(target, config, results_dir, max_depth, respect_robots, rate_limit)
        self.downloaded_scripts = {}
        self.script_analysis = {}
        self.download_scripts = download_scripts
        self.script_save_dir = os.path.join(results_dir, "scripts")
        os.makedirs(self.script_save_dir, exist_ok=True)
    
    @property
    def name(self) -> str:
        return "script_analyzer"
    
    async def scan(self) -> ScanResult:
        """Scan target website for scripts"""
        ToolDescription.print_tool_info(self.name)
        
        output_file = self.get_output_file()
        
        # Ensure target is a URL
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"https://{self.target}"
        
        # Create aiohttp session
        async with aiohttp.ClientSession(headers=await self._get_headers()) as session:
            # Check robots.txt if required
            if self.respect_robots and not await self._check_robots_txt(session):
                return ScanResult(
                    target=self.target,
                    scanner_name=self.name,
                    success=False,
                    message="Scanning not allowed by robots.txt"
                )
            
            # Start crawling from the main page
            await self._crawl_for_scripts(session, self.target, 0)
            
            # Analyze all downloaded scripts
            for script_url, script_content in self.downloaded_scripts.items():
                self.script_analysis[script_url] = await self._analyze_script(script_url, script_content)
            
            # Generate visualizations
            dependency_graph = await self._generate_dependency_graph()
            
            # Write results to file
            await self._write_results(output_file, dependency_graph)
            
            # Print summary
            self._print_summary()
            
        return ScanResult(
            target=self.target,
            scanner_name=self.name,
            success=True,
            message=f"Analyzed {len(self.downloaded_scripts)} JavaScript files",
            output_file=output_file
        )
    
    async def _crawl_for_scripts(self, session: aiohttp.ClientSession, url: str, depth: int) -> None:
        """Crawl a page and extract scripts"""
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        if not await self._is_allowed(url):
            return
        
        self.visited_urls.add(url)
        
        try:
            await self._rate_limit_request()
            
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                
                content_type = response.headers.get('Content-Type', '')
                if not content_type.startswith('text/html'):
                    return
                
                html_content = await response.text()
                
                # Parse HTML
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Extract script tags
                script_tags = soup.find_all('script')
                
                for script in script_tags:
                    # External scripts
                    if script.get('src'):
                        script_url = await self._normalize_url(script.get('src'), url)
                        if script_url and script_url not in self.downloaded_scripts:
                            await self._download_script(session, script_url)
                    
                    # Inline scripts
                    elif script.string and len(script.string.strip()) > 0:
                        # Generate a unique name for the inline script
                        inline_name = f"inline_{hash(script.string) & 0xffffffff}_{url.split('/')[-1]}.js"
                        inline_url = f"{url}#{inline_name}"
                        
                        if inline_url not in self.downloaded_scripts:
                            self.downloaded_scripts[inline_url] = script.string
                            
                            if self.download_scripts:
                                script_path = os.path.join(self.script_save_dir, inline_name)
                                async with aiofiles.open(script_path, 'w') as f:
                                    await f.write(script.string)
                
                # Extract links for further crawling
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link.get('href')
                    normalized_url = await self._normalize_url(href, url)
                    
                    if normalized_url and normalized_url not in self.visited_urls:
                        if depth < self.max_depth:
                            await self._crawl_for_scripts(session, normalized_url, depth + 1)
        
        except Exception as e:
            self.logger.error(f"Error crawling for scripts at {url}: {e}")
    
    async def _download_script(self, session: aiohttp.ClientSession, script_url: str) -> None:
        """Download a JavaScript file"""
        try:
            await self._rate_limit_request()
            
            async with session.get(script_url, timeout=10) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Ensure it's a JavaScript file
                    if 'javascript' in content_type or script_url.endswith('.js'):
                        script_content = await response.text()
                        self.downloaded_scripts[script_url] = script_content
                        
                        if self.download_scripts:
                            # Create a valid filename from the URL
                            filename = script_url.split('/')[-1]
                            if not filename.endswith('.js'):
                                filename += '.js'
                            
                            # Replace invalid characters
                            filename = re.sub(r'[\\/:"*?<>|]', '_', filename)
                            
                            script_path = os.path.join(self.script_save_dir, filename)
                            async with aiofiles.open(script_path, 'w') as f:
                                await f.write(script_content)
        
        except Exception as e:
            self.logger.error(f"Error downloading script {script_url}: {e}")
    
    async def _analyze_script(self, script_url: str, script_content: str) -> Dict:
        """Analyze a JavaScript file for various indicators"""
        analysis = {
            "size_bytes": len(script_content),
            "imports": [],
            "exports": [],
            "api_endpoints": [],
            "dom_interactions": [],
            "storage_usage": False,
            "cookie_usage": False,
            "sensitive_functions": [],
            "frameworks": [],
            "minified": False,
            "obfuscated": False
        }
        
        # Check if minified
        lines = script_content.count('\n')
        avg_line_length = len(script_content) / max(lines, 1)
        analysis["minified"] = avg_line_length > 200
        
        # Check for obfuscation indicators
        obfuscation_patterns = [
            r'eval\(function\(p,a,c,k,e,',  # Typical packer
            r'_0x[a-f0-9]{4}',             # Hex obfuscation
            r'\\x[a-f0-9]{2}',             # Hex escapes
            r'String\.fromCharCode\(',     # Character code conversion
            r'atob\('                      # Base64 encoding
        ]
        
        for pattern in obfuscation_patterns:
            if re.search(pattern, script_content):
                analysis["obfuscated"] = True
                break
        
        # Detect framework usage
        framework_patterns = {
            "jQuery": r'jQuery|\$\(',
            "React": r'React|ReactDOM',
            "Angular": r'angular\.|ng\.',
            "Vue": r'Vue\.|createApp\(',
            "Backbone": r'Backbone\.',
            "D3.js": r'd3\.',
            "Lodash": r'_\.|lodash',
            "Axios": r'axios\.'
        }
        
        for framework, pattern in framework_patterns.items():
            if re.search(pattern, script_content):
                analysis["frameworks"].append(framework)
        
        # Detect imports/exports
        import_patterns = [
            r'import\s+[\w\s{},*]+\s+from\s+[\'"]([^\'"]+)[\'"]',
            r'require\([\'"]([^\'"]+)[\'"]\)'
        ]
        
        for pattern in import_patterns:
            for match in re.finditer(pattern, script_content):
                if match.group(1) not in analysis["imports"]:
                    analysis["imports"].append(match.group(1))
        
        export_patterns = [
            r'export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)',
            r'module\.exports\s*='
        ]
        
        for pattern in export_patterns:
            for match in re.finditer(pattern, script_content):
                if match.group(1) not in analysis["exports"] and hasattr(match, 'group') and len(match.groups()) > 0:
                    analysis["exports"].append(match.group(1))
        
        # Detect API endpoints
        api_patterns = [
            r'(?:fetch|axios\.(?:get|post|put|delete))\([\'"]([^\'"]+)[\'"]\)',
            r'\.ajax\(\{.*?url:\s*[\'"]([^\'"]+)[\'"]',
            r'\.open\([\'"](?:GET|POST|PUT|DELETE)[\'"],\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, script_content):
                if match.group(1) not in analysis["api_endpoints"]:
                    analysis["api_endpoints"].append(match.group(1))
        
        # Detect DOM interactions
        dom_patterns = [
            r'document\.(?:getElementById|querySelector|querySelectorAll|getElementsByClassName|getElementsByTagName)',
            r'\$\([\'"][\w\s#.]+[\'"]\)',
            r'innerHTML|outerHTML|textContent|innerText'
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, script_content):
                analysis["dom_interactions"].append(pattern.replace(r'\.', '.').replace(r'\(', '('))
        
        # Detect storage usage
        if re.search(r'localStorage|sessionStorage', script_content):
            analysis["storage_usage"] = True
        
        # Detect cookie usage
        if re.search(r'document\.cookie', script_content):
            analysis["cookie_usage"] = True
        
        # Detect sensitive functions
        sensitive_patterns = {
            "eval": r'eval\(',
            "new Function": r'new Function\(',
            "document.write": r'document\.write\(',
            "crypto functions": r'crypto\.|SubtleCrypto',
            "postMessage": r'postMessage\(',
            "XMLHttpRequest": r'XMLHttpRequest',
            "WebSocket": r'WebSocket\('
        }
        
        for name, pattern in sensitive_patterns.items():
            if re.search(pattern, script_content):
                analysis["sensitive_functions"].append(name)
        
        return analysis
    
    async def _generate_dependency_graph(self) -> str:
        """Generate a visualization of script dependencies"""
        # Create a graph for imports/dependencies
        graph = nx.DiGraph()
        
        # Add nodes for all scripts
        for script_url in self.downloaded_scripts.keys():
            graph.add_node(os.path.basename(script_url), url=script_url)
        
        # Add edges for imports
        for script_url, analysis in self.script_analysis.items():
            script_node = os.path.basename(script_url)
            
            for imported in analysis["imports"]:
                # Find the imported script
                imported_script = None
                for url in self.downloaded_scripts.keys():
                    if imported in url or os.path.basename(url) == imported:
                        imported_script = os.path.basename(url)
                        break
                
                if imported_script and imported_script != script_node:
                    graph.add_edge(script_node, imported_script)
        
        # Generate visualization
        plt.figure(figsize=(10, 8))
        
        # Node colors based on framework
        node_colors = []
        for node in graph.nodes():
            script_url = graph.nodes[node].get('url', '')
            
            if script_url in self.script_analysis:
                analysis = self.script_analysis[script_url]
                
                if analysis.get("obfuscated", False):
                    node_colors.append('red')
                elif analysis.get("minified", False):
                    node_colors.append('orange')
                elif len(analysis.get("frameworks", [])) > 0:
                    node_colors.append('blue')
                else:
                    node_colors.append('green')
            else:
                node_colors.append('gray')
        
        # Draw the graph
        pos = nx.spring_layout(graph, k=0.3, iterations=50)
        nx.draw(graph, pos, with_labels=True, node_color=node_colors, 
                node_size=500, edge_color='gray', linewidths=0.5, 
                font_size=8, arrows=True, alpha=0.8)
        
        # Add legend
        import matplotlib.patches as mpatches
        obfuscated_patch = mpatches.Patch(color='red', label='Obfuscated')
        minified_patch = mpatches.Patch(color='orange', label='Minified')
        framework_patch = mpatches.Patch(color='blue', label='Framework')
        regular_patch = mpatches.Patch(color='green', label='Regular JS')
        plt.legend(handles=[obfuscated_patch, minified_patch, framework_patch, regular_patch])
        
        # Save to base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=150)
        plt.close()
        
        base64_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return base64_image
    
    async def _write_results(self, output_file: str, dependency_graph: str) -> None:
        """Write script analysis results to file"""
        # Count frameworks
        framework_count = {}
        for analysis in self.script_analysis.values():
            for framework in analysis.get("frameworks", []):
                if framework not in framework_count:
                    framework_count[framework] = 0
                framework_count[framework] += 1
        
        # Count API endpoints
        api_count = 0
        for analysis in self.script_analysis.values():
            api_count += len(analysis.get("api_endpoints", []))
        
        result = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "scripts_analyzed": len(self.downloaded_scripts),
            "pages_crawled": len(self.visited_urls),
            "framework_usage": framework_count,
            "api_endpoints_found": api_count,
            "obfuscated_scripts": sum(1 for a in self.script_analysis.values() if a.get("obfuscated", False)),
            "minified_scripts": sum(1 for a in self.script_analysis.values() if a.get("minified", False)),
            "detailed_analysis": {url: analysis for url, analysis in self.script_analysis.items()},
            "dependency_graph": dependency_graph
        }
        
        async with aiofiles.open(output_file, "w") as f:
            await f.write(json.dumps(result, indent=2))
    
    def _print_summary(self) -> None:
        """Print a summary of the script analysis results"""
        # Count frameworks
        framework_count = {}
        for analysis in self.script_analysis.values():
            for framework in analysis.get("frameworks", []):
                if framework not in framework_count:
                    framework_count[framework] = 0
                framework_count[framework] += 1
        
        # Count API endpoints
        api_endpoints = set()
        for analysis in self.script_analysis.values():
            api_endpoints.update(analysis.get("api_endpoints", []))
        
        print("\nJavaScript Analysis Results:")
        print("-" * 50)
        print(f"Target: {self.target}")
        print(f"Pages Crawled: {len(self.visited_urls)}")
        print(f"Scripts Analyzed: {len(self.downloaded_scripts)}")
        print(f"API Endpoints Found: {len(api_endpoints)}")
        print(f"Obfuscated Scripts: {sum(1 for a in self.script_analysis.values() if a.get('obfuscated', False))}")
        print(f"Minified Scripts: {sum(1 for a in self.script_analysis.values() if a.get('minified', False))}")
        
        if framework_count:
            print("\nFramework Usage:")
            for framework, count in framework_count.items():
                print(f"  - {framework}: {count}")
        
        print("-" * 50 + "\n")


# ---- Web Analysis Strategy ----

class WebAnalysisStrategy(ScanStrategy):
    """Strategy for web application reconnaissance"""
    
    def __init__(self, target: str, config: ScannerConfig, results_dir: str = "recon_results",
                 max_depth: int = 2, respect_robots: bool = True, download_scripts: bool = True,
                 rate_limit: float = 1.0):
        super().__init__(target, config, results_dir)
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.download_scripts = download_scripts
        self.rate_limit = rate_limit
    
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute the web analysis strategy"""
        self.logger.info(f"Starting web analysis for {self.target}")
        results = AggregatedResult(self.target)
        
        # Create the API endpoint scanner
        api_scanner = APIEndpointScanner(
            self.target,
            self.config,
            self.results_dir,
            self.max_depth,
            self.respect_robots,
            self.rate_limit
        )
        
        # Run the API endpoint scan
        api_result = await api_scanner.scan()
        results.add_result(api_result)
        
        # Create the script analyzer
        script_analyzer = ScriptAnalyzer(
            self.target,
            self.config,
            self.results_dir,
            self.max_depth,
            self.respect_robots,
            self.rate_limit,
            self.download_scripts
        )
        
        # Run the script analysis
        script_result = await script_analyzer.scan()
        results.add_result(script_result)
        
        # Save the aggregated report
        report_file = os.path.join(self.results_dir, f"web_analysis_{self.target}.json")
        await results.save_to_file(report_file)
        self.logger.info(f"Web analysis complete, report saved to {report_file}")
        
        return results


# ---- Data Processing Extensions ----

# Extend NetworkDataProcessor to handle web analysis results
def extract_web_metrics(self) -> Dict:
    """Extract metrics from web analysis results"""
    if 'api_endpoints' not in self.metrics:
        self.metrics['api_endpoints'] = {}  # API endpoints by target
    
    if 'scripts' not in self.metrics:
        self.metrics['scripts'] = {}        # Scripts by target
    
    if 'web_frameworks' not in self.metrics:
        self.metrics['web_frameworks'] = {} # Web frameworks by target
    
    if 'web_vulnerabilities' not in self.metrics:
        self.metrics['web_vulnerabilities'] = {}  # Web vulnerabilities by target
    
    # Process each scan type and target
    for scan_type, targets in self.data.items():
        for target, data in targets.items():
            # Initialize target metrics if not exist
            if target not in self.metrics['api_endpoints']:
                self.metrics['api_endpoints'][target] = []
            if target not in self.metrics['scripts']:
                self.metrics['scripts'][target] = []
            if target not in self.metrics['web_frameworks']:
                self.metrics['web_frameworks'][target] = {}
            if target not in self.metrics['web_vulnerabilities']:
                self.metrics['web_vulnerabilities'][target] = []
            
            # Process API endpoint scanner results
            if scan_type == 'api_endpoint_scanner' and 'output_file' in data:
                try:
                    with open(data['output_file'], 'r') as f:
                        api_data = json.load(f)
                        if 'discovered_endpoints' in api_data:
                            self.metrics['api_endpoints'][target].extend(api_data['discovered_endpoints'])
                except Exception as e:
                    self.logger.error(f"Error processing API endpoint data: {e}")
            
            # Process script analyzer results
            if scan_type == 'script_analyzer' and 'output_file' in data:
                try:
                    with open(data['output_file'], 'r') as f:
                        script_data = json.load(f)
                        
                        # Add scripts
                        if 'detailed_analysis' in script_data:
                            for url, analysis in script_data['detailed_analysis'].items():
                                self.metrics['scripts'][target].append({
                                    'url': url,
                                    'size': analysis.get('size_bytes', 0),
                                    'obfuscated': analysis.get('obfuscated', False),
                                    'minified': analysis.get('minified', False),
                                    'apis': analysis.get('api_endpoints', []),
                                    'frameworks': analysis.get('frameworks', []),
                                    'sensitive_functions': analysis.get('sensitive_functions', [])
                                })
                        
                        # Add framework usage
                        if 'framework_usage' in script_data:
                            self.metrics['web_frameworks'][target] = script_data['framework_usage']
                        
                        # Add potential web vulnerabilities
                        for url, analysis in script_data.get('detailed_analysis', {}).items():
                            # Check for risky code patterns
                            if analysis.get('obfuscated', False):
                                self.metrics['web_vulnerabilities'][target].append({
                                    'name': 'Obfuscated JavaScript',
                                    'description': f'Potentially malicious obfuscated code in {os.path.basename(url)}',
                                    'severity': 'medium',
                                    'url': url
                                })
                            
                            for func in analysis.get('sensitive_functions', []):
                                if func in ['eval', 'new Function', 'document.write']:
                                    self.metrics['web_vulnerabilities'][target].append({
                                        'name': f'Dangerous Function: {func}',
                                        'description': f'Use of potentially unsafe JavaScript function in {os.path.basename(url)}',
                                        'severity': 'high',
                                        'url': url
                                    })
                except Exception as e:
                    self.logger.error(f"Error processing script analyzer data: {e}")
    
    return self.metrics


# Add method to NetworkDataProcessor class
NetworkDataProcessor.extract_web_metrics = extract_web_metrics


# ---- Visualization Extensions ----

class WebAnalysisVisualizer:
    """Creates visualizations for web analysis results"""
    
    def __init__(self, metrics: Dict, output_dir: str = "visual_reports"):
        self.metrics = metrics
        self.output_dir = output_dir
        self.report_data = {}
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
    
    def create_api_endpoint_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a chart showing API endpoints by target"""
        if not targets:
            targets = list(self.metrics['api_endpoints'].keys())
        
        # Count API endpoints for each target
        endpoint_counts = {target: len(endpoints) for target, endpoints in self.metrics['api_endpoints'].items() 
                          if target in targets and endpoints}
        
        if not endpoint_counts:
            return None
        
        # Sort data for better visualization
        sorted_items = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_targets = [item[0] for item in sorted_items]
        sorted_counts = [item[1] for item in sorted_items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color='purple'
        ))
        
        fig.update_layout(
            title="API Endpoints by Target",
            xaxis_title="Target",
            yaxis_title="Number of API Endpoints",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "api_endpoints_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'API Endpoints by Target'
        }
        
        self.report_data['api_endpoints_chart'] = result
        return result
    
    def create_script_analysis_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a chart showing script analysis by target"""
        if not targets:
            targets = list(self.metrics['scripts'].keys())
        
        # Prepare data for stacked bar chart
        regular_scripts = []
        minified_scripts = []
        obfuscated_scripts = []
        
        for target in targets:
            if target in self.metrics['scripts'] and self.metrics['scripts'][target]:
                scripts = self.metrics['scripts'][target]
                regular_count = sum(1 for s in scripts if not s.get('minified', False) and not s.get('obfuscated', False))
                minified_count = sum(1 for s in scripts if s.get('minified', False) and not s.get('obfuscated', False))
                obfuscated_count = sum(1 for s in scripts if s.get('obfuscated', False))
                
                regular_scripts.append(regular_count)
                minified_scripts.append(minified_count)
                obfuscated_scripts.append(obfuscated_count)
            else:
                regular_scripts.append(0)
                minified_scripts.append(0)
                obfuscated_scripts.append(0)
        
        # Create stacked bar chart
        fig = go.Figure(data=[
            go.Bar(name='Regular', x=targets, y=regular_scripts, marker_color='green'),
            go.Bar(name='Minified', x=targets, y=minified_scripts, marker_color='orange'),
            go.Bar(name='Obfuscated', x=targets, y=obfuscated_scripts, marker_color='red')
        ])
        
        fig.update_layout(
            title="JavaScript Files by Target",
            xaxis_title="Target",
            yaxis_title="Number of JavaScript Files",
            template="plotly_white",
            barmode='stack'
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "script_analysis_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'JavaScript Analysis by Target'
        }
        
        self.report_data['script_analysis_chart'] = result
        return result
    
    def create_framework_usage_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a chart showing web framework usage by target"""
        if not targets:
            targets = list(self.metrics['web_frameworks'].keys())
        
        # Collect all unique frameworks across targets
        all_frameworks = set()
        for target in targets:
            if target in self.metrics['web_frameworks']:
                all_frameworks.update(self.metrics['web_frameworks'][target].keys())
        
        all_frameworks = sorted(all_frameworks)
        
        if not all_frameworks:
            return None
        
        # Prepare data for heatmap
        heatmap_data = []
        for target in targets:
            target_data = []
            for framework in all_frameworks:
                if target in self.metrics['web_frameworks'] and framework in self.metrics['web_frameworks'][target]:
                    target_data.append(self.metrics['web_frameworks'][target][framework])
                else:
                    target_data.append(0)
            heatmap_data.append(target_data)
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=all_frameworks,
            y=targets,
            colorscale='Viridis',
            showscale=True
        ))
        
        fig.update_layout(
            title="Web Framework Usage by Target",
            xaxis_title="Framework",
            yaxis_title="Target",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "framework_usage_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'heatmap',
            'title': 'Web Framework Usage by Target'
        }
        
        self.report_data['framework_usage_chart'] = result
        return result
    
    def create_web_vulnerabilities_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a chart showing web vulnerabilities by target"""
        if not targets:
            targets = list(self.metrics['web_vulnerabilities'].keys())
        
        # Prepare data for pie charts
        pie_charts = []
        
        for target in targets:
            if target in self.metrics['web_vulnerabilities'] and self.metrics['web_vulnerabilities'][target]:
                vulns = self.metrics['web_vulnerabilities'][target]
                
                # Count vulnerabilities by type
                vuln_counts = {}
                for vuln in vulns:
                    name = vuln.get('name', 'Unknown')
                    if name not in vuln_counts:
                        vuln_counts[name] = 0
                    vuln_counts[name] += 1
                
                # Sort by count
                sorted_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)
                labels = [item[0] for item in sorted_vulns]
                values = [item[1] for item in sorted_vulns]
                
                # Create pie chart
                pie_charts.append(go.Pie(
                    labels=labels,
                    values=values,
                    name=target,
                    domain={'row': 0, 'column': len(pie_charts)},
                    hole=0.4,
                    textinfo='label+value',
                    title=target
                ))
        
        if not pie_charts:
            return None
        
        # Create figure with all pie charts
        fig = go.Figure(data=pie_charts)
        
        fig.update_layout(
            title="Web Vulnerabilities by Target",
            grid={'rows': 1, 'columns': len(pie_charts)},
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "web_vulnerabilities_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'pie',
            'title': 'Web Vulnerabilities by Target'
        }
        
        self.report_data['web_vulnerabilities_chart'] = result
        return result
    
    def generate_all_charts(self, targets: Optional[List[str]] = None) -> Dict:
        """Generate all web analysis charts for the given targets"""
        self.create_api_endpoint_chart(targets)
        self.create_script_analysis_chart(targets)
        self.create_framework_usage_chart(targets)
        self.create_web_vulnerabilities_chart(targets)
        
        return self.report_data


# ---- HTML Report Extension ----

# Add Web Analysis section to HTMLReportGenerator
def _generate_web_section(self) -> str:
    """Generate the web analysis section for the HTML report"""
    html = ""
    
    # Add API endpoint chart if available
    if 'api_endpoints_chart' in self.charts and self.charts['api_endpoints_chart']:
        html += f"""
        <div class="chart-container">
            <img src="data:image/png;base64,{self.charts['api_endpoints_chart']['base64_image']}" alt="API Endpoints Chart">
            <p>Number of API endpoints discovered on each target.</p>
        </div>
        """
    
    # Add script analysis chart if available
    if 'script_analysis_chart' in self.charts and self.charts['script_analysis_chart']:
        html += f"""
        <div class="chart-container">
            <img src="data:image/png;base64,{self.charts['script_analysis_chart']['base64_image']}" alt="Script Analysis Chart">
            <p>Distribution of JavaScript files on each target, classified by type.</p>
        </div>
        """
    
    # Add framework usage chart if available
    if 'framework_usage_chart' in self.charts and self.charts['framework_usage_chart']:
        html += f"""
        <div class="chart-container">
            <img src="data:image/png;base64,{self.charts['framework_usage_chart']['base64_image']}" alt="Framework Usage Chart">
            <p>Heatmap showing web framework usage across targets.</p>
        </div>
        """
    
    # Add web vulnerabilities chart if available
    if 'web_vulnerabilities_chart' in self.charts and self.charts['web_vulnerabilities_chart']:
        html += f"""
        <div class="chart-container">
            <img src="data:image/png;base64,{self.charts['web_vulnerabilities_chart']['base64_image']}" alt="Web Vulnerabilities Chart">
            <p>Distribution of web vulnerabilities by type for each target.</p>
        </div>
        """
    
    # Add API endpoints table
    html += """
    <h3>API Endpoints</h3>
    <table>
        <tr>
            <th>Target</th>
            <th>Endpoint</th>
            <th>Detected In</th>
        </tr>
    """
    
    has_endpoints = False
    
    for target, endpoints in self.metrics.get('api_endpoints', {}).items():
        if not endpoints:
            continue
            
        has_endpoints = True
        
        for i, endpoint in enumerate(endpoints[:20]):  # Limit to first 20 endpoints
            html += f"""
            <tr>
                <td>{target if i == 0 else ''}</td>
                <td>{endpoint}</td>
                <td>{"HTML" if "/api/" in endpoint or "/v1/" in endpoint else "JavaScript"}</td>
            </tr>
            """
        
        if len(endpoints) > 20:
            html += f"""
            <tr>
                <td></td>
                <td><em>... and {len(endpoints) - 20} more</em></td>
                <td></td>
            </tr>
            """
    
    if not has_endpoints:
        html += """
        <tr>
            <td colspan="3" style="text-align:center;">No API endpoints discovered</td>
        </tr>
        """
    
    html += """
    </table>
    """
    
    # Add JavaScript analysis table
    html += """
    <h3>JavaScript Analysis</h3>
    <table>
        <tr>
            <th>Target</th>
            <th>Script</th>
            <th>Size (KB)</th>
            <th>Type</th>
            <th>Frameworks</th>
            <th>Risk Factors</th>
        </tr>
    """
    
    has_scripts = False
    
    for target, scripts in self.metrics.get('scripts', {}).items():
        if not scripts:
            continue
            
        has_scripts = True
        
        for i, script in enumerate(scripts[:15]):  # Limit to first 15 scripts
            script_url = script.get('url', '')
            script_name = os.path.basename(script_url)
            script_size = f"{script.get('size', 0) / 1024:.1f}"
            
            # Determine type
            if script.get('obfuscated', False):
                script_type = '<span style="color:red">Obfuscated</span>'
            elif script.get('minified', False):
                script_type = '<span style="color:orange">Minified</span>'
            else:
                script_type = '<span style="color:green">Regular</span>'
            
            # Frameworks
            frameworks = ", ".join(script.get('frameworks', []))
            
            # Risk factors
            risk_factors = []
            if script.get('obfuscated', False):
                risk_factors.append("Obfuscation")
            
            for func in script.get('sensitive_functions', []):
                if func in ['eval', 'new Function', 'document.write']:
                    risk_factors.append(func)
            
            risk_html = ""
            if risk_factors:
                risk_html = f"<span style=\"color:red\">{', '.join(risk_factors)}</span>"
            
            html += f"""
            <tr>
                <td>{target if i == 0 else ''}</td>
                <td>{script_name}</td>
                <td>{script_size}</td>
                <td>{script_type}</td>
                <td>{frameworks}</td>
                <td>{risk_html}</td>
            </tr>
            """
        
        if len(scripts) > 15:
            html += f"""
            <tr>
                <td></td>
                <td><em>... and {len(scripts) - 15} more</em></td>
                <td></td>
                <td></td>
                <td></td>
                <td></td>
            </tr>
            """
    
    if not has_scripts:
        html += """
        <tr>
            <td colspan="6" style="text-align:center;">No JavaScript files analyzed</td>
        </tr>
        """
    
    html += """
    </table>
    
    <p><strong>Note:</strong> Obfuscated scripts and scripts using potentially dangerous functions like eval() may represent security risks and should be investigated further.</p>
    """
    
    # Add web vulnerabilities table
    if 'web_vulnerabilities' in self.metrics:
        html += """
        <h3>Web Vulnerabilities</h3>
        <table>
            <tr>
                <th>Target</th>
                <th>Vulnerability</th>
                <th>Description</th>
                <th>Severity</th>
            </tr>
        """
        
        has_vulns = False
        
        for target, vulns in self.metrics['web_vulnerabilities'].items():
            if not vulns:
                continue
                
            has_vulns = True
            
            for i, vuln in enumerate(vulns):
                name = vuln.get('name', 'Unknown')
                description = vuln.get('description', '')
                severity = vuln.get('severity', 'medium')
                
                # Determine color based on severity
                color = "orange"
                if severity.lower() == "high":
                    color = "red"
                elif severity.lower() == "low":
                    color = "green"
                
                html += f"""
                <tr>
                    <td>{target if i == 0 else ''}</td>
                    <td>{name}</td>
                    <td>{description}</td>
                    <td style="color:{color}"><strong>{severity.upper()}</strong></td>
                </tr>
                """
        
        if not has_vulns:
            html += """
            <tr>
                <td colspan="4" style="text-align:center;">No web vulnerabilities detected</td>
            </tr>
            """
        
        html += """
        </table>
        """
    
    return html


# Extend the HTMLReportGenerator.generate_html_report method to include web section
def extended_generate_html_report(self, output_file: str, title: str = "Network Reconnaissance Report") -> str:
    """Generate a comprehensive HTML report with all charts and data including web analysis"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        .chart-container {{
            margin: 20px 0;
            text-align: center;
        }}
        .chart-container img {{
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .footer {{
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }}
        .alert {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .alert-danger {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }}
        .alert-warning {{
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
        }}
        .alert-success {{
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Executive Summary</h2>
        {self._generate_executive_summary()}
        
        <h2>Security Scores</h2>
        {self._generate_security_score_section()}
        
        <h2>Vulnerability Analysis</h2>
        {self._generate_vulnerability_section()}
        
        <h2>Network Analysis</h2>
        {self._generate_network_section()}
        
        <h2>Open Ports Analysis</h2>
        {self._generate_ports_section()}
        
        <h2>Web Analysis</h2>
        {self._generate_web_section()}
        
        <h2>OSINT Data</h2>
        {self._generate_osint_section()}
        
        <h2>Statistical Analysis</h2>
        {self._generate_regression_section()}
        
        <div class="footer">
            <p>This report was automatically generated by the Network Reconnaissance and Vulnerability Assessment Tool</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html)
    
    return output_file


# Add the new method to HTMLReportGenerator
HTMLReportGenerator._generate_web_section = _generate_web_section

# Override the generate_html_report method
original_generate_html_report = HTMLReportGenerator.generate_html_report
HTMLReportGenerator.generate_html_report = extended_generate_html_report


# ---- CLI Integration ----

# Extend main_async function to include web analysis options
async def extended_main_async():
    """Main async entry point with web analysis options"""
    parser = argparse.ArgumentParser(description="Enhanced Network Reconnaissance and Vulnerability Assessment Tool")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="Target IP address(es) or domain(s)")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--results-dir", type=str, default="recon_results", help="Directory to store results")
    
    # Add strategy options
    strategy_group = parser.add_argument_group("Scan Strategy")
    strategy_group.add_argument("--strategy", type=str, 
                               choices=["network_recon", "smb_enum", "vulnerability", "osint", "web_analysis", "all"], 
                               default="network_recon", help="Scanning strategy to use")
    
    # Add web analysis options
    web_group = parser.add_argument_group("Web Analysis")
    web_group.add_argument("--web-analysis", action="store_true", help="Perform web application analysis")
    web_group.add_argument("--max-depth", type=int, default=2, help="Maximum crawling depth")
    web_group.add_argument("--respect-robots", action="store_true", default=True, 
                          help="Respect robots.txt restrictions")
    web_group.add_argument("--download-scripts", action="store_true", default=True,
                          help="Download JavaScript files for analysis")
    web_group.add_argument("--rate-limit", type=float, default=1.0,
                          help="Rate limit for web requests (requests per second)")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("recon.log"),
            logging.StreamHandler()
        ]
    )
    
    # Load config
    config = await SMBScannerConfig.from_yaml(args.config)
    
    # Create credential if provided
    credential = None
    if args.username or args.password:
        credential = Credential(args.username or "", args.password or "")
    
    # Run appropriate strategy based on selection
    results = {}
    
    for target in args.targets:
        # Run web analysis if requested
        if args.web_analysis or args.strategy == "web_analysis" or args.strategy == "all":
            logging.info(f"Running web analysis for {target}")
            
            web_strategy = WebAnalysisStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir,
                max_depth=args.max_depth,
                respect_robots=args.respect_robots,
                download_scripts=args.download_scripts,
                rate_limit=args.rate_limit
            )
            
            results[f"{target}_web"] = await web_strategy.execute()
        
        # Run other strategies as needed
        if args.strategy == "network_recon" or args.strategy == "all":
            network_strategy = NetworkReconStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir
            )
            results[f"{target}_network"] = await network_strategy.execute(credential)
        
        if args.strategy == "osint" or args.strategy == "all":
            osint_strategy = OSINTStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir
            )
            results[f"{target}_osint"] = await osint_strategy.execute()
        
        if args.strategy == "smb_enum" or args.strategy == "all":
            logging.info(f"Running SMB enumeration for {target}")
            enumerator = SMBEnumerator(
                targets=[target],
                config=config,
                username=args.username,
                password=args.password,
                results_dir=args.results_dir
            )
            
            if await enumerator.validate_environment():
                smb_results = await enumerator.run("intelligent")
                results.update(smb_results)
            else:
                logging.error("SMB enumeration environment validation failed")
        
        if args.strategy == "vulnerability" or args.strategy == "all":
            logging.info(f"Running vulnerability scan for {target}")
            vuln_strategy = VulnerabilityScanStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir
            )
            
            if await enumerator.validate_environment():
                results[f"{target}_vuln"] = await vuln_strategy.execute(credential)
            else:
                logging.error("Vulnerability scanning environment validation failed")
    
    # Process all results and generate comprehensive report with web analysis data
    if results:
        # Create data processor
        processor = NetworkDataProcessor(args.results_dir)
        
        # Load all results
        for target in args.targets:
            await processor.load_scan_results(target)
        
        # Extract standard metrics
        metrics = processor.extract_metrics()
        
        # Extract web metrics
        web_metrics = processor.extract_web_metrics()
        
        # Create visualizer
        visualizer = NetworkVisualizer(metrics, "visual_reports")
        charts = visualizer.generate_all_charts(args.targets)
        
        # Create web visualizer
        web_visualizer = WebAnalysisVisualizer(metrics, "visual_reports")
        web_charts = web_visualizer.generate_all_charts(args.targets)
        
        # Combine all charts
        all_charts = {**charts, **web_charts}
        
        # Generate regression analysis if enough targets
        regression_results = None
        if len(metrics['security_score']) >= 2:
            df, features = processor.prepare_data_for_regression()
            analyzer = RegressionAnalyzer(df, features)
            regression_results = analyzer.perform_regression()
            if regression_results:
                visualizer.create_regression_chart(regression_results, df)
        
        # Generate HTML report
        report_generator = HTMLReportGenerator(metrics, all_charts, regression_results)
        report_file = os.path.join("visual_reports", f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        output_file = report_generator.generate_html_report(report_file, "Network and Web Application Reconnaissance Report")
        
        logging.info(f"Comprehensive report saved to {output_file}")


# Update main function
def extended_main():
    """Entry point for the script"""
    asyncio.run(extended_main_async())


# Override main function with the extended version
main = extended_main
