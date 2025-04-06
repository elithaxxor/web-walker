import logging
import asyncio
from fetcher import WebPageFetcher
from parser import MyHTMLParser

logger = logging.getLogger(__name__)

class WebPageAnalyzer:
    def __init__(self, fetcher: WebPageFetcher):
        """Initialize the analyzer with a fetcher instance."""
        self.fetcher = fetcher

    def analyze_page(self, status_code, headers, content_type, body, hostname, path, is_https, detect_db=False, detect_hidden=False):
        """Analyze the fetched page based on its content type."""
        if "text/html" in content_type:
            self._analyze_html(body, headers, hostname, path, is_https, detect_db, detect_hidden)
        else:
            logger.info(f"Content type {content_type} not supported for analysis.")

    def _analyze_html(self, html, headers, hostname, path, is_https, detect_db, detect_hidden):
        """Analyze HTML content, extracting and reporting data."""
        parser = MyHTMLParser()
        parser.feed(html)
        
        if detect_db:
            self.fetcher.detect_database(headers, html)
        
        for link in parser.links:
            logger.info(f"Link: {self.fetcher._resolve_url(hostname, path, link, is_https)}")
        
        if detect_hidden:
            self._report_hidden_elements(parser.hidden_elements)
            self._report_suspicious_patterns(parser.suspicious_patterns)
        
        asyncio.run(self._fetch_external_scripts(parser.scripts, hostname, path, is_https))

    async def _fetch_external_scripts(self, scripts, hostname, path, is_https):
        """Asynchronously fetch external scripts."""
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.fetcher.fetch_external_resource(
                    self.fetcher._resolve_url(hostname, path, script["src"], is_https), session
                )
                for script in scripts if script["type"] == "external"
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for script, result in zip([s for s in scripts if s["type"] == "external"], results):
                if isinstance(result, str):
                    script["content"] = result
                    logger.info(f"External Script {script['src']}:\n{result[:100]}...")

    def _report_hidden_elements(self, hidden_elements):
        """Report hidden elements found in the HTML."""
        if hidden_elements:
            logger.info("Hidden Elements:")
            for elem in hidden_elements:
                logger.info(f"Tag: {elem['tag']}, Reason: {elem['reason']}")

    def _report_suspicious_patterns(self, suspicious_patterns):
        """Report suspicious patterns found in the HTML."""
        if suspicious_patterns:
            logger.info("Suspicious Patterns:")
            for pattern in suspicious_patterns:
                logger.info(f"Tag: {pattern['tag']}, Attr: {pattern['attr']}, Reason: {pattern['reason']}")
