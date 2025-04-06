import argparse
import logging
from fetcher import WebPageFetcher, ConnectionError, HTTPError
from analyzer import WebPageAnalyzer

logger = logging.getLogger(__name__)

def main():
    """Main function to run the web analyzer."""
    parser = argparse.ArgumentParser(description="Web Analyzer")
    parser.add_argument("--url", help="URL to analyze")
    parser.add_argument("--show-cert", action="store_true", help="Show SSL certificate")
    parser.add_argument("--detect-db", action="store_true", help="Detect databases")
    parser.add_argument("--detect-hidden", action="store_true", help="Detect hidden/suspicious elements")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    fetcher = WebPageFetcher()
    analyzer = WebPageAnalyzer(fetcher)

    url = args.url or input("Enter URL: ")
    try:
        status_code, headers, content_type, body, hostname, path, is_https = fetcher.fetch_page(
            url, args.show_cert, not args.no_verify_ssl
        )
        analyzer.analyze_page(
            status_code, headers, content_type, body, hostname, path, is_https, args.detect_db, args.detect_hidden
        )
    except (ConnectionError, HTTPError) as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    main()
