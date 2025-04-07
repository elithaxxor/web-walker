from html.parser import HTMLParser
from typing import List, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class SecurityHTMLParser(HTMLParser):
    """Parses HTML to extract text and detect suspicious patterns."""
    
    def __init__(self):
        """Initialize the parser with empty text and patterns lists."""
        super().__init__()
        self.text = ""  # Accumulated text content
        self.suspicious_patterns = []  # List of detected security issues
        logging.info("Initialized SecurityHTMLParser")

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        """Checks for suspicious HTML patterns in tags.
        
        Args:
            tag (str): The HTML tag name.
            attrs (List[Tuple[str, str]]): List of (name, value) attribute pairs.
        """
        logging.debug(f"Encountered start tag: {tag} with attributes: {attrs}")
        attrs_dict = dict(attrs)
        if tag == 'script' and 'src' not in attrs_dict:
            self.suspicious_patterns.append("Inline script detected")
            logging.warning("Detected inline script")
        if tag == 'a' and 'href' in attrs_dict and attrs_dict['href'].lower().startswith('javascript:'):
            self.suspicious_patterns.append("JavaScript URI in link")
            logging.warning("Detected JavaScript URI in link")

    def handle_data(self, data: str) -> None:
        """Collects text data from the HTML.
        
        Args:
            data (str): The text content between tags.
        """
        logging.debug(f"Encountered data: {data.strip()}")
        self.text += data.strip()

    def get_text(self) -> str:
        """Retrieve the accumulated text content."""
        return self.text

    def get_suspicious_patterns(self) -> List[str]:
        """Retrieve the list of detected suspicious patterns."""
        return self.suspicious_patterns

    def display_results(self) -> None:
        """Display the text and suspicious patterns to the end user."""
        print("Parsed Text:")
        print(self.get_text())
        print("\nSuspicious Patterns Detected:")
        for pattern in self.get_suspicious_patterns():
            print(f"- {pattern}")

def main():
    """Main function to run the parser as a standalone script."""
    parser = SecurityHTMLParser()
    html_content = """
    <html>
        <head><title>Test</title></head>
        <body>
            <h1>Sample HTML</h1>
            <script>alert('Hello');</script>
            <a href="javascript:alert('Hi');">Click me</a>
            <p>Some text.</p>
        </body>
    </html>
    """
    parser.feed(html_content)
    parser.display_results()

if __name__ == "__main__":
    main()
