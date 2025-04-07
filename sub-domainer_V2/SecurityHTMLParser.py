from html.parser import HTMLParser
from typing import List, Tuple

class SecurityHTMLParser(HTMLParser):
    """Parses HTML to extract text and detect suspicious patterns."""
    def __init__(self):
        """Initialize the parser with empty text and patterns lists."""
        super().__init__()
        self.text = ""  # Accumulated text content
        self.suspicious_patterns = []  # List of detected security issues

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        """Checks for suspicious HTML patterns in tags.
        
        Args:
            tag (str): The HTML tag name.
            attrs (List[Tuple[str, str]]): List of (name, value) attribute pairs.
        """
        attrs_dict = dict(attrs)
        if tag == 'script' and 'src' not in attrs_dict:
            self.suspicious_patterns.append("Inline script detected")
        if tag == 'a' and 'href' in attrs_dict and attrs_dict['href'].lower().startswith('javascript:'):
            self.suspicious_patterns.append("JavaScript URI in link")

    def handle_data(self, data: str) -> None:
        """Collects text data from the HTML.
        
        Args:
            data (str): The text content between tags.
        """
        self.text += data.strip()
