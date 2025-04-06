from html.parser import HTMLParser
import re
import logging

logger = logging.getLogger(__name__)

class MyHTMLParser(HTMLParser):
    def __init__(self):
        """Initialize the parser with empty lists for collected data."""
        super().__init__()
        self.links = []
        self.scripts = []
        self.hidden_elements = []
        self.suspicious_patterns = []

    def handle_starttag(self, tag, attrs):
        """Handle the start of an HTML tag, collecting relevant data."""
        if tag == "a":
            for attr, value in attrs:
                if attr == "href":
                    self.links.append(value)
        elif tag == "script":
            src = next((v for a, v in attrs if a == "src"), None)
            self.scripts.append({"type": "external" if src else "inline", "src": src, "content": "" if not src else None})
        self._check_hidden_elements(tag, attrs)
        self._check_suspicious_patterns(tag, attrs)

    def _check_hidden_elements(self, tag, attrs):
        """Check for hidden elements based on attributes or styles."""
        style = next((v.lower() for a, v in attrs if a == "style"), "")
        if any(a == "hidden" for a, _ in attrs) or "display: none" in style:
            self.hidden_elements.append({"tag": tag, "reason": "hidden"})

    def _check_suspicious_patterns(self, tag, attrs):
        """Check for suspicious patterns like event handlers or obfuscation."""
        for attr, value in attrs:
            if attr.startswith("on") and value:
                self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "event handler"})
            elif attr == "href" and value.startswith("javascript:"):
                self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "javascript URI"})
            elif re.search(r"eval\(|unescape\(", value):
                self.suspicious_patterns.append({"tag": tag, "attr": attr, "value": value, "reason": "obfuscation"})
