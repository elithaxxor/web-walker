
---

# WebWalker V2.1

**WebWalker** is a powerful, security-focused command-line tool designed to analyze web pages with an emphasis on identifying potential security risks and extracting meaningful insights. Whether you're a developer, security researcher, or enthusiast, WebWalker equips you with the ability to fetch web pages, inspect SSL/TLS certificates, analyze HTML for suspicious patterns, and optionally leverage Large Language Models (LLMs) for advanced text analysis like sentiment analysis and named entity recognition (NER).

## Features

- **Web Page Fetching**: Retrieve and display basic information about a web page, including HTTP status codes and content snippets.
- **HTML Security Analysis**: Parse HTML to uncover hidden elements (e.g., `display: none`, offscreen elements) and flag suspicious patterns (e.g., inline scripts, JavaScript URIs).
- **SSL/TLS Certificate Inspection**: Extract and display detailed information about a website's SSL certificate, such as issuer, validity, and subject alternative names (SANs).
- **Optional LLM Integration**: Use Hugging Face's Transformers library to perform advanced text analysis, including sentiment analysis and named entity recognition, on web page content.

## Installation

### Prerequisites

To use WebWalker, ensure you have the following installed:
- **Python 3.6 or higher**: The tool is written in Python and requires a compatible version.
- **Required Dependency**: The `cryptography` library for SSL certificate analysis.
- **Optional Dependency**: The `transformers` library for LLM-based features (sentiment analysis and NER).

### Steps to Install

1. **Install Python**: If you don’t already have Python installed, download it from [python.org](https://www.python.org/downloads/) and follow the installation instructions for your operating system.

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/webwalker.git
   cd webwalker
   ```

3. **Install Required Dependencies**:
   Use pip to install the `cryptography` library:
   ```bash
   pip install cryptography
   ```

4. **(Optional) Install LLM Support**:
   For sentiment analysis or NER, install the `transformers` library:
   ```bash
   pip install transformers
   ```

> **Note**: If `transformers` is not installed, LLM-related features will be unavailable, and WebWalker will log a warning when you attempt to use them.

## Usage

WebWalker supports two modes of operation: **Command-Line Mode** for quick, one-off analyses and **Interactive Mode** for a more dynamic, menu-driven experience.

### Command-Line Mode

In Command-Line Mode, you specify the URL and options directly when running the script. The syntax is:

```bash
python webwalker.py <URL> [--show-cert] [--enable-llm <model>]
```

- `<URL>`: The web page URL to analyze (e.g., `https://example.com`). This is required.
- `--show-cert`: (Optional) Display detailed SSL/TLS certificate information (HTTPS URLs only).
- `--enable-llm <model>`: (Optional) Enable LLM analysis with one of the following models:
  - `sentiment`: Analyze the sentiment of the page's text.
  - `ner`: Perform named entity recognition on the page's text.

#### Command-Line Examples

- **Basic Page Fetch**:
  ```bash
  python webwalker.py https://example.com
  ```
  - Output: Logs the HTTP status code and a snippet of the page content.

- **Fetch with Certificate Details**:
  ```bash
  python webwalker.py https://example.com --show-cert
  ```
  - Output: Logs the page details plus SSL certificate information (e.g., subject, issuer, validity).

- **Fetch with Sentiment Analysis**:
  ```bash
  python webwalker.py https://example.com --enable-llm sentiment
  ```
  - Output: Logs the page details and the sentiment of the text (e.g., "POSITIVE (score: 0.95)") if `transformers` is installed.

- **Fetch with Named Entity Recognition**:
  ```bash
  python webwalker.py https://example.com --enable-llm ner
  ```
  - Output: Logs the page details and a list of extracted entities (e.g., names, organizations) if `transformers` is installed.

### Interactive Mode

If you run WebWalker without arguments, it launches **Interactive Mode**, providing a menu-driven interface for entering commands.

Start Interactive Mode with:
```bash
python webwalker.py
```

You’ll see a prompt like this:
```
Welcome to WebWalker Interactive Mode
Available commands:
  fetch <url> : Fetch the URL
  cert <url> : Fetch and show certificate
  sentiment <url> : Fetch and perform sentiment analysis
  ner <url> : Fetch and perform NER
  help : Show this message
  exit : Exit
WebWalker>
```

#### Available Commands

- **`fetch <url>`**: Fetch the specified URL and display basic information.
- **`cert <url>`**: Fetch the URL and show its SSL certificate details (HTTPS only).
- **`sentiment <url>`**: Fetch the URL and analyze the text's sentiment (requires `transformers`).
- **`ner <url>`**: Fetch the URL and extract named entities (requires `transformers`).
- **`help`**: Display the command list.
- **`exit`**: Quit Interactive Mode.

#### Example Interactive Session

```
WebWalker> fetch https://example.com
[INFO] HTTP Status: 200
[INFO] Content snippet: <html><head><title>Example Domain</title></head>...

WebWalker> cert https://example.com
[INFO] HTTP Status: 200
[INFO] Content snippet: <html><head><title>Example Domain</title></head>...
[INFO] Certificate Info:
[INFO]   Subject: CN=example.com
[INFO]   Issuer: CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US
[INFO]   Validity: valid
[INFO]   Valid From: 2023-01-01T00:00:00
[INFO]   Valid To: 2023-04-01T00:00:00
[INFO]   SANs: DNS:example.com, DNS:www.example.com
[INFO]   SHA-256 Fingerprint: 1234abcd...

WebWalker> sentiment https://example.com
[INFO] HTTP Status: 200
[INFO] Content snippet: <html><head><title>Example Domain</title></head>...
[INFO] Sentiment: POSITIVE (score: 0.95)

WebWalker> exit
```

## How It Works

WebWalker is built with modularity in mind, relying on several key components:

- **`HTTPClient`**: Manages HTTP/HTTPS requests and retrieves raw certificates.
- **`SecurityHTMLParser`**: Parses HTML to detect hidden or suspicious elements and extracts text for analysis.
- **`CertificateAnalyzer`**: Processes and formats SSL certificate details.
- **`LLMAnalyzer`**: Integrates with the `transformers` library for optional LLM-based text analysis.

### Security Features

- **Hidden Element Detection**: Identifies elements hidden via CSS (`display: none`, `visibility: hidden`) or HTML attributes (`hidden`).
- **Suspicious Pattern Detection**: Flags potential risks like inline event handlers (e.g., `onclick="..."`) or JavaScript URIs (e.g., `href="javascript:..."`).

### LLM Capabilities

When `transformers` is installed, WebWalker can:
- Analyze the **sentiment** of a page's text (e.g., positive, negative, neutral).
- Identify **named entities** such as people, organizations, or locations in the text.

## Changelog

### Version 1.0.0 (Initial Release)
- Initial implementation of web page fetching and basic content analysis.
- Added SSL/TLS certificate inspection functionality.
- Integrated optional LLM support for sentiment analysis and NER.
- Introduced Interactive Mode with a command menu.
- Included logging and basic error handling.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

---

This README provides everything a user needs to get started with WebWalker, from installation to detailed usage examples, while also offering a changelog to track future updates. Let me know if you'd like to adjust anything!
