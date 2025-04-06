
---

# WebAnalyzer

**WebAnalyzer** is a security-focused tool designed for fetching and analyzing web pages. It extracts links, scripts, hidden elements, and suspicious patterns from HTML content, while also offering features like SSL certificate inspection and database detection. This tool is ideal for security auditing, reconnaissance, and web page analysis.

## Table of Contents
- [Features](#features)
- [Improvements Between Versions](#improvements-between-versions)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Examples](#examples)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Fetch Web Pages**: Supports HTTP and HTTPS with automatic redirect handling.
- **SSL Certificate Inspection**: Optionally displays detailed SSL certificate information for HTTPS URLs.
- **HTML Parsing**: Extracts links, scripts (inline and external), hidden elements, and suspicious patterns.
- **Database Detection**: Identifies potential use of MySQL, PostgreSQL, or SQLite based on HTML content and headers.
- **Suspicious Pattern Detection**: Detects inline event handlers, `javascript:` URIs, and potential obfuscation (e.g., `eval`).
- **Asynchronous Fetching**: Utilizes `aiohttp` for concurrent fetching of external scripts, boosting performance.
- **Modular Design**: Organized into separate modules for fetching, parsing, analyzing, and orchestration.

## Improvements Between Versions

The WebAnalyzer project has undergone significant enhancements from its initial release. Below are the key changes between versions:

### Version 1.0 (Initial Version)
- **Basic Fetching**: Used `requests` for simple web page retrieval.
- **Limited Parsing**: Only extracted links from HTML content.
- **No Robustness**: Lacked error handling and SSL support.

### Version 2.0 (Current Version)
- **Modular Structure**: Code split into `fetcher.py`, `parser.py`, `analyzer.py`, and `main.py` for improved maintainability.
- **Enhanced Error Handling**: Added retries for network requests, custom exceptions (`HTTPError`, `ConnectionError`), and detailed logging.
- **SSL Security**: Enabled SSL verification by default, with an option to disable it using `--no-verify-ssl`.
- **Advanced Detection**: Added database detection (MySQL, PostgreSQL, SQLite) and expanded suspicious pattern analysis (e.g., inline event handlers, `javascript:` URIs).
- **Performance Boost**: Switched to `aiohttp` for asynchronous fetching of external scripts.
- **Command-Line Flexibility**: Introduced options for SSL inspection, database detection, and hidden element analysis.

These updates make WebAnalyzer more reliable, secure, and efficient for web analysis tasks.

## Installation

Follow these steps to set up WebAnalyzer on your system:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/WebAnalyzer.git
   cd WebAnalyzer
   ```

2. **Install Dependencies**:
   WebAnalyzer requires `aiohttp` and `cryptography`. Install them with:
   ```bash
   pip install aiohttp cryptography
   ```

3. **Run the Tool**:
   Launch the tool with a sample URL:
   ```bash
   python main.py --url https://example.com
   ```

## Usage

WebAnalyzer is a command-line tool with customizable options to tailor its functionality to your needs.

### Command-Line Options

- `--url <URL>`: The URL to analyze. If omitted, the tool prompts for input.
- `--show-cert`: Displays detailed SSL certificate information (HTTPS only).
- `--detect-db`: Enables detection of database signatures (MySQL, PostgreSQL, SQLite).
- `--detect-hidden`: Activates detection of hidden elements and suspicious patterns.
- `--no-verify-ssl`: Disables SSL certificate verification (use cautiously).

### Examples

1. **Basic Analysis**:
   Fetch and analyze a web page to extract links:
   ```bash
   python main.py --url https://example.com
   ```

2. **Inspect SSL Certificate**:
   Retrieve and display SSL certificate details:
   ```bash
   python main.py --url https://example.com --show-cert
   ```

3. **Detect Databases and Hidden Elements**:
   Analyze a page for database usage and hidden/suspicious content:
   ```bash
   python main.py --url https://example.com --detect-db --detect-hidden
   ```

4. **Bypass SSL Verification**:
   Fetch a page without verifying its SSL certificate (for testing purposes):
   ```bash
   python main.py --url https://example.com --no-verify-ssl
   ```

5. **Interactive Mode**:
   Run the tool without a URL to enter one manually:
   ```bash
   python main.py
   Enter URL: https://example.com
   ```

## Project Structure

The codebase is organized into four main modules:

- **`fetcher.py`**: Manages web page fetching, SSL verification, and external resource retrieval.
- **`parser.py`**: Parses HTML to extract links, scripts, hidden elements, and suspicious patterns.
- **`analyzer.py`**: Analyzes parsed data, detects databases, and generates reports.
- **`main.py`**: Coordinates execution, processes command-line arguments, and handles user interaction.

This structure enhances maintainability and scalability.

## Contributing

We welcome contributions! If you have ideas for new features or improvements, please open an issue or submit a pull request. Ensure your code aligns with the project’s structure and includes relevant tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

This `README.md` provides a clear, user-friendly guide to WebAnalyzer, detailing its evolution, features, and usage with practical examples. It’s designed to help users quickly get started and make the most of the tool.
