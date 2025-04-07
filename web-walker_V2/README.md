---

# 🕵️🔍 WebAnalyzer

**WebAnalyzer** is a powerful tool for analyzing web pages with a focus on security and detailed insights. It extracts links, scripts, hidden elements, and identifies suspicious patterns while offering advanced features like SSL certificate inspection and database detection.

<p align="center">
  <img src="https://via.placeholder.com/1200x300/0d1117/3498db?text=WebAnalyzer:+Web+Security+Analysis+Tool" alt="WebAnalyzer Banner">
</p>

[![Python Version](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![GitHub Issues](https://img.shields.io/badge/Issues-0-red?style=for-the-badge&logo=github)](https://github.com/yourusername/WebAnalyzer/issues)
[![Stars](https to yourusername/WebAnalyzer/stargazers)](https://github.com/yourusername/WebAnalyzer)

---

## 📋 Table of Contents

- [🌟 Features](#-features)
- [🔄 Version Improvements](#-version-improvements)
- [⚙️ Installation](#-installation)
- [🚀 Usage](#-usage)
- [🛠️ Examples](#-examples)
- [🏗️ Project Structure](#-project-structure)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## 🌟 Features

### 🌐 Core Features

- **📡 Web Page Fetching**: Supports HTTP and HTTPS with automatic redirect handling.
- **🔒 SSL Certificate Inspection**: Detailed SSL certificate analysis for HTTPS sites.
- **📊 HTML Parsing**: Extracts links, scripts, hidden elements, and suspicious patterns.
- **🗃️ Database Detection**: Detects MySQL, PostgreSQL, and SQLite usage.
- **🔍 Suspicious Pattern Detection**: Identifies inline scripts, `javascript:` URIs, and potential obfuscation.
- **⚡ Asynchronous Processing**: Uses `aiohttp` for fast, concurrent resource fetching.
- **🧩 Modular Design**: Clean architecture with separate modules for different functionalities.

### 🛡️ Security Features

- **🔐 SSL Verification**: Enabled by default for secure connections.
- **🔍 Vulnerability Detection**: Identifies potential security risks in web pages.
- **📝 Logging**: Detailed logs for comprehensive analysis.

### 📊 Performance Features

- **🔄 Asynchronous Fetching**: Faster processing with concurrent requests.
- **🎯 Efficient Parsing**: Optimized HTML parsing for quick results.
- **📁 Modular Architecture**: Easy to maintain and extend.

---

## 🔄 Version Improvements

### Version Comparison

| Feature                  | Version 1.0                          | Version 2.0 (Current)                |
|---------------------------|---------------------------------------|---------------------------------------|
| **Fetching Method**      | Basic `requests`                      | Asynchronous `aiohttp`               |
| **HTML Parsing**          | Limited to links                     | Comprehensive parsing               |
| **SSL Support**           | No SSL verification                   | SSL verification by default        |
| **Error Handling**        | Basic error handling                 | Robust error handling              |
| **Database Detection**    | No database detection               | Detects MySQL, PostgreSQL, SQLite   |
| **Performance**           | Synchronous processing                | Asynchronous, faster processing    |
| **Code Structure**        | Monolithic structure                 | Modular architecture               |

---

## ⚙️ Installation

### Prerequisites

- Python 3.7+
- pip package manager

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/WebAnalyzer.git
cd WebAnalyzer

# Install dependencies
pip install aiohttp cryptography beautifulsoup4

# Run the tool
python main.py --url https://example.com
```

<details>
<summary>📦 View dependencies</summary>

```
aiohttp>=3.8.1
beautifulsoup4>=4.10.0
cryptography>=36.0.0
```
</details>

---

## 🚀 Usage

### Command-Line Options

| Option                 | Description                                   | Default          |
|-------------------------|-----------------------------------------------|------------------|
| `--url <URL>`           | Target URL to analyze                        | Required         |
| `--show-cert`           | Display SSL certificate details             | Disabled         |
| `--detect-db`           | Enable database detection                   | Disabled         |
| `--detect-hidden`       | Detect hidden elements and suspicious patterns | Disabled       |
| `--no-verify-ssl`        | Disable SSL certificate verification          | Verification on  |
| `--verbose`             | Enable verbose output                       | Disabled         |

### Examples

#### Basic Usage
```bash
python main.py --url https://example.com
```

#### Advanced Usage
```bash
python main.py --url https://example.com --show-cert --detect-db --detect-hidden
```

#### Interactive Mode
```bash
python main.py
Enter URL: https://example.com
```

---

## 🛠️ Examples

### Basic Analysis
```bash
python main.py --url https://example.com
```

### SSL Certificate Inspection
```bash
python main.py --url https://example.com --show-cert
```

### Comprehensive Analysis
```bash
python main.py --url https://example.com --detect-db --detect-hidden --verbose
```

---

## 🏗️ Project Structure

### Module Overview

- **`main.py`**: Entry point and command-line interface.
- **`fetcher.py`**: Handles web requests and SSL verification.
- **`parser.py`**: Parses HTML content and extracts relevant data.
- **`analyzer.py`**: Performs security analysis and generates reports.

### Code Structure

```plaintext
WebAnalyzer/
├── main.py
├── fetcher.py
├── parser.py
├── analyzer.py
├── requirements.txt
└── LICENSE
```

---

## 🤝 Contributing

### How to Contribute

1. **Fork** the repository.
2. **Create** a feature branch: `git checkout -b feature/feature-name`
3. **Commit** your changes: `git commit -m 'Add feature'`
4. **Push** to the branch: `git push origin feature/feature-name`
5. **Submit** a pull request.

### Contribution Guidelines

- Follow PEP 8 coding standards.
- Include unit tests for new features.
- Update documentation as needed.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

<p align="center">
  <img src="https://via.placeholder.com/1200x300/0d1117/3498db?text=WebAnalyzer:+Web+Security+Analysis+Tool" alt="WebAnalyzer Banner">
</p>

<p align="center">
  Made with ❤️ for the security community
</p>

<p align="center">
  ⭐ Star this repo if you find it useful! ⭐
</p>

---
