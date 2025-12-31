# 🎯 ParamHunter Pro

**ParamHunter Pro** is an advanced static analysis and penetration testing tool designed to uncover hidden secrets, vulnerabilities, and information leaks in source code and web assets. 

It is designed for security researchers, penetration testers, and bug bounty hunters to quickly analyze files and directories for "low-hanging fruit" and deep-hidden secrets.

## ✨ Key Features

- **🔐 Secret Detection**: Identifies API keys, JWT tokens, AWS keys, Google Storage URLs, and more.
- **🎲 Advanced Entropy Analysis**: Uses Shannon Entropy to detect *unknown* high-entropy secrets (like random passwords or encryption keys) that regex misses.
- **☁️ Cloud Infrastructure Discovery**: Detects exposed S3 buckets, Azure Blobs, Internal IP addresses, and Cloud Metadata URLs.
- **💬 Deep Comment Analysis**: Extracts and analyzes comments from 15+ languages (Python, JS, HTML, etc.) to find leaked credentials or "TODO" notes.
- **🚨 Vulnerability Scanning**: Flags dangerous sinks (DOM XSS), SQL injection patterns, and unsafe functions (`eval`, `exec`).
- **🕷️ Companion Web Crawler**: Includes a robust crawler to download assets from target websites for offline analysis.

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/eyasuasegid/param-hunter-pro.git
   cd param-hunter-pro
   ```

2. Install dependencies:
   ```bash
   pip3 install requests beautifulsoup4 colorama
   ```

## 🛠️ Usage

### 1. Param Hunter (The Analyzer)

**Basic Scan (Summary Only)**
By default, the tool shows a clean summary of findings to avoid clutter.
```bash
python3 param_hunter_pro.py <file_or_directory>
```

**Detailed Listing (`-l`)**
Use the `-l` flag to see specific details.
```bash
# List all Cloud Infrastructure findings (S3 buckets, etc.)
python3 param_hunter_pro.py target/ -l cloud

# List High-Entropy Strings (potential secrets)
python3 param_hunter_pro.py target/ -l entropy

# List all Potentially Vulnerable Sinks
python3 param_hunter_pro.py target/ -l vuln

# List comments (filter by language)
python3 param_hunter_pro.py target/ -l comment python
python3 param_hunter_pro.py target/ -l comment html

# Show EVERYTHING
python3 param_hunter_pro.py target/ -l all
```

**Available Flags**
- `-l cloud`: Cloud resources & internal IPs.
- `-l entropy`: High-entropy strings.
- `-l secret`: Secrets (Specific regex matches).
- `-l vuln`: Vulnerabilities.
- `-l comment`: Comments (optionally add `html`, `js`, `python`, `other`).
- `-l service`: Detected services and versions.
- `-l url`: URLs and parameters.
- `-l all`: Full report.




## ⚠️ Disclaimer

This tool is for **educational and authorized security testing purposes only**. Do not use this tool on systems you do not have explicit permission to test. The authors are not responsible for any misuse.
