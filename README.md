# XSeeker

# Advanced XSS Vulnerability Scanner

A comprehensive XSS vulnerability scanner that detects various types of XSS vulnerabilities including Reflected, Stored, DOM-based, Blind, Mutation, Self, mXSS, Event-based, and Polyglot XSS. The scanner includes WAF bypass capabilities, payload fuzzing, and automated reporting.

## Features

- Detects multiple types of XSS vulnerabilities:
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
  - Blind XSS
  - Mutation XSS
  - Self XSS
  - mXSS
  - Event-based XSS
  - Polyglot XSS

- Advanced WAF bypass techniques:
  - Multiple encoding methods
  - Obfuscation techniques
  - Null byte injection
  - Mixed case payloads
  - Whitespace manipulation

- Comprehensive payload testing:
  - Pre-defined payload database
  - Custom payload support
  - Payload fuzzing
  - Context-aware testing

- Automated reporting:
  - JSON report generation
  - Detailed vulnerability information
  - Response analysis
  - Screenshot capture (optional)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/xss-scanner.git
cd xss-scanner
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python xss_scanner.py https://target-url.com
```

With configuration file:
```bash
python xss_scanner.py https://target-url.com --config config.yaml
```

## Configuration

The scanner can be configured using the `config.yaml` file. Key configuration options include:

- Scanner settings (timeout, threads, user agent)
- Payload categories
- WAF bypass techniques
- Reporting options

## Output

The scanner generates two types of output:

1. Console output with real-time scanning progress and findings
2. JSON report file (`xss_report.json`) containing detailed vulnerability information

## Example Report

```json
{
    "url": "https://example.com/search",
    "type": "reflected",
    "payload": "<script>alert(1)</script>",
    "response_length": 1234,
    "status_code": 200
}
```

## Security Notice

This tool is for educational and authorized security testing purposes only. Always:

1. Obtain proper authorization before testing any website
2. Follow responsible disclosure practices
3. Respect website terms of service and robots.txt
4. Do not use for malicious purposes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
