# SubX

SubX is a fast and concurrent subdomain takeover detection tool written in Go. It scans subdomains, checks for potential vulnerabilities (like takeover issues), and identifies the underlying services using both built-in mappings and external fingerprint data.

[GitHub Repository](https://github.com/Karthikdude/SubX)

## Table of Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Acknowledgments](#acknowledgments)

## Description

SubX is designed to help security researchers and bug bounty hunters quickly assess subdomains for potential takeover vulnerabilities. It uses concurrent HTTP requests, performs CNAME lookups, and integrates external service fingerprints to identify the hosting service for each subdomain.

## What's New in Version 2.0

Version 2.0 introduces a comprehensive set of new features and improvements:

### Enhanced Service Detection
- **Advanced Fingerprinting**: Added pattern-based detection with regex support
- **Content Analysis**: Detects services based on HTTP response content and headers
- **Expanded Service Database**: Significantly increased the number of detectable services

### Improved Reporting
- **HTML Reports**: Generate interactive HTML reports with vulnerability details
- **Risk Scoring**: Prioritize findings with high/medium/low risk classifications
- **Notification Integration**: Send alerts via Slack, Discord, or email

### Performance Enhancements
- **Adaptive Rate Limiting**: Automatically adjusts request rates based on target response times
- **DNS Caching**: Reduces redundant DNS lookups for faster scanning
- **Distributed Scanning**: Supports scanning across multiple machines

### Additional Features
- **Screenshot Capture**: Automatically capture screenshots of vulnerable subdomains
- **Historical Data Comparison**: Store and compare results over time
- **API Integration**: Use the built-in REST API for programmatic access
- **Configuration Files**: Define settings in YAML/JSON config files

### Security and Usability
- **Proxy Support**: Route requests through SOCKS/HTTP proxies
- **Custom User-Agent**: Set custom User-Agent headers for requests
- **Progress Indicators**: Real-time progress bars and status updates
- **Interactive Mode**: Filter and analyze results in real-time

## Installation

### Prerequisites

- **Go:** Version 1.15 or later is recommended.
- **Git:** For cloning the repository.
- **Dependencies:**  
  All dependencies will be automatically installed with the go mod command.

### Step-by-Step Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/Karthikdude/SubX.git
    ```

2. **Change to the project directory:**
    ```bash
    cd SubX
    ```

3. **Install dependencies:**
    ```bash
    go mod download
    ```

4. **Build the tool:**
    ```bash
    go build -o subx main.go
    ```
    
5. **Move to Global:**
    ```bash
    sudo mv subx /usr/local/bin/
    ```

## Usage

SubX is a command-line tool with several options. Below are a few examples:

### Scan a Single Domain

```bash
subx -u example.com -https -ssl -error
```

### Scan a List of Subdomains

```bash
subx -l subdomains.txt -https -error -ssl -hide -o results.json
```

### Generate an HTML Report

```bash
subx -l subdomains.txt -https -o report.html -screenshot
```

### Use Configuration File

```bash
subx -config config.yaml
```

### Start Web UI

```bash
subx -web -web-port 8081
```

### Command-Line Options

#### Basic Options
- `-u`: Test a single domain
- `-l`: Provide a file containing a list of subdomains
- `-t`: Set the number of threads (default: 100)
- `-time`: Specify the timeout in seconds (default: 30)
- `-o`: Output file (supports `.txt`, `.json`, `.csv`, or `.html` formats)
- `-ssl`: Skip invalid SSL sites
- `-https`: Use HTTPS by default
- `-a`: Skip CNAME check and send requests to every URL
- `-m`: Flag dead records but valid CNAME entries
- `-hide`: Hide failed checks and invulnerable subdomains
- `-cname`: Print detailed CNAME information
- `-error`: Hide errors and failed requests

#### Advanced Options
- `-config`: Path to configuration file (YAML/JSON)
- `-v`: Verbosity level (0-3)
- `-proxy`: Proxy URL (e.g., socks5://127.0.0.1:9050)
- `-ua`: Custom User-Agent string
- `-rate`: Maximum requests per second
- `-adaptive-rate`: Enable adaptive rate limiting
- `-dns`: Custom DNS server (e.g., 8.8.8.8:53)
- `-doh`: DNS over HTTPS server URL
- `-screenshot`: Capture screenshots of vulnerable domains
- `-screenshot-dir`: Directory to save screenshots
- `-db`: Path to SQLite database for historical data
- `-api`: Start RESTful API server
- `-api-port`: Port for API server
- `-web`: Start web UI
- `-web-port`: Port for web UI
- `-slack`: Slack webhook URL for notifications
- `-discord`: Discord webhook URL for notifications
- `-email`: Email address for notifications
- `-smtp`: SMTP server for email notifications
- `-smtp-user`: SMTP username
- `-smtp-pass`: SMTP password
- `-resumable`: Enable resumable scanning
- `-resume-file`: File to store resumable scan state
- `-plugin-dir`: Directory containing detection plugins
- `-respect-robots`: Respect robots.txt directives
- `-interactive`: Enable interactive mode
- `-distributed`: Enable distributed scanning
- `-master`: Master node address for distributed scanning
- `-worker`: Run as worker node for distributed scanning
- `-worker-port`: Port for worker node

## Features

- **Concurrent Scanning:** Uses goroutines and a semaphore to limit the number of concurrent threads.
- **Detailed Output:** Displays structured results including Subdomain, URL, HTTP status, CNAME record, and identified service.
- **External Fingerprints:** Integrates service fingerprints from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) to enhance service identification.
- **Customizable Options:** Various command-line flags allow users to tailor the scanning process.
- **Output Options:** Save results to a JSON, plain text, CSV, or HTML file.
- **Pattern-Based Detection:** Uses regex patterns to identify services beyond exact CNAME matches.
- **Content Analysis:** Detects services based on HTTP response content and headers.
- **Risk Scoring:** Prioritizes findings with high/medium/low risk classifications.
- **Screenshot Capture:** Automatically captures screenshots of vulnerable subdomains.
- **Historical Data:** Stores results in a SQLite database for comparison over time.
- **API Integration:** Provides a RESTful API for programmatic access.
- **Web UI:** Includes a web interface for easier use.
- **Notification Integration:** Sends alerts via Slack, Discord, or email.
- **Distributed Scanning:** Supports scanning across multiple machines.
- **Resumable Scanning:** Allows pausing and resuming long scans.
- **Plugin System:** Supports custom detection modules.

## Screenshots

*(Optional: Include screenshots to showcase the tool's output. For example:)*

![SubX Sample Output](screenshot.png)

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch:  
   ```bash
   git checkout -b feature-branch
   ```
3. Make your changes and commit them:  
   ```bash
   git commit -am "Add new feature"
   ```
4. Push your branch:  
   ```bash
   git push origin feature-branch
   ```
5. Open a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

**Ethical Use Notice:**  
This tool is provided for educational and authorized penetration testing purposes only. The developers and contributors of SubX are not responsible for any misuse. Always ensure you have proper authorization before scanning any domain.

## Acknowledgments

- [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) for the external fingerprint data.
- [fatih/color](https://github.com/fatih/color) for the colorful terminal output.
- Thanks to the open-source community for their continuous support and inspiration.
