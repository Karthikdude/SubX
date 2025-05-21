# SubX - Advanced Subdomain Takeover Scanner

<p align="center">
  <img src="https://raw.githubusercontent.com/Karthikdude/SubX/main/static/logo.png" alt="SubX Logo" width="200"/>
</p>

<p align="center">
  <a href="https://github.com/Karthikdude/SubX/releases"><img src="https://img.shields.io/github/v/release/Karthikdude/SubX?color=blueviolet&style=flat-square" alt="GitHub release"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Made%20with-Go-00ADD8?style=flat-square" alt="Made with Go"></a>
  <a href="https://github.com/Karthikdude/SubX/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Karthikdude/SubX?color=brightgreen&style=flat-square" alt="License"></a>
  <a href="https://github.com/Karthikdude/SubX/stargazers"><img src="https://img.shields.io/github/stars/Karthikdude/SubX?color=yellow&style=flat-square" alt="Stars"></a>
</p>

SubX is a powerful and highly concurrent subdomain takeover detection tool written in Go. It scans subdomains, checks for potential vulnerabilities (like takeover issues), and identifies the underlying services using advanced pattern matching, content analysis, and CNAME fingerprinting.

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

- **Go:** Version 1.18 or later is recommended for optimal performance.
- **Git:** For cloning the repository.
- **Chrome/Chromium:** (Optional) Required only for screenshot capture functionality.
- **SQLite:** (Optional) Required only for historical data storage.

### Step-by-Step Installation

#### Method 1: From Source

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
    
5. **Move to your PATH:** (Optional)
    ```bash
    # Linux/macOS
    sudo mv subx /usr/local/bin/
    
    # Windows (Run as Administrator)
    move subx.exe C:\Windows\System32\
    ```

#### Method 2: Using Go Install

```bash
go install github.com/Karthikdude/SubX@latest
```

#### Method 3: Using Pre-built Binaries

1. Download the latest release for your platform from the [Releases page](https://github.com/Karthikdude/SubX/releases).
2. Extract the archive and move the binary to your PATH.

### Docker Installation

SubX can also be run as a Docker container:

```bash
# Build the Docker image
docker build -t subx .

# Run SubX in a container
docker run -it --rm subx -u example.com
```

### Verifying Installation

Verify that SubX is installed correctly:

```bash
subx -version
```

You should see output similar to:

```
SubX v2.0.0 - Advanced Subdomain Takeover Scanner
Copyright (c) 2025 Karthik S Sathyan
```

## Usage

SubX offers a wide range of options for customizing your scans. Below are examples covering basic to advanced usage scenarios:

### Basic Usage

#### Scan a Single Domain

```bash
subx -u example.com -https
```

#### Scan a List of Subdomains

```bash
subx -l subdomains.txt -https -o results.json
```

### Advanced Usage

#### Generate a Comprehensive HTML Report with Screenshots

```bash
subx -l subdomains.txt -https -o report.html -screenshot -screenshot-dir ./screenshots
```

#### Use a Configuration File

```bash
subx -config config.yaml
```

#### Enable Adaptive Rate Limiting and DNS Caching

```bash
subx -l large-subdomain-list.txt -adaptive-rate -dns-cache
```

#### Distributed Scanning (Master Node)

```bash
subx -l massive-subdomain-list.txt -distributed -master -master-port 8082
```

#### Distributed Scanning (Worker Node)

```bash
subx -worker -master http://master-ip:8082
```

#### Start the Web UI

```bash
subx -web -web-port 8081
```

#### Start the API Server

```bash
subx -api -api-port 8080
```

#### Use with Proxy and Custom User-Agent

```bash
subx -l subdomains.txt -proxy socks5://127.0.0.1:9050 -ua "Mozilla/5.0 SubX Security Scanner"
```

#### Enable Slack Notifications

```bash
subx -l subdomains.txt -slack https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### Integration with Other Tools

#### Pipe from Subfinder

```bash
subfinder -d example.com | subx -https
```

#### Continuous Monitoring with Cron

Add to crontab to run daily scans:

```bash
0 0 * * * /usr/local/bin/subx -l /path/to/domains.txt -o /path/to/reports/$(date +\%Y-\%m-\%d).json -db /path/to/history.db
```

### API Usage Examples

#### Get All Scan Results

```bash
curl http://localhost:8080/api/v1/results
```

#### Start a New Scan

```bash
curl -X POST -H "Content-Type: application/json" -d '{"domains":["example.com"],"options":{"https":true}}' http://localhost:8080/api/v1/scan
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

### Core Capabilities
- **High-Performance Concurrent Scanning:** Utilizes Go's goroutines and semaphores to efficiently manage thousands of concurrent requests while maintaining control over system resources.
- **Intelligent Rate Limiting:** Adaptive rate limiting automatically adjusts request rates based on target response times to avoid detection and throttling.
- **Comprehensive Service Detection:** Identifies over 50 different services vulnerable to subdomain takeover using multiple detection methods.

### Advanced Detection Methods
- **Multi-layered Detection:** Combines CNAME analysis, HTTP response status codes, body content, and header inspection for accurate vulnerability identification.
- **Pattern-Based Recognition:** Uses sophisticated regex patterns to identify services beyond exact CNAME matches.
- **Content Analysis Engine:** Deep inspection of HTTP response content and headers to detect subtle indicators of takeover opportunities.
- **Fingerprint Database:** Integrates service fingerprints from multiple sources and maintains an up-to-date database of takeover signatures.

### Risk Assessment
- **Intelligent Risk Scoring:** Prioritizes findings with high/medium/low risk classifications based on vulnerability type, service, and exploitation difficulty.
- **Vulnerability Verification:** Automatically verifies potential takeover vulnerabilities to reduce false positives.
- **Contextual Analysis:** Evaluates the security context of discovered vulnerabilities to provide more meaningful results.

### Reporting and Visualization
- **Multi-format Reporting:** Export results to JSON, CSV, plain text, or interactive HTML reports.
- **Screenshot Capture:** Automatically captures visual evidence of vulnerable subdomains.
- **Historical Comparison:** Tracks changes over time to identify newly vulnerable subdomains.
- **Interactive Web UI:** Modern dark-themed interface for easier analysis and management of scan results.

### Integration and Automation
- **RESTful API:** Comprehensive API for programmatic access and integration with other security tools.
- **Notification System:** Sends real-time alerts via Slack, Discord, or email when vulnerabilities are discovered.
- **CI/CD Integration:** Easily integrates into continuous security testing pipelines.

### Performance and Reliability
- **DNS Caching:** Reduces redundant DNS lookups for faster scanning and reduced network traffic.
- **Distributed Scanning:** Scale across multiple machines for scanning large target lists.
- **Resumable Scanning:** Pause and resume long-running scans without losing progress.
- **Proxy Support:** Route requests through SOCKS or HTTP proxies for anonymity and bypassing restrictions.

### Extensibility
- **Plugin System:** Extend functionality with custom detection modules using a simple JSON-based plugin architecture.
- **Custom Fingerprints:** Add your own service fingerprints without modifying the core code.
- **Configuration Files:** Define complex scanning profiles in YAML or JSON configuration files.

### Ethical Features
- **Robots.txt Respect:** Option to honor robots.txt directives on target domains.
- **Rate Control:** Configurable rate limiting to prevent denial of service to targets.
- **Custom User-Agent:** Identify your scanning with a specific User-Agent string.

## Plugin System

SubX v2.0 introduces a powerful plugin system that allows you to extend the tool's capabilities without modifying the core code. Plugins are defined in JSON format and can be placed in the `plugins` directory.

### Plugin Structure

Each plugin is a JSON file with the following structure:

```json
{
  "name": "Plugin Name",
  "description": "Plugin description",
  "version": "1.0.0",
  "author": "Author Name",
  "fingerprints": [
    {
      "cname": ["example.com"],
      "headers": {
        "header-name": "header-value"
      },
      "body": [
        "text to match in response body"
      ],
      "status": [404, 403],
      "risk": "high|medium|low"
    }
  ]
}
```

### Available Plugins

SubX comes with several built-in plugins:

1. **AWS S3 Bucket Plugin**: Detects misconfigured Amazon S3 buckets vulnerable to takeover.
2. **Azure Blob Storage Plugin**: Identifies unclaimed Azure Blob Storage instances.
3. **GitHub Pages Plugin**: Detects unclaimed GitHub Pages sites.
4. **Heroku Plugin**: Finds abandoned Heroku applications.
5. **Netlify Plugin**: Detects unclaimed Netlify deployments.
6. **Shopify Plugin**: Identifies abandoned Shopify storefronts.
7. **Fastly Plugin**: Detects misconfigured Fastly CDN endpoints.
8. **Pantheon Plugin**: Identifies unclaimed Pantheon sites.
9. **Tumblr Plugin**: Detects abandoned Tumblr blogs.
10. **Unbounce Plugin**: Identifies unclaimed Unbounce landing pages.

### Creating Custom Plugins

To create a custom plugin:

1. Create a new JSON file in the `plugins` directory
2. Define your fingerprints following the structure above
3. Restart SubX or use the `-plugin-dir` flag to specify your plugins directory

Custom plugins are automatically loaded at startup and integrated into the detection process.

## Web Interface

SubX v2.0 includes a modern, responsive web interface for easier management and visualization of scan results.

### Key Features

- **Dashboard**: Overview of scan statistics and recent activity
- **Interactive Scanning**: Configure and launch scans directly from the UI
- **Real-time Results**: View scan results as they come in
- **Advanced Filtering**: Filter and search through results
- **Visual Reports**: Charts and graphs for better data visualization
- **Responsive Design**: Works on desktop and mobile devices

### Starting the Web Interface

```bash
subx -web -web-port 8081
```

Then open your browser and navigate to `http://localhost:8081`

### Screenshots

#### Dashboard
![SubX Dashboard](https://raw.githubusercontent.com/Karthikdude/SubX/main/static/screenshots/dashboard.png)

#### Scan Configuration
![SubX Scan Configuration](https://raw.githubusercontent.com/Karthikdude/SubX/main/static/screenshots/scan-config.png)

#### Results View
![SubX Results](https://raw.githubusercontent.com/Karthikdude/SubX/main/static/screenshots/results.png)

#### HTML Report
![SubX HTML Report](https://raw.githubusercontent.com/Karthikdude/SubX/main/static/screenshots/html-report.png)

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

### Ethical Use Notice

SubX is a powerful security tool designed for ethical security research, bug bounty hunting, and authorized penetration testing. Please use this tool responsibly and ethically.

- **Authorization**: Always ensure you have proper authorization before scanning any domain or system.
- **Legal Compliance**: Comply with all applicable laws and regulations in your jurisdiction.
- **Responsible Disclosure**: If you discover vulnerabilities using SubX, follow responsible disclosure practices.
- **No Malicious Use**: Do not use SubX for any illegal or malicious purposes.

### Limitation of Liability

The developers and contributors of SubX are not responsible for any misuse of this tool or for any damages resulting from its use. SubX is provided "as is" without any warranty of any kind.

### Academic and Research Use

If you use SubX in academic research or publications, please cite it appropriately. We encourage the security research community to build upon and improve this tool.

## Acknowledgments

SubX v2.0 would not have been possible without the contributions and inspiration from the security research community. Special thanks to:

### Projects & Libraries
- [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - For pioneering subdomain takeover research and providing the foundation for our fingerprint database.
- [haccer/subjack](https://github.com/haccer/subjack) - For inspiration on the concurrent scanning approach.
- [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) - For setting a high standard in subdomain enumeration tools.
- [tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) - For inspiration on efficient HTTP probing techniques.
- [OJ/gobuster](https://github.com/OJ/gobuster) - For inspiration on directory and DNS enumeration approaches.

### Go Libraries
- [fatih/color](https://github.com/fatih/color) - For the colorful terminal output.
- [chromedp/chromedp](https://github.com/chromedp/chromedp) - For headless browser automation used in screenshot capture.
- [gorilla/mux](https://github.com/gorilla/mux) - For the powerful HTTP router used in our API.
- [miekg/dns](https://github.com/miekg/dns) - For the robust DNS library.
- [schollz/progressbar](https://github.com/schollz/progressbar) - For the elegant progress bar implementation.
- [slack-go/slack](https://github.com/slack-go/slack) - For Slack notification integration.
- [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3) - For SQLite database integration.

### Individuals
- [Karthik S Sathyan](https://github.com/Karthikdude) - For creating and maintaining SubX.
- [Patrik Hudak](https://0xpatrik.com) - For his extensive research on subdomain takeovers.
- [Frans Rosén](https://twitter.com/fransrosen) - For his contributions to subdomain takeover research.
- [Luke Stephens (hakluke)](https://twitter.com/hakluke) - For inspiration and educational content on subdomain takeovers.
- [Jason Haddix](https://twitter.com/jhaddix) - For promoting best practices in bug bounty hunting.

### Community
- The entire bug bounty and security research community for their continuous feedback and support.
- All contributors who have submitted bug reports, feature requests, and pull requests.
- Everyone who has shared their experiences and use cases, helping to improve SubX.
