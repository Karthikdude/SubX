
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

## Installation

### Prerequisites

- **Go:** Version 1.15 or later is recommended.
- **Git:** For cloning the repository.
- **Dependencies:**  
  - [fatih/color](https://github.com/fatih/color) – for colorful terminal output.  
    Install with:
    ```bash
    go get github.com/fatih/color
    ```

### Step-by-Step Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/Karthikdude/SubX.git
    ```

2. **Change to the project directory:**
    ```bash
    cd SubX
    ```

3. **Build the tool:**
    ```bash
    go build -o subx main.go
    ```

## Usage

SubX is a command-line tool with several options. Below are a few examples:

### Scan a Single Domain

```bash
./subx -u example.com -https
```

### Scan a List of Subdomains

```bash
./subx -l subdomains.txt -https -o results.json
```

### Command-Line Options

- `-u`: Test a single domain.
- `-l`: Provide a file containing a list of subdomains.
- `-t`: Set the number of threads (default: 100).
- `-time`: Specify the timeout in seconds (default: 30).
- `-o`: Output file (supports `.txt` or `.json` formats).
- `-ssl`: Skip invalid SSL sites.
- `-https`: Use HTTPS by default.
- `-a`: Skip CNAME check and send requests to every URL.
- `-m`: Flag dead records but valid CNAME entries.
- `-hide`: Hide failed checks and invulnerable subdomains.
- `-cname`: Print detailed CNAME information.
- `-error`: Hide errors and failed requests.

## Features

- **Concurrent Scanning:** Uses goroutines and a semaphore to limit the number of concurrent threads.
- **Detailed Output:** Displays structured results including Subdomain, URL, HTTP status, CNAME record, and identified service.
- **External Fingerprints:** Integrates service fingerprints from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) to enhance service identification.
- **Customizable Options:** Various command-line flags allow users to tailor the scanning process.
- **Output Options:** Save results to a JSON or plain text file.

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
```

