# Cyber OSINT Recon

An OSINT (Open Source Intelligence) tool written in Go for collecting information about domains and companies.

**Developer**: Kai_HT (redsec.kaiht.kr)  
**Team**: RedSec (redsec.co.kr)

## Features

### Core Features
- Domain WHOIS information collection
- DNS record lookup (A, AAAA, MX, NS, TXT, CNAME)
- Subdomain discovery
- IP address and geolocation information
- Email address collection (Go + Python theHarvester)
- Web technology stack analysis
- Report generation (JSON, HTML, Markdown)
- Real-time progress tracking with estimated remaining time

### Extended OSINT Features
- Email pivot analysis
- Username enumeration (Go + Python Sherlock)
- Social media profile discovery
- Company background research
- Related asset discovery
- Code repository search
- Document repository search
- Data spillage detection
- Security threat intelligence
- Asset inventory generation

### Advanced OSINT Features (Requires API Keys)
- Shodan/Censys IP/port scanning (Go with official libraries)
- Web Archive (Wayback Machine) search
- GitHub code trace (Go + Python GitHub Dorking)
- Employee profile enumeration
- Corporate information (Crunchbase/OpenCorporates)
- VirusTotal malware/blacklist verification (Go with official library)

## Installation

### Prerequisites

- Go 1.21 or higher
- Python 3.x (for enhanced OSINT features)

### Build

```bash
go mod download
go build -o cyber-osint-recon cmd/cyber-osint-recon/main.go
```

### Python Dependencies (Optional but Recommended)

For enhanced OSINT features (Sherlock username enumeration, theHarvester email collection, GitHub dorking):

**Windows:**
```bash
setup_python.bat
```

**Linux/macOS:**
```bash
chmod +x setup_python.sh
./setup_python.sh
```

Or manually:
```bash
pip install -r python_modules/requirements.txt
```

## Usage

### Basic Usage

```bash
# Scan a domain
./cyber-osint-recon scan example.com

# Scan by company name (automatically searches for domains)
./cyber-osint-recon scan "Example Corp"

# Scan domain with company name specified
./cyber-osint-recon scan example.com --company "Example Corp"
```

### Output Formats

```bash
# Specify output format (json, html, markdown)
./cyber-osint-recon scan example.com --output json
./cyber-osint-recon scan example.com --output html
./cyber-osint-recon scan example.com --output markdown

# Save results to file
./cyber-osint-recon scan example.com --output html --save report.html
```

### Advanced Options

```bash
# Disable subdomain search
./cyber-osint-recon scan example.com --subdomains=false

# Adjust email collection depth
./cyber-osint-recon scan example.com --depth 3

# Adjust worker count for subdomain search
./cyber-osint-recon scan example.com --workers 20

# Use API keys for enhanced scanning
./cyber-osint-recon scan example.com \
  --shodan-key YOUR_SHODAN_KEY \
  --censys-key YOUR_CENSYS_TOKEN \
  --virustotal-key YOUR_VIRUSTOTAL_KEY \
  --github-token YOUR_GITHUB_TOKEN
```

### Help

```bash
# Show general help
./cyber-osint-recon --help

# Show scan command help with examples
./cyber-osint-recon scan --help
```

## Notes

- You can scan by **domain** (e.g., `example.com`) or **company name** (e.g., `"Example Corp"`).
- When scanning by company name, the tool automatically searches for associated domains.
- When scanning by domain, it directly scans that domain.
- The tool displays real-time progress with estimated remaining time.

## Project Structure

```
.
├── cmd/
│   └── cyber-osint-recon/
│       └── main.go          # CLI entry point
├── cmd/
│   └── cyber-osint-recon/
│       └── main.go          # CLI entry point
├── internal/
│   ├── collector/           # Information collection modules
│   │   ├── company.go       # Domain search by company name
│   │   ├── domain.go        # WHOIS information
│   │   ├── dns.go           # DNS records
│   │   ├── subdomain.go     # Subdomain discovery
│   │   ├── email.go         # Email collection
│   │   ├── techstack.go     # Technology stack analysis
│   │   ├── extended.go      # Extended OSINT features
│   │   ├── enhanced.go      # Advanced OSINT features (Shodan, Censys, VirusTotal)
│   │   └── python.go        # Python module integration
│   ├── reporter/            # Report generation modules
│   │   ├── json.go
│   │   ├── html.go
│   │   └── markdown.go
│   └── models/              # Data models
│       └── report.go
├── python_modules/          # Python OSINT modules
│   ├── sherlock_username.py # Username enumeration
│   ├── theharvester_email.py # Email collection
│   ├── github_dorking.py    # GitHub code search
│   └── requirements.txt    # Python dependencies
├── setup_python.sh          # Python setup script (Linux/macOS)
├── setup_python.bat         # Python setup script (Windows)
└── go.mod
```

## License

MIT
