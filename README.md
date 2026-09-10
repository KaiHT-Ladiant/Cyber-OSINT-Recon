# CyRecon

**CyRecon** (short for *Cyber OSINT Recon*) is an OSINT toolkit written in Go for collecting information about domains and companies.

![CyRecon icon](assets/cyrecon-icon.png)

**Developer**: Kai_HT (redsec.kaiht.kr)  
**Team**: RedSec (redsec.co.kr)

## Name

| Full name | Short name | Binary |
|-----------|------------|--------|
| Cyber OSINT Recon | **CyRecon** | `cyber-osint-recon` / `cyrecon` |

## Features

### Core Features
- Domain WHOIS information collection
- DNS record lookup (A, AAAA, MX, NS, TXT, CNAME)
- Subdomain discovery
- IP address and geolocation information
- Email address collection (Go + Python theHarvester)
- Web technology stack analysis
- Report generation (JSON, HTML, Markdown, DOCX, Excel)
- Real-time progress tracking with estimated remaining time

### Scan Modes `[Mode]`
- **single** — scan one domain, or resolve domains from a company name
- **multi** — scan many confirmed domains from a list file (one domain per line)

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
go build -o cyrecon ./cmd/cyber-osint-recon
# or keep the classic binary name:
go build -o cyber-osint-recon ./cmd/cyber-osint-recon
```

### Windows build (with application icon)

The CyRecon icon is embedded into Windows `.exe` builds via `cmd/cyber-osint-recon/resource_windows_amd64.syso` (generated from `assets/cyrecon.ico` with goversioninfo).

```powershell
# Regenerate icon/version resource (from repo root)
go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest -64 -o cmd/cyber-osint-recon/resource_windows_amd64.syso cmd/cyber-osint-recon/versioninfo.json

# Cross-compile / native Windows build
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags="-s -w" -o Releases/cyber-osint-recon-windows-amd64.exe ./cmd/cyber-osint-recon
```

Or use `.\create_release.ps1 -Token <GITHUB_TOKEN>` which rebuilds with the icon before uploading.

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

### [Mode] Single domain / company

```bash
# Scan a domain
./cyrecon scan example.com

# Scan by company name (automatically searches for domains)
./cyrecon scan "Example Corp"

# Scan domain with company name specified
./cyrecon scan example.com --company "Example Corp"

# Explicit single mode
./cyrecon scan --mode single example.com
```

### [Mode] Multi domain list

```bash
# Scan many confirmed domains from a list file
./cyrecon scan --mode multi --list domains.txt
./cyrecon scan --mode multi domains.txt

# Example list format: see domains.list.example
```

On an interactive terminal, omitting `--mode` shows a `[Mode]` selection prompt (`single` / `multi`).

### Output Formats

```bash
./cyrecon scan example.com --output json
./cyrecon scan example.com --output html
./cyrecon scan example.com --output markdown
./cyrecon scan example.com --output docx
./cyrecon scan example.com --output excel
./cyrecon scan example.com --output html --save report.html
```

### Advanced Options

```bash
./cyrecon scan example.com --subdomains=false
./cyrecon scan example.com --depth 3
./cyrecon scan example.com --workers 20

./cyrecon scan example.com \
  --shodan-key YOUR_SHODAN_KEY \
  --censys-key YOUR_CENSYS_TOKEN \
  --virustotal-key YOUR_VIRUSTOTAL_KEY \
  --github-token YOUR_GITHUB_TOKEN
```

### Help

```bash
./cyrecon --help
./cyrecon scan --help
```

## Notes

- You can scan by **domain** (e.g., `example.com`) or **company name** (e.g., `"Example Corp"`).
- When scanning by company name, the tool automatically searches for associated domains.
- **Multi mode** is intended for already-confirmed domain lists; it does not re-discover domains from a company name.
- The tool displays real-time progress with estimated remaining time.

## Project Structure

```
.
├── assets/
│   ├── cyrecon-icon.png     # CyRecon icon (docs / README)
│   └── cyrecon.ico          # Windows application icon source
├── cmd/
│   └── cyber-osint-recon/
│       ├── main.go          # CLI entry point + flags
│       ├── mode.go          # [Mode] single/multi selection + list loader
│       ├── scan.go          # Scan orchestration
│       ├── progress.go      # Progress tracker
│       ├── versioninfo.json # Windows version/icon metadata
│       └── resource_windows_amd64.syso  # Embedded Windows exe icon/version
├── internal/
│   ├── collector/           # Information collection modules
│   ├── reporter/            # Report generation modules
│   ├── models/              # Data models
│   └── config/              # API key config
├── python_modules/          # Python OSINT modules
├── domains.list.example     # Example multi-mode domain list
├── setup_python.sh
├── setup_python.bat
└── go.mod
```

## License

MIT
