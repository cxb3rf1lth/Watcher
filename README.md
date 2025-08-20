# 🚨 Watcher - The Ultimate Automated Recon & Vulnerability Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-linux-green.svg)](https://www.linux.org/)

**Watcher** is a comprehensive automated reconnaissance and vulnerability assessment tool designed for security professionals and penetration testers. It orchestrates multiple security tools to perform thorough reconnaissance, vulnerability scanning, and automated exploitation attempts.

## ⚠️ **DISCLAIMER**

> **FOR AUTHORIZED, LEGAL TESTING ONLY!**
> 
> You are responsible for your own actions. This tool launches intrusive attacks and should only be used against systems you own or have explicit written permission to test. The author is not responsible for any misuse of this tool.

## ✨ Features

### 🔍 **Comprehensive Reconnaissance**
- **Subdomain Enumeration**: Using Amass, Subfinder, and AssetFinder
- **Port Scanning**: Masscan and Naabu for fast port discovery
- **Web Technology Detection**: HTTPx for service identification
- **Parameter Discovery**: ParamSpider and Arjun for parameter extraction
- **Historical Data**: Wayback URLs for historical endpoint discovery

### 🛡️ **Vulnerability Assessment**
- **Nuclei Templates**: Comprehensive vulnerability scanning with community templates
- **Web Application Security**: 
  - XSS detection with DalFox and XSStrike
  - SQL injection testing with SQLMap
  - Directory and file discovery with FFUF
- **WordPress Security**: WPScan for WordPress-specific vulnerabilities
- **SSL/TLS Analysis**: SSLyze for cryptographic assessment
- **Git Repository Analysis**: GitDumper for exposed repositories

### 🎯 **Automated Exploitation**
- **Proof-of-Concept Generation**: Automated PoC creation for detected vulnerabilities
- **Payload Integration**: PayloadsAllTheThings integration for comprehensive testing
- **Custom Exploit Attempts**: Automated exploitation for RCE, LFI, and SSRF vulnerabilities

### 📊 **Professional Reporting**
- **Rich Console Output**: Beautiful terminal interface with Rich library
- **Multiple Report Formats**: Text and HTML reports
- **Screenshot Capture**: Aquatone and EyeWitness for visual documentation
- **Webhook Notifications**: Discord/Slack integration for real-time updates

## 🚀 Installation

### Prerequisites

- **Operating System**: Linux (Ubuntu/Debian/Arch recommended)
- **Python**: 3.6+ with pip
- **Go**: Latest version for Go-based tools
- **Ruby**: For WPScan and other Ruby tools
- **Root/Sudo Access**: Required for some tool installations

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/cxb3rf1lth/Watcher.git
cd Watcher

# Make the script executable
chmod +x watcher.py

# Run with dependency check (will auto-install most tools)
python3 watcher.py --menu
```

### Manual Installation

If you prefer to install dependencies manually:

```bash
# Essential Python packages
pip3 install requests beautifulsoup4 rich argparse

# Security tools (Ubuntu/Debian)
sudo apt update
sudo apt install -y amass naabu nuclei ffuf nikto sslyze sqlmap httpx masscan aquatone eyewitness pandoc

# Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/LukaSikic/subzy@latest

# Ruby tools
gem install wpscan

# Additional tools
git clone https://github.com/internetwache/GitTools.git ~/GitTools
git clone https://github.com/devanshbatham/ParamSpider.git ~/ParamSpider
git clone https://github.com/s0md3v/Arjun.git ~/Arjun
```

## 💻 Usage

### Interactive Menu Mode

```bash
python3 watcher.py --menu
```

The interactive menu provides options to:
1. Start new scan
2. Check dependencies & install
3. Show installed tools
4. Show warnings/errors
5. Exit

### Command Line Mode

#### Single Target Scan
```bash
python3 watcher.py example.com
```

#### Multiple Targets
```bash
python3 watcher.py example.com target2.com target3.com
```

#### Target File Input
```bash
# Create a file with targets (one per line)
echo -e "example.com\ntarget2.com\ntarget3.com" > targets.txt
python3 watcher.py targets.txt
```

#### Advanced Options
```bash
# Specify thread count
python3 watcher.py example.com --threads 4

# Force menu mode
python3 watcher.py --menu
```

### Configuration

#### Webhook Notifications
Edit the `WEBHOOK_URL` variable in `watcher.py` to enable Discord/Slack notifications:

```python
WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
```

#### Custom Wordlists
The tool automatically uses SecLists. To use custom wordlists, modify the `SECLISTS` path in the script.

## 📁 Output Structure

```
~/recon_results/
└── target.com-20231201_143022/
    ├── amass_subs.txt          # Subdomain enumeration
    ├── subfinder.txt           # Alternative subdomain results
    ├── assetfinder.txt         # Asset discovery results
    ├── masscan.txt             # Port scan results
    ├── naabu.txt               # Fast port scan
    ├── httpx.txt               # Live web services
    ├── waybackurls.txt         # Historical URLs
    ├── paramspider.txt         # Parameter discovery
    ├── nuclei.txt              # Vulnerability scan results
    ├── ffuf_dirs.html          # Directory discovery
    ├── nikto.txt               # Web server scan
    ├── dalfox.txt              # XSS scan results
    ├── sqlmap/                 # SQL injection results
    ├── aquatone/               # Screenshots
    ├── eyewitness/             # Alternative screenshots
    ├── report.txt              # Comprehensive text report
    └── report.html             # HTML formatted report
```

## 🔧 Tool Dependencies

### Core Security Tools
- **amass**: Subdomain enumeration
- **subfinder**: Fast subdomain discovery
- **assetfinder**: Asset discovery
- **naabu**: Port scanning
- **masscan**: High-speed port scanner
- **nuclei**: Vulnerability scanner
- **httpx**: HTTP toolkit
- **ffuf**: Web fuzzer
- **nikto**: Web vulnerability scanner
- **sqlmap**: SQL injection testing
- **dalfox**: XSS scanner
- **wpscan**: WordPress security scanner
- **sslyze**: SSL/TLS analyzer

### Supporting Tools
- **aquatone**: Screenshot tool
- **eyewitness**: Web application screenshot
- **gf**: Grep functionality for patterns
- **paramspider**: Parameter discovery
- **waybackurls**: Wayback machine URL extraction
- **subzy**: Subdomain takeover detection
- **kiterunner**: Content discovery
- **pandoc**: Document conversion

## 🔍 Scan Phases

1. **Reconnaissance Phase**
   - Subdomain enumeration and validation
   - Port scanning and service detection
   - Technology stack identification

2. **Discovery Phase**
   - Directory and file discovery
   - Parameter extraction
   - Historical data analysis

3. **Vulnerability Assessment**
   - Automated vulnerability scanning
   - Web application security testing
   - SSL/TLS security analysis

4. **Exploitation Phase**
   - Automated proof-of-concept generation
   - Safe exploitation attempts
   - Evidence collection

5. **Reporting Phase**
   - Comprehensive report generation
   - Screenshot compilation
   - Results aggregation

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
git clone https://github.com/cxb3rf1lth/Watcher.git
cd Watcher
# Make your changes
# Test thoroughly
# Submit PR
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Bl4ckC3llSec / Cxb3rF1lthSec**

- GitHub: [@cxb3rf1lth](https://github.com/cxb3rf1lth)

## ⚖️ Legal Notice

This tool is intended for legal security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any targets. The developers assume no liability for misuse of this tool.

## 📚 Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Hunter's Methodology](https://github.com/jhaddix/tbhm)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
