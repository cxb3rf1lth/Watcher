# Watcher (Ultimate Recon/Vuln/PoC Automation)

**By Bl4ckC3llSec / Cxb3rF1lthSec**

## Description

Watcher is the most complete, automated, and modular recon and vulnerability pipeline for authorized security research. It automatically installs, checks, and orchestrates 25+ tools for:

- Subdomain/asset discovery, takeover, portscan, web fuzzing, screenshot, OOB, parameter fuzz, nuclei, dalfox, SQLMap, LFI, SSRF, and more.
- Massive wordlist and payload integration: SecLists, PayloadsAllTheThings, FuzzDB, custom lists (auto-detected!).
- Full reporting, evidence collection, automated PoC and webhook notification, with a TUI dashboard and live progress.
- Modular design — easy to update, patch, and extend.

**For legal/authorized testing only!**

---

## Setup

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/cxb3rf1lth/Watcher.git
cd Watcher

# Make the script executable
chmod +x watcher_ultimate.py

# Install Python dependencies
pip3 install requests beautifulsoup4 rich

# Run the script (it will auto-install most security tools)
python3 watcher_ultimate.py --menu
```

### Detailed Setup

1. **Prerequisites**: Python 3.8+, pip, and preferably a Linux system (Ubuntu/Debian/Arch)
2. **Optional**: Place `PayloadsAllTheThings-master.zip` in your `$HOME` for enhanced payload integration
3. **Optional**: Download SecLists, FuzzDB, and place in `/usr/share/wordlists` or `$HOME`
4. **Optional**: Add webhook URL in script for Discord/Slack alerts
5. **Auto-install**: The script will automatically install and configure 25+ security tools on first run

---

## Usage

### Interactive Menu Mode

```sh
python3 watcher_ultimate.py --menu
```

The interactive menu provides options to:
1. **Start new scan** - Begin reconnaissance on target domains
2. **Check dependencies & install** - Automatically install required security tools
3. **Show installed tools** - Display status of all security tools
4. **Show warnings/errors** - View any installation or runtime issues
5. **Exit** - Close the application

### Command Line Mode

#### Single Target Scan
```sh
python3 watcher_ultimate.py example.com
```

#### Multiple Targets
```sh
python3 watcher_ultimate.py example.com target2.com target3.com
```

#### Target File Input
```sh
# Create a file with targets (one per line)
echo -e "example.com\ntarget2.com\ntarget3.com" > targets.txt
python3 watcher_ultimate.py targets.txt
```

#### Advanced Options
```sh
# Specify thread count for parallel processing
python3 watcher_ultimate.py example.com --threads 4

# Force interactive menu mode
python3 watcher_ultimate.py --menu
```

### Configuration Options

#### Webhook Notifications
To enable real-time notifications via Discord or Slack, edit the `WEBHOOK_URL` variable in `watcher_ultimate.py`:

```python
WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
```

#### Custom Wordlists
The tool automatically uses SecLists when available. To customize wordlist paths, modify the `SECLISTS` variable in the script.
