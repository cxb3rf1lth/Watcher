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

1. Place `PayloadsAllTheThings-master.zip` in your `$HOME`.
2. (Optional) Download SecLists, FuzzDB, and place in `/usr/share/wordlists` or `$HOME`.
3. (Optional) Add webhook URL in script for Discord/Slack alerts.
4. Install Python 3.8+ and `pip` if not present.
5. Run the script — it will handle all other dependencies!

---

## Usage

### Launch the main menu:

```sh
python3 watcher_ultimate.py --menu
