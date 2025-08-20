#!/usr/bin/env python3
"""
Watcher Recon Tool - Ultimate Reconnaissance and Vulnerability Pipeline
By Bl4ckC3llSec / Cxb3rF1lthSec

A modular recon and vulnerability assessment tool for authorized security research.
Features: subdomain discovery, asset discovery, port scanning, web fuzzing, and more.

For legal/authorized testing only!
"""

import os
import sys
import subprocess
import argparse
import json
import time
import threading
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('watcher_recon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WatcherRecon:
    """Main Watcher Reconnaissance Tool Class"""
    
    def __init__(self):
        self.target = None
        self.output_dir = "watcher_output"
        self.wordlists_path = self._find_wordlists()
        self.results = {
            'subdomains': [],
            'ports': [],
            'urls': [],
            'vulnerabilities': []
        }
        
    def _find_wordlists(self) -> str:
        """Find wordlists directory (SecLists, FuzzDB, etc.)"""
        possible_paths = [
            "/usr/share/wordlists",
            os.path.expanduser("~/SecLists"),
            os.path.expanduser("~/wordlists"),
            os.path.expanduser("~/FuzzDB")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Found wordlists at: {path}")
                return path
                
        logger.warning("No wordlists found. Some features may be limited.")
        return ""
    
    def setup_output_directory(self):
        """Create output directory structure"""
        dirs = [
            self.output_dir,
            f"{self.output_dir}/subdomains",
            f"{self.output_dir}/ports",
            f"{self.output_dir}/screenshots",
            f"{self.output_dir}/vulnerabilities"
        ]
        
        for directory in dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Output directory created: {self.output_dir}")
    
    def subdomain_discovery(self, target: str) -> List[str]:
        """Perform subdomain discovery using multiple techniques"""
        logger.info(f"Starting subdomain discovery for {target}")
        subdomains = set()
        
        # Method 1: Basic DNS enumeration
        try:
            # Using dig for common subdomains
            common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging']
            for sub in common_subs:
                try:
                    result = subprocess.run(
                        ['dig', '+short', f'{sub}.{target}'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.stdout.strip() and not result.stderr:
                        subdomains.add(f'{sub}.{target}')
                        logger.info(f"Found subdomain: {sub}.{target}")
                except subprocess.TimeoutExpired:
                    continue
                except Exception as e:
                    logger.debug(f"Error checking {sub}.{target}: {e}")
        except Exception as e:
            logger.error(f"Error in subdomain discovery: {e}")
        
        # Save results
        subdomain_list = list(subdomains)
        self.results['subdomains'] = subdomain_list
        
        with open(f"{self.output_dir}/subdomains/subdomains.txt", 'w') as f:
            for subdomain in subdomain_list:
                f.write(f"{subdomain}\n")
        
        logger.info(f"Found {len(subdomain_list)} subdomains")
        return subdomain_list
    
    def port_scan(self, target: str, ports: str = "1-1000") -> List[Dict]:
        """Perform port scanning"""
        logger.info(f"Starting port scan for {target}")
        open_ports = []
        
        # Basic port scan implementation
        # In a real implementation, you'd use nmap or similar tools
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        for port in common_ports:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    port_info = {
                        'port': port,
                        'state': 'open',
                        'service': self._get_service_name(port)
                    }
                    open_ports.append(port_info)
                    logger.info(f"Found open port: {port}")
                    
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
        
        self.results['ports'] = open_ports
        
        # Save results
        with open(f"{self.output_dir}/ports/ports.json", 'w') as f:
            json.dump(open_ports, f, indent=2)
        
        logger.info(f"Found {len(open_ports)} open ports")
        return open_ports
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            8080: 'http-alt', 8443: 'https-alt'
        }
        return services.get(port, 'unknown')
    
    def web_discovery(self, targets: List[str]) -> List[str]:
        """Discover web applications and endpoints"""
        logger.info("Starting web discovery")
        web_urls = []
        
        for target in targets:
            # Check HTTP and HTTPS
            for protocol in ['http', 'https']:
                url = f"{protocol}://{target}"
                try:
                    # Basic HTTP check (in real implementation, use requests)
                    import urllib.request
                    urllib.request.urlopen(url, timeout=10)
                    web_urls.append(url)
                    logger.info(f"Found web service: {url}")
                except:
                    continue
        
        self.results['urls'] = web_urls
        
        # Save results
        with open(f"{self.output_dir}/urls.txt", 'w') as f:
            for url in web_urls:
                f.write(f"{url}\n")
        
        logger.info(f"Found {len(web_urls)} web services")
        return web_urls
    
    def vulnerability_scan(self, targets: List[str]) -> List[Dict]:
        """Basic vulnerability scanning"""
        logger.info("Starting vulnerability scan")
        vulnerabilities = []
        
        # Basic vulnerability checks
        for target in targets:
            # Check for common vulnerabilities
            vulns = self._check_common_vulns(target)
            vulnerabilities.extend(vulns)
        
        self.results['vulnerabilities'] = vulnerabilities
        
        # Save results
        with open(f"{self.output_dir}/vulnerabilities/vulns.json", 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        
        logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities
    
    def _check_common_vulns(self, target: str) -> List[Dict]:
        """Check for common vulnerabilities"""
        vulns = []
        
        # Example vulnerability checks
        try:
            # Check for default credentials, open directories, etc.
            # This is a placeholder for actual vulnerability scanning logic
            
            # Check for HTTP methods
            import urllib.request
            import urllib.error
            
            methods = ['OPTIONS', 'TRACE', 'PUT', 'DELETE']
            for method in methods:
                try:
                    req = urllib.request.Request(f"http://{target}", method=method)
                    response = urllib.request.urlopen(req, timeout=5)
                    if response.status == 200:
                        vulns.append({
                            'target': target,
                            'vulnerability': f'HTTP {method} method enabled',
                            'severity': 'Medium',
                            'description': f'Server allows {method} method'
                        })
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Error in vulnerability check for {target}: {e}")
        
        return vulns
    
    def generate_report(self) -> str:
        """Generate comprehensive report"""
        logger.info("Generating final report")
        
        report = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'subdomains_found': len(self.results['subdomains']),
                'open_ports': len(self.results['ports']),
                'web_services': len(self.results['urls']),
                'vulnerabilities': len(self.results['vulnerabilities'])
            },
            'results': self.results
        }
        
        report_file = f"{self.output_dir}/watcher_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate text summary
        summary_file = f"{self.output_dir}/summary.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Watcher Recon Report for {self.target}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Scan completed: {report['timestamp']}\n\n")
            f.write("Summary:\n")
            f.write(f"- Subdomains found: {report['summary']['subdomains_found']}\n")
            f.write(f"- Open ports: {report['summary']['open_ports']}\n")
            f.write(f"- Web services: {report['summary']['web_services']}\n")
            f.write(f"- Vulnerabilities: {report['summary']['vulnerabilities']}\n\n")
            
            if self.results['subdomains']:
                f.write("Subdomains:\n")
                for subdomain in self.results['subdomains']:
                    f.write(f"  - {subdomain}\n")
                f.write("\n")
            
            if self.results['ports']:
                f.write("Open Ports:\n")
                for port in self.results['ports']:
                    f.write(f"  - {port['port']} ({port['service']})\n")
                f.write("\n")
            
            if self.results['vulnerabilities']:
                f.write("Vulnerabilities:\n")
                for vuln in self.results['vulnerabilities']:
                    f.write(f"  - {vuln['vulnerability']} ({vuln['severity']})\n")
        
        logger.info(f"Report generated: {report_file}")
        return report_file
    
    def run_full_scan(self, target: str):
        """Run complete reconnaissance scan"""
        self.target = target
        logger.info(f"Starting full reconnaissance scan for {target}")
        
        # Setup
        self.setup_output_directory()
        
        # Subdomain discovery
        subdomains = self.subdomain_discovery(target)
        all_targets = [target] + subdomains
        
        # Port scanning
        for t in all_targets[:5]:  # Limit to first 5 targets for demo
            self.port_scan(t)
        
        # Web discovery
        self.web_discovery(all_targets)
        
        # Vulnerability scanning
        self.vulnerability_scan(all_targets[:3])  # Limit for demo
        
        # Generate report
        report_file = self.generate_report()
        
        logger.info(f"Reconnaissance scan completed for {target}")
        logger.info(f"Results saved to: {self.output_dir}")
        
        return report_file

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Watcher - Ultimate Recon/Vuln/PoC Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 watcher_recon.py -t example.com
  python3 watcher_recon.py -t example.com --subdomain-only
  python3 watcher_recon.py -t example.com --port-scan-only
  python3 watcher_recon.py --menu

For legal/authorized testing only!
        """
    )
    
    parser.add_argument('-t', '--target', help='Target domain or IP address')
    parser.add_argument('--menu', action='store_true', help='Launch interactive menu')
    parser.add_argument('--subdomain-only', action='store_true', help='Only perform subdomain discovery')
    parser.add_argument('--port-scan-only', action='store_true', help='Only perform port scanning')
    parser.add_argument('--web-only', action='store_true', help='Only perform web discovery')
    parser.add_argument('-o', '--output', default='watcher_output', help='Output directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize Watcher
    watcher = WatcherRecon()
    watcher.output_dir = args.output
    
    if args.menu:
        # Interactive menu
        print("\n" + "="*60)
        print("    Watcher - Ultimate Recon/Vuln/PoC Automation")
        print("    By Bl4ckC3llSec / Cxb3rF1lthSec")
        print("="*60)
        print("\n[!] For legal/authorized testing only!\n")
        
        target = input("Enter target domain/IP: ").strip()
        if not target:
            print("Error: No target specified")
            sys.exit(1)
        
        print(f"\nStarting reconnaissance for: {target}")
        watcher.run_full_scan(target)
        
    elif args.target:
        if args.subdomain_only:
            watcher.setup_output_directory()
            watcher.subdomain_discovery(args.target)
        elif args.port_scan_only:
            watcher.setup_output_directory()
            watcher.port_scan(args.target)
        elif args.web_only:
            watcher.setup_output_directory()
            watcher.web_discovery([args.target])
        else:
            watcher.run_full_scan(args.target)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()