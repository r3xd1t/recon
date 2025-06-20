#!/usr/bin/env python3
"""
ReconPulse - Offensive Security Reconnaissance Tool with Terminal Output
"""

import argparse
import socket
import time
import json
import dns.resolver
import whois
import requests
import nmap
import logging
from datetime import datetime
import ssl
from bs4 import BeautifulSoup
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ReconPulse')

# Color codes for terminal output
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ====================== PASSIVE RECON ======================
def whois_lookup(domain):
    try:
        logger.info(f"Performing WHOIS lookup for {domain}")
        result = whois.whois(domain)
        
        # Print to terminal
        print(f"\n{colors.OKGREEN}WHOIS Information:{colors.ENDC}")
        print(f"{colors.OKBLUE}Domain: {colors.ENDC}{result.domain_name}")
        print(f"{colors.OKBLUE}Registrar: {colors.ENDC}{result.registrar}")
        print(f"{colors.OKBLUE}Creation Date: {colors.ENDC}{result.creation_date}")
        print(f"{colors.OKBLUE}Expiration Date: {colors.ENDC}{result.expiration_date}")
        print(f"{colors.OKBLUE}Name Servers: {colors.ENDC}{', '.join(result.name_servers)}")
        
        return result
    except Exception as e:
        error_msg = f"WHOIS lookup failed: {str(e)}"
        logger.error(error_msg)
        print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return error_msg

def dns_enumeration(domain):
    logger.info(f"Enumerating DNS records for {domain}")
    records = {}
    record_types = ['A', 'MX', 'TXT', 'NS']
    
    print(f"\n{colors.OKGREEN}DNS Records:{colors.ENDC}")
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
            
            # Print to terminal
            print(f"{colors.OKBLUE}{rtype} Records:{colors.ENDC}")
            for record in records[rtype]:
                print(f"  {record}")
                
        except dns.resolver.NoAnswer:
            records[rtype] = ["No records found"]
            print(f"{colors.WARNING}No {rtype} records found{colors.ENDC}")
        except Exception as e:
            error_msg = f"Error retrieving {rtype} records: {str(e)}"
            records[rtype] = [error_msg]
            logger.error(error_msg)
            print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
    
    return records

def subdomain_enumeration(domain):
    logger.info(f"Enumerating subdomains for {domain}")
    subdomains = set()
    
    print(f"\n{colors.OKGREEN}Subdomain Enumeration:{colors.ENDC}")
    
    # crt.sh API
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry['name_value'].lower().strip()
                if name.endswith(domain) and name != domain:
                    subdomains.add(name)
                    
        print(f"{colors.OKBLUE}Found {len(subdomains)} subdomains via crt.sh{colors.ENDC}")
        
    except Exception as e:
        error_msg = f"crt.sh API error: {str(e)}"
        logger.error(error_msg)
        print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
    
    return sorted(subdomains)

# ===================== ACTIVE RECON =====================
def port_scan(target, ports="1-1000"):
    logger.info(f"Scanning ports on {target}")
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, ports=ports, arguments='-sV')
        
        results = {}
        print(f"\n{colors.OKGREEN}Port Scan Results for {target}:{colors.ENDC}")
        
        for host in scanner.all_hosts():
            if 'tcp' in scanner[host]:
                results[host] = scanner[host]['tcp']
                print(f"{colors.OKBLUE}Host: {host}{colors.ENDC}")
                
                for port, info in scanner[host]['tcp'].items():
                    service = info.get('name', 'unknown')
                    version = info.get('version', '')
                    product = info.get('product', '')
                    print(f"  Port {port}: {service} {product} {version}")
        
        return results
    except Exception as e:
        error_msg = f"Port scan failed: {str(e)}"
        logger.error(error_msg)
        print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return {"error": error_msg}

def banner_grabbing(target, port):
    try:
        logger.debug(f"Grabbing banner from {target}:{port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            banner = s.recv(1024).decode(errors='ignore').strip()
            
            # Print to terminal
            print(f"\n{colors.OKGREEN}Banner from {target}:{port}:{colors.ENDC}")
            print(banner)
            
            return banner
    except Exception as e:
        error_msg = f"Banner grab failed: {str(e)}"
        print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return error_msg

def detect_technologies(url):
    """Simplified technology detection"""
    try:
        logger.info(f"Detecting technologies for {url}")
        response = requests.get(url, timeout=5)
        tech = {}
        
        # Print to terminal
        print(f"\n{colors.OKGREEN}Technology Detection for {url}:{colors.ENDC}")
        
        # Server header
        if 'Server' in response.headers:
            server = response.headers['Server']
            tech['Web Server'] = [server]
            print(f"{colors.OKBLUE}Web Server: {colors.ENDC}{server}")
        
        # X-Powered-By header
        if 'X-Powered-By' in response.headers:
            powered_by = response.headers['X-Powered-By']
            tech['Backend'] = [powered_by]
            print(f"{colors.OKBLUE}Backend: {colors.ENDC}{powered_by}")
        
        # HTML analysis
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Detect jQuery
        jquery_scripts = soup.find_all('script', src=lambda x: x and 'jquery' in x)
        if jquery_scripts:
            versions = set()
            for script in jquery_scripts:
                src = script.get('src', '')
                if 'jquery' in src:
                    # Extract version from URL
                    if 'jquery-' in src:
                        version = src.split('jquery-')[1].split('.min.js')[0]
                        versions.add(version)
            if versions:
                tech['jQuery'] = list(versions)
                print(f"{colors.OKBLUE}jQuery: {colors.ENDC}{', '.join(versions)}")
        
        # Detect React
        react_scripts = [script for script in soup.find_all('script') 
                         if 'react' in script.get('src', '') or 'React' in script.text]
        if react_scripts:
            tech['React'] = ['Detected']
            print(f"{colors.OKBLUE}React: {colors.ENDC}Detected")
        
        # Detect common frameworks
        if 'wp-content' in response.text:
            tech['WordPress'] = ['Detected']
            print(f"{colors.OKBLUE}WordPress: {colors.ENDC}Detected")
        
        # Detect Bootstrap
        if 'bootstrap' in response.text:
            tech['Bootstrap'] = ['Detected']
            print(f"{colors.OKBLUE}Bootstrap: {colors.ENDC}Detected")
            
        return tech
    except Exception as e:
        error_msg = f"Technology detection failed: {str(e)}"
        logger.error(error_msg)
        print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return {"error": error_msg}

# ===================== REPORTING =====================
def generate_text_report(data, domain):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    report = f"ReconPulse Report - {domain}\n"
    report += f"Generated: {timestamp}\n"
    report += "=" * 50 + "\n\n"
    
    # WHOIS section
    report += "[WHOIS INFORMATION]\n"
    report += str(data.get('whois', 'No data')) + "\n\n"
    
    # DNS section
    report += "[DNS RECORDS]\n"
    for rtype, values in data.get('dns', {}).items():
        report += f"{rtype}:\n"
        for value in values:
            report += f"  {value}\n"
    report += "\n"
    
    # Subdomains section
    report += "[SUBDOMAINS]\n"
    for sub in data.get('subdomains', []):
        report += f"- {sub}\n"
    report += "\n"
    
    # Port scan section
    report += "[PORT SCAN RESULTS]\n"
    for host, ports in data.get('port_scan', {}).items():
        report += f"Host: {host}\n"
        for port, info in ports.items():
            service = info.get('name', 'unknown')
            version = info.get('version', '')
            report += f"  Port {port}: {service} {version}\n"
    report += "\n"
    
    # Technology detection
    if 'tech_detect' in data:
        report += "[TECHNOLOGY DETECTION]\n"
        for tech, versions in data['tech_detect'].items():
            report += f"- {tech}: {', '.join(versions)}\n"
    
    return report

def generate_html_report(data, domain):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ReconPulse Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .section {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 20px; }}
        .section-title {{ font-size: 1.4em; margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
        pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        ul {{ list-style-type: none; padding-left: 0; }}
        li {{ padding: 5px 0; border-bottom: 1px solid #f0f0f0; }}
        .tech-item {{ padding: 8px; background: #f9f9f9; margin: 5px 0; border-radius: 3px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #777; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ReconPulse Report</h1>
            <h2>Domain: {domain}</h2>
            <p>Generated: {timestamp}</p>
        </div>
    """
    
    # WHOIS section
    html += """
    <div class="section">
        <h3 class="section-title">WHOIS Information</h3>
        <pre>""" + str(data.get('whois', 'No data')) + """</pre>
    </div>
    """
    
    # DNS section
    html += """
    <div class="section">
        <h3 class="section-title">DNS Records</h3>
    """
    for rtype, values in data.get('dns', {}).items():
        html += f"<h4>{rtype} Records</h4><ul>"
        for value in values:
            html += f"<li>{value}</li>"
        html += "</ul>"
    html += "</div>"
    
    # Subdomains section
    if 'subdomains' in data and data['subdomains']:
        html += """
        <div class="section">
            <h3 class="section-title">Subdomains</h3>
            <ul>
        """
        for sub in data['subdomains']:
            html += f"<li>{sub}</li>"
        html += "</ul></div>"
    
    # Port scan section
    if 'port_scan' in data and data['port_scan']:
        html += """
        <div class="section">
            <h3 class="section-title">Port Scan Results</h3>
        """
        for host, ports in data['port_scan'].items():
            html += f"<h4>Host: {host}</h4><ul>"
            for port, info in ports.items():
                service = info.get('name', 'unknown')
                version = info.get('version', '')
                html += f"<li>Port {port}: {service} {version}</li>"
            html += "</ul>"
        html += "</div>"
    
    # Technology detection
    if 'tech_detect' in data and data['tech_detect']:
        html += """
        <div class="section">
            <h3 class="section-title">Technology Detection</h3>
            <div class="tech-list">
        """
        for tech, versions in data['tech_detect'].items():
            html += f"<div class='tech-item'><strong>{tech}</strong>: {', '.join(versions)}</div>"
        html += "</div></div>"
    
    # Footer
    html += """
        <div class="footer">
            <p>Report generated by ReconPulse | Offensive Security Tool</p>
        </div>
    </div>
</body>
</html>
    """
    
    return html

# ===================== MAIN FUNCTION =====================
def main():
    parser = argparse.ArgumentParser(
        description='ReconPulse - Offensive Security Reconnaissance Tool',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('domain', help='Target domain to investigate')
    parser.add_argument('--whois', action='store_true', help='Perform WHOIS lookup')
    parser.add_argument('--dns', action='store_true', help='Perform DNS enumeration')
    parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains')
    parser.add_argument('--portscan', action='store_true', help='Perform port scanning')
    parser.add_argument('--banner', action='store_true', help='Grab banners from open ports')
    parser.add_argument('--tech', action='store_true', help='Detect web technologies')
    parser.add_argument('--all', action='store_true', help='Run all reconnaissance modules')
    parser.add_argument('-o', '--output', choices=['txt', 'html'], default='html', 
                        help='Output report format')
    parser.add_argument('-v', '--verbose', action='count', default=0, 
                        help='Increase verbosity level (e.g., -v, -vv)')
    
    args = parser.parse_args()
    
    # Configure logging based on verbosity
    if args.verbose == 1:
        logger.setLevel(logging.INFO)
    elif args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    
    # If --all specified, enable all modules
    if args.all:
        args.whois = args.dns = args.subdomains = args.portscan = args.tech = True
    
    # Print banner
    print(f"\n{colors.HEADER}{'='*60}")
    print(f"ReconPulse - Offensive Reconnaissance Tool")
    print(f"Target: {args.domain}")
    print(f"{'='*60}{colors.ENDC}\n")
    
    # Collect results
    results = {'domain': args.domain}
    start_time = time.time()
    
    # Passive recon modules
    if args.whois:
        results['whois'] = whois_lookup(args.domain)
    
    if args.dns:
        results['dns'] = dns_enumeration(args.domain)
    
    if args.subdomains:
        results['subdomains'] = subdomain_enumeration(args.domain)
        if results['subdomains']:
            print(f"\n{colors.OKGREEN}All Subdomains:{colors.ENDC}")
            for sub in results['subdomains']:
                print(f"  {sub}")
    
    # Active recon modules
    if args.portscan:
        try:
            target_ip = socket.gethostbyname(args.domain)
            results['port_scan'] = port_scan(target_ip)
        except Exception as e:
            error_msg = f"IP resolution failed: {str(e)}"
            logger.error(error_msg)
            print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
            results['port_scan'] = {"error": "IP resolution failed"}
    
    if args.tech:
        url = f"http://{args.domain}"
        results['tech_detect'] = detect_technologies(url)
    
    # Banner grabbing (requires port scan first)
    if args.banner and 'port_scan' in results and not isinstance(results['port_scan'], dict):
        try:
            target_ip = socket.gethostbyname(args.domain)
            banners = {}
            for port in results['port_scan'][target_ip]:
                banners[port] = banner_grabbing(target_ip, port)
            results['banners'] = banners
        except Exception as e:
            error_msg = f"Banner grabbing failed: {str(e)}"
            logger.error(error_msg)
            print(f"{colors.FAIL}{error_msg}{colors.ENDC}")
    
    # Generate report
    report_filename = f"recon_report_{args.domain.replace('.', '_')}_{int(time.time())}"
    
    if args.output == 'txt':
        report = generate_text_report(results, args.domain)
        report_filename += ".txt"
        with open(report_filename, 'w') as f:
            f.write(report)
    else:  # HTML is default
        report = generate_html_report(results, args.domain)
        report_filename += ".html"
        with open(report_filename, 'w') as f:
            f.write(report)
    
    # Print summary
    print(f"\n{colors.OKGREEN}{'='*60}")
    print(f"Recon Summary for {args.domain}")
    print(f"{'='*60}{colors.ENDC}")
    print(f"{colors.BOLD}Report generated: {colors.ENDC}{report_filename}")
    print(f"{colors.BOLD}Scan duration: {colors.ENDC}{time.time() - start_time:.2f} seconds")
    
    logger.info(f"Report generated: {report_filename}")
    logger.info(f"Recon completed in {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
