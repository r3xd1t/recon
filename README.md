# ReconPulse

Offensive reconnaissance tool for penetration testers

✨ Features
Passive Reconnaissance

 WHOIS Lookup - Retrieve domain registration information

 NS Enumeration - Fetch A, MX, TXT, NS records

 Subdomain Enumeration - Discover subdomains using crt.sh API

Active Scanning

 Port Scanning - Nmap-based TCP/SYN scans

 Banner Grabbing - Service version detection

 Technology Detection - Identify web frameworks and CMS

Reporting

 HTML Reports - Professional visual format

 Text Reports - Lightweight output

 Terminal Output - Real-time colored results

🛠 Installation
    Requirements

    Python 3.10+

    Nmap

    Kali Linux (recommended)

Setup
 bash

# Clone repository
  git clone https://github.com/yourusername/ReconPulse.git
 
 cd ReconPulse

# Create virtual environment
  python3 -m venv venv
  source venv/bin/activate

# Install dependencies
  pip install -r requirements.txt

# Set permissions
 chmod +x reconpulse.py

Post-Install
bash

# Enable privileged scanning
 sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Verify installation
 ./reconpulse.py --help

🚀 Usage
Basic Scan
bash

python reconpulse.py example.com --whois --dns

Full Reconnaissance
bash

 sudo python reconpulse.py example.com --all -o html

Module-Based Scanning
bash

# Subdomain discovery
 python reconpulse.py example.com --subdomains -v

# Port scanning only
 sudo python reconpulse.py example.com --portscan

# Technology detection
 python reconpulse.py example.com --tech -o txt

🧩 Modules
 Passive Reconnaissance
 Module	Command	Description
 WHOIS	--whois	Retrieves domain registration details
 DNS Enum	--dns	Gets A, MX, TXT, NS records
 Subdomains	--subdomains	Discovers subdomains via crt.sh
 Active Scanning
 Module	Command	Description
 Port Scan	--portscan	Scans open ports (requires sudo)
 Banner Grab	--banner	Retrieves service banners
 Tech Detect	--tech	Identifies web technologies
