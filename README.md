This documentation explains how to set up the environment, install the required Go binaries, and use the tool effectively.

# 🕵️ Automated Reconnaissance Pipeline

A Python wrapper for ProjectDiscovery tools that automates the flow of subdomain enumeration, DNS resolution, port scanning, web probing, and crawling.

**Key Features:**
* **Burp Suite Integration:** Automatically routes `httpx` and `katana` traffic through a proxy (e.g., `127.0.0.1:8080`) to populate your Site Map.
* **Smart Filtering:** Chains tools efficiently (Subdomains → DNS → Ports → Live Web → Endpoints).
* **Burp Import File:** Generates a clean `urls_for_burp.txt` for easy target importing.
* **Rich UI:** Beautiful terminal output with status spinners and progress logs.

## 📋 Prerequisites

1.  **Python 3.8+**
2.  **Go (Golang):** Required to install the underlying scanning engines.

## 🛠️ Installation

### 1. Install Python Dependencies
bash
pip install -r requirements.txt


2. Install External Tools (Go Binaries)
This script acts as an orchestrator for the following tools. You must have them installed and in your system $PATH (or ~/go/bin).

Run the following commands to install all required tools:

go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
go install -v [github.com/projectdiscovery/dnsx/cmd/dnsx@latest](https://github.com/projectdiscovery/dnsx/cmd/dnsx@latest)
go install -v [github.com/projectdiscovery/naabu/v2/cmd/naabu@latest](https://github.com/projectdiscovery/naabu/v2/cmd/naabu@latest)
go install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://github.com/projectdiscovery/httpx/cmd/httpx@latest)
go install -v [github.com/projectdiscovery/katana/cmd/katana@latest](https://github.com/projectdiscovery/katana/cmd/katana@latest)

Note on HTTPX: Ensure you are using the ProjectDiscovery Go version of httpx, not the Python library of the same name. The script attempts to auto-detect the correct binary.

🚀 Usage
Basic Scan
Performs a full reconnaissance chain on a single domain.

python3 recon.py -d example.com

Scan with Burp Proxy
Routes HTTP probing and crawling traffic through Burp Suite.

   1.Open Burp Suite -> Proxy -> Options.

   2.Ensure proxy listener is running (default 127.0.0.1:8080).

   3.Run:
python3 recon.py -d example.com -p [http://127.0.0.1:8080](http://127.0.0.1:8080)

Scan a List of Domains
python3 recon.py -l targets.txt


Dry Run
Prints the commands that would be executed without actually running them.
python3 recon.py -d example.com --dry-run

📂 Output Structure
By default, results are saved in the recon_results/ directory:
File	Description
subfinder.txt	All discovered subdomains.
dnsx.txt	Subdomains that resolved (active).
naabu.txt	Open ports found on active subdomains.
httpx.txt	Live web servers with status codes/titles.
katana.txt	Crawled endpoints (JS, parameters, etc.).
urls_for_burp.txt	Clean list of all URLs for easy copy-paste into Burp.
summary.json	Statistical summary of the run.


⚙️ Workflow Logic

    Subfinder: Finds passive subdomains.

    DNSx: Filters out dead subdomains.

    Naabu: Scans for open ports (Standard web ports + 8000, 8080, 8443, etc).

    HTTPx: Probes for active web services (Proxy aware).

    Katana: Crawls the active web services for endpoints (Proxy aware).

    Post-Processing: Cleans data and generates a summary.
























