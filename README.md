# 🛡️ DefRecon: Advanced Defense Infrastructure Reconnaissance Tool

DefRecon is a sophisticated Python-based tool designed for comprehensive defense infrastructure reconnaissance. It automatically analyzes target web applications to detect and fingerprint various security and network components, including **Web Application Firewalls (WAFs)**, **Network Firewalls**, **CDNs**, **Web Servers**, and **Backend Technologies**.

This tool provides a consolidated view of the target's security posture by leveraging multiple collection methods, including HTTP header analysis, DNS/network lookups, TLS fingerprinting, and active behavioral testing (for WAF/Firewall detection).

## ✨ Features

* **HTTP Fingerprinting:** Collects and analyzes HTTP headers (`Server`, `X-Powered-By`, cookies) and response body patterns to identify web servers and backend technologies (e.g., WordPress, Laravel, React).
* **WAF Detection:** Uses both **signature-based** (headers/cookies) and **behavioral-based** (malicious payload testing and timing analysis) methods for high-confidence WAF identification.
* **Network Firewall Analysis:** Integrates parallel **Nmap scans** (`-sS`, `-sF`, `-sX`, `-sN`, `-sA`) to detect stateful firewalls, filtering rules, and inconsistent port responses. *Requires `sudo` for full functionality (SYN scans).*
* **DNS & CDN Recon:** Collects `A`, `CNAME`, and `MX` records to identify IP addresses, CDNs (e.g., Cloudflare, Akamai), and mail servers.
* **ASN & Geolocation:** Performs **IPWhois** lookups to identify the owning **ASN** and country of the target's IP address.
* **TLS/SSL Info:** Collects details on the TLS version, cipher suite, and certificate information.
* **Structured Output:** Generates a clean, detailed **JSON report** containing all collected signals and an executive summary of detected components.

## 🚀 Installation

DefRecon requires Python 3 and a few external libraries. It also optionally relies on the `nmap` system utility for full firewall detection capabilities.

### Prerequisites

1.  **Python 3:** Ensure you have Python 3 installed.
2.  **Nmap:** Install the `nmap` tool on your system for the firewall detection module.

    ```bash
    # Debian/Ubuntu
    sudo apt update && sudo apt install nmap

    # macOS (using Homebrew)
    brew install nmap
    ```

### Library Installation

Clone the repository and install the required Python dependencies:

```bash
git clone [https://github.com/YourUsername/DefRecon.git](https://github.com/YourUsername/DefRecon.git)
cd DefRecon
pip install -r requirements.txt
