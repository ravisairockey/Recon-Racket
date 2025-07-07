# 🛡️ Reconamil.sh
> Automated recon and scanning framework for bug bounty, pentesting & red teaming.

![bash](https://img.shields.io/badge/Shell-Bash-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-purple?style=for-the-badge)

---

## 🚀 What is Reconamil.sh?
**Reconamil.sh** is a modular, automated shell script built for recon and scanning:

- ✅ Subdomain enumeration  
- ✅ Port & service discovery  
- ✅ Vulnerability scanning  
- ✅ HTML report & log export  
- ✅ Interactive CLI menu for repeated scans

Crafted and maintained by **@AmilRSV**.

---


## 🔍 Workflow diagram

```mermaid
graph TD
    A[Start] --> B{Target Provided?}
    B -- Yes --> C[Show Banner]
    C --> D{Recon Mode?}
    D -- Yes --> E[Run subfinder & amass]
    E --> F[Run nmap scan]
    D -- No --> F
    F --> G[Run nikto & wpscan]
    G --> H[Generate HTML report]
    H --> I[Show menu]
    I -->|1| J[View scan log]
    I -->|2| K[View HTML report]
    I -->|3| L[Run again]
    I -->|0| M[Exit]
 ```
✨ Features

    Reconnaissance with subfinder, amass

    Fast port & service scanning with nmap

    Vulnerability scanning (nikto, wpscan)

    Clean HTML report export

    Timestamped logs in logs/ folder

    Interactive terminal menu

    Easy to extend with more tools

🧰 Installation & Setup

⚠️ Requires:

    nmap

    subfinder

    amass

    nikto

    wpscan

git clone https://github.com/YourUser/Reconamil.sh.git
cd Reconamil.sh
chmod +x Reconamil.sh

📦 Usage

./Reconamil.sh -t example.com [-r] [-p ports]

Option	Description
-t target	Specify target domain or IP (required)
-r	Enable recon mode (subfinder, amass)
-p ports	Ports to scan (default: top-ports 1000)
-h	Show help
🧪 Example

./Reconamil.sh -t example.com -r -p "1-1000"

Expected:

    Runs subdomain scan (subfinder, amass)

    nmap scan on ports 1–1000

    nikto & wpscan vulnerability checks

    Saves logs:

        logs/scan_TIMESTAMP.txt

        logs/recon_TIMESTAMP.txt

        logs/report_TIMESTAMP.html

📊 Sample HTML report preview

Includes:

    Target info

    Nmap scan results

    Recon output (if enabled)

    Nikto & wpscan findings

(Screenshot / template coming soon!)
🛠️ Extending

Add your favorite tools easily:

    gobuster for directory brute-force

    httpx or ffuf for URL fuzzing

    Slack / Discord / Telegram notifications

📂 Project structure

Reconamil.sh/
├── Reconamil.sh
├── logs/
│   ├── scan_TIMESTAMP.txt
│   ├── recon_TIMESTAMP.txt
│   └── report_TIMESTAMP.html
└── README.md

⚡ Contributing

Pull requests welcome!

Tips:

    Keep functions modular

    Use color codes for clarity

    Always log into logs/ folder

📜 License

MIT License
✒️ Author

Made with ❤️ by @AmilRSV

    ⚔️ “Automation is the future of recon.”
