# 🛡️ Reconamil.sh
> Automated recon and scanning framework for bug bounty, pentesting & red teaming.

![bash](https://img.shields.io/badge/Shell-Bash-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-purple?style=for-the-badge)

---

## 🚀 What is Reconamil.sh?
**Reconamil.sh** is a modular, automated shell script built for recon and scanning:

- ✅ Subdomain enumeration (subfinder, amass)
- ✅ Port & service discovery (nmap)
- ✅ Vulnerability scanning (nikto, wpscan, nuclei)
- ✅ SMB scanning (SMBMap)
- ✅ Network discovery (netdiscover)
- ✅ Directory fuzzing (ffuf, gobuster, feroxbuster)
- ✅ FTP enumeration (nmap --script ftp*)
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
    F --> G[Run nikto, wpscan, nuclei]
    G --> H[Run SMBMap & netdiscover]
    H --> I[Run ffuf, gobuster, feroxbuster, FTP enum]
    I --> J[Generate HTML report]
    J --> K[Show menu]
    K -->|1| L[View scan log]
    K -->|2| M[View HTML report]
    K -->|3| N[Run again]
    K -->|0| O[Exit]
```

---

## ✨ Features

- Subdomain & recon tools: subfinder, amass
- Fast port & service scan: nmap
- Vulnerability scanning: nikto, wpscan, nuclei
- SMB enumeration: SMBMap
- Network discovery: netdiscover
- Directory brute-forcing: ffuf, gobuster, feroxbuster
- FTP enumeration: nmap --script ftp*
- Clean HTML report export
- Timestamped logs in `logs/` folder
- Interactive CLI menu
- Checks & prompts to install missing tools automatically

---

## 🧰 Installation & Setup

⚠️ **Requires:**

- `nmap`
- `subfinder`
- `amass`
- `nikto`
- `wpscan`
- `nuclei`
- `SMBMap`
- `netdiscover`
- `ffuf`, `gobuster`, `feroxbuster`

```bash
git clone https://github.com/ravisairockey/Recon-Racket
cd Recon-Racket
chmod +x Reconamil.sh
```

---

## 📦 Usage

```bash
./Reconamil.sh -t example.com [-r] [-p ports]
```

| Option       | Description                                        |
|-------------:|---------------------------------------------------:|
| `-t target`  | Specify target domain or IP (**required**)        |
| `-r`         | Enable recon mode (subfinder, amass)              |
| `-p ports`   | Ports to scan (default: `top-ports 1000`)        |
| `-h`         | Show help                                         |

---

## 🧪 Example

```bash
./Reconamil.sh -t example.com -r -p "1-1000"
```

Expected:
- Runs subfinder & amass
- nmap scan on ports 1–1000
- nikto, wpscan, nuclei vulnerability checks
- SMB scan & network discovery
- Directory fuzzing & FTP enum
- Saves logs:
  - `logs/scan_TIMESTAMP.txt`
  - `logs/recon_TIMESTAMP.txt`
  - `logs/report_TIMESTAMP.html`

---

## 📊 HTML report preview

Includes:
- Target info
- Scan results & recon output
- Vulnerability findings
- SMB & FTP checks
- Directory fuzz results

*(Screenshot / template coming soon!)*

---

## 🛠️ Extending

Add even more tools easily:
- `httpx` for HTTP probing
- `Slack / Discord` notifications
- Automatic upload to dashboards

---

## 📂 Project structure

```plaintext
Reconamil.sh/
├── Reconamil.sh
├── logs/
│   ├── scan_TIMESTAMP.txt
│   ├── recon_TIMESTAMP.txt
│   └── report_TIMESTAMP.html
└── README.md
```

---

## ⚡ Contributing

Pull requests welcome!

**Tips:**
- Keep functions modular
- Use color codes for clarity
- Always log into `logs/`

---

## 📜 License

MIT License

---

## ✒️ Author

Made with ❤️ by **@AmilRSV**

> ⚔️ “Automation is the future of recon.”

---

✅ Want more?
- Add `docs/` folder with real screenshots
- HTML report template
- GitHub Actions CI badge

Just say: **"yes, add those"** 🚀
