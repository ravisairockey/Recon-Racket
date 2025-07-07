# 🛡️ Reconamil.sh
> Automated recon and scanning framework for bug bounty, pentesting & red teaming.

![bash](https://img.shields.io/badge/Shell-Bash-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-purple?style=for-the-badge)

---

## 🚀 What is Reconamil.sh?
**Reconamil.sh** is a modular, automated shell script built for recon and scanning:

✅ Subdomain enumeration  
✅ Port & service discovery  
✅ Vulnerability scanning  
✅ HTML report & log export  
✅ Interactive CLI menu for repeated scans

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
