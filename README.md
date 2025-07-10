# RSV-Recon

This is a comprehensive, interactive reconnaissance script designed for penetration testers. It is based on the excellent `enumify` script and has been enhanced with additional features, a more user-friendly interface, and detailed HTML reporting.

## Features

*   **Interactive Menu**: An easy-to-use menu for discovering hosts and selecting scan types.
*   **Flag-based Operation**: Can also be run with command-line flags for automation and scripting.
*   **Modular Scans**: Choose from a variety of scan types, including Port, Script, UDP, Vulnerability, and Fuzzing scans.
*   **Kali-Optimized**: Uses `rustscan` for fast port scanning if available, and checks for common Kali toolsets like `seclists`.
*   **Recon Recommendations**: Intelligently suggests and runs further enumeration commands based on discovered services.
*   **Comprehensive HTML Reporting**: Generates a detailed, dark-mode HTML report at the end of every scan, consolidating all findings.

## Installation

To install RSV-Recon, simply clone the repository and run the installation script with `sudo`.

```bash
git clone https://github.com/ravisairockey/Recon-Racket.git
cd Recon-Racket
sudo bash install.sh
```

The installation script will:
1.  Check for and install all necessary dependencies.
2.  Set the correct permissions for the main script.
3.  Create a symbolic link to `/usr/local/bin/`, allowing you to run `reconamil.sh` from any directory.

## Usage

**Interactive Mode (Recommended):**

Simply run the script without any arguments:
```bash
reconamil.sh
```
You will be guided through host discovery and scan type selection.

**Flag-based Mode:**

You can also run the script with flags for faster execution:
```bash
reconamil.sh -H <TARGET-IP> -t <TYPE>
```

**Scan Types:**
*   `Port`: Shows all open ports.
*   `Script`: Runs a script scan on found ports.
*   `UDP`: Runs a UDP scan.
*   `Vulns`: Runs CVE and vulnerability scans.
*   `Recon`: Suggests and runs further recon commands.
*   `Fuzz`: Runs a `ffuf` scan on discovered web servers.
*   `All`: Runs all available scans.
