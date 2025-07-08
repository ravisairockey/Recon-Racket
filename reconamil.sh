#!/bin/bash
# RSV-Recon: Comprehensive Network Assessment Tool
# Author: AmilRSV
# Inspired by enumify by @wirzka

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global Variables
TARGET=""
OUTPUT_DIR=""
LOG_DIR=""
HTML_REPORT=""
NETWORK_RANGE="192.168.1.0/24" # Default network range
OPEN_PORTS=""

# Banner
banner() {
printf "${PURPLE}
RRRRRRRRRRRRRRRRR      SSSSSSSSSSSSSSS VVVVVVVV           VVVVVVVV
R::::::::::::::::R   SS:::::::::::::::SV::::::V           V::::::V
R::::::RRRRRR:::::R S:::::SSSSSS::::::SV::::::V           V::::::V
RR:::::R     R:::::RS:::::S     SSSSSSSV::::::V           V::::::V
  R::::R     R:::::RS:::::S             V:::::V           V:::::V 
  R::::R     R:::::RS:::::S              V:::::V         V:::::V  
  R::::RRRRRR:::::R  S::::SSSS            V:::::V       V:::::V   
  R:::::::::::::RR    SS::::::SSSSS        V:::::V     V:::::V    
  R::::RRRRRR:::::R     SSS::::::::SS       V:::::V   V:::::V     
  R::::R     R:::::R       SSSSSS::::S       V:::::V V:::::V      
  R::::R     R:::::R            S:::::S       V:::::V:::::V       
  R::::R     R:::::R            S:::::S        V:::::::::V        
RR:::::R     R:::::RSSSSSSS     S:::::S         V:::::::V         
R::::::R     R:::::RS::::::SSSSSS:::::S          V:::::V          
R::::::R     R:::::RS:::::::::::::::SS            V:::V           
RRRRRRRR     RRRRRRR SSSSSSSSSSSSSSS               VVV            
${NC}
${CYAN}crafted by @AmilRSV${NC}\n\n"
}

# Initialize directories
init_dirs() {
    OUTPUT_DIR="recon-${TARGET}-$(date +%Y%m%d_%H%M%S)"
    LOG_DIR="$OUTPUT_DIR/logs"
    HTML_REPORT="$OUTPUT_DIR/report.html"
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$OUTPUT_DIR/nmap" "$OUTPUT_DIR/recon"
}

# Check and install dependencies
check_dependencies() {
    local missing=()
    local tools=("nmap" "subfinder" "amass" "nikto" "wpscan" "nuclei" "smbmap" "netdiscover" "ffuf" "hydra" "smtp-user-enum" "smbclient" "enum4linux" "xsltproc")

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing[*]}${NC}"
        read -p "Attempt to install missing tools? (y/n): " install_choice
        if [[ "$install_choice" == "y" ]]; then
            sudo apt update
            sudo apt install -y "${missing[@]}" || {
                echo -e "${RED}[!] Failed to install some tools. Manual installation may be required.${NC}"
                exit 1
            }
        else
            echo -e "${YELLOW}[!] Some features may not work without these tools${NC}"
            sleep 2
        fi
    fi
}

# Network discovery
network_discovery() {
    echo -e "${GREEN}[+] Running network discovery...${NC}"
    sudo netdiscover -PN -r "$NETWORK_RANGE" | tee "$LOG_DIR/netdiscover.log"
    
    mapfile -t DISCOVERED_IPS < <(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$LOG_DIR/netdiscover.log" | sort -u)
    
    echo -e "\n${YELLOW}[+] Discovered Targets:${NC}"
    for i in "${!DISCOVERED_IPS[@]}"; do
        echo "$((i+1)). ${DISCOVERED_IPS[$i]}"
    done
    
    read -p "Select target (number) or enter custom IP: " target_choice
    
    if [[ "$target_choice" =~ ^[0-9]+$ ]] && [ "$target_choice" -le "${#DISCOVERED_IPS[@]}" ]; then
        TARGET="${DISCOVERED_IPS[$((target_choice-1))]}"
    else
        TARGET="$target_choice"
    fi
    
    echo -e "${GREEN}[+] Selected target: $TARGET${NC}"
}

# Nmap progress bar
progressBar() {
    [ -z "${2##*[!0-9]*}" ] && return 1
    [ "$(stty size | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
    fill="$(printf "%-$((width == 100 ? $2 : ($2 / 2)))s" "#" | tr ' ' '#')"
    empty="$(printf "%-$((width - (width == 100 ? $2 : ($2 / 2))))s" " ")"
    printf "In progress: ${PURPLE}$1${NC} Scan ($3 elapsed - $4 remaining)   \n"
    printf "[${fill}>${empty}] $2%% done   \n"
    printf "\e[2A"
}

nmapProgressBar() {
    refreshRate="${2:-1}"
    outputFile="$OUTPUT_DIR/nmap/comprehensive_scan.nmap"
    tmpOutputFile="${outputFile}.tmp"

    if [ ! -e "${outputFile}" ]; then
        $1 --stats-every "${refreshRate}s" >"${tmpOutputFile}" 2>&1 &
    fi

    while { [ ! -e "${outputFile}" ] || ! grep -q "Nmap done at" "${outputFile}"; } && { [ ! -e "${tmpOutputFile}" ] || ! grep -i -q "quitting" "${tmpOutputFile}"; }; do
        scanType="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/.*undergoing \(.*\) Scan.*/\1/p}')"
        percent="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/% done/{s/.*About \(.*\)\..*% done.*/\1/p}')"
        elapsed="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/Stats: \(.*\) elapsed.*/\1/p}')"
        remaining="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/remaining/{s/.* (\(.*\) remaining.*/\1/p}')"
        progressBar "${scanType:-No}" "${percent:-0}" "${elapsed:-0:00:00}" "${remaining:-0:00:00}"
        sleep "${refreshRate}"
    done
    printf "\033[0K\r\n\033[0K\r\n"

    if [ -e "${outputFile}" ]; then
        sed -n '/PORT.*STATE.*SERVICE/,/^# Nmap/H;${x;s/^\n\|\n[^\n]*\n# Nmap.*//gp}' "${outputFile}" | awk '!/^SF(:|-).*$/' | grep -v 'service unrecognized despite'
    else
        cat "${tmpOutputFile}"
    fi
    rm -f "${tmpOutputFile}"
}

# Comprehensive Scan
run_scan() {
    echo -e "${GREEN}[+] Running Comprehensive Scan... This may take a while.${NC}"
    nmapProgressBar "sudo nmap -p- -A -sC -sV -oA \"$OUTPUT_DIR/nmap/comprehensive_scan\" \"$TARGET\""
    
    OPEN_PORTS=$(grep -oP '\d+\/open' "$OUTPUT_DIR/nmap/comprehensive_scan.nmap" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    
    if [ -z "$OPEN_PORTS" ]; then
        echo -e "${YELLOW}[!] No open TCP ports found${NC}"
    else
        echo -e "${GREEN}[+] Open TCP ports: $OPEN_PORTS${NC}"
    fi
}

# Recon Recommendations and Execution
run_recon() {
    echo -e "${GREEN}[+] Running further enumeration based on open ports...${NC}"
    
    # Web vulnerability scanning
    if [[ "$OPEN_PORTS" == *"80"* || "$OPEN_PORTS" == *"443"* ]]; then
        echo -e "${CYAN}[+] Web vulnerability scanning...${NC}"
        
        echo -e "${BLUE}[*] Running Nikto...${NC}"
        nikto -h "$TARGET" -output "$OUTPUT_DIR/recon/nikto_scan.txt" | tee "$LOG_DIR/nikto.log"
        
        echo -e "${BLUE}[*] Running Nuclei...${NC}"
        nuclei -u "http://$TARGET" -t vulnerabilities,technologies,misconfigurations -o "$OUTPUT_DIR/recon/nuclei_scan.txt" | tee "$LOG_DIR/nuclei.log"
        
        if grep -q "wordpress" "$OUTPUT_DIR/nmap/comprehensive_scan.nmap"; then
            echo -e "${BLUE}[*] Running WPScan...${NC}"
            wpscan --url "http://$TARGET" --no-update --enumerate p,t,u -o "$OUTPUT_DIR/recon/wpscan.txt" | tee "$LOG_DIR/wpscan.log"
        fi
        
        echo -e "${BLUE}[*] Running directory brute-force...${NC}"
        ffuf -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/recon/ffuf_scan.json" | tee "$LOG_DIR/ffuf.log"
    fi
    
    # FTP
    if [[ "$OPEN_PORTS" == *"21"* ]]; then
        echo -e "${CYAN}[+] FTP enumeration...${NC}"
        echo -e "${BLUE}[*] Running Hydra for FTP bruteforce...${NC}"
        hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/2020-200_most_common_passwords.txt "$TARGET" ftp -o "$OUTPUT_DIR/recon/hydra_ftp.txt"
    fi

    # SMB
    if [[ "$OPEN_PORTS" == *"445"* || "$OPEN_PORTS" == *"139"* ]]; then
        echo -e "${CYAN}[+] SMB enumeration...${NC}"
        smbmap -H "$TARGET" | tee "$OUTPUT_DIR/recon/smbmap_scan.txt"
        smbclient -L "//$TARGET/" -N | tee -a "$OUTPUT_DIR/recon/smbclient_scan.txt"
        enum4linux -a "$TARGET" | tee "$OUTPUT_DIR/recon/enum4linux.txt"
    fi

    # Subdomain discovery (if target is a domain)
    if [[ "$TARGET" =~ [a-zA-Z] ]]; then
        echo -e "${CYAN}[+] Running subdomain discovery...${NC}"
        subfinder -d "$TARGET" -o "$OUTPUT_DIR/recon/subdomains.txt" | tee "$LOG_DIR/subfinder.log"
        amass enum -passive -d "$TARGET" -o "$OUTPUT_DIR/recon/amass_subdomains.txt" | tee "$LOG_DIR/amass.log"
    fi
}

# Generate HTML report
generate_report() {
    echo -e "${GREEN}[+] Generating HTML report...${NC}"
    
    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSV-Recon Report for $TARGET</title>
    <style>
        body { font-family: 'Courier New', Courier, monospace; background-color: #1a1a1a; color: #e0e0e0; margin: 20px; }
        h1, h2, h3 { color: #9d72ff; border-bottom: 1px solid #555; padding-bottom: 5px; }
        .section { background-color: #2b2b2b; padding: 15px; margin: 15px 0; border-left: 4px solid #9d72ff; border-radius: 5px; }
        .critical { color: #ff4d4d; font-weight: bold; }
        .high { color: #ff8c00; }
        .medium { color: #ffd700; }
        .low { color: #7cfc00; }
        pre { background-color: #111; padding: 10px; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
        footer { text-align: center; margin-top: 30px; font-size: 0.8em; color: #888; }
        a { color: #9d72ff; }
    </style>
</head>
<body>
    <h1>RSV-Recon Report</h1>
    <div class="section">
        <p><strong>Target:</strong> $TARGET</p>
        <p><strong>Scan Date:</strong> $(date)</p>
    </div>

    <div class="section">
        <h2>Nmap Scan Results</h2>
        <pre>$(cat "$OUTPUT_DIR/nmap/comprehensive_scan.nmap" 2>/dev/null || echo "Nmap data not available.")</pre>
    </div>

    <div class="section">
        <h2>Vulnerability Scan Results</h2>
        <h3>Nuclei Scan</h3>
        <pre class="critical">$(grep -i "critical" "$OUTPUT_DIR/recon/nuclei_scan.txt" 2>/dev/null || echo "No critical findings.")</pre>
        <pre class="high">$(grep -i "high" "$OUTPUT_DIR/recon/nuclei_scan.txt" 2>/dev/null || echo "No high findings.")</pre>
        <pre class="medium">$(grep -i "medium" "$OUTPUT_DIR/recon/nuclei_scan.txt" 2>/dev/null || echo "No medium findings.")</pre>
        <pre class="low">$(grep -i "low" "$OUTPUT_DIR/recon/nuclei_scan.txt" 2>/dev/null || echo "No low findings.")</pre>
        <h3>Nikto Scan</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/nikto_scan.txt" 2>/dev/null || echo "Nikto scan data not available.")</pre>
    </div>

    <div class="section">
        <h2>Enumeration Results</h2>
        <h3>Subdomains</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/subdomains.txt" 2>/dev/null || echo "No subdomains found.")</pre>
        <h3>FTP Brute-force</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/hydra_ftp.txt" 2>/dev/null || echo "FTP brute-force not run or no results.")</pre>
        <h3>SMB Enumeration</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/smbmap_scan.txt" 2>/dev/null || echo "smbmap not run or no results.")</pre>
        <pre>$(cat "$OUTPUT_DIR/recon/smbclient_scan.txt" 2>/dev/null || echo "smbclient not run or no results.")</pre>
        <pre>$(cat "$OUTPUT_DIR/recon/enum4linux.txt" 2>/dev/null || echo "enum4linux not run or no results.")</pre>
        <h3>Web Directory Brute-force</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/ffuf_scan.json" 2>/dev/null || echo "ffuf not run or no results.")</pre>
        <h3>WordPress Scan</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/wpscan.txt" 2>/dev/null || echo "WPScan not run or no results.")</pre>
    </div>

    <footer>
        <p>Report generated by AmilRSV | <a href="https://github.com/ravisairockey" target="_blank">https://github.com/ravisairockey</a></p>
    </footer>
</body>
</html>
EOF

    echo -e "${GREEN}[+] Report generated: $HTML_REPORT${NC}"
}

# Main menu
main_menu() {
    while true; do
        clear
        banner
        echo -e "${YELLOW}Main Menu${NC}"
        echo -e "${GREEN}1. Start Full Recon"
        echo -e "2. View Last Report"
        echo -e "3. Exit${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                network_discovery
                if [ -n "$TARGET" ]; then
                    init_dirs
                    run_scan
                    run_recon
                    generate_report
                    echo -e "${GREEN}All scans complete. Report generated at $HTML_REPORT${NC}"
                fi
                ;;
            2) 
                if [ -n "$HTML_REPORT" ] && [ -f "$HTML_REPORT" ]; then
                    xdg-open "$HTML_REPORT" 2>/dev/null || firefox "$HTML_REPORT" 2>/dev/null || echo -e "${RED}Could not open report. Please open manually: $HTML_REPORT${NC}"
                else
                    echo -e "${RED}Report not found. Generate one first.${NC}"
                fi
                ;;
            3) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}";;
        esac
        read -p "Press Enter to continue..."
    done
}

# Main function
main() {
    banner
    check_dependencies
    
    if [ $# -eq 0 ]; then
        main_menu
    else
        while [ $# -gt 0 ]; do
            key="$1"
            case "${key}" in
                -H|--host)
                TARGET="$2"
                shift; shift
                ;;
                *)
                echo "Unknown option: $1"; exit 1
                ;;
            esac
        done

        if [ -n "$TARGET" ]; then
            init_dirs
            run_scan
            run_recon
            generate_report
            echo -e "${GREEN}All scans complete. Report generated at $HTML_REPORT${NC}"
        else
            echo -e "${RED}No target specified. Use -H <host>${NC}"
            exit 1
        fi
    fi
}

# Start the script
main "$@"
