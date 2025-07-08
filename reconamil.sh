#!/bin/bash
# RSV-Recon: Comprehensive Network Assessment Tool
# Author: AmilRSV
# Inspired by enumify by @wirzka & @warrantea_v01d

# --- ANSI Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Global Variables ---
TARGET=""
OUTPUT_DIR=""
LOG_DIR=""
HTML_REPORT=""
OPEN_PORTS=""
UDP_PORTS=""

# --- Banner ---
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

# --- Helper Functions ---
usage() {
    echo -e "${GREEN}Usage: $0 -H <TARGET-IP>${NC}"
    echo -e "${YELLOW}Example: $0 -H 192.168.1.1${NC}"
    exit 1
}

init_dirs() {
    OUTPUT_DIR="recon-${TARGET}-$(date +%Y%m%d_%H%M%S)"
    LOG_DIR="$OUTPUT_DIR/logs"
    HTML_REPORT="$OUTPUT_DIR/report.html"
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$OUTPUT_DIR/nmap" "$OUTPUT_DIR/recon"
    echo -e "${GREEN}[+] Output will be saved to: $OUTPUT_DIR${NC}"
}

check_dependencies() {
    local missing=()
    local tools=("nmap" "arp-scan" "nikto" "nuclei" "ffuf" "hydra" "smbmap" "smbclient" "enum4linux")
    echo -e "${BLUE}[*] Checking for necessary tools...${NC}"
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing[*]}${NC}"
        read -p "Attempt to install missing tools? (y/n): " install_choice
        if [[ "$install_choice" == "y" ]]; then
            sudo apt update && sudo apt install -y "${missing[@]}"
        fi
    fi
}

# --- Scanning Functions ---

network_discovery() {
    echo -e "${GREEN}[+] Discovering hosts with arp-scan...${NC}"
    sudo arp-scan -l | tee "$LOG_DIR/arp_scan.log"
    mapfile -t DISCOVERED_IPS < <(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$LOG_DIR/arp_scan.log" | sort -u)
    
    if [ ${#DISCOVERED_IPS[@]} -eq 0 ]; then
        echo -e "${RED}[!] No hosts found. Exiting.${NC}"
        exit 1
    fi

    echo -e "\n${YELLOW}[+] Discovered Targets:${NC}"
    for i in "${!DISCOVERED_IPS[@]}"; do echo "$((i+1)). ${DISCOVERED_IPS[$i]}"; done
    
    read -p "Select target (number) or enter custom IP: " target_choice
    if [[ "$target_choice" =~ ^[0-9]+$ ]] && [ "$target_choice" -le "${#DISCOVERED_IPS[@]}" ]; then
        TARGET="${DISCOVERED_IPS[$((target_choice-1))]}"
    else
        TARGET="$target_choice"
    fi
}

port_scan() {
    echo -e "\n${GREEN}--- Starting Full TCP Port Scan ---${NC}"
    sudo nmap -p- -T4 --min-rate 1000 -oN "$OUTPUT_DIR/nmap/full_tcp_scan.nmap" "$TARGET"
    OPEN_PORTS=$(grep -oP '^\d+\/open' "$OUTPUT_DIR/nmap/full_tcp_scan.nmap" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    echo -e "${YELLOW}Scan Complete. Open TCP Ports:${NC}"
    grep --color=always -E '^[0-9]+' "$OUTPUT_DIR/nmap/full_tcp_scan.nmap"
}

script_scan() {
    if [ -z "$OPEN_PORTS" ]; then return; fi
    echo -e "\n${GREEN}--- Starting Script & Version Scan on Open Ports ---${NC}"
    sudo nmap -sCV -p"$OPEN_PORTS" -oN "$OUTPUT_DIR/nmap/script_scan.nmap" "$TARGET"
    echo -e "${YELLOW}Scan Complete. Service Versions:${NC}"
    grep --color=always -E '^[0-9]+' "$OUTPUT_DIR/nmap/script_scan.nmap"
}

udp_scan() {
    echo -e "\n${GREEN}--- Starting Top 100 UDP Scan ---${NC}"
    sudo nmap -sU --top-ports 100 -oN "$OUTPUT_DIR/nmap/udp_scan.nmap" "$TARGET"
    UDP_PORTS=$(grep -oP '^\d+\/open' "$OUTPUT_DIR/nmap/udp_scan.nmap" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    echo -e "${YELLOW}Scan Complete. Open UDP Ports:${NC}"
    grep --color=always -E '^[0-9]+' "$OUTPUT_DIR/nmap/udp_scan.nmap"
}

vuln_scan() {
    if [ -z "$OPEN_PORTS" ]; then return; fi
    echo -e "\n${GREEN}--- Starting Vulnerability Scans ---${NC}"
    
    # Nmap Vuln Scan
    echo -e "${BLUE}[*] Running Nmap NSE vulnerability scripts...${NC}"
    sudo nmap -sV --script="vuln" -p"$OPEN_PORTS" -oN "$OUTPUT_DIR/nmap/vuln_scan.nmap" "$TARGET"
    echo -e "${YELLOW}Nmap Vuln Scan Results:${NC}"
    cat "$OUTPUT_DIR/nmap/vuln_scan.nmap"

    # Web Scans
    if [[ ",$OPEN_PORTS," == *",80,"* || ",$OPEN_PORTS," == *",443,"* ]]; then
        echo -e "\n${BLUE}[*] Running Nikto...${NC}"
        nikto -h "$TARGET" -output "$OUTPUT_DIR/recon/nikto.txt"
        echo -e "${YELLOW}Nikto Results:${NC}"
        cat "$OUTPUT_DIR/recon/nikto.txt"

        echo -e "\n${BLUE}[*] Running Nuclei...${NC}"
        nuclei -u "http://$TARGET" -t vulnerabilities -o "$OUTPUT_DIR/recon/nuclei.txt"
        echo -e "${YELLOW}Nuclei Results:${NC}"
        cat "$OUTPUT_DIR/recon/nuclei.txt"
    fi
}

recon_recommend_and_run() {
    if [ -z "$OPEN_PORTS" ]; then return; fi
    echo -e "\n${GREEN}--- Starting Recommended Recon Actions ---${NC}"

    # Web Recon
    if [[ ",$OPEN_PORTS," == *",80,"* || ",$OPEN_PORTS," == *",443,"* ]]; then
        echo -e "\n${BLUE}[*] Running FFUF for web directory bruteforcing...${NC}"
        ffuf -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/recon/ffuf.json"
        echo -e "${YELLOW}FFUF Results:${NC}"
        cat "$OUTPUT_DIR/recon/ffuf.json"
    fi

    # FTP Recon
    if [[ ",$OPEN_PORTS," == *",21,"* ]]; then
        echo -e "\n${BLUE}[*] Running Hydra for FTP bruteforce...${NC}"
        hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/2020-200_most_common_passwords.txt "$TARGET" ftp -o "$OUTPUT_DIR/recon/hydra_ftp.txt"
        echo -e "${YELLOW}Hydra FTP Results:${NC}"
        cat "$OUTPUT_DIR/recon/hydra_ftp.txt"
    fi

    # SMB Recon
    if [[ ",$OPEN_PORTS," == *",445,"* || ",$OPEN_PORTS," == *",139,"* ]]; then
        echo -e "\n${BLUE}[*] Running SMB enumeration...${NC}"
        smbmap -H "$TARGET" | tee "$OUTPUT_DIR/recon/smbmap.txt"
        smbclient -L "//$TARGET/" -N | tee "$OUTPUT_DIR/recon/smbclient.txt"
        enum4linux -a "$TARGET" | tee "$OUTPUT_DIR/recon/enum4linux.txt"
        echo -e "${YELLOW}SMB Enumeration Complete. Check logs in output directory.${NC}"
    fi
}

# --- Reporting ---
generate_report() {
    echo -e "\n${GREEN}--- Generating HTML Report ---${NC}"
    
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
    <div class="section"><h2>Nmap Script Scan</h2><pre>$(cat "$OUTPUT_DIR/nmap/script_scan.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Nmap Vuln Scan</h2><pre>$(cat "$OUTPUT_DIR/nmap/vuln_scan.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Nikto Scan</h2><pre>$(cat "$OUTPUT_DIR/recon/nikto.txt" 2>/dev/null)</pre></div>
    <div class="section"><h2>Nuclei Scan</h2><pre>$(cat "$OUTPUT_DIR/recon/nuclei.txt" 2>/dev/null)</pre></div>
    <div class="section"><h2>FFUF Scan</h2><pre>$(cat "$OUTPUT_DIR/recon/ffuf.json" 2>/dev/null)</pre></div>
    <div class="section"><h2>Hydra FTP Scan</h2><pre>$(cat "$OUTPUT_DIR/recon/hydra_ftp.txt" 2>/dev/null)</pre></div>
    <div class="section"><h2>SMBMap Scan</h2><pre>$(cat "$OUTPUT_DIR/recon/smbmap.txt" 2>/dev/null)</pre></div>
    <footer><p>Report generated by AmilRSV | <a href="https://github.com/ravisairockey" target="_blank">https://github.com/ravisairockey</a></p></footer>
</body>
</html>
EOF

    echo -e "${GREEN}[+] Report generated: $HTML_REPORT${NC}"
    xdg-open "$HTML_REPORT" 2>/dev/null
}

# --- Main Execution ---
main() {
    banner
    check_dependencies

    # Argument parsing
    if [ $# -eq 0 ]; then
        network_discovery
    else
        while [ $# -gt 0 ]; do
            case "$1" in
                -H|--host) TARGET="$2"; shift; shift;;
                *) usage;;
            esac
        done
    fi

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] No target selected. Exiting.${NC}"
        exit 1
    fi

    init_dirs
    port_scan
    script_scan
    udp_scan
    vuln_scan
    recon_recommend_and_run
    generate_report
    
    echo -e "\n${PURPLE}=== All Scans Complete ===${NC}"
}

main "$@"
