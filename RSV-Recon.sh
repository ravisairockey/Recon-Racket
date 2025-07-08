#!/bin/bash
# RSV-Recon: Comprehensive Network Assessment Tool
# Author: AmilRSV

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
OUTPUT_DIR="recon-$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$OUTPUT_DIR/logs"
HTML_REPORT="$OUTPUT_DIR/report.html"
NETWORK_RANGE="192.168.1.0/24" # Default network range
INTERACTIVE_MODE=true
FAST_SCAN=true

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
${CYAN}Author: AmilRSV | https://github.com/ravisairockey${NC}\n\n"
}

# Initialize directories
init_dirs() {
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$OUTPUT_DIR/nmap" "$OUTPUT_DIR/recon"
}

# Check and install dependencies
check_dependencies() {
    local missing=()
    local tools=("nmap" "subfinder" "amass" "nikto" "wpscan" "nuclei" "smbmap" "netdiscover" 
                 "ffuf" "gobuster" "feroxbuster" "cutycapt" "xsltproc")

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
    
    # Extract discovered IPs
    mapfile -t DISCOVERED_IPS < <(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$LOG_DIR/netdiscover.log" | sort -u)
    
    # Display menu for target selection
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

# Fast scan
fast_scan() {
    echo -e "${GREEN}[+] Running fast TCP scan...${NC}"
    sudo nmap -T4 -Pn -sS -F --open -oA "$OUTPUT_DIR/nmap/fast_tcp" "$TARGET" | tee "$LOG_DIR/fast_scan.log"
    
    # Extract open ports for detailed scan
    OPEN_PORTS=$(grep -oP '\d+\/open' "$OUTPUT_DIR/nmap/fast_tcp.nmap" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    
    if [ -z "$OPEN_PORTS" ]; then
        echo -e "${YELLOW}[!] No open TCP ports found${NC}"
    else
        echo -e "${GREEN}[+] Open TCP ports: $OPEN_PORTS${NC}"
    fi
}

# Full scan (runs if fast scan finds open ports)
full_scan() {
    if [ -n "$OPEN_PORTS" ]; then
        echo -e "${GREEN}[+] Running full service scan...${NC}"
        sudo nmap -T4 -Pn -sSV -p "$OPEN_PORTS" --script=banner -oA "$OUTPUT_DIR/nmap/full_tcp" "$TARGET" | tee "$LOG_DIR/full_scan.log"
        
        # Run additional NSE scripts based on detected services
        if grep -q "ftp" "$OUTPUT_DIR/nmap/full_tcp.nmap"; then
            echo -e "${CYAN}[+] Running FTP-specific scans...${NC}"
            sudo nmap -Pn -sV --script="ftp* and not brute" -p "$(echo "$OPEN_PORTS" | grep -oE '21|2121')" "$TARGET" -oN "$OUTPUT_DIR/nmap/ftp_scripts.nmap"
        fi
    fi
}

# Vulnerability scanning
vulnerability_scan() {
    echo -e "${GREEN}[+] Running vulnerability scans...${NC}"
    
    # Web vulnerability scanning
    if [[ "$OPEN_PORTS" == *"80"* || "$OPEN_PORTS" == *"443"* ]]; then
        echo -e "${CYAN}[+] Web vulnerability scanning...${NC}"
        
        # Nikto scan
        echo -e "${BLUE}[*] Running Nikto...${NC}"
        nikto -h "$TARGET" -output "$OUTPUT_DIR/recon/nikto_scan.txt" | tee "$LOG_DIR/nikto.log"
        
        # Nuclei scan
        echo -e "${BLUE}[*] Running Nuclei...${NC}"
        nuclei -u "http://$TARGET" -t vulnerabilities -o "$OUTPUT_DIR/recon/nuclei_scan.txt" | tee "$LOG_DIR/nuclei.log"
        
        # Check for WordPress
        if grep -q "wordpress" "$OUTPUT_DIR/nmap/full_tcp.nmap"; then
            echo -e "${BLUE}[*] Running WPScan...${NC}"
            wpscan --url "http://$TARGET" --no-update -o "$OUTPUT_DIR/recon/wpscan.txt" | tee "$LOG_DIR/wpscan.log"
        fi
        
        # Directory brute-forcing
        echo -e "${BLUE}[*] Running directory brute-force...${NC}"
        ffuf -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/recon/ffuf_scan.json" | tee "$LOG_DIR/ffuf.log"
    fi
    
    # SMB enumeration
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        echo -e "${CYAN}[+] SMB enumeration...${NC}"
        smbmap -H "$TARGET" | tee "$OUTPUT_DIR/recon/smbmap_scan.txt"
        smbclient -L "//$TARGET/" -N | tee -a "$OUTPUT_DIR/recon/smbclient_scan.txt"
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
    
    # Convert Nmap XML to HTML
    if [ -f "$OUTPUT_DIR/nmap/full_tcp.xml" ]; then
        xsltproc "$OUTPUT_DIR/nmap/full_tcp.xml" -o "$OUTPUT_DIR/nmap/nmap_scan.html"
    fi
    
    # Create comprehensive HTML report
    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>RSV-Recon Report for $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #4b0082; }
        h2 { color: #2e8b57; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        .vulnerability { background-color: #fff0f0; padding: 10px; margin: 10px 0; border-left: 3px solid #ff0000; }
        .service { background-color: #f0f8ff; padding: 10px; margin: 10px 0; border-left: 3px solid #1e90ff; }
        .critical { color: #ff0000; font-weight: bold; }
        .warning { color: #ff8c00; }
        .info { color: #1e90ff; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>RSV-Recon Report</h1>
    <p><strong>Target:</strong> $TARGET</p>
    <p><strong>Scan Date:</strong> $(date)</p>
    
    <h2>Summary</h2>
    <div class="service">
        <h3>Open Ports</h3>
        <pre>$(grep -oP '\d+\/open' "$OUTPUT_DIR/nmap/fast_tcp.nmap" 2>/dev/null || echo "No open ports found")</pre>
    </div>
    
    <h2>Critical Findings</h2>
EOF

    # Add critical vulnerabilities from Nuclei
    if [ -f "$OUTPUT_DIR/recon/nuclei_scan.txt" ]; then
        grep -i "critical" "$OUTPUT_DIR/recon/nuclei_scan.txt" >> "$HTML_REPORT"
    fi
    
    # Add service details
    cat >> "$HTML_REPORT" <<EOF
    <h2>Service Details</h2>
EOF

    # Add Nmap results if available
    if [ -f "$OUTPUT_DIR/nmap/full_tcp.nmap" ]; then
        cat >> "$HTML_REPORT" <<EOF
    <div class="service">
        <h3>Nmap Results</h3>
        <pre>$(cat "$OUTPUT_DIR/nmap/full_tcp.nmap")</pre>
    </div>
EOF
    fi

    # Add footer
    cat >> "$HTML_REPORT" <<EOF
    <footer>
        <p>Report generated by RSV-Recon (https://github.com/ravisairockey)</p>
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
        echo -e "${GREEN}1. Network Discovery"
        echo -e "2. Fast Scan"
        echo -e "3. Full Scan"
        echo -e "4. Vulnerability Scan"
        echo -e "5. Generate Report"
        echo -e "6. View Report"
        echo -e "7. Exit${NC}"
        echo -e "${CYAN}Current Target: ${TARGET:-Not Set}${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1) network_discovery ;;
            2) fast_scan ;;
            3) full_scan ;;
            4) vulnerability_scan ;;
            5) generate_report ;;
            6) 
                if [ -f "$HTML_REPORT" ]; then
                    xdg-open "$HTML_REPORT" 2>/dev/null || \
                    firefox "$HTML_REPORT" 2>/dev/null || \
                    chrome "$HTML_REPORT" 2>/dev/null || \
                    echo -e "${RED}Could not open report. Please open manually: $HTML_REPORT${NC}"
                else
                    echo -e "${RED}Report not found. Generate it first.${NC}"
                fi
                sleep 2
                ;;
            7) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Main function
main() {
    init_dirs
    check_dependencies
    
    if [ $# -eq 0 ]; then
        # Interactive mode
        network_discovery
        main_menu
    else
        # Command-line mode
        echo -e "${YELLOW}[!] Command-line mode not fully implemented yet. Use interactive mode.${NC}"
        exit 1
    fi
}

# Start the script
main "$@"
