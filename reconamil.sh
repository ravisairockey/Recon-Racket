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
${CYAN}crafted by @AmilRSV${NC}\n\n"
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
    sudo nmap -T4 -Pn -sV -O -F --open -oA "$OUTPUT_DIR/nmap/fast_tcp" "$TARGET" | tee "$LOG_DIR/fast_scan.log"
    
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
        echo -e "${GREEN}[+] Running full service and vulnerability scan...${NC}"
        sudo nmap -T4 -Pn -sSV -p "$OPEN_PORTS" --script="banner,vuln" -oA "$OUTPUT_DIR/nmap/full_tcp" "$TARGET" | tee "$LOG_DIR/full_scan.log"
        
        # Run additional NSE scripts based on detected services
        if grep -q "ftp" "$OUTPUT_DIR/nmap/full_tcp.nmap"; then
            echo -e "${CYAN}[+] Running FTP-specific scans...${NC}"
            sudo nmap -Pn -sV --script="ftp* and not brute" -p "$(echo "$OPEN_PORTS" | grep -oE '21|2121')" "$TARGET" -oN "$OUTPUT_DIR/nmap/ftp_scripts.nmap"
        fi

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
    fi
}

# Generate HTML report
generate_report() {
    echo -e "${GREEN}[+] Generating HTML report...${NC}"
    
    # Create comprehensive HTML report
    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSV-Recon Report for $TARGET</title>
    <style>
        body { 
            font-family: 'Courier New', Courier, monospace; 
            background-color: #1a1a1a;
            color: #e0e0e0;
            margin: 20px; 
        }
        h1, h2, h3 { 
            color: #9d72ff;
            border-bottom: 1px solid #555;
            padding-bottom: 5px;
        }
        .section {
            background-color: #2b2b2b;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #9d72ff;
            border-radius: 5px;
        }
        .critical { color: #ff4d4d; font-weight: bold; }
        .high { color: #ff8c00; }
        .medium { color: #ffd700; }
        .low { color: #7cfc00; }
        pre { 
            background-color: #111; 
            padding: 10px; 
            border-radius: 3px; 
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        footer {
            text-align: center;
            margin-top: 30px;
            font-size: 0.8em;
            color: #888;
        }
    </style>
</head>
<body>
    <h1>RSV-Recon Report</h1>
    <div class="section">
        <p><strong>Target:</strong> $TARGET</p>
        <p><strong>Scan Date:</strong> $(date)</p>
    </div>

    <div class="section">
        <h2>Summary</h2>
        <h3>Open Ports</h3>
        <pre>$(grep -oP '\d+\/open' "$OUTPUT_DIR/nmap/fast_tcp.nmap" 2>/dev/null || echo "No open ports found")</pre>
        <h3>OS Detection</h3>
        <pre>$(grep "OS details:" "$OUTPUT_DIR/nmap/fast_tcp.nmap" | cut -d':' -f2- 2>/dev/null || echo "OS not detected")</pre>
    </div>

    <div class="section">
        <h2>Nmap Full Scan Results</h2>
        <pre>$(cat "$OUTPUT_DIR/nmap/full_tcp.nmap" 2>/dev/null || echo "Full scan data not available.")</pre>
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
        <h3>WPScan</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/wpscan.txt" 2>/dev/null || echo "WPScan data not available.")</pre>
    </div>

    <div class="section">
        <h2>Enumeration Results</h2>
        <h3>Subdomains</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/subdomains.txt" 2>/dev/null || echo "No subdomains found.")</pre>
        <h3>SMB Shares</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/smbmap_scan.txt" 2>/dev/null || echo "No SMB shares found.")</pre>
        <h3>Directory Brute-force</h3>
        <pre>$(cat "$OUTPUT_DIR/recon/ffuf_scan.json" 2>/dev/null || echo "No directories found.")</pre>
    </div>

    <footer>
        <p>Report generated by AmilRSV</p>
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
        echo -e "${CYAN}Current Target: ${TARGET:-Not Set}${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                network_discovery
                fast_scan
                full_scan
                generate_report
                ;;
            2) 
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
            3) exit 0 ;;
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
        main_menu
    else
        # Command-line mode
        TARGET=$1
        echo -e "${GREEN}[+] Target set to: $TARGET${NC}"
        fast_scan
        full_scan
        generate_report
    fi
}

# Start the script
main "$@"
