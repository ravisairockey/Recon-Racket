#!/bin/bash

# ReconAmil.sh - Automated recon & scanning by AmilRSV
# https://github.com/YourUser/Reconamil

# Define colors
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; PURPLE='\033[0;35m'; NC='\033[0m'

LOG_DIR="logs"
mkdir -p "$LOG_DIR"

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
 crafted by @AmilRSV
${NC}\n"
}

usage() {
echo -e "${BLUE}Usage: $0 -t <target> [-r] [-p ports] [-h]${NC}"
echo -e "  -t <target>  Target domain or IP"
echo -e "  -r           Enable recon mode"
echo -e "  -p <ports>   Ports to scan (default: top 1000 ports)"
echo -e "  -h           Show help"
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}$1 not found!${NC} Try: sudo apt install $1"
    fi
}

# Defaults
RECON=false; PORTS="top-ports 1000"

while getopts ":t:rp:h" opt; do
    case $opt in
        t) TARGET=$OPTARG ;;
        r) RECON=true ;;
        p) PORTS=$OPTARG ;;
        h) usage; exit 0 ;;
        \?) echo -e "${RED}Invalid option: -$OPTARG${NC}"; usage; exit 1 ;;
        :) echo -e "${RED}Option -$OPTARG needs argument.${NC}"; usage; exit 1 ;;
    esac
done

if [ -z "$TARGET" ]; then echo -e "${RED}Target required!${NC}"; usage; exit 1; fi

banner

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
SCAN_FILE="$LOG_DIR/scan_$TIMESTAMP.txt"
RECON_FILE="$LOG_DIR/recon_$TIMESTAMP.txt"
HTML_REPORT="$LOG_DIR/report_$TIMESTAMP.html"

echo -e "${YELLOW}Target: $TARGET${NC}"

if [ "$RECON" = true ]; then
    check_tool subfinder; check_tool amass
    echo -e "${GREEN}Starting recon...${NC}"
    {
        echo "### subfinder"; subfinder -d "$TARGET"
        echo -e "\n### amass"; amass enum -d "$TARGET"
    } | tee "$RECON_FILE"
fi

check_tool nmap; check_tool nikto; check_tool wpscan
echo -e "${GREEN}Running nmap scan...${NC}"
nmap -sC -sV -T4 --$PORTS "$TARGET" | tee "$SCAN_FILE"

echo -e "${GREEN}Running nikto...${NC}"
nikto -h "$TARGET" >> "$SCAN_FILE"

echo -e "${GREEN}Running wpscan...${NC}"
wpscan --url "http://$TARGET" --enumerate p >> "$SCAN_FILE"

# Simple HTML
{
echo "<html><head><title>Reconamil Report</title></head><body>"
echo "<h1>Target: $TARGET</h1><h3>Scan:</h3><pre>"; cat "$SCAN_FILE"; echo "</pre>"
if [ "$RECON" = true ]; then echo "<h3>Recon:</h3><pre>"; cat "$RECON_FILE"; echo "</pre>"; fi
echo "</body></html>"
} > "$HTML_REPORT"

echo -e "${GREEN}HTML report created: $HTML_REPORT${NC}"

# Menu
while true; do
echo -e "\n${YELLOW}--- Menu ---${NC}"
echo "1. View scan log"; echo "2. View HTML report"; echo "3. Network discovery"
echo "4. SMB enum"; echo "5. FTP enum"; echo "6. ffuf"; echo "7. gobuster"
echo "8. feroxbuster"; echo "9. nuclei"; echo "10. Run all again"; echo "0. Exit"
read -p "Choose: " option

case $option in
1) less "$SCAN_FILE" ;;
2) xdg-open "$HTML_REPORT" 2>/dev/null || echo "Open: $HTML_REPORT" ;;
3) check_tool netdiscover; netdiscover -r "$TARGET/24" ;;
4) check_tool smbmap; smbmap -H "$TARGET" ;;
5) echo -e "${GREEN}Running FTP enum...${NC}"; nmap -p 21 --script ftp* "$TARGET" | tee "$LOG_DIR/ftp_$TIMESTAMP.txt" ;;
6) check_tool ffuf; read -p "Wordlist path: " w; ffuf -u http://$TARGET/FUZZ -w "$w" ;;
7) check_tool gobuster; read -p "Wordlist path: " w; gobuster dir -u http://$TARGET -w "$w" ;;
8) check_tool feroxbuster; feroxbuster -u http://$TARGET ;;
9) check_tool nuclei; nuclei -u http://$TARGET ;;
10) $0 -t "$TARGET" ${RECON:+-r} -p "$PORTS"; exit 0 ;;
0) echo -e "${PURPLE}Bye!${NC}"; exit 0 ;;
*) echo -e "${RED}Invalid.${NC}";;
esac
done
