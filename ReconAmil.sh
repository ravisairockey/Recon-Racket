#!/bin/bash

# Reconamil.sh - Automated recon and scanning framework
# Author: AmilRSV

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'

LOG_DIR="logs"
mkdir -p "$LOG_DIR"

banner() {
    printf "${PURPLE}
8 888888888o.   8 8888888888       ,o888888o.        ,o888888o.     b.             8                     8 888888888o.      d888888o.   \`8.\`888b           ,8'
8 8888    \`88.  8 8888            8888     \`88.   . 8888     \`88.   888o.          8                     8 8888    \`88.   .\`8888:' \`88.  \`8.\`888b         ,8'
8 8888     \`88  8 8888         ,8 8888       \`8. ,8 8888       \`8b  Y88888o.       8                     8 8888     \`88   8.\`8888.   Y8   \`8.\`888b       ,8'
8 8888     ,88  8 8888         88 8888           88 8888        \`8b .\`Y888888o.    8                     8 8888     ,88   \`8.\`8888.        \`8.\`888b     ,8'
8 8888.   ,88'  8 888888888888 88 8888           88 8888         88 8o. \`Y888888o. 8                     8 8888.   ,88'    \`8.\`8888.        \`8.\`888b   ,8'
8 888888888P'   8 8888         88 8888           88 8888         88 8\`Y8o. \`Y88888o8                     8 888888888P'      \`8.\`8888.        \`8.\`888b ,8'
8 8888\`8b       8 8888         88 8888           88 8888        ,8P 8   \`Y8o. \`Y8888                     8 8888\`8b           \`8.\`8888.        \`8.\`888b8'
8 8888 \`8b.     8 8888         \`8 8888       .8' \`8 8888       ,8P  8      \`Y8o. \`Y8                     8 8888 \`8b.     8b   \`8.\`8888.        \`8.\`888'
8 8888   \`8b.   8 8888            8888     ,88'   \` 8888     ,88'   8         \`Y8o.\`                     8 8888   \`8b.   \`8b.  ;8.\`8888         \`8.\`8'
8 8888     \`88. 8 888888888888     \`8888888P'        \`8888888P'     8            \`Yo                     8 8888     \`88.  \`Y8888P ,88P'          \`8.\`
                          crafted by @AmilRSV
${NC}\n"
}

usage() {
    echo -e "${BLUE}Usage: $0 -t <target> [-r] [-p ports] [-h]${NC}"
    echo -e "  -t <target>      Specify target domain or IP"
    echo -e "  -r               Enable recon mode"
    echo -e "  -p <ports>       Specify ports to scan (default: top 1000 ports)"
    echo -e "  -h               Show help"
    printf "Script by ${PURPLE}@AmilRSV${NC} \n"
}

# Options
RECON=false
PORTS="top-ports 1000"

while getopts ":t:rp:h" opt; do
    case $opt in
        t) TARGET=$OPTARG ;;
        r) RECON=true ;;
        p) PORTS=$OPTARG ;;
        h) usage; exit 0 ;;
        \?) echo -e "${RED}Invalid option: -$OPTARG${NC}" >&2; usage; exit 1 ;;
        :) echo -e "${RED}Option -$OPTARG needs argument.${NC}" >&2; usage; exit 1 ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo -e "${RED}Target required!${NC}"
    usage
    exit 1
fi

banner

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
SCAN_FILE="$LOG_DIR/scan_$TIMESTAMP.txt"
RECON_FILE="$LOG_DIR/recon_$TIMESTAMP.txt"
HTML_REPORT="$LOG_DIR/report_$TIMESTAMP.html"

echo -e "${YELLOW}Target: $TARGET${NC}"

if [ "$RECON" = true ]; then
    echo -e "${GREEN}Starting recon...${NC}"
    {
        echo "### subfinder"
        subfinder -d "$TARGET"
        echo -e "\n### amass"
        amass enum -d "$TARGET"
    } | tee "$RECON_FILE"
    echo -e "${GREEN}Recon saved to $RECON_FILE${NC}"
fi

echo -e "${GREEN}Running nmap scan...${NC}"
nmap -sC -sV -T4 --$PORTS "$TARGET" | tee "$SCAN_FILE"

echo -e "${GREEN}Running nikto...${NC}"
nikto -h "$TARGET" >> "$SCAN_FILE"

echo -e "${GREEN}Running wpscan (if target is WP)...${NC}"
wpscan --url "http://$TARGET" --enumerate p >> "$SCAN_FILE"

echo -e "${GREEN}Scan finished. Logs in: $SCAN_FILE${NC}"

# Simple HTML report
{
echo "<html><head><title>Reconamil Report</title></head><body>"
echo "<h1>Reconamil Report by AmilRSV</h1>"
echo "<h2>Target: $TARGET</h2>"
echo "<h3>Scan Log:</h3><pre>"
cat "$SCAN_FILE"
echo "</pre>"
if [ "$RECON" = true ]; then
    echo "<h3>Recon Log:</h3><pre>"
    cat "$RECON_FILE"
    echo "</pre>"
fi
echo "</body></html>"
} > "$HTML_REPORT"

echo -e "${GREEN}HTML report created: ${BLUE}$HTML_REPORT${NC}"

# Menu
while true; do
    echo -e "\n${YELLOW}--- Menu ---${NC}"
    echo "1. View latest scan log"
    echo "2. View HTML report"
    echo "3. Run full scan again"
    echo "0. Exit"
    read -p "Choose option: " option

    case $option in
        1)
            less "$SCAN_FILE"
            ;;
        2)
            xdg-open "$HTML_REPORT" 2>/dev/null || echo -e "${RED}Couldn’t open report. Open manually: $HTML_REPORT${NC}"
            ;;
        3)
            $0 -t "$TARGET" ${RECON:+-r} -p "$PORTS"
            exit 0
            ;;
        0)
            echo -e "${PURPLE}Bye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option.${NC}"
            ;;
    esac
done
