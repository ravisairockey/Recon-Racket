#!/bin/bash

# incursore.sh - automated recon and scanning framework
# Author: AmilRSV

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'

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
    echo -e "  -t <target>      Specify the target domain or IP address"
    echo -e "  -r               Enable recon mode"
    echo -e "  -p <ports>       Specify ports to scan (default: top 1000 ports)"
    echo -e "  -h               Show this help message"
    printf "Script created and maintained by ${PURPLE}@AmilRSV${NC} \n"
}

# Parse options
RECON=false
PORTS="top-ports 1000"

while getopts ":t:rp:h" opt; do
    case $opt in
        t) TARGET=$OPTARG ;;
        r) RECON=true ;;
        p) PORTS=$OPTARG ;;
        h) usage; exit 0 ;;
        \?) echo -e "${RED}Invalid option: -$OPTARG${NC}" >&2; usage; exit 1 ;;
        :) echo -e "${RED}Option -$OPTARG requires an argument.${NC}" >&2; usage; exit 1 ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo -e "${RED}Target is required!${NC}"
    usage
    exit 1
fi

banner

echo -e "${YELLOW}Starting scan on target: ${TARGET}${NC}"

if [ "$RECON" = true ]; then
    echo -e "${GREEN}Recon mode enabled...${NC}"
    # Add your recon commands here (e.g., subfinder, amass)
fi

echo -e "${GREEN}Running nmap scan on ports: ${PORTS}${NC}"
nmap -sC -sV -T4 --$PORTS $TARGET

echo -e "${GREEN}Scan completed.${NC}"
