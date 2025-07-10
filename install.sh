#!/bin/bash

# --- ANSI Colors ---
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

echo -e "${BLUE}[*] Starting installation for RSV-Recon...${NC}"

# --- Check for Root ---
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Please run this installation script as root or with sudo.${NC}"
  exit 1
fi

# --- Dependency Installation ---
check_dependencies() {
    local missing=()
    # Full list of dependencies for the main script
    local tools=("nmap" "arp-scan" "nikto" "nuclei" "ffuf" "hydra" "smbmap" "smbclient" "enum4linux" "rustscan" "dirbuster")
    echo -e "${BLUE}[*] Checking for necessary tools...${NC}"
    
    # Update package list
    echo -e "${YELLOW}[*] Updating package lists...${NC}"
    apt-get update -y
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] ${tool} not found. Attempting to install...${NC}"
            apt-get install -y "$tool"
            if ! command -v "$tool" &> /dev/null; then
                echo -e "${RED}[!] Failed to install ${tool}. Please install it manually.${NC}"
            fi
        else
            echo -e "${GREEN}[+] ${tool} is already installed.${NC}"
        fi
    done

    # Check for seclists
    if [ ! -d /usr/share/seclists ]; then
        echo -e "${YELLOW}[!] SecLists not found. Attempting to install...${NC}"
        apt-get install -y seclists
    else
        echo -e "${GREEN}[+] SecLists is already installed.${NC}"
    fi
}

check_dependencies

# --- Make Script Executable ---
echo -e "\n${BLUE}[*] Setting execute permissions for reconamil.sh...${NC}"
chmod +x reconamil.sh
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Permissions set successfully.${NC}"
else
    echo -e "${RED}[!] Failed to set permissions.${NC}"
    exit 1
fi

# --- Create Symlink ---
echo -e "\n${BLUE}[*] Creating symbolic link in /usr/local/bin/...${NC}"
if [ -L /usr/local/bin/reconamil ]; then
    rm /usr/local/bin/reconamil
fi
ln -s "$(pwd)/reconamil.sh" /usr/local/bin/reconamil
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Symbolic link created. You can now run 'reconamil.sh' from anywhere.${NC}"
else
    echo -e "${RED}[!] Failed to create symbolic link.${NC}"
fi

echo -e "\n${GREEN}=== Installation Complete! ===${NC}"
