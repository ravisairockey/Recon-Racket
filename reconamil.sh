#!/bin/bash
# RSV-Recon: The Ultimate Recon Script
# Author: RSVamil
# Based on enumify by @wirzka & @warrantea_v01d

# --- ANSI Colors ---
RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
NC='\033[0m'

# --- Global Variables ---
HOST=""
TYPE=""
DNS=""
OUTPUTDIR=""
DNSSERVER=""
DNSSTRING=""
NMAPPATH=""
allTCPPorts=""
udpPorts=""
osType=""
nmapType=""

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
${CYAN}crafted by @RSVamil${NC}\n\n"
}

# --- Helper Functions ---
usage() {
        banner
        echo
        printf "${GREEN}Usage:${NC} ${RED}$(basename $0) -H/--host ${NC}<TARGET-IP>${RED} -t/--type ${NC}<TYPE>${RED}\n"
        printf "${YELLOW}If no flags are given, the script will start in interactive menu mode.${NC}\n\n"
        printf "${CYAN}Scan Types:\n"
        printf "${CYAN}\tPort    : ${NC}Shows all open ports ${YELLOW}\n"
        printf "${CYAN}\tScript  : ${NC}Runs a script scan on found ports ${YELLOW}\n"
        printf "${CYAN}\tUDP     : ${NC}Runs a UDP scan \"requires sudo\" ${YELLOW}\n"
        printf "${CYAN}\tVulns   : ${NC}Runs CVE scan and nmap Vulns scan on all found ports ${YELLOW}\n"
        printf "${CYAN}\tRecon   : ${NC}Suggests recon commands, then prompts to automatically run them\n"
        printf "${CYAN}\tAll     : ${NC}Runs all the scans ${YELLOW}\n"
        printf "${NC}\n"
        printf "Crafted by ${PURPLE}@RSVamil${NC} \n"
        exit 1
}

header() {
        # No need to print banner again if in interactive mode
        if [ "$INTERACTIVE_MODE" = true ] ; then
            : # Do nothing
        else
            banner
        fi
        echo
        if expr "${TYPE}" : '^\([Aa]ll\)$' >/dev/null; then
                printf "${GREEN}Hail Mary on ${NC}${PURPLE}${HOST}${NC}"
        else
                printf "${GREEN}Launching a ${TYPE} scan on ${NC}${HOST}"
        fi

        if expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                urlIP="$(host -4 -W 1 ${HOST} ${DNSSERVER} 2>/dev/null | grep ${HOST} | head -n 1 | awk {'print $NF'})"
                if [ -n "${urlIP}" ]; then
                        printf "${YELLOW} with IP ${NC}${urlIP}\n\n"
                else
                        printf ".. ${RED}Could not resolve IP of ${NC}${HOST}\n\n"
                fi
        else
                printf "\n"
        fi

        if expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                subnet="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"
        fi

        kernel="$(uname -s)"
        checkPing="$(checkPing "${urlIP:-$HOST}")"
        nmapType="$(echo "${checkPing}" | head -n 1)"

        ttl="$(echo "${checkPing}" | tail -n 1)"
        if [ "${ttl}" != "nmap -Pn" ]; then
                osType="$(checkOS "${ttl}")"
                printf "${NC}\n"
                printf "${GREEN}Host is likely running ${NC}${PURPLE}${osType}${NC}\n"
        fi
        echo
}

assignPorts() {
        if [ -f "nmap/full_TCP_$1.nmap" ]; then
                allTCPPorts="$(grep '^[0-9]' "nmap/full_TCP_$1.nmap" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')"
        fi

        if [ -f "nmap/UDP_$1.nmap" ]; then
                udpPorts="$(grep '^[0-9]' "nmap/UDP_$1.nmap" | grep 'open' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')"
        fi
}

checkPing() {
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi
        pingTest="$(ping -c 1 -${TW} 1 "$1" 2>/dev/null | grep ttl)"
        if [ -z "${pingTest}" ]; then
                echo "${NMAPPATH} -Pn"
        else
                echo "${NMAPPATH}"
                if expr "$1" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                        ttl="$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)"
                else
                        ttl="$(echo "${pingTest}" | cut -d " " -f 7 | cut -d "=" -f 2)"
                fi
                echo "${ttl}"
        fi
}

checkOS() {
        case "$1" in
        25[456]) echo "OpenBSD/Cisco/Oracle" ;;
        12[78]) echo "Windows" ;;
        6[34]) echo "Linux" ;;
        *) echo "Some alien stuff!" ;;
        esac
}

print_header() {
    local title=" $1 "
    local width
    width=$(tput cols)
    if [ -z "$width" ] || [ "$width" -lt 20 ]; then
        width=80
    fi
    local padding_total=$((width - ${#title}))
    local padding_left=$((padding_total / 2))
    local padding_right=$((padding_total - padding_left))
    printf "\n${PURPLE}%*s" $padding_left '' | tr ' ' '─'
    printf "${CYAN}${title}"
    printf "%*s${NC}\n" $padding_right '' | tr ' ' '─'
}

# --- Scanning Functions ---
portScan() {
        print_header "Starting Port Scan"
        
        if command -v rustscan &> /dev/null; then
            printf "${YELLOW}[*] RustScan Launched${NC}\n"
            rustscan --ulimit 5000 -a ${HOST} -- -sV -oN nmap/Port_${HOST}.nmap
        else
            printf "${YELLOW}[!] Rustscan not found, using nmap.${NC}\n"
            ${nmapType} -T4 --max-retries 1 --max-scan-delay 20 --open -oN nmap/Port_${HOST}.nmap ${HOST} ${DNSSTRING}
        fi
        
        assignPorts "${HOST}"
        printf "${NC}\n"
        printf "${YELLOW}[*] Full TCP port scan launched\n${NC}"
        ${nmapType} -p- -T4 --max-retries 2 -vv --max-scan-delay 30 -Pn --open -oN nmap/full_TCP_${HOST}.nmap ${HOST} ${DNSSTRING}
        assignPorts "${HOST}"
        echo
}

scriptScan() {
        print_header "Starting Script & Version Scan"
        ports="${allTCPPorts}"
        if [ -z "${ports}" ]; then
                printf "${YELLOW}No ports in port scan.. Skipping!\n"
        else
                ${nmapType} -Pn -sCV -p${ports} --open -oN nmap/Script_TCP_${HOST}.nmap ${HOST} ${DNSSTRING}
        fi
        echo
}

UDPScan() {
        print_header "Starting UDP Scan"
        if [ "${USER}" != 'root' ]; then
                echo "${RED}[!] ALERT${NC} UDP scan needs to be run as root."
                sudo -v
        fi
        sudo ${nmapType} -sU --max-retries 1 --open -oN nmap/UDP_${HOST}.nmap ${HOST} ${DNSSTRING}
        assignPorts "${HOST}"
        if [ -n "${udpPorts}" ]; then
                echo
                printf "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')\n"
                printf "${NC}\n"
                sudo nmap -Pn -sCVU -p${udpPorts} --open -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}
        fi
        echo
}

vulnsScan() {
        print_header "Starting Vulnerability Scan"
        ports="${allTCPPorts}"
        if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
                printf "${RED}Please install 'vulners.nse' nmap script and rerun.\n"
        else
                printf "${YELLOW}> Running CVE scan on ports\n"
                printf "${NC}\n"
                nmap -sV -Pn --script vulners --script-args mincvss=7.0 -p${ports} --open -oN nmap/CVEs_${HOST}.nmap ${HOST} ${DNSSTRING}
                echo
        fi
        printf "${YELLOW}> Running Vuln scan on ports\n"
        printf "${NC}\n"
        nmap -sV -Pn --script vuln -p${ports} --open -oN nmap/Vulns_${HOST}.nmap ${HOST} ${DNSSTRING}
        echo
}

recon() {
        print_header "Recon Recommendations"
        reconRecommend "${HOST}" | tee "nmap/Recon_${HOST}.nmap"
        allRecon="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | cut -d " " -f 1 | sort | uniq)"

        for tool in ${allRecon}; do
                if ! type "${tool}" >/dev/null 2>&1; then
                        missingTools="$(echo ${missingTools} ${tool} | awk '{$1=$1};1')"
                fi
        done

        if [ -n "${missingTools}" ]; then
                printf "${RED}Missing tools: ${NC}${missingTools}\n"
                availableRecon="$(echo "${allRecon}" | tr " " "\n" | awk -vORS=', ' '!/'"$(echo "${missingTools}" | tr " " "|")"'/' | sed 's/..$//')"
        else
                availableRecon="$(echo "${allRecon}" | tr "\n" " " | sed 's/\ /,\ /g' | sed 's/..$//')"
        fi

        if [ -n "${availableRecon}" ]; then
                printf "${YELLOW}\n"
                printf "Run recon commands?${NC} (All/Skip) [All]: "
                read reconCommand
                if [ -z "${reconCommand}" ] || expr "${reconCommand}" : '^\([Aa]ll\)$' >/dev/null; then
                        runRecon "${HOST}" "All"
                fi
        fi
}

reconRecommend() {
        printf "\n\n\n\n"
        printf "${YELLOW}[*] Recon Recommendations\n"
        printf "${NC}\n"
        
        if [ ! -f "nmap/Script_TCP_${HOST}.nmap" ]; then
            return
        fi

        # Use while read loop for robust line-by-line processing
        cat "nmap/Script_TCP_${HOST}.nmap" | grep "open" | grep -v "#" | sort | uniq | while read -r line; do
            if echo "${line}" | grep -q "ftp"; then
                    local ftpPort
                    ftpPort="$(echo "${line}" | cut -d'/' -f1)"
                    printf "${NC}\n"
                    printf "${YELLOW}> FTP bruteforcing with default creds:\n"
                    printf "${NC}\n"
                    echo "hydra -s $ftpPort -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u -f \"${HOST}\" ftp"
            fi
            if echo "${line}" | grep -i -q http; then
                    local port
                    port="$(echo "${line}" | cut -d "/" -f 1)"
                    local urlType
                    if echo "${line}" | grep -q ssl/http; then urlType='https://'; else urlType='http://'; fi
                    printf "${NC}\n"
                    printf "${YELLOW}> Web Server Recon on port ${port}:\n"
                    printf "${NC}\n"
                    echo "nikto -host \"${urlType}${HOST}:${port}\""
                    if [ -f /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt ]; then
                        echo "ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u \"${urlType}${HOST}:${port}/FUZZ\""
                    else
                        printf "${RED}[!] Wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt not found. Skipping FFUF scan.${NC}\n"
                    fi
            fi
            if echo "${line}" | grep -q "445/tcp"; then
                    printf "${NC}\n"
                    printf "${YELLOW}> SMB Recon:\n"
                    printf "${NC}\n"
                    echo "smbmap -H \"${HOST}\""
                    echo "smbclient -L \"//${HOST}/\" -U \"guest\"%"
                    echo "enum4linux -a \"${HOST}\""
            fi
        done
        echo
}

runRecon() {
        print_header "Running Recon Commands"
        mkdir -p recon/
        
        local recon_file="nmap/Recon_${HOST}.nmap"
        if [ ! -f "$recon_file" ]; then
            printf "${YELLOW}[!] No recon recommendations found to run.${NC}\n"
            return
        fi

        grep "${HOST}" "$recon_file" | while read -r line; do
            local currentScan
            currentScan="$(echo "${line}" | cut -d ' ' -f 1)"
            local fileName
            fileName="${currentScan}_${HOST}_$(echo "$line" | grep -oP '(?<=:)\d+' || echo 'default').txt"
            
            printf "${NC}\n"
            printf "${YELLOW}[+] Starting ${currentScan} session\n"
            printf "${NC}\n"
            
            # Execute command, strip ANSI codes, and save to file
            local output
            output=$(eval "${line}" 2>&1)
            echo "${output}" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' > "recon/${fileName}"
            
            # Also print clean output to console
            cat "recon/${fileName}"

            printf "${NC}\n"
            printf "${YELLOW}[-] Finished ${currentScan} session\n"
        done
        echo
}

# --- Reporting ---
generate_html_report() {
    HTML_REPORT="report.html"
    echo -e "\n${GREEN}--- Generating HTML Report ---${NC}"
    
    local current_dir
    current_dir=$(pwd)

    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSV-Recon Report for $HOST</title>
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
        <p><strong>Target:</strong> $HOST</p>
        <p><strong>Scan Date:</strong> $(date)</p>
    </div>
    <div class="section"><h2>Initial Port Scan</h2><pre>$(cat "${current_dir}/nmap/Port_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Full TCP Scan</h2><pre>$(cat "${current_dir}/nmap/full_TCP_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Script Scan</h2><pre>$(cat "${current_dir}/nmap/Script_TCP_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>UDP Scan</h2><pre>$(cat "${current_dir}/nmap/UDP_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>CVEs Scan</h2><pre>$(cat "${current_dir}/nmap/CVEs_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Vulns Scan</h2><pre>$(cat "${current_dir}/nmap/Vulns_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Recon Results</h2>
        <h3>Nikto</h3><pre>$(cat "${current_dir}/recon/nikto"*.txt 2>/dev/null)</pre>
        <h3>FFUF</h3><pre>$(cat "${current_dir}/recon/ffuf"*.txt 2>/dev/null)</pre>
        <h3>Hydra</h3><pre>$(cat "${current_dir}/recon/hydra"*.txt 2>/dev/null)</pre>
        <h3>SMBMap</h3><pre>$(cat "${current_dir}/recon/smbmap"*.txt 2>/dev/null)</pre>
        <h3>SMBClient</h3><pre>$(cat "${current_dir}/recon/smbclient"*.txt 2>/dev/null)</pre>
        <h3>Enum4Linux</h3><pre>$(cat "${current_dir}/recon/enum4linux"*.txt 2>/dev/null)</pre>
    </div>
    <div class="section"><h2>Full Console Log</h2><pre>$(cat "${current_dir}/RSV-Recon_${HOST}_${TYPE}.txt" 2>/dev/null)</pre></div>
    <footer><p>Report generated by RSVamil | <a href="https://github.com/ravisairockey" target="_blank">https://github.com/ravisairockey</a></p></footer>
</body>
</html>
EOF

    echo -e "${GREEN}[+] Report generated: ${current_dir}/${HTML_REPORT}${NC}"
    xdg-open "${current_dir}/${HTML_REPORT}" 2>/dev/null
}

footer() {
        printf "${GREEN}[!] Finished all scans\n"
        printf "${NC}\n\n"
        elapsedEnd="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
        elapsedSeconds=$((elapsedEnd - elapsedStart))
        if [ ${elapsedSeconds} -gt 3600 ]; then
                hours=$((elapsedSeconds / 3600))
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "${YELLOW}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
        elif [ ${elapsedSeconds} -gt 60 ]; then
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "${YELLOW}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
        else
                printf "${YELLOW}Completed in ${elapsedSeconds} seconds\n"
        fi
        printf "${NC}\n"
        generate_html_report
}

# --- Interactive Menu Functions ---
network_discovery() {
    echo -e "${GREEN}[+] Discovering hosts with arp-scan...${NC}"
    sudo arp-scan -l | tee "arp_scan.log" >/dev/null
    mapfile -t DISCOVERED_IPS < <(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "arp_scan.log" | sort -u)
    rm "arp_scan.log"
    
    if [ ${#DISCOVERED_IPS[@]} -eq 0 ]; then
        echo -e "${RED}[!] No hosts found. Exiting.${NC}"
        exit 1
    fi

    echo -e "\n${YELLOW}[+] Discovered Targets:${NC}"
    for i in "${!DISCOVERED_IPS[@]}"; do echo "$((i+1)). ${DISCOVERED_IPS[$i]}"; done
    
    read -p "Select target (number) or enter custom IP: " target_choice
    if [[ "$target_choice" =~ ^[0-9]+$ ]] && [ "$target_choice" -le "${#DISCOVERED_IPS[@]}" ]; then
        HOST="${DISCOVERED_IPS[$((target_choice-1))]}"
    else
        HOST="$target_choice"
    fi
}

main_menu() {
    network_discovery
    echo
    printf "${PURPLE}┌───────────────────────────────────────────┐\n"
    printf "│${CYAN} Select Scan Type for target ${YELLOW}%-13s ${PURPLE}│\n" "$HOST"
    printf "├───────────────────────────────────────────┤\n"
    printf "│${CYAN} 1. Port Scan                          ${PURPLE}│\n"
    printf "│${CYAN} 2. Script Scan                        ${PURPLE}│\n"
    printf "│${CYAN} 3. UDP Scan                           ${PURPLE}│\n"
    printf "│${CYAN} 4. Vulns Scan                         ${PURPLE}│\n"
    printf "│${CYAN} 5. Recon Actions                      ${PURPLE}│\n"
    printf "│${CYAN} 6. Fuzz Scan Only (ffuf)              ${PURPLE}│\n"
    printf "│${CYAN} 7. All (Hail Mary)                    ${PURPLE}│\n"
    printf "│${CYAN} 8. Exit                               ${PURPLE}│\n"
    printf "└───────────────────────────────────────────┘\n${NC}"
    read -p "Select an option [7]: " scan_choice

    case $scan_choice in
        1) TYPE="Port" ;;
        2) TYPE="Script" ;;
        3) TYPE="UDP" ;;
        4) TYPE="Vulns" ;;
        5) TYPE="Recon" ;;
        6) TYPE="Fuzz" ;;
        7|'') TYPE="All" ;;
        8) exit 0 ;;
        *) echo -e "${RED}Invalid option. Exiting.${NC}"; exit 1 ;;
    esac
}

# --- Main Execution Logic ---
run_fuzz_scan() {
    print_header "Fuzz Scan"
    mkdir -p recon/
    
    if [ ! -f "nmap/Script_TCP_${HOST}.nmap" ]; then
        print_header "Prerequisite: Running Port and Script Scan"
        portScan
        scriptScan
    fi

    if [ ! -f "nmap/Script_TCP_${HOST}.nmap" ]; then
        printf "${RED}[!] Script scan file not found. Cannot determine web servers to fuzz.${NC}\n"
        return
    fi

    printf "\n${YELLOW}> Fuzzing discovered Web Servers:${NC}\n"
    cat "nmap/Script_TCP_${HOST}.nmap" | grep "open" | grep -i "http" | while read -r line; do
        port=$(echo "${line}" | cut -d'/' -f1)
        urlType='http://'
        if echo "${line}" | grep -q "ssl/http"; then
            urlType='https://'
        fi
        
        printf "\n${BLUE}[*] Fuzzing ${urlType}${HOST}:${port}${NC}\n"
        if [ -f /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt ]; then
            fuzz_output_file="recon/ffuf_${HOST}_${port}.txt"
            ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u "${urlType}${HOST}:${port}/FUZZ" 2>&1 | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | tee "${fuzz_output_file}"
        else
            printf "${RED}[!] Wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt not found. Skipping FFUF scan.${NC}\n"
        fi
    done
}

run_scans() {
        if [ -z "${NMAPPATH}" ] && type nmap >/dev/null 2>&1; then
                NMAPPATH="$(type nmap | awk {'print $NF'})"
        else
                printf "${RED}\nNmap is not installed. Eject! Eject! Eject!${NC}\n\n" && exit 1
        fi

        if [ -n "${DNS}" ]; then
                DNSSERVER="${DNS}"
                DNSSTRING="--dns-server=${DNSSERVER}"
        else
                DNSSERVER="$(grep 'nameserver' /etc/resolv.conf | grep -v '#' | head -n 1 | awk {'print $NF'})"
                DNSSTRING="--system-dns"
        fi

        if [ -z "${OUTPUTDIR}" ]; then
                OUTPUTDIR="${HOST}"
        fi

        if ! expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null && ! expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                printf "${RED}\n"
                printf "${RED}Invalid IP or URL!\n"
                usage
        fi

        if ! case "${TYPE}" in [Nn]etwork | [Pp]ort | [Ss]cript | [Ff]ull | UDP | udp | [Vv]ulns | [Rr]econ | [Aa]ll | [Ff]uzz) false ;; esac then
                mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ recon/ || usage
                
                elapsedStart="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
                assignPorts "${HOST}"
                header
                case "${TYPE}" in
                [Pp]ort) portScan ;;
                [Ss]cript)
                        [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan
                        scriptScan
                        ;;
                [Uu]dp) UDPScan ;;
                [Vv]ulns)
                        [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan
                        vulnsScan
                        ;;
                [Rr]econ)
                        [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan
                        [ ! -f "nmap/Script_TCP_${HOST}.nmap" ] && scriptScan
                        recon
                        ;;
                [Ff]uzz)
                        run_fuzz_scan
                        ;;
                [Aa]ll)
                        portScan
                        scriptScan
                        UDPScan
                        recon
                        vulnsScan
                        ;;
                esac
                footer
        else
                printf "${RED}\n"
                printf "${RED}Invalid Type!\n"
                usage
        fi
}


# --- Entry Point ---
if [ $# -eq 0 ]; then
    # Interactive Mode
    INTERACTIVE_MODE=true
    banner
    main_menu
    run_scans
else
    # Flag Mode
    INTERACTIVE_MODE=false
    while [ $# -gt 0 ]; do
        key="$1"
        case "${key}" in
        -H | --host) HOST="$2"; shift; shift;;
        -t | --type) TYPE="$2"; shift; shift;;
        -d | --dns) DNS="$2"; shift; shift;;
        -o | --output) OUTPUTDIR="$2"; shift; shift;;
        *) POSITIONAL="${POSITIONAL} $1"; shift;;
        esac
    done
    set -- ${POSITIONAL}
    if [ -z "${HOST}" ] || [ -z "${TYPE}" ]; then
        usage
    fi
    run_scans
fi
