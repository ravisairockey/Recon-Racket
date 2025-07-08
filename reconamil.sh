#!/bin/sh
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
origIFS="${IFS}"

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
        banner
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
                allTCPPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/full_TCP_$1.nmap" | sed 's/.$//')"
        fi

        if [ -f "nmap/UDP_$1.nmap" ]; then
                udpPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/UDP_$1.nmap" | sed 's/.$//')"
                if [ "${udpPorts}" = "Al" ]; then
                        udpPorts=""
                fi
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

# --- Scanning Functions ---
portScan() {
        echo
        printf "${GREEN}---------------------Starting Port Scan-----------------------\n"
        printf "${NC}\n"
        
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
        printf "${YELLOW}[*] Script Scan launched on open ports\n"
        printf "${NC}\n"
        ports="${allTCPPorts}"
        if [ -z "${ports}" ]; then
                printf "${YELLOW}No ports in port scan.. Skipping!\n"
        else
                ${nmapType} -Pn -sCV -p${ports} --open -oN nmap/Script_TCP_${HOST}.nmap ${HOST} ${DNSSTRING}
        fi
        echo
}

UDPScan() {
        printf "${YELLOW}[*] UDP port scan launched\n"
        printf "${NC}\n"
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
        printf "${YELLOW}[!] Vulnerability Scan\n"
        printf "${NC}\n"
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
        IFS="
"
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
        IFS="${origIFS}"
}

reconRecommend() {
        printf "\n\n\n\n"
        printf "${YELLOW}[*] Recon Recommendations\n"
        printf "${NC}\n"
        IFS="
"
        if [ -f "nmap/Script_TCP_${HOST}.nmap" ]; then
                ports="${allTCPPorts}"
                file="$(cat "nmap/Script_TCP_${HOST}.nmap" | grep "open" | grep -v "#" | sort | uniq)"
        fi
        if echo "${file}" | grep -q "ftp"; then
                ftpPort="$(echo "${file}" | grep ftp | awk -F'/' '{if (NR <= 1) print $1}')"
                printf "${NC}\n"
                printf "${YELLOW}> FTP bruteforcing with default creds:\n"
                printf "${NC}\n"
                echo "hydra -s $ftpPort -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u -f \"${HOST}\" ftp | tee \"recon/ftpBruteforce_${HOST}.txt\""
        fi
        if echo "${file}" | grep -i -q http; then
                printf "${NC}\n"
                printf "${YELLOW}> Web Servers Recon:\n"
                printf "${NC}\n"
                for line in ${file}; do
                        if echo "${line}" | grep -i -q http; then
                                port="$(echo "${line}" | cut -d "/" -f 1)"
                                if echo "${line}" | grep -q ssl/http; then urlType='https://'; else urlType='http://'; fi
                                echo "nikto -host \"${urlType}${HOST}:${port}\" | tee \"recon/nikto_${HOST}_${port}.txt\""
                                echo "ffuf -ic -w /usr/share/wordlists/dirb/common.txt -u \"${urlType}${HOST}:${port}/FUZZ\" | tee \"recon/ffuf_${HOST}_${port}.txt\""
                        fi
                done
        fi
        if echo "${file}" | grep -q "445/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}> SMB Recon:\n"
                printf "${NC}\n"
                echo "smbmap -H \"${HOST}\" | tee \"recon/smbmap_${HOST}.txt\""
                echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"recon/smbclient_${HOST}.txt\""
                echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
        fi
        IFS="${origIFS}"
        echo
}

runRecon() {
        echo
        printf "${GREEN}[*] Running Recon on the target\n"
        printf "${NC}\n"
        IFS="
"
        mkdir -p recon/
        if [ "$2" = "All" ]; then
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap")"
        else
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | grep "$2")"
        fi
        for line in ${reconCommands}; do
                currentScan="$(echo "${line}" | cut -d ' ' -f 1)"
                fileName="$(echo "${line}" | awk -F "recon/" '{print $2}')"
                if [ -n "${fileName}" ] && [ ! -f recon/"${fileName}" ]; then
                        printf "${NC}\n"
                        printf "${YELLOW}[+] Starting ${currentScan} session\n"
                        printf "${NC}\n"
                        eval "${line}"
                        printf "${NC}\n"
                        printf "${YELLOW}[-] Finished ${currentScan} session\n"
                        printf "${NC}\n"
                        printf "${YELLOW}--------------------------------------\n"
                fi
        done
        IFS="${origIFS}"
        echo
}

# --- Reporting ---
generate_html_report() {
    HTML_REPORT="report.html"
    echo -e "\n${GREEN}--- Generating HTML Report ---${NC}"
    
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
    <div class="section"><h2>Initial Port Scan</h2><pre>$(cat "nmap/Port_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Full TCP Scan</h2><pre>$(cat "nmap/full_TCP_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Script Scan</h2><pre>$(cat "nmap/Script_TCP_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>UDP Scan</h2><pre>$(cat "nmap/UDP_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>CVEs Scan</h2><pre>$(cat "nmap/CVEs_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Vulns Scan</h2><pre>$(cat "nmap/Vulns_${HOST}.nmap" 2>/dev/null)</pre></div>
    <div class="section"><h2>Recon Results</h2>
        <h3>Nikto</h3><pre>$(cat recon/nikto* 2>/dev/null)</pre>
        <h3>FFUF</h3><pre>$(cat recon/ffuf* 2>/dev/null)</pre>
        <h3>Hydra</h3><pre>$(cat recon/ftpBruteforce* 2>/dev/null)</pre>
        <h3>SMBMap</h3><pre>$(cat recon/smbmap* 2>/dev/null)</pre>
        <h3>SMBClient</h3><pre>$(cat recon/smbclient* 2>/dev/null)</pre>
        <h3>Enum4Linux</h3><pre>$(cat recon/enum4linux* 2>/dev/null)</pre>
    </div>
    <footer><p>Report generated by RSVamil | <a href="https://github.com/ravisairockey" target="_blank">https://github.com/ravisairockey</a></p></footer>
</body>
</html>
EOF

    echo -e "${GREEN}[+] Report generated: $HTML_REPORT${NC}"
    xdg-open "$HTML_REPORT" 2>/dev/null
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
    sudo arp-scan -l | tee "arp_scan.log"
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
    echo -e "\n${CYAN}Select Scan Type for target ${HOST}:${NC}"
    printf "${CYAN}\t1. Port\n"
    printf "${CYAN}\t2. Script\n"
    printf "${CYAN}\t3. UDP\n"
    printf "${CYAN}\t4. Vulns\n"
    printf "${CYAN}\t5. Recon\n"
    printf "${CYAN}\t6. All (Hail Mary)\n"
    printf "${CYAN}\t7. Exit\n${NC}"
    read -p "Select an option [6]: " scan_choice

    case $scan_choice in
        1) TYPE="Port" ;;
        2) TYPE="Script" ;;
        3) TYPE="UDP" ;;
        4) TYPE="Vulns" ;;
        5) TYPE="Recon" ;;
        6|'') TYPE="All" ;;
        7) exit 0 ;;
        *) echo -e "${RED}Invalid option. Exiting.${NC}"; exit 1 ;;
    esac
}

# --- Main Execution Logic ---
run_scans() {
        # Set path to nmap binary or default to nmap in $PATH
        if [ -z "${NMAPPATH}" ] && type nmap >/dev/null 2>&1; then
                NMAPPATH="$(type nmap | awk {'print $NF'})"
        else
                printf "${RED}\nNmap is not installed. Eject! Eject! Eject!${NC}\n\n" && exit 1
        fi

        # Set DNS or default to system DNS
        if [ -n "${DNS}" ]; then
                DNSSERVER="${DNS}"
                DNSSTRING="--dns-server=${DNSSERVER}"
        else
                DNSSERVER="$(grep 'nameserver' /etc/resolv.conf | grep -v '#' | head -n 1 | awk {'print $NF'})"
                DNSSTRING="--system-dns"
        fi

        # Set output dir or default to host-based dir
        if [ -z "${OUTPUTDIR}" ]; then
                OUTPUTDIR="${HOST}"
        fi

        if ! expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null && ! expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                printf "${RED}\n"
                printf "${RED}Invalid IP or URL!\n"
                usage
        fi

        if ! case "${TYPE}" in [Nn]etwork | [Pp]ort | [Ss]cript | [Ff]ull | UDP | udp | [Vv]ulns | [Rr]econ | [Aa]ll) false ;; esac then
                mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage
                
                elapsedStart="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
                assignPorts "${HOST}"
                header
                case "${TYPE}" in
                [Pp]ort) portScan "${HOST}" ;;
                [Ss]cript)
                        [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan "${HOST}"
                        scriptScan "${HOST}"
                        ;;
                [Uu]dp) UDPScan "${HOST}" ;;
                [Vv]ulns)
                        [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan "${HOST}"
                        vulnsScan "${HOST}"
                        ;;
                [Rr]econ)
                        [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan "${HOST}"
                        [ ! -f "nmap/Script_TCP_${HOST}.nmap" ] && scriptScan "${HOST}"
                        recon "${HOST}"
                        ;;
                [Aa]ll)
                        portScan "${HOST}"
                        scriptScan "${HOST}"
                        UDPScan "${HOST}"
                        recon "${HOST}"
                        vulnsScan "${HOST}"
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
    banner
    main_menu
    run_scans
else
    # Flag Mode
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
