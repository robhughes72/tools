#!/bin/bash
# SMB/RPC Professional Auditor - 2026 Checklist Edition
# -----------------------------------------------------------------------------
# USAGE OPTIONS:
#   -t [IP]        Target a single IP address
#   -L [file.txt]  Target a list of IPs from a text file (one per line)
#   -u [user]      Username for authenticated enumeration
#   -p [pass]      Password for authenticated enumeration
#   -w [domain]    Domain or Workgroup name (use "." for local accounts)
#
# EXAMPLES:
#   Null Session:   ./script.sh -t 10.0.0.1
#   Auth Scan:      ./script.sh -t 10.0.0.1 -u "admin" -p "password" -w "."
#   Scan IP List:   ./script.sh -L targets.txt -u "domainuser" -p "pass" -w "CORP"
# -----------------------------------------------------------------------------

# --- Configuration ---
DATE_STR=$(date +%Y-%m-%d_%H%M)
OUTPUT_DIR="SMB_Audit_$DATE_STR"
RESULTS_FILE="$OUTPUT_DIR/results.txt"
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; NC='\033[0m'

mkdir -p "$OUTPUT_DIR"
# Global Mirror: Capture ALL output (STDOUT & STDERR) to terminal and results.txt
exec > >(tee -ia "$RESULTS_FILE")
exec 2>&1

while getopts "t:L:u:p:w:" opt; do
    case ${opt} in
        t) TARGETS+=("$OPTARG") ;;
        L) readarray -t LIST_IPS < "$OPTARG"; TARGETS+=("${LIST_IPS[@]}") ;;
        u) USER=$OPTARG ;;
        p) PASS=$OPTARG ;;
        w) DOMAIN=$OPTARG ;;
    esac
done

[ -z "${TARGETS}" ] && echo "Usage: $0 -t [IP] OR -L [List] [-u User -p Pass -w Domain]" && exit 1

for IP in "${TARGETS[@]}"; do
    [ -z "$IP" ] && continue
    echo -e "\n${YEL}==================================================${NC}"
    echo -e "${YEL}>>> AUDITING TARGET: $IP${NC}"
    echo -e "${YEL}==================================================${NC}"

    # --- 1. DISCOVERY & SECURITY POLICY (NMAP) ---
    echo -e "${YEL}[*] PHASE 1: DISCOVERY & SECURITY CHECKLIST${NC}"
    # Using your confirmed working flags [Source 21]
    SEC_SCAN=$(nmap -p 135,139,445 --script smb-security-mode,smb2-security-mode,smb-protocols,smb-os-discovery -Pn "$IP" 2>/dev/null)
    echo "$SEC_SCAN"

    if echo "$SEC_SCAN" | grep -iq "NT LM 0.12"; then
        echo -e "Checklist: SMBv1 Legacy Protocol... ${RED}[ FAIL ] (Vulnerable)${NC}"
    else
        echo -e "Checklist: SMBv1 Legacy Protocol... ${GRN}[ PASS ]${NC}"
    fi

    # Exact matching for your required passing syntax
    if echo "$SEC_SCAN" | grep -iq "Message signing enabled and required"; then
        echo -e "Checklist: SMB Packet Signing...    ${GRN}[ PASS ] (Required)${NC}"
    else
        echo -e "Checklist: SMB Packet Signing...    ${RED}[ FAIL ] (Optional/Disabled)${NC}"
    fi
    echo "--------------------------------------------------"

    # --- 2. UNUATHENTICATED / NULL SESSION (CHECKLIST SPECIFIC) ---
    echo -e "${YEL}[*] PHASE 2: ANONYMOUS / NULL-SESSION CHECKS${NC}"
    
    echo -e "\n[+] Anonymous SAM Dump (samrdump.py):"
    /usr/share/doc/python3-impacket/examples/samrdump.py "$IP" 2>/dev/null | head -n 15

  
    # --- 3. PRIMARY ENUMERATION (ENUM4LINUX-NG) ---
    echo -e "${YEL}[*] PHASE 3: PRIMARY DISCOVERY (enum4linux-ng)${NC}"
    NG_LOG="$OUTPUT_DIR/${IP}_ng.txt"
    enum4linux-ng -A -R -u "${USER:-}" -p "${PASS:-}" -w "${DOMAIN:-.}" "$IP" > "$NG_LOG" 2>&1
    cat "$NG_LOG"


        # Check for SID listing if credentials are provided
        if [ -n "$USER" ]; then
            echo -e "\n[+] Authenticated SID Lookup (lookupsid.py):"
            /usr/share/doc/python3-impacket/examples/lookupsid.py "${DOMAIN:-.}/${USER}:${PASS}@${IP}" 2>/dev/null | head -n 15
        fi

    echo "--------------------------------------------------"

    # --- 4. SHARE & IPC$ VERIFICATION ---
    echo -e "${YEL}[*] PHASE 5: SHARE ACCESS & IPC$ VERIFICATION${NC}"
    # Explicitly check IPC$ read-only access for the report [Source 15]
    echo -ne "    IPC$ Access: "
    smbclient -L "//$IP" -U "${DOMAIN:-.}/${USER:-guest}%${PASS:-}" 2>/dev/null | grep -qi "IPC" && echo -e "${GRN}[ READ-ONLY ] (Confirmed)${NC}" || echo -e "${RED}[ DENIED ]${NC}"
    
    # Recursive share listing
    smbmap -H "$IP" -d "${DOMAIN:-.}" -u "${USER:-guest}" -p "${PASS:-}" --depth 2
    echo "--------------------------------------------------"

    # --- 5. DETECTION-ONLY VULNERABILITY CHECKS ---
    echo -e "${YEL}[*] PHASE 6: VULNERABILITY DETECTION${NC}"
    nmap -p 445 --script smb-vuln* -Pn "$IP"
    echo -e "\n${YEL}==================================================${NC}"
done

echo -e "\n${GRN}[+] AUDIT COMPLETE. DATA SAVED TO: $RESULTS_FILE${NC}"
