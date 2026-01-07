#!/bin/bash

# RDP Security Audit Script - 2026 Kali Edition
# Usage: ./rdp_audit.sh -t <target> [-l <file>] [-u <user>] [-p <pass>] [-d <domain>]

show_help() {
    echo "Usage: $0 [options]"
    echo "  -t <target>     Single IP or CIDR range"
    echo "  -l <file>       Path to a file containing a list of IPs"
    echo "  -u <user>       Username for authenticated checks (optional)"
    echo "  -p <pass>       Password for authenticated checks (optional)"
    echo "  -d <domain>     Domain for authenticated checks (optional)"
    exit 1
}

# Parse variables
while getopts "t:l:u:p:d:h" opt; do
    case "$opt" in
        t) TARGETS=$OPTARG ;;
        l) TARGET_FILE=$OPTARG ;;
        u) USER=$OPTARG ;;
        p) PASS=$OPTARG ;;
        d) DOMAIN=$OPTARG ;;
        h) show_help ;;
        *) show_help ;;
    esac
done

if [[ -z "$TARGETS" && -z "$TARGET_FILE" ]]; then show_help; fi

# Prepare target list (Restored -l functionality)
if [[ -f "$TARGET_FILE" ]]; then
    IP_LIST=$(cat "$TARGET_FILE")
else
    IP_LIST=$TARGETS
fi

for ip in $IP_LIST; do
    echo -e "\n\e[1;34m[*] Starting Audit for: $ip\e[0m"

    # 1. Reachability & Port Check
    echo "[+] Checking Port 3389..."
    if ! nmap -p 3389 --open -Pn "$ip" | grep -q "3389/tcp open"; then
        echo "[-] RDP Port Closed or Filtered. Skipping $ip."
        continue
    fi

    # 2. NLA, Encryption, & Cipher Enumeration
    echo "[+] Enumerating NLA and Ciphers..."
    SCAN_DATA=$(nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info "$ip")
    echo "$SCAN_DATA" | sed 's/^/    /'

    # 3. Vulnerability Scanning (Fixed script selection)
    echo "[+] Scanning for RDP Vulnerabilities (BlueKeep, MS12-020, etc.)..."
    # Using 'rdp-vuln*' captures all available scripts in the suite to prevent missing file errors
    VULN_DATA=$(nmap -p 3389 --script "rdp-vuln*" "$ip")
    echo "$VULN_DATA" | sed 's/^/    /'

    # 4. Authenticated Session & Feature Hardening (Optional)
    if [[ -n "$USER" && -n "$PASS" ]]; then
        echo "[+] Testing Authenticated Redirection Policies..."
        # Uses xfreerdp to test if server permits redirection (Exit 0 = Auth Success)
        xfreerdp /v:"$ip" /u:"$USER" /p:"$PASS" ${DOMAIN:+/d:"$DOMAIN"} /cert:ignore /auth-only > /tmp/rdp_auth.log 2>&1
        if grep -q "Authentication only, exit status 0" /tmp/rdp_auth.log; then
            echo "    [SUCCESS] Credentials valid. Redirection features may be accessible."
        else
            echo "    [FAILED] Authentication failed for $USER."
        fi
    fi

    # 5. Dynamic Recommendations (Only triggered if criteria not met)
    echo -e "\e[1;33m[!] Audit Summary for $ip:\e[0m"
    HAS_ISSUES=false

    if ! echo "$SCAN_DATA" | grep -q "CredSSP: SUCCESS"; then
        echo "    - RECOMMENDATION: Enforce NLA (Network Level Authentication)."
        HAS_ISSUES=true
    fi

    if echo "$SCAN_DATA" | grep -E "TLSv1.0|TLSv1.1" > /dev/null; then
        echo "    - RECOMMENDATION: Disable legacy TLS 1.0/1.1; enforce TLS 1.2 or 1.3."
        HAS_ISSUES=true
    fi

    if echo "$VULN_DATA" | grep -qi "VULNERABLE"; then
        echo "    - RECOMMENDATION: CRITICAL - Apply patches for identified CVEs immediately."
        HAS_ISSUES=true
    fi

    if ! $HAS_ISSUES; then
        echo "    - Server configuration meets baseline security requirements."
    fi
done
