#!/bin/bash

# RDP Security Audit Script - 2026 Kali Edition
# Usage: ./rdp_audit.sh -t <target> [-l <file>] [-u <user>] [-p <pass>] [-d <domain>] [-o <output_file>]

show_help() {
    echo "Usage: $0 [options]"
    echo "  -t <target>      Single IP or CIDR range"
    echo "  -l <file>        Path to a file containing a list of IPs"
    echo "  -u <user>        Username for authenticated checks (optional)"
    echo "  -p <pass>        Password for authenticated checks (optional)"
    echo "  -d <domain>      Domain for authenticated checks (optional)"
    echo "  -o <output_file> Path to save results (default: rdp_audit_results.txt)"
    exit 1
}

OUTPUT_FILE="rdp_audit_results.txt"

while getopts "t:l:u:p:d:o:h" opt; do
    case "$opt" in
        t) TARGETS=$OPTARG ;;
        l) TARGET_FILE=$OPTARG ;;
        u) USER=$OPTARG ;;
        p) PASS=$OPTARG ;;
        d) DOMAIN=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        h) show_help ;;
        *) show_help ;;
    esac
done

if [[ -z "$TARGETS" && -z "$TARGET_FILE" ]]; then show_help; fi

if [[ -f "$TARGET_FILE" ]]; then
    IP_LIST=$(cat "$TARGET_FILE")
else
    IP_LIST=$TARGETS
fi

> "$OUTPUT_FILE"

run_audit() {
    for ip in $IP_LIST; do
        echo -e "\n\e[1;34m[*] Starting Audit for: $ip\e[0m"

        # 1. Reachability & Port Check
        if ! nmap -p 3389 --open -Pn "$ip" | grep -q "3389/tcp open"; then
            echo "[-] RDP Port Closed or Filtered. Skipping $ip."
            continue
        fi

        # 2. Nmap Enumeration
        echo "[+] Enumerating NLA and Ciphers via Nmap..."
        SCAN_DATA=$(nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info "$ip")
        echo "$SCAN_DATA" | sed 's/^/    /'

        # 3. Active NLA Validation (The xfreerdp3 Check)
        # Only run this if Nmap indicates RDSTLS is a success (which often causes the false positive)
        NLA_ENFORCED=false
        if echo "$SCAN_DATA" | grep -q "RDSTLS: SUCCESS"; then
            echo "[+] RDSTLS detected. Validating if NLA is strictly enforced..."
            # Run xfreerdp3 with /sec:tls to see if server rejects it
            timeout 5s xfreerdp3 /v:"$ip":3389 /cert:ignore /sec:tls /auth-only > /tmp/rdp_nla_check.log 2>&1
            
            # Check for the specific NLA-enforced failure message
            if grep -q "HYBRID_REQUIRED_BY_SERVER" /tmp/rdp_nla_check.log; then
                echo "    [CONFIRMED] Server rejected TLS-only connection: NLA is ENFORCED."
                NLA_ENFORCED=true
            elif grep -q "Authentication only, exit status 0" /tmp/rdp_nla_check.log; then
                echo -e "    \e[1;31m[!] WARNING: NLA NOT enforced.\e[0m Server accepted TLS-only connection."
                NLA_ENFORCED=false
            fi
        fi

        # 4. testssl.sh Cipher and Protocol Audit
        echo "[+] Running testssl.sh for detailed Protocol/Cipher issues..."
        testssl --quiet -p -E -U "$ip:3389" 2>/dev/null | grep -E "not ok|vulnerable|weak|offered" | sed 's/^/    /'

        # 5. Vulnerability Scanning
        echo "[+] Scanning for RDP Vulnerabilities..."
        VULN_DATA=$(nmap -p 3389 --script "rdp-vuln*" "$ip")
        echo "$VULN_DATA" | sed 's/^/    /'

        # 6. Authenticated Session (Optional)
        if [[ -n "$USER" && -n "$PASS" ]]; then
            echo "[+] Testing Authenticated Redirection Policies..."
            xfreerdp3 /v:"$ip" /u:"$USER" /p:"$PASS" ${DOMAIN:+/d:"$DOMAIN"} /cert:ignore /auth-only > /tmp/rdp_auth.log 2>&1
            if grep -q "Authentication only, exit status 0" /tmp/rdp_auth.log; then
                echo "    [SUCCESS] Credentials valid."
            else
                echo "    [FAILED] Authentication failed for $USER."
            fi
        fi

        # 7. Summary Logic
        echo -e "\e[1;33m[!] Audit Summary for $ip:\e[0m"
        HAS_ISSUES=false

        # Only recommend NLA if it's not enforced AND Nmap didn't see CredSSP as the only option
        if ! $NLA_ENFORCED; then
            if ! echo "$SCAN_DATA" | grep -q "CredSSP (NLA): SUCCESS" || echo "$SCAN_DATA" | grep -q "Native RDP: SUCCESS"; then
                echo "    - RECOMMENDATION: Enforce NLA (Network Level Authentication)."
                HAS_ISSUES=true
            fi
        fi

        if echo "$SCAN_DATA" | grep -E "TLSv1.0|TLSv1.1" > /dev/null; then
            echo "    - RECOMMENDATION: Disable legacy TLS 1.0/1.1; enforce TLS 1.2+."
            HAS_ISSUES=true
        fi

        if echo "$VULN_DATA" | grep -qi "VULNERABLE"; then
            echo "    - RECOMMENDATION: CRITICAL - Apply patches for identified CVEs."
            HAS_ISSUES=true
        fi

        if ! $HAS_ISSUES; then
            echo "    - Server configuration meets baseline security requirements."
        fi
    done
}

run_audit 2>&1 | tee -a "$OUTPUT_FILE"
echo -e "\n\e[1;32m[+] Audit Complete. Results: $OUTPUT_FILE\e[0m"
