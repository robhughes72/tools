#!/bin/bash

# RDP Security Audit Script - 2026 Kali Edition
# Independent Flagging of TLS 1.0/1.1, RC4, CBC, and 3DES

show_help() {
    echo "Usage: $0 -t <target> [-l <file>] [-o <output_file>]"
    exit 1
}

OUTPUT_FILE="rdp_audit_results.txt"
while getopts "t:l:o:h" opt; do
    case "$opt" in
        t) TARGETS=$OPTARG ;;
        l) TARGET_FILE=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        h) show_help ;;
        *) show_help ;;
    esac
done

[[ -z "$TARGETS" && -z "$TARGET_FILE" ]] && show_help
IP_LIST=${TARGET_FILE:+$(cat "$TARGET_FILE")}
IP_LIST=${IP_LIST:-$TARGETS}

> "$OUTPUT_FILE"

run_audit() {
    for ip in $IP_LIST; do
        echo -e "\n\e[1;34m[*] Starting Audit for: $ip\e[0m"

        # 1. Port Check
        if ! nmap -p 3389 --open -Pn "$ip" | grep -q "3389/tcp open"; then
            echo "[-] RDP Port Closed. Skipping $ip."
            continue
        fi

        # 2. Nmap RDP Info (NLA Check Source of Truth)
        echo "[+] Running Nmap RDP Enumeration..."
        SCAN_DATA=$(nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 "$ip" -Pn)
        echo "$SCAN_DATA" | sed 's/^/    /'

        # 3. NLA Enforcement Logic (Suppressed if CredSSP SUCCESS found)
        NLA_ENFORCED=false
        if echo "$SCAN_DATA" | grep -q "CredSSP (NLA): SUCCESS"; then
            NLA_ENFORCED=true
            echo "    [CHECK] CredSSP (NLA) confirmed: NLA is Enforced."
        fi

        # 4. Independent Protocol & Cipher Scans (RED Flagging)
        echo "[+] Checking for Legacy Protocols and Weak Ciphers..."
        TMP_TLS="/tmp/nmap_tls_$ip.txt"
        nmap --script ssl-enum-ciphers -p 3389 "$ip" -Pn > "$TMP_TLS"

        # Independent Discovery Flags
        FOUND_TLS=false
        FOUND_RC4=false
        FOUND_CBC=false
        FOUND_3DES=false

        # Detect TLS 1.0/1.1
        if grep -E "TLSv1\.0|TLSv1\.1" "$TMP_TLS" > /dev/null; then
            echo -e "    \e[1;31m[!] LEGACY PROTOCOLS DETECTED (TLS 1.0/1.1):\e[0m"
            grep -E "TLSv1\.0|TLSv1\.1" "$TMP_TLS" | sed 's/^/      /' | grep --color=always -E "TLSv1\.0|TLSv1\.1"
            FOUND_TLS=true
        fi

        # Detect RC4
        if grep -i "RC4" "$TMP_TLS" > /dev/null; then
            echo -e "    \e[1;31m[!] WEAK CIPHERS DETECTED (RC4):\e[0m"
            grep -i "RC4" "$TMP_TLS" | sed 's/^/      /' | grep --color=always -i "RC4"
            FOUND_RC4=true
        fi

        # Detect CBC
        if grep "CBC" "$TMP_TLS" > /dev/null; then
            echo -e "    \e[1;31m[!] WEAK CIPHERS DETECTED (CBC):\e[0m"
            grep "CBC" "$TMP_TLS" | sed 's/^/      /' | grep --color=always "CBC"
            FOUND_CBC=true
        fi

        # Detect 3DES
        if grep "3DES" "$TMP_TLS" > /dev/null; then
            echo -e "    \e[1;31m[!] WEAK CIPHERS DETECTED (3DES):\e[0m"
            grep "3DES" "$TMP_TLS" | sed 's/^/      /' | grep --color=always "3DES"
            FOUND_3DES=true
        fi

        # 5. testssl.sh Audit (Bypassing OpenSSL 3.x restrictions)
        echo "[+] Running testssl.sh Audit..."
        TESTSSL_OUT=$(testssl --quiet --openssl-timeout 5 --cipher 'ALL:COMPLEMENTOFALL:eNULL@SECLEVEL=0' -p -4 -W -e "$ip:3389" 2>/dev/null)
        
        echo "$TESTSSL_OUT" | grep -E "not ok|vulnerable|weak|offered|TLS1|RC4|DES|CBC" | while read -r line; do
            echo -e "    \e[1;31m$line\e[0m"
            [[ "$line" =~ "TLS1" ]] && FOUND_TLS=true
            [[ "$line" =~ "RC4" ]] && FOUND_RC4=true
            [[ "$line" =~ "CBC" ]] && FOUND_CBC=true
            [[ "$line" =~ "DES" || "$line" =~ "3DES" ]] && FOUND_3DES=true
        done

        # 6. SUMMARY LOGIC (STRICTLY INDEPENDENT)
        echo -e "\e[1;33m[!] Audit Summary for $ip:\e[0m"
        HAS_ISSUES=false

        # NLA Suppression Logic
        if [ "$NLA_ENFORCED" = "false" ]; then
            echo -e "    \e[1;31m- RECOMMENDATION: Enforce NLA (Network Level Authentication).\e[0m"
            HAS_ISSUES=true
        fi

        # Protocol Recommendation
        if [ "$FOUND_TLS" = "true" ]; then
            echo -e "    \e[1;31m- RECOMMENDATION: Disable Legacy Protocols (TLS 1.0 and TLS 1.1).\e[0m"
            HAS_ISSUES=true
        fi

        # RC4 Recommendation
        if [ "$FOUND_RC4" = "true" ]; then
            echo -e "    \e[1;31m- RECOMMENDATION: Disable RC4 Ciphers.\e[0m"
            HAS_ISSUES=true
        fi

        # Logic for CBC and 3DES recommendation text
        CIPHER_REC=""
        if [ "$FOUND_CBC" = "true" ] && [ "$FOUND_3DES" = "true" ]; then
            CIPHER_REC="Disable Weak Ciphers (CBC Mode and 3DES)."
        elif [ "$FOUND_CBC" = "true" ]; then
            CIPHER_REC="Disable Weak Ciphers (CBC Mode)."
        elif [ "$FOUND_3DES" = "true" ]; then
            CIPHER_REC="Disable Weak Ciphers (3DES)."
        fi

        if [[ -n "$CIPHER_REC" ]]; then
            echo -e "    \e[1;31m- RECOMMENDATION: $CIPHER_REC\e[0m"
            HAS_ISSUES=true
        fi

        # Vulnerability Recommendation
        if echo "$SCAN_DATA" | grep -qi "VULNERABLE"; then
            echo -e "    \e[1;31m- RECOMMENDATION: CRITICAL - Patch identified RDP vulnerabilities.\e[0m"
            HAS_ISSUES=true
        fi

        if [ "$HAS_ISSUES" = "false" ]; then
            echo "    - Server configuration meets baseline security requirements."
        fi
        
        rm -f "$TMP_TLS"
    done
}

run_audit 2>&1 | tee -a "$OUTPUT_FILE"
echo -e "\n\e[1;32m[+] Audit Complete. Results: $OUTPUT_FILE\e[0m"
