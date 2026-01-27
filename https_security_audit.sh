#!/bin/bash

# HTTPS Security Audit Script - 2026 Kali Edition (Multi-Port Support)
# Logic: Status Detection + Forced Color Nmap Verification

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' 

show_help() {
    echo -e "${BLUE}HTTPS Security Audit Tool - 2026 Edition${NC}"
    echo "Usage: $0 [options]"
    echo "  -t <target>      Single IP:Port, Domain:Port, or CIDR"
    echo "  -l <file>        Path to a file containing targets (e.g., 1.1.1.1:8443)"
    echo "  -o <output_file> Path to save results (default: https_results.txt)"
    exit 1
}

OUTPUT_FILE="https_results.txt"
while getopts "t:l:o:h" opt; do
    case "$opt" in
        t) TARGETS=$OPTARG ;;
        l) TARGET_FILE=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        h|*) show_help ;;
    esac
done

if [[ -z "$TARGETS" && -z "$TARGET_FILE" ]]; then show_help; fi
IP_LIST=${TARGET_FILE:-$TARGETS}
if [[ -f "$IP_LIST" ]]; then IP_LIST=$(cat "$IP_LIST"); fi

echo "--- HTTPS Audit Report $(date) ---" > "$OUTPUT_FILE"

for entry in $IP_LIST; do
    # Logic to split IP and Port; default to 443 if no colon found
    if [[ $entry == *":"* ]]; then
        ADDR=$(echo $entry | cut -d':' -f1)
        PORT=$(echo $entry | cut -d':' -f2)
    else
        ADDR=$entry
        PORT=443
    fi

    log() { echo -e "$1" | tee -a "$OUTPUT_FILE"; }

    log "\n${BLUE}[*] Starting HTTPS Audit for: $ADDR on Port: $PORT${NC}"

    # Port Check using the dynamic port
    if ! nmap -p "$PORT" --open -Pn "$ADDR" | grep -q "$PORT/tcp open"; then
        log "${RED}[-] Port $PORT closed or filtered on $ADDR. Skipping.${NC}"
        continue
    fi

    log "[+] Running deep scan (testssl)..."
    # testssl requires port appended with colon
    TESTSSL_DATA=$(testssl --quiet --color 0 -p -S -U -H "$ADDR:$PORT" 2>/dev/null)

    # 1. Capture Primary Findings
    FINDINGS=$(echo "$TESTSSL_DATA" | grep -EiB 1 "vulnerable|not ok|weak|missing|does not match|too long|incomplete|deprecated|obsoleted|not offered|not set|offered|CBC" | grep -vEi "not vulnerable|\(OK\)|---")

    if [[ -n "$FINDINGS" ]]; then
        log "${YELLOW}[!] Significant Findings Identified:${NC}"
        echo "$FINDINGS" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
    fi

    # 2. CURL HSTS Verification (Updated with port logic)
    log "${BLUE}[+] Running CURL Verification for HSTS Header...${NC}"
    HSTS_HEADER=$(curl -s -I -k "https://$ADDR:$PORT" | grep -i "Strict-Transport-Security")
    
    if [[ -n "$HSTS_HEADER" ]]; then
        log "    ${GREEN}[VERIFIED] HSTS Found: $HSTS_HEADER${NC}"
    else
        log "    ${RED}[FAILED] HSTS Header NOT found via CURL check.${NC}"
    fi

    # 3. Deep Nmap Probes (Updated with port logic)
    if echo "$FINDINGS" | grep -qiE "CBC|vulnerable|deprecated|TLSv1|3DES|obsoleted"; then
        log "${BLUE}[+] Triggering Deep Nmap Probes (Issues Highlighted in RED)...${NC}"
        
        # Probe 1: CBC / Lucky 13 Detail
        log "    [PROBE] Enumerating CBC Ciphers:"
        nmap -sV -p "$PORT" --script ssl-enum-ciphers "$ADDR" | grep --color=always -Ei "CBC|$" | sed 's/^/        /' | tee -a "$OUTPUT_FILE"

        # Probe 2: Sweet 32 / 3DES / TLS Detail
        log "    [PROBE] Enumerating 3DES and Legacy Protocols (TLS 1.0/1.1):"
        nmap -Pn -T4 -sT -p "$PORT" --script ssl-enum-ciphers "$ADDR" | \
        grep --color=always -Ei "3DES|TLSv1\.0|TLSv1\.1|$" | sed 's/^/        /' | tee -a "$OUTPUT_FILE"
    fi

    # 4. Final Summary
    log "${YELLOW}[!] Audit Summary for $ADDR:$PORT:${NC}"
    HAS_ISSUES=false

    if echo "$FINDINGS" | grep -qiE "vulnerable|NOT ok"; then
        log "    ${RED}- [CRITICAL] Cryptographic Vulnerability (BEAST, Lucky13, etc).${NC}"
        HAS_ISSUES=true
    fi

    if echo "$FINDINGS" | grep -qiE "certificate|chain|match|long|expired|incomplete"; then
        log "    ${RED}- [CERTIFICATE] Trust or Validity issue (Mismatch/Broken Chain).${NC}"
        HAS_ISSUES=true
    fi

    if echo "$FINDINGS" | grep -qiE "weak|deprecated|obsoleted|TLSv1.0|TLSv1.1|SSLv|CBC|3DES"; then
        log "    ${RED}- [CIPHER/PROTO] Legacy Protocol or Weak Cipher (CBC/3DES) detected.${NC}"
        HAS_ISSUES=true
    fi

    if [[ -z "$HSTS_HEADER" ]]; then
        log "    ${RED}- [HEADERS] CRITICAL: HSTS header is MISSING (Verified via CURL).${NC}"
        HAS_ISSUES=true
    fi

    if ! $HAS_ISSUES; then
        log "    ${GREEN}- [PASS] No issues matching security patterns found.${NC}"
    fi
done

log "\n${GREEN}[+] Audit Complete. Results: $OUTPUT_FILE${NC}"
