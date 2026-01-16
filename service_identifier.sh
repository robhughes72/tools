#!/bin/bash

# Generic Service Discovery Engine - 2026 Standard
# Optimized for dynamic identity extraction from unknown ports

TARGET=$1
PORT=$2

if [[ -z "$TARGET" || -z "$PORT" ]]; then
    echo -e "\e[1;31m[!] Usage: $0 <target_ip> <port>\e[0m"
    exit 1
fi

echo -e "\e[1;34m[*] Probing Unknown Service on $TARGET:$PORT...\e[0m"

# --- Phase 1: High-Fidelity Data Collection ---
# 1. SSL/TLS Extraction (Authoritative)
SSL_RAW=$(nmap -sV --script ssl-cert -p "$PORT" "$TARGET" -Pn 2>/dev/null)
CN_RAW=$(echo "$SSL_RAW" | sed -n 's/.*commonName=\([^/]*\).*/\1/p' | xargs)
ORG_RAW=$(echo "$SSL_RAW" | sed -n 's/.*organizationName=\([^/]*\).*/\1/p' | xargs)
# Extracting the Issuer CN as it typically contains the Product Suite/Family (e.g., PPDM, PowerProtect)
ISSUER_CN=$(echo "$SSL_RAW" | grep "Issuer:" | grep -oP "commonName=\K[^/ ]+" | head -n 1)

# 2. Raw Banner Grab (The Nudge)
BANNER=$(echo "" | nc -vv -n -w2 "$TARGET" "$PORT" 2>&1 | tr -d '\r' | grep -vE "UNKNOWN|connected|succeeded" | head -n 1 | xargs)

# 3. HTTP Header Discovery
HTTP_HEAD=$(curl -I -s -k --connect-timeout 2 "https://$TARGET:$PORT" 2>/dev/null | grep -i "Server:" | cut -d' ' -f2- | tr -d '\r')

# --- Phase 2: Dynamic Inference Engine (Generic Logic) ---

# A. Clean Technical Noise from Product Name
# Strips @binding and alphanumeric IDs to reveal the service name
CLEAN_PROD=$(echo "$CN_RAW" | awk -F'[@ ]' '{print $1}' | sed -E 's/ID-[a-f0-9-]{10,}//g' | xargs)

# B. Clean Vendor Name
# Strips legal suffixes to find the core brand
CLEAN_VEND=$(echo "$ORG_RAW" | sed -E 's/( Corporation| Corp| Inc| Ltd| LLC|@.*)//g' | awk '{print $1, $2}' | xargs)

# C. Formulate the Identity based on best available data
if [[ -n "$CLEAN_PROD" || -n "$ISSUER_CN" ]]; then
    # Merge Vendor + Issuer (Suite) + Product for high-fidelity ID
    if [[ "$ISSUER_CN" != "$CLEAN_PROD" && -n "$ISSUER_CN" ]]; then
        IDENTIFIED_AS="$CLEAN_VEND $ISSUER_CN $CLEAN_PROD"
    else
        IDENTIFIED_AS="$CLEAN_VEND $CLEAN_PROD"
    fi
    SOURCE="SSL/TLS Metadata Analysis (Subject & Issuer)"
elif [[ -n "$HTTP_HEAD" ]]; then
    IDENTIFIED_AS="$HTTP_HEAD"
    SOURCE="HTTP Server Header"
elif [[ -n "$BANNER" ]]; then
    IDENTIFIED_AS="$BANNER"
    SOURCE="Raw Service Banner"
else
    # --- Phase 3: High-Intensity Last Resort ---
    echo "[!] Smart probes inconclusive. Running High-Intensity Fingerprinting..."
    NMAP_HIGH=$(nmap -sV --version-intensity 9 -p "$PORT" "$TARGET" -Pn)
    IDENTIFIED_AS=$(echo "$NMAP_HIGH" | grep "$PORT/tcp" | awk '{print $3, $4, $5}' | tr -d '?')
    SOURCE="Nmap Fingerprint Database (Intensive)"
fi

# --- Phase 4: Final Output Analysis ---
echo -e "\n\e[1;33m[!] IDENTITY ANALYSIS:\e[0m"
echo -e "    \e[1;32mIDENTIFIED AS:  $IDENTIFIED_AS\e[0m"
echo -e "    \e[1;36mSOURCE:         $SOURCE\e[0m"

# Port Collision Awareness
EXPECTED=$(grep -w "$PORT/tcp" /etc/services | awk '{print $1}' | head -n 1)
if [[ -n "$EXPECTED" && "$IDENTIFIED_AS" != *"$EXPECTED"* ]]; then
    echo -e "\n\e[1;31m[!] ALERT: Port Collision Detected\e[0m"
    echo "    Port $PORT is historically assigned to '$EXPECTED'."
    echo "    The actual service identifies as '$IDENTIFIED_AS'."
fi

echo -e "\n\e[1;34m[*] Identification Complete for $TARGET:$PORT\e[0m"
