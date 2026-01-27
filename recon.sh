#!/bin/bash

# --- Phase 1: Discovery 1 ---
read -p "Perform host discovery (Ping Sweep)? [y/n]: " do_discovery
TARGET_FILE="targets.txt"

if [[ "$do_discovery" =~ ^[Yy]$ ]]; then
    read -p "Enter target range (e.g., 192.168.1.0/24): " range
    nmap -sn "$range" -oG discovery.gnmap
    grep "Up" discovery.gnmap | awk '{print $2}' > "$TARGET_FILE"
    echo "[+] Found $(wc -l < "$TARGET_FILE") hosts. Saved to $TARGET_FILE."
else
    [[ ! -f "$TARGET_FILE" ]] && echo "[-] Error: $TARGET_FILE missing." && exit 1
fi

# --- Phase 2: Scanning ---
echo "1) Top 20 TCP | 2) Top 100 TCP | 3) Full TCP | 4) Default UDP | 5) Fast UDP"
read -p "Choice [1-5]: " choice
case $choice in
    1) SCAN_TYPE="top20-tcp"; FLAGS="--top-ports 20" ;;
    2) SCAN_TYPE="top100-tcp"; FLAGS="-F" ;;
    3) SCAN_TYPE="full-tcp"; FLAGS="-p-" ;;
    4) SCAN_TYPE="default-udp"; FLAGS="-sU --top-ports 1000" ;;
    5) SCAN_TYPE="fast-udp"; FLAGS="-sU -F --defeat-icmp-ratelimit" ;;
    *) exit 1 ;;
esac

nmap -vv -n -sV -Pn -oA "$SCAN_TYPE" -iL "$TARGET_FILE" $FLAGS

# --- Phase 3: Parsing (SMB & SSL Fixed) ---
GNMAP_FILE="${SCAN_TYPE}.gnmap"
echo "[*] Parsing services from $GNMAP_FILE..."

# Extract unique services, resolving SSL tunnels and forcing SMB/RDP naming
services=$(grep "Ports: " "$GNMAP_FILE" | sed 's/Ports: /\n/g' | tr ',' '\n' | awk -F'/' '
{
    # 1. Resolve Tunnel (ssl/http -> https)
    svc = ($5 == "ssl") ? $6 : $5;
    gsub(/\?/, "", svc);

    # 2. Force Map critical ports to clean names
    if ($1 == "445") { print "smb" }
    else if ($1 == "3389") { print "rdp" }
    else if (svc != "") { print svc }
}' | sort -u | grep -v "^$")

for service in $services; do
    # Define clean filename and the specific pattern to match in the GNMAP file
    case "$service" in
        "smb"|"microsoft-ds") 
            clean_name="smb"
            match_pattern="445/open/" 
            ;;
        "rdp"|"ms-wbt-server") 
            clean_name="rdp"
            match_pattern="3389/open/" 
            ;;
        "http"|"https")
            # For web, we match the service name precisely to avoid ssl_http duplicates
            clean_name="$service"
            match_pattern="/open/[^,]*/$service/"
            ;;
        *) 
            # Catch-all for every other service (ssh, telnet, etc.)
            clean_name=$(echo "$service" | tr -d '[:punct:]')
            match_pattern="/open/[^,]*/$service/"
            ;;
    esac

    # Extract IPs using the match pattern. 
    # Use -E to ensure the regex handles the / / boundaries correctly.
    grep -E "$match_pattern" "$GNMAP_FILE" | awk '{print $2}' | sort -u > "${clean_name}.txt"

    if [ -s "${clean_name}.txt" ]; then
        echo "[+] Created ${clean_name}.txt ($(wc -l < "${clean_name}.txt") hosts)"
    else
        rm "${clean_name}.txt" 2>/dev/null
    fi
done

echo "--- Process Complete ---"
