#!/bin/bash
# Zabbix Agent Enumeration Script (Updated for Multi-Target Support)
# -----------------------------------------------------------------------------
# Usage: 
#   ./zbx_enum.sh -i 10.10.10.1 -p 10050
#   ./zbx_enum.sh -f targets.txt -p 10050
# -----------------------------------------------------------------------------

PORT=10050
TARGETS=()

usage() {
    echo "Usage: $0 [-i IP_ADDRESS] [-f FILE_OF_IPS] [-p PORT]"
    exit 1
}

# Parse Arguments
while getopts "i:f:p:" opt; do
    case "$opt" in
        i) TARGETS+=("$OPTARG") ;;
        f) while IFS= read -r line; do [[ -n "$line" ]] && TARGETS+=("$line"); done < "$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        *) usage ;;
    esac
done

if [ ${#TARGETS[@]} -eq 0 ]; then
    usage
fi

zbx_query() {
    local target="$1"
    local cmd="$2"
    
    # Create the 8-byte little-endian length header manually.
    local len_hex=$(printf "%016x" ${#cmd} | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\8\7\6\5\4\3\2\1/')
    
    # Send binary header and command directly through the pipe.
    # We pipe to 'tr' and 'strings' to clean the response.
    local response=$( { printf "ZBXD\x01"; echo "$len_hex" | xxd -r -p; printf "$cmd"; } | nc -w 3 "$target" "$PORT" | tr -d '\0' | strings | sed 's/ZBXD.//' )
    
    if [[ -n "$response" ]]; then
        echo "    [+] $cmd: $response"
    else
        echo "    [-] $cmd: No Response/Timeout"
    fi
}

for ip in "${TARGETS[@]}"; do
    echo "[+] Starting Zabbix Agent Enumeration on $ip:$PORT"
    
    # Check if port is open first to save time
    if ! nc -z -w 2 "$ip" "$PORT" 2>/dev/null; then
        echo " [!] Port $PORT is closed or host is unreachable. Skipping."
        continue
    fi

    zbx_query "$ip" "agent.ping"
    zbx_query "$ip" "agent.version"
    zbx_query "$ip" "system.uname"
    zbx_query "$ip" "system.hostname"
    zbx_query "$ip" "net.if.list"
    
    echo ""
done

echo "[+] All tasks completed."
