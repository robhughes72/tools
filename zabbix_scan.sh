#!/bin/bash
# Zabbix Agent Enumeration Script
# -----------------------------------------------------------------------------
# INFO: If the script successfully returns a version or hostname, you have 
# confirmed Information Leakage.
# -----------------------------------------------------------------------------

TARGET_IP="10.0.0.0"
PORT=10050

zbx_query() {
    local cmd="$1"
    # Create the 8-byte little-endian length header manually.
    # Note: We do NOT use command substitution for the final packet.
    local len_hex=$(printf "%016x" ${#cmd} | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\8\7\6\5\4\3\2\1/')
    
    echo -n "[*] Querying $cmd: "
    
    # Send binary header and command directly through the pipe.
    # We pipe to 'tr' and 'strings' to clean the AGENT'S binary response 
    # without ever letting Bash store it in a variable.
    { printf "ZBXD\x01"; echo "$len_hex" | xxd -r -p; printf "$cmd"; } | nc -w 3 $TARGET_IP $PORT | tr -d '\0' | strings | sed 's/ZBXD.//'
}

echo "[+] Starting Zabbix Agent Enumeration on $TARGET_IP"

zbx_query "agent.ping"
zbx_query "agent.version"
zbx_query "system.uname"
zbx_query "system.hostname"
zbx_query "net.if.list"

echo "[+] Enumeration Complete."
