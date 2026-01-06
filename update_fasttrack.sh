#!/bin/bash

# Target file path
WORDLIST="/usr/share/wordlists/fasttrack.txt"
# Backup file path
BACKUP="/usr/share/wordlists/fasttrack.txt.bak"

# Ensure the script is run with sudo
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo ./update_fasttrack.sh)"
  exit
fi

# 1. Create a backup before modifying
echo "[+] Creating backup at $BACKUP"
cp "$WORDLIST" "$BACKUP"

# 2. Define seasons and years
# Includes past years and current 2026
SEASONS=("Winter" "Spring" "Summer" "Fall" "Autumn")
YEARS=(2023 2024 2025 2026)

echo "[+] Generating seasonal variations for years 2023-2026..."

# 3. Create a temporary file for new passwords
TEMP_PW=$(mktemp)

for year in "${YEARS[@]}"; do
    for season in "${SEASONS[@]}"; do
        # Capitalized: Winter2026
        echo "${season}${year}" >> "$TEMP_PW"
        # Lowercase: winter2026
        echo "${season,,}${year}" >> "$TEMP_PW"
        # Variations with common special characters (optional but recommended)
        echo "${season}${year}!" >> "$TEMP_PW"
        echo "${season}${year}*" >> "$TEMP_PW"
    done
done

# 4. Append to fasttrack.txt and remove duplicates
cat "$TEMP_PW" >> "$WORDLIST"
sort -u "$WORDLIST" -o "$WORDLIST"

# Clean up
rm "$TEMP_PW"

echo "[+] Update complete. New seasonal passwords added to $WORDLIST."
