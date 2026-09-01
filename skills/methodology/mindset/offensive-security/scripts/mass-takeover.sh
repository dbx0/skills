#!/bin/bash
# Multi-program subdomain takeover scanner
# Usage: ./mass-takeover.sh <scope_file>
# Scope file format: one apex domain per line

set -euo pipefail
SCOPE_FILE="${1:?Usage: $0 <scope_file>}"
OUTPUT_DIR="./takeover-results/$(date +%Y%m%d_%H%M%S)"
KALI="bx0@192.168.0.8"
PATH_EXPORT='export PATH=$PATH:$(go env GOPATH)/bin'
mkdir -p "$OUTPUT_DIR"

echo "[*] Output: $OUTPUT_DIR | Targets: $(wc -l < "$SCOPE_FILE") domains"

echo "[*] Phase 1: Subdomain enum..."
while IFS= read -r domain; do
    [[ -z "$domain" || "$domain" == \#* ]] && continue
    ssh "$KALI" "$PATH_EXPORT; subfinder -d '$domain' -silent -all 2>/dev/null" >> "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null || true
done < "$SCOPE_FILE"
sort -u "$OUTPUT_DIR/all_subdomains.txt" -o "$OUTPUT_DIR/all_subdomains.txt"
echo "[*] $(wc -l < "$OUTPUT_DIR/all_subdomains.txt") unique subs"

echo "[*] Phase 2: Nuclei takeover scan..."
ssh "$KALI" "$PATH_EXPORT; nuclei -l '$OUTPUT_DIR/all_subdomains.txt' -t http/takeovers/ -silent -timeout 15 -retries 2 -no-color -o '$OUTPUT_DIR/nuclei_results.txt'" || true

echo "[*] Phase 3: CNAME map..."
while IFS= read -r sub; do
    cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1)
    [[ -n "$cname" ]] && echo "$sub → $cname"
done < "$OUTPUT_DIR/all_subdomains.txt" > "$OUTPUT_DIR/cname_map.txt"

[[ -s "$OUTPUT_DIR/nuclei_results.txt" ]] && cat "$OUTPUT_DIR/nuclei_results.txt" || echo "[✓] No takeovers."
echo "[!] Manually verify all positives before reporting."
