#!/usr/bin/env bash
# eip2612pa/audit_demo.sh — one-shot demo audit of a real public mainnet contract.
# Run with no arguments. Requires: bash, curl, python3.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONTRACT="0x6dc35147eb53152cd834b5799a07934f13f398a3"

echo "==============================================="
echo " eip2612pa demo audit"
echo "==============================================="
echo " contract: $CONTRACT"
echo " network:  Pharos Pacific Ocean Mainnet (1672)"
echo " output:   Markdown, all severities"
echo "==============================================="
echo

bash "$SCRIPT_DIR/audit.sh" "$CONTRACT" --network mainnet --format md
