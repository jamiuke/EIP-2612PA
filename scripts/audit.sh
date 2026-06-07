#!/usr/bin/env bash
# eip2612pa/audit.sh — zero-dep bash auditor for EIP-2612 permit implementations.
# Usage:
#   bash scripts/audit.sh 0xCONTRACT --network mainnet
#   bash scripts/audit.sh 0xCONTRACT --network testnet --format json
#   bash scripts/audit.sh 0xCONTRACT --network mainnet --strict
#
# Requires: bash 4+, curl, python3
# Read-only: never asks for a private key, never sends a transaction.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -------------------- args --------------------
if [[ $# -lt 1 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
  cat <<EOF
Usage: bash scripts/audit.sh 0xCONTRACT [--network mainnet|atlantic-testnet] [--format md|json|txt] [--strict]

Networks:
  atlantic-testnet  (default) — Pharos Atlantic Testnet, chain 688689
  mainnet                       — Pharos Pacific Ocean Mainnet, chain 1672

Examples:
  bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet
  bash scripts/audit.sh 0xYOUR_CONTRACT --network testnet --format json
  bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet --strict
EOF
  exit 0
fi

CONTRACT="${1,,}"
NETWORK="atlantic-testnet"
FORMAT="md"
STRICT=0

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --network)  NETWORK="$2"; shift 2 ;;
    --format)   FORMAT="$2"; shift 2 ;;
    --strict)   STRICT=1; shift ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

# validate
if [[ ! "$CONTRACT" =~ ^0x[0-9a-f]{40}$ ]]; then
  echo "ERROR: contract must look like 0x + 40 hex chars" >&2; exit 2
fi

case "$NETWORK" in
  mainnet)
    CHAIN_ID=1672
    RPC="https://rpc.pharos.xyz"
    EXPLORER="https://www.pharosscan.xyz"
    NET_LABEL="Pharos Pacific Ocean Mainnet (chain 1672)"
    ;;
  atlantic-testnet|testnet)
    CHAIN_ID=688689
    RPC="https://atlantic.dplabs-internal.com"
    EXPLORER="https://atlantic.pharosscan.xyz"
    NET_LABEL="Pharos Atlantic Testnet (chain 688689)"
    ;;
  *) echo "ERROR: unknown network: $NETWORK" >&2; exit 2 ;;
esac

case "$FORMAT" in md|json|txt) ;; *) echo "ERROR: format must be md|json|txt" >&2; exit 2 ;; esac

# -------------------- fetch bytecode --------------------
PAYLOAD=$(printf '{"jsonrpc":"2.0","method":"eth_getCode","params":["%s","latest"],"id":1}' "$CONTRACT")

RESP=$(curl -sS -X POST -H "Content-Type: application/json" --data "$PAYLOAD" "$RPC")
BYTECODE_HEX=$(printf '%s' "$RESP" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if "error" in d:
    print("ERROR:", d["error"].get("message", d["error"]), file=sys.stderr); sys.exit(3)
r = d.get("result", "")
if not r or r == "0x":
    print("ERROR: contract has no deployed code (or address is an EOA)", file=sys.stderr); sys.exit(4)
print(r)
')

BYTECODE_SIZE=$((${#BYTECODE_HEX} / 2 - 1))
echo "[eip2612pa] fetched ${BYTECODE_SIZE} bytes of bytecode for $CONTRACT on $NET_LABEL" >&2

# -------------------- run auditor --------------------
REPORT_JSON=$(export EIP2612PA_BYTECODE_HEX="$BYTECODE_HEX" && BYTECODE_HEX="$BYTECODE_HEX" python3 <<'PYEOF'
import os, json

bytecode = os.environ["EIP2612PA_BYTECODE_HEX"]
assert bytecode.startswith("0x")
raw = bytes.fromhex(bytecode[2:])

SLOAD = 0x54
SSTORE = 0x55
TIMESTAMP = 0x42
JUMPDEST = 0x5b
STOP = 0x00
RETURN = 0xf3
REVERT = 0xfd
JUMPI = 0x57
EQ = 0x14
STATICCALL = 0xfa
PUSH20 = 0x73
PUSH32 = 0x7f

EIP2612_TYPEHASH = "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
SEL_PERMIT = "d505accf"
SEL_NONCES = "7ecebe00"
SEL_DOMAIN_SEPARATOR = "3644e515"
SEL_NAME = "06fdde03"
ECRECOVER_PRECOMPILE = "0000000000000000000000000000000000000001"

def iter_opcodes(b):
    i = 0
    while i < len(b):
        op = b[i]
        yield i, op
        if 0x60 <= op <= 0x7f:
            i += (op - 0x5f) + 1
        else:
            i += 1

def extract_string_literals(raw):
    push_regions = []
    for off, op in iter_opcodes(raw):
        if 0x60 <= op <= 0x7f:
            n = op - 0x5f
            payload = raw[off + 1:off + 1 + n]
            push_regions.append((off, payload, n))
    literals = []
    i = 0
    while i < len(push_regions):
        start_off, payload, n = push_regions[i]
        if not all(0x20 <= b <= 0x7e for b in payload):
            i += 1
            continue
        literal_start = start_off
        literal_bytes = bytearray()
        for j in range(i, len(push_regions)):
            off_j, payload_j, n_j = push_regions[j]
            if not all(0x20 <= b <= 0x7e for b in payload_j):
                break
            literal_bytes.extend(payload_j)
            if j + 1 < len(push_regions):
                off_next, _, _ = push_regions[j + 1]
                if off_next != off_j + n_j + 1:
                    break
        literal_str = literal_bytes.decode("ascii", errors="replace").rstrip("\x00")
        if len(literal_str) >= 3:
            literals.append((literal_start, literal_str))
        i += 1
    return literals

def find_selectors(raw):
    if len(raw) < 4: return {}
    results = {}
    for i in range(len(raw) - 3):
        sel_hex = "".join(f"{b:02x}" for b in raw[i:i + 4])
        if sel_hex in {SEL_PERMIT, SEL_NONCES, SEL_DOMAIN_SEPARATOR, SEL_NAME}:
            results.setdefault(sel_hex, []).append(i)
    return results

def has_opcode_near(raw, opcode, ref, window=128):
    lo = max(0, ref - window)
    hi = min(len(raw), ref + window)
    for off, op in iter_opcodes(raw[lo:hi]):
        if op == opcode:
            return True, lo + off
    return False, None

def has_ecrecover_near(raw, ref, window=256):
    lo = max(0, ref - window)
    hi = min(len(raw), ref + window)
    target = bytes.fromhex(ECRECOVER_PRECOMPILE)
    for i in range(lo, hi - 20):
        if raw[i] == PUSH20:
            payload = raw[i + 1:i + 1 + 20]
            if payload == target:
                for off, op in iter_opcodes(raw[i + 21:hi]):
                    if op == STATICCALL:
                        return True, i
    return False, None

def has_nonce_increment_near(raw, permit_offset, window=512):
    lo = max(0, permit_offset)
    hi = min(len(raw), permit_offset + window)
    sloads = []
    for off, op in iter_opcodes(raw[lo:hi]):
        if op == SLOAD:
            sloads.append(lo + off)
        elif op == SSTORE and sloads:
            return True, sloads[-1], lo + off
    return False, None, None

literals = extract_string_literals(raw)
selectors = find_selectors(raw)
checks = []

# Check 1: permit selector
if SEL_PERMIT in selectors:
    offs = selectors[SEL_PERMIT]
    checks.append({"id":1,"name":"permit() selector present","verdict":"PASS","evidence":f"Found selector 0xd505accf at offsets {[hex(o) for o in offs[:3]]}","severity":100})
    permit_ref = offs[0]
else:
    checks.append({"id":1,"name":"permit() selector present","verdict":"NOT_FOUND","evidence":"Selector 0xd505accf (permit) not found in bytecode","severity":100})
    permit_ref = None

# Check 2: nonces
if SEL_NONCES in selectors:
    checks.append({"id":2,"name":"nonces() getter present","verdict":"PASS","evidence":f"Found selector 0x7ecebe00 at offsets {[hex(o) for o in selectors[SEL_NONCES][:3]]}","severity":100})
else:
    checks.append({"id":2,"name":"nonces() getter present","verdict":"FAIL","evidence":"Selector 0x7ecebe00 (nonces) not found — off-chain tooling cannot predict next nonce","severity":100})

# Check 3: DOMAIN_SEPARATOR
if SEL_DOMAIN_SEPARATOR in selectors:
    checks.append({"id":3,"name":"DOMAIN_SEPARATOR() getter present","verdict":"PASS","evidence":f"Found selector 0x3644e515 at offsets {[hex(o) for o in selectors[SEL_DOMAIN_SEPARATOR][:3]]}","severity":100})
else:
    checks.append({"id":3,"name":"DOMAIN_SEPARATOR() getter present","verdict":"WARN","evidence":"Selector 0x3644e515 (DOMAIN_SEPARATOR) not found — permits may use an internal-only domain","severity":80})

# Check 4: Permit type-hash
has_permit_typehash = any(s == EIP2612_TYPEHASH for _, s in literals)
if has_permit_typehash:
    off = next(o for o, s in literals if s == EIP2612_TYPEHASH)
    checks.append({"id":4,"name":"Permit(...) type-hash literal present","verdict":"PASS","evidence":f"Found 56-byte string at offset 0x{off:x} (matches canonical Permit type-hash)","severity":95})
else:
    checks.append({"id":4,"name":"Permit(...) type-hash literal present","verdict":"NOT_FOUND","evidence":"No Permit(...) string literal in bytecode — contract may not implement EIP-2612 typed-data hashing","severity":95})

# Check 5: ecrecover
if permit_ref is not None:
    found, off = has_ecrecover_near(raw, permit_ref, 512)
    if found:
        checks.append({"id":5,"name":"ECDSA recovery uses ecrecover (precompile 0x01)","verdict":"PASS","evidence":f"Found STATICCALL to precompile 0x01 at offset 0x{off:x} (within 512 bytes of permit entry)","severity":100})
    else:
        checks.append({"id":5,"name":"ECDSA recovery uses ecrecover (precompile 0x01)","verdict":"FAIL","evidence":"No STATICCALL to precompile 0x01 (ecrecover) found near permit() — signature not actually verified","severity":100})
else:
    checks.append({"id":5,"name":"ECDSA recovery uses ecrecover (precompile 0x01)","verdict":"SKIP","evidence":"Skipped: no permit() reference point","severity":100})

# Check 6: nonce increment
if permit_ref is not None:
    found, sload_off, sstore_off = has_nonce_increment_near(raw, permit_ref, 512)
    if found:
        checks.append({"id":6,"name":"nonce is incremented after use","verdict":"PASS","evidence":f"Found SLOAD at 0x{sload_off:x} (read nonces[owner]) and SSTORE at 0x{sstore_off:x} (write back) within 512 bytes of permit()","severity":80})
    else:
        checks.append({"id":6,"name":"nonce is incremented after use","verdict":"FAIL","evidence":"No SLOAD→SSTORE pair detected near permit() — permit signatures may be replayable","severity":80})
else:
    checks.append({"id":6,"name":"nonce is incremented after use","verdict":"SKIP","evidence":"Skipped: no permit() reference point","severity":80})

# Check 7: deadline via TIMESTAMP
if permit_ref is not None:
    found, off = has_opcode_near(raw, TIMESTAMP, permit_ref, 256)
    if found:
        checks.append({"id":7,"name":"deadline is checked against block.timestamp","verdict":"PASS","evidence":f"Found TIMESTAMP opcode (0x42) at offset 0x{off:x} within 256 bytes of permit()","severity":90})
    else:
        checks.append({"id":7,"name":"deadline is checked against block.timestamp","verdict":"FAIL","evidence":"No TIMESTAMP opcode (0x42) near permit() — old signatures may be valid forever","severity":90})
else:
    checks.append({"id":7,"name":"deadline is checked against block.timestamp","verdict":"SKIP","evidence":"Skipped: no permit() reference point","severity":90})

# Check 8: owner EQ check
if permit_ref is not None:
    found, off = has_opcode_near(raw, EQ, permit_ref, 256)
    if found:
        checks.append({"id":8,"name":"owner is checked against ecrecover return","verdict":"PASS","evidence":f"Found EQ opcode (0x14) at offset 0x{off:x} within 256 bytes of permit()","severity":90})
    else:
        checks.append({"id":8,"name":"owner is checked against ecrecover return","verdict":"WARN","evidence":"No EQ opcode (0x14) near permit() — the recovered address may not be compared to owner","severity":90})
else:
    checks.append({"id":8,"name":"owner is checked against ecrecover return","verdict":"SKIP","evidence":"Skipped: no permit() reference point","severity":90})

# Overall score
if any(c["id"] == 1 and c["verdict"] == "NOT_FOUND" for c in checks):
    overall = 0
    audit_verdict = "NOT_EIP2612"
else:
    fail_severities = [c["severity"] for c in checks if c["verdict"] == "FAIL"]
    overall = min(fail_severities) if fail_severities else 100
    audit_verdict = "PASS" if overall == 100 else ("PARTIAL" if overall >= 60 else "FAIL")

report = {
    "bytecode_size": len(raw),
    "has_permit": permit_ref is not None,
    "has_nonces": SEL_NONCES in selectors,
    "has_domain_separator": SEL_DOMAIN_SEPARATOR in selectors,
    "overall_score": overall,
    "verdict": audit_verdict,
    "checks": checks,
    "literals_found": len(literals),
}
print(json.dumps(report))
PYEOF
)

# -------------------- render --------------------
EXPLORER_LINK="$EXPLORER/address/$CONTRACT"
echo "$REPORT_JSON" | python3 "$SCRIPT_DIR/_render.py" \
  "contract=$CONTRACT" \
  "network=$NETWORK" \
  "chain_id=$CHAIN_ID" \
  "net_label=$NET_LABEL" \
  "explorer_link=$EXPLORER_LINK" \
  "bytecode_size=$BYTECODE_SIZE" \
  "format=$FORMAT"

# -------------------- strict mode --------------------
if [[ "$STRICT" -eq 1 ]]; then
  FAIL_COUNT=$(echo "$REPORT_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for c in d["checks"] if c["verdict"] in ("FAIL","NOT_FOUND")))')
  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "" >&2
    echo "[eip2612pa] STRICT MODE: $FAIL_COUNT check(s) FAILED — exiting 1" >&2
    exit 1
  fi
fi
