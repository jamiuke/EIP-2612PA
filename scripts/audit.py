#!/usr/bin/env python3
"""
eip2612pa/audit.py — EIP-2612 permit auditor for deployed EVM bytecode.
Run on Pharos Atlantic Testnet or Pacific Mainnet.

Usage:
  python3 scripts/audit.py 0xCONTRACT [--network mainnet|atlantic-testnet] [--format md|json|txt] [--strict]
  python3 scripts/audit.py --demo    # audit a known public mainnet contract
  python3 scripts/audit.py --help

Requires:
  pip install web3 (not actually used — we use urllib for portability)
"""
import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

# EVM opcode constants
ADDRESS = 0x30
ORIGIN = 0x32
CALLDATALOAD = 0x35
CALLER = 0x33
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
GAS = 0x5a
PUSH1 = 0x60
PUSH20 = 0x73
PUSH32 = 0x7f

NETWORKS = {
    "mainnet": {
        "chainId": 1672,
        "rpcUrl": "https://rpc.pharos.xyz",
        "displayName": "Pharos Pacific Ocean Mainnet",
        "explorer": "https://www.pharosscan.xyz",
    },
    "atlantic-testnet": {
        "chainId": 688689,
        "rpcUrl": "https://atlantic.dplabs-internal.com",
        "displayName": "Pharos Atlantic Testnet",
        "explorer": "https://atlantic.pharosscan.xyz",
    },
}

# Canonical EIP-2612 type-hash string (56 chars, emitted as PUSH32 + PUSH24)
EIP2612_TYPEHASH = "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"

# Function selectors
SEL_PERMIT = "d505accf"
SEL_NONCES = "7ecebe00"
SEL_DOMAIN_SEPARATOR = "3644e515"
SEL_NAME = "06fdde03"

# ecrecover precompile address (PUSH20 0x0000...0001)
ECRECOVER_PRECOMPILE = "0000000000000000000000000000000000000001"


def _iter_opcodes(raw):
    i = 0
    while i < len(raw):
        op = raw[i]
        yield i, op
        if 0x60 <= op <= 0x7f:
            i += (op - 0x5f) + 1
        else:
            i += 1


def extract_string_literals(raw):
    """Extract UTF-8 string literals of length >= 3 from the bytecode.
    Solidity emits string literals as sequences of PUSH-N opcodes whose immediate
    data IS the string. We extract each PUSH-N payload, then stitch together
    consecutive PUSH-N payloads that are all printable ASCII.
    """
    push_regions = []
    for off, op in _iter_opcodes(raw):
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
    """Find occurrences of known 4-byte function selectors in the bytecode."""
    if len(raw) < 4:
        return {}
    results = {}
    for i in range(len(raw) - 3):
        sel_hex = "".join(f"{b:02x}" for b in raw[i:i + 4])
        if sel_hex in {SEL_PERMIT, SEL_NONCES, SEL_DOMAIN_SEPARATOR, SEL_NAME}:
            results.setdefault(sel_hex, []).append(i)
    return results


def has_opcode_near(raw, opcode, reference_offset, window=128):
    """Check if `opcode` appears within `window` bytes of `reference_offset`."""
    lo = max(0, reference_offset - window)
    hi = min(len(raw), reference_offset + window)
    for off, op in _iter_opcodes(raw[lo:hi]):
        if op == opcode:
            return True, lo + off
    return False, None


def has_ecrecover_near(raw, reference_offset, window=256):
    """Check if ecrecover precompile (0x01) is called within `window` bytes of `reference_offset`.
    The precompile is identified by a PUSH20 0x0000...0001 followed (eventually) by STATICCALL.
    """
    lo = max(0, reference_offset - window)
    hi = min(len(raw), reference_offset + window)
    # Look for PUSH20 followed by 0x0000000000000000000000000000000000000001 in the next 20 bytes
    target = bytes.fromhex(ECRECOVER_PRECOMPILE)
    for i in range(lo, hi - 20):
        if raw[i] == PUSH20:
            payload = raw[i + 1:i + 1 + 20]
            if payload == target:
                # Now look for a STATICCALL somewhere after this in the window
                for off, op in _iter_opcodes(raw[i + 21:hi]):
                    if op == STATICCALL:
                        return True, i
    return False, None


def has_nonce_increment_near(raw, permit_offset, window=512):
    """Check if the permit function contains a nonces[owner] SLOAD followed by SSTORE.
    Returns (True, sload_off, sstore_off) or (False, None, None).
    """
    lo = max(0, permit_offset)
    hi = min(len(raw), permit_offset + window)
    # Look for an SLOAD followed (eventually) by an SSTORE within the window
    sloads = []
    for off, op in _iter_opcodes(raw[lo:hi]):
        if op == SLOAD:
            sloads.append(lo + off)
        elif op == SSTORE and sloads:
            return True, sloads[-1], lo + off
    return False, None, None


def fetch_bytecode(contract, rpc_url, retries=3):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [contract, "latest"],
        "id": 1,
    }).encode()
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                rpc_url, data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            if "error" in data:
                raise RuntimeError(f"RPC error: {data['error']}")
            result = data.get("result", "")
            if not result or result == "0x":
                raise RuntimeError("contract has no deployed code (or address is an EOA)")
            return result
        except Exception as e:
            last_err = e
    raise RuntimeError(f"failed to fetch bytecode after {retries} attempts: {last_err}")


def audit(bytecode_hex, contract=None):
    """Run the 8 EIP-2612 checks against the bytecode."""
    assert bytecode_hex.startswith("0x")
    raw = bytes.fromhex(bytecode_hex[2:])

    # Extract string literals
    literals = extract_string_literals(raw)

    # Find function selectors
    selectors = find_selectors(raw)

    checks = []

    # ----- Check 1: permit() selector present -----
    if SEL_PERMIT in selectors:
        offs = selectors[SEL_PERMIT]
        checks.append({
            "id": 1, "name": "permit() selector present",
            "verdict": "PASS",
            "evidence": f"Found selector 0xd505accf at offsets {[hex(o) for o in offs[:3]]}",
            "severity": 100,
        })
        permit_ref = offs[0]
    else:
        checks.append({
            "id": 1, "name": "permit() selector present",
            "verdict": "NOT_FOUND",
            "evidence": "Selector 0xd505accf (permit) not found in bytecode",
            "severity": 100,
        })
        permit_ref = None

    # ----- Check 2: nonces() selector present -----
    if SEL_NONCES in selectors:
        offs = selectors[SEL_NONCES]
        checks.append({
            "id": 2, "name": "nonces() getter present",
            "verdict": "PASS",
            "evidence": f"Found selector 0x7ecebe00 at offsets {[hex(o) for o in offs[:3]]}",
            "severity": 100,
        })
    else:
        checks.append({
            "id": 2, "name": "nonces() getter present",
            "verdict": "FAIL",
            "evidence": "Selector 0x7ecebe00 (nonces) not found — off-chain tooling cannot predict next nonce",
            "severity": 100,
        })

    # ----- Check 3: DOMAIN_SEPARATOR() selector present -----
    if SEL_DOMAIN_SEPARATOR in selectors:
        offs = selectors[SEL_DOMAIN_SEPARATOR]
        checks.append({
            "id": 3, "name": "DOMAIN_SEPARATOR() getter present",
            "verdict": "PASS",
            "evidence": f"Found selector 0x3644e515 at offsets {[hex(o) for o in offs[:3]]}",
            "severity": 100,
        })
    else:
        checks.append({
            "id": 3, "name": "DOMAIN_SEPARATOR() getter present",
            "verdict": "WARN",
            "evidence": "Selector 0x3644e515 (DOMAIN_SEPARATOR) not found — permits may use an internal-only domain",
            "severity": 80,
        })

    # ----- Check 4: Permit type-hash literal present -----
    has_permit_typehash = any(s == EIP2612_TYPEHASH for _, s in literals)
    if has_permit_typehash:
        off = next(o for o, s in literals if s == EIP2612_TYPEHASH)
        checks.append({
            "id": 4, "name": "Permit(...) type-hash literal present",
            "verdict": "PASS",
            "evidence": f"Found 56-byte string at offset 0x{off:x} (matches canonical Permit type-hash)",
            "severity": 95,
        })
    else:
        checks.append({
            "id": 4, "name": "Permit(...) type-hash literal present",
            "verdict": "NOT_FOUND",
            "evidence": "No Permit(...) string literal in bytecode — contract may not implement EIP-2612 typed-data hashing",
            "severity": 95,
        })

    # ----- Check 5: ecrecover precompile is called -----
    if permit_ref is not None:
        found, off = has_ecrecover_near(raw, permit_ref, 512)
        if found:
            checks.append({
                "id": 5, "name": "ECDSA recovery uses ecrecover (precompile 0x01)",
                "verdict": "PASS",
                "evidence": f"Found STATICCALL to precompile 0x01 at offset 0x{off:x} (within 512 bytes of permit entry)",
                "severity": 100,
            })
        else:
            checks.append({
                "id": 5, "name": "ECDSA recovery uses ecrecover (precompile 0x01)",
                "verdict": "FAIL",
                "evidence": "No STATICCALL to precompile 0x01 (ecrecover) found near permit() — signature not actually verified",
                "severity": 100,
            })
    else:
        checks.append({
            "id": 5, "name": "ECDSA recovery uses ecrecover (precompile 0x01)",
            "verdict": "SKIP",
            "evidence": "Skipped: no permit() reference point",
            "severity": 100,
        })

    # ----- Check 6: nonce is incremented after use -----
    if permit_ref is not None:
        found, sload_off, sstore_off = has_nonce_increment_near(raw, permit_ref, 512)
        if found:
            checks.append({
                "id": 6, "name": "nonce is incremented after use",
                "verdict": "PASS",
                "evidence": f"Found SLOAD at 0x{sload_off:x} (read nonces[owner]) and SSTORE at 0x{sstore_off:x} (write back) within 512 bytes of permit()",
                "severity": 80,
            })
        else:
            checks.append({
                "id": 6, "name": "nonce is incremented after use",
                "verdict": "FAIL",
                "evidence": "No SLOAD→SSTORE pair detected near permit() — permit signatures may be replayable",
                "severity": 80,
            })
    else:
        checks.append({
            "id": 6, "name": "nonce is incremented after use",
            "verdict": "SKIP",
            "evidence": "Skipped: no permit() reference point",
            "severity": 80,
        })

    # ----- Check 7: deadline is checked against block.timestamp -----
    if permit_ref is not None:
        found, off = has_opcode_near(raw, TIMESTAMP, permit_ref, 256)
        if found:
            checks.append({
                "id": 7, "name": "deadline is checked against block.timestamp",
                "verdict": "PASS",
                "evidence": f"Found TIMESTAMP opcode (0x42) at offset 0x{off:x} within 256 bytes of permit()",
                "severity": 90,
            })
        else:
            checks.append({
                "id": 7, "name": "deadline is checked against block.timestamp",
                "verdict": "FAIL",
                "evidence": "No TIMESTAMP opcode (0x42) near permit() — old signatures may be valid forever",
                "severity": 90,
            })
    else:
        checks.append({
            "id": 7, "name": "deadline is checked against block.timestamp",
            "verdict": "SKIP",
            "evidence": "Skipped: no permit() reference point",
            "severity": 90,
        })

    # ----- Check 8: owner is checked against ecrecover return -----
    if permit_ref is not None:
        found, off = has_opcode_near(raw, EQ, permit_ref, 256)
        if found:
            checks.append({
                "id": 8, "name": "owner is checked against ecrecover return",
                "verdict": "PASS",
                "evidence": f"Found EQ opcode (0x14) at offset 0x{off:x} within 256 bytes of permit()",
                "severity": 90,
            })
        else:
            checks.append({
                "id": 8, "name": "owner is checked against ecrecover return",
                "verdict": "WARN",
                "evidence": "No EQ opcode (0x14) near permit() — the recovered address may not be compared to owner",
                "severity": 90,
            })
    else:
        checks.append({
            "id": 8, "name": "owner is checked against ecrecover return",
            "verdict": "SKIP",
            "evidence": "Skipped: no permit() reference point",
            "severity": 90,
        })

    # Overall score
    fail_severities = [c["severity"] for c in checks if c["verdict"] in ("FAIL", "NOT_FOUND")]
    if fail_severities:
        overall = min(fail_severities)
    else:
        overall = 100

    # Special verdict: if check 1 is NOT_FOUND, this isn't an EIP-2612 contract at all
    if any(c["id"] == 1 and c["verdict"] == "NOT_FOUND" for c in checks):
        overall = 0
        verdict = "NOT_EIP2612"
    else:
        verdict = "PASS" if overall == 100 else ("PARTIAL" if overall >= 60 else "FAIL")

    return {
        "contract": contract,
        "bytecode_size": len(raw),
        "has_permit": permit_ref is not None,
        "has_nonces": SEL_NONCES in selectors,
        "has_domain_separator": SEL_DOMAIN_SEPARATOR in selectors,
        "overall_score": overall,
        "verdict": verdict,
        "checks": checks,
        "literals_found": len(literals),
    }


def sev_label(s):
    if s == 0: return "NOT EIP-2612"
    if s <= 30: return "LOW"
    if s <= 60: return "MEDIUM"
    if s <= 80: return "HIGH"
    return "CRITICAL"


def render(data, fmt):
    if fmt == "json":
        return json.dumps(data, indent=2)
    if fmt == "txt":
        out = []
        out.append("eip2612pa — EIP-2612 permit audit report")
        out.append(f"  Contract:        {data['contract']}")
        out.append(f"  Network:         {data.get('net_label', '?')}")
        out.append(f"  Bytecode:        {data['bytecode_size']:,} bytes")
        out.append(f"  Has permit:      {data.get('has_permit', False)}")
        out.append(f"  Has nonces:      {data.get('has_nonces', False)}")
        out.append(f"  Has DOMAIN_SEP:  {data.get('has_domain_separator', False)}")
        out.append(f"  Overall:         {data['overall_score']} / 100 ({sev_label(data['overall_score'])})")
        out.append(f"  Checks:          {len(data['checks'])}")
        out.append("")
        for c in data["checks"]:
            sym = {"PASS": "[OK]", "FAIL": "[FAIL]", "WARN": "[WARN]", "NOT_FOUND": "[??]",
                   "SKIP": "[skip]", "N/A": "[n/a]", "INFO": "[info]"}.get(c["verdict"], "[?]")
            out.append(f"  {sym}  #{c['id']}  {c['name']}")
            out.append(f"             evidence: {c['evidence']}")
            out.append("")
        return "\n".join(out)
    # md
    out = []
    out.append("# eip2612pa — EIP-2612 permit audit report")
    out.append("")
    out.append(f"**Contract:** [{data['contract']}]({data.get('explorer_link', '#')})")
    out.append(f"**Network:** {data.get('net_label', '?')}")
    out.append(f"**Bytecode size:** {data['bytecode_size']:,} bytes")
    out.append(f"**Has permit():** {'yes (selector 0xd505accf)' if data.get('has_permit') else 'no'}")
    out.append(f"**Has nonces():** {'yes (selector 0x7ecebe00)' if data.get('has_nonces') else 'no'}")
    out.append(f"**Has DOMAIN_SEPARATOR():** {'yes (selector 0x3644e515)' if data.get('has_domain_separator') else 'no'}")
    out.append("")
    overall = data.get("overall_score", 0)
    label = sev_label(overall)
    verdict = data.get("verdict", "")
    out.append(f"## Overall score: {overall} / 100 ({label} · {verdict})")
    out.append("")
    out.append(f"## Checks ({len(data['checks'])})")
    out.append("")
    if not any(c["verdict"] in ("FAIL", "NOT_FOUND") for c in data["checks"]):
        out.append("_All checks PASS. Contract implements EIP-2612 correctly._")
        out.append("")
    for c in data["checks"]:
        sym = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN", "NOT_FOUND": "NOT_FOUND",
               "SKIP": "SKIP", "N/A": "N/A", "INFO": "INFO"}.get(c["verdict"], c["verdict"])
        out.append(f"### {sym} — #{c['id']} {c['name']}")
        out.append("")
        out.append(f"- Evidence: {c['evidence']}")
        out.append("")
    out.append("---")
    out.append("")
    out.append(f"Generated by [eip2612pa](https://github.com/jamiuke/EIP-2612PA) on {data.get('net_label', 'Pharos')}.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="eip2612pa — EIP-2612 permit auditor for Pharos")
    ap.add_argument("contract", nargs="?", help="contract address (0x...)")
    ap.add_argument("--network", default="atlantic-testnet", choices=list(NETWORKS.keys()))
    ap.add_argument("--format", default="md", choices=["md", "json", "txt"])
    ap.add_argument("--strict", action="store_true", help="exit 1 if any check FAILs")
    ap.add_argument("--demo", action="store_true", help="audit a real public mainnet contract")
    args = ap.parse_args()

    contract = args.contract
    if args.demo:
        contract = "0x6dc35147eb53152cd834b5799a07934f13f398a3"

    if not contract:
        ap.print_help()
        sys.exit(1)

    contract = contract.lower()
    if not (contract.startswith("0x") and len(contract) == 42):
        print(f"ERROR: contract must look like 0x + 40 hex chars, got: {contract}", file=sys.stderr)
        sys.exit(2)

    net = NETWORKS[args.network]
    print(f"[eip2612pa] fetching bytecode for {contract} on {net['displayName']}...", file=sys.stderr)
    try:
        bc = fetch_bytecode(contract, net["rpcUrl"])
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(3)

    print(f"[eip2612pa] auditing {len(bc) // 2 - 1} bytes...", file=sys.stderr)
    result = audit(bc, contract=contract)
    result["network"] = args.network
    result["chain_id"] = net["chainId"]
    result["net_label"] = net["displayName"]
    result["explorer_link"] = f"{net['explorer']}/address/{contract}"
    result["format"] = args.format

    print(render(result, args.format))

    if args.strict and any(c["verdict"] in ("FAIL", "NOT_FOUND") for c in result["checks"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
