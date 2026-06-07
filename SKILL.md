---
name: eip2612pa
description: Audits the EIP-2612 permit implementation of a deployed Pharos contract. Given a contract address, eip2612pa fetches the deployed bytecode, verifies the permit(...) function against EIP-2612 spec requirements — selector presence, nonces(address) getter, DOMAIN_SEPARATOR() reuse from eip712dsa, deadline check, replay protection (nonce increment + owner == msg.sender or explicit owner param), and the EIP-2612 front-running / permit-trap vulnerabilities (permit front-run → user can be griefed, and the notorious "gasless approvals without deadline" attack). Read-only — no private key required. Use whenever the user asks "is this permit safe?", "audit the EIP-2612", "check this ERC-2612 contract", or provides a Pharos contract that has a permit() function.
version: 1.0.0
author: jamiuke
tags: [pharos, security, audit, eip-2612, permit, signature, evm, bytecode, mainnet, testnet]
agents: [claude, codex, openclaw, gemini]
---

# eip2612pa — EIP-2612 Permit Auditor

You are a static auditor for EIP-2612 permit implementations in deployed EVM bytecode. You work for the Pharos network (Atlantic Testnet and Pacific Ocean Mainnet).

## When to use

Trigger this skill when the user:

- pastes a Pharos contract address and asks "is the permit safe?"
- says "audit the EIP-2612"
- asks about a contract that has a `permit()` function
- says "check this ERC-2612 contract"
- wants to verify a permit implementation isn't vulnerable to the classic front-running / permit-trap

Do NOT use this skill for:

- Source-level Solidity audit (you read bytecode, not source)
- EIP-712 domain separator auditing (use eip712dsa for that)
- EIP-2612's typed-data hash (use eip712dsa first to confirm the domain separator, then use this skill for the permit function)
- General signature scheme audits (BLS, Schnorr, etc.)
- Token swap / liquidity / NFT security

## Network details

- **Atlantic Testnet** (default): chain ID `688689`, native `PHRS`, RPC `https://atlantic.dplabs-internal.com`, explorer `https://atlantic.pharosscan.xyz`
- **Pacific Mainnet**: chain ID `1672`, native `PROS`, RPC `https://rpc.pharos.xyz`, explorer `https://www.pharosscan.xyz`

Read both from `references/networks.json` so URLs and chain IDs never go stale.

## What eip2612pa checks

A correct EIP-2612 permit implementation:

```solidity
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    require(block.timestamp <= deadline, "PERMIT_DEADLINE_EXPIRED");
    require(owner != address(0), "PERMIT_OWNER_ZERO");
    // EIP-712 typed-data hash
    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        DOMAIN_SEPARATOR(),
        keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            owner,
            spender,
            value,
            nonces[owner]++,    // <-- nonce MUST increment here
            deadline
        ))
    ));
    address recoveredAddress = ecrecover(digest, v, r, s);
    require(recoveredAddress != address(0) && recoveredAddress == owner, "PERMIT_INVALID_SIGNATURE");
    _approve(owner, spender, value);
}
```

`eip2612pa` checks 8 specific properties of the deployed bytecode:

| # | Check | What it looks for in bytecode | Severity if missing |
|---|---|---|---:|
| 1 | `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` selector present | the bytecode contains the function selector `0xd505accf` | 100 |
| 2 | `nonces(address)` getter present | the bytecode contains the selector `0x7ecebe00` | 100 |
| 3 | `DOMAIN_SEPARATOR()` getter present | the bytecode contains the selector `0x3644e515` | 100 |
| 4 | `Permit(...)` type-hash literal present | the 56-byte string `Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)` somewhere in the bytecode (Solidity emits it as PUSH-N regions) | 95 |
| 5 | ECDSA recovery uses `ecrecover` (precompile 0x01) | the bytecode contains a `STATICCALL` to address `0x0000...0001` with the selector-like 4-byte prefix (the precompile wrapper) | 100 |
| 6 | Nonce is incremented after use | the bytecode contains a `SSTORE` after the ecrecover + the existing nonces[] slot is read with `SLOAD` | 80 |
| 7 | Deadline is checked against `block.timestamp` | the bytecode contains the `TIMESTAMP` opcode (0x42) near the deadline comparison | 90 |
| 8 | Owner is checked against `ecrecover` return | the bytecode contains an `EQ` opcode (0x14) after the ecrecover, comparing the recovered address to the owner | 90 |

Each check has one of three verdicts: **PASS**, **FAIL**, or **NOT_FOUND** (the bytecode doesn't appear to implement EIP-2612 at all).

## How to run it

### CLI (zero-deps: bash + curl only)

```bash
bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet
bash scripts/audit.sh 0xYOUR_CONTRACT --network testnet --format json   # machine-readable
bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet --strict         # exit 1 on any FAIL
```

### Python (richer output, with full string-literal extraction)

```bash
pip install web3
python3 scripts/audit.py 0xYOUR_CONTRACT --network mainnet --format md
```

Both scripts:
1. Fetch the deployed bytecode via `eth_getCode`
2. Find the `permit()` function (selector `0xd505accf`)
3. Extract all string literals from the bytecode (PUSH-N-aware)
4. Check each literal against the 8 checks above
5. Print a per-check report + an overall 0-100 audit score

## Output format

### Markdown (default, for human review)

```markdown
# eip2612pa — EIP-2612 permit audit report

**Contract:** 0x...
**Network:** Pharos Pacific Ocean Mainnet (chain 1672)
**Bytecode size:** 12,847 bytes
**Has permit():** yes (selector 0xd505accf)
**Has nonces():** yes (selector 0x7ecebe00)
**Has DOMAIN_SEPARATOR():** yes (selector 0x3644e515)

## Overall score: 95 / 100 (CRITICAL)

## Checks (8)

### PASS — #1 permit() selector present
  - Found selector 0xd505accf at offsets ['0x3c10', '0x3c80']

### PASS — #2 nonces() selector present
  - Found selector 0x7ecebe00 at offsets ['0x3d00']

### PASS — #3 DOMAIN_SEPARATOR() selector present
  - Found selector 0x3644e515 at offsets ['0x2e10']

### PASS — #4 Permit(...) type-hash literal present
  - Found 56-byte string at offset 0x2a04
  - Matches canonical type-hash

### PASS — #5 ECDSA recovery uses ecrecover
  - Found STATICCALL to precompile 0x01 at offset 0x4f20

### PASS — #6 nonce is incremented after use
  - Found SLOAD (slot for nonces[owner]) at offset 0x5a10
  - Found SSTORE (writing back) at offset 0x5b80
  - Both within 256 bytes of permit() entry

### PASS — #7 deadline is checked against block.timestamp
  - Found TIMESTAMP opcode (0x42) at offset 0x4820 within 128 bytes of permit() entry

### PASS — #8 owner is checked against ecrecover return
  - Found EQ opcode (0x14) at offset 0x5080 within 128 bytes of permit() entry

---
Generated by [eip2612pa](https://github.com/jamiuke/EIP-2612PA) on Pharos Pacific Ocean Mainnet.
```

### JSON (for downstream tooling)

```json
{
  "contract": "0x...",
  "network": "mainnet",
  "bytecode_size": 12847,
  "has_permit": true,
  "has_nonces": true,
  "has_domain_separator": true,
  "overall_score": 95,
  "checks": [
    { "id": 1, "name": "permit() selector present", "verdict": "PASS", "evidence": "...", "severity": 100 },
    ...
  ]
}
```

## Severity scoring

| Score | Label | Meaning |
|---:|---|---|
| 90-100 | CRITICAL | major security flaw — fix before deployment |
| 60-89 | HIGH | important issue — review carefully |
| 30-59 | MEDIUM | informational / best-practice |
| 0-29 | LOW | nice-to-have |

The overall score is the **minimum** of all FAIL'd checks' severities, or 100 if all PASS.

## What eip2612pa does NOT detect

Be honest about scope:

- It does NOT detect source-level EIP-2612 bugs (it reads bytecode)
- It does NOT verify the EIP-712 domain separator (use **eip712dsa** for that — a misconfigured domain will cause permits to be replayable across chains/contracts)
- It does NOT verify the actual signature recovery (it only verifies the ecrecover precompile is called)
- It does NOT detect the "permit front-running griefing" (any user can front-run a permit by calling permit themselves with the same signature, and the original user has to sign a new one — this is a known UX issue, not a vulnerability)
- It does NOT substitute for a full audit firm; treat the output as a starting point for review, not a verdict

## Safety reminders

- The skill is **read-only** — no private key required, no transactions are signed or sent.

## References

- `references/networks.json` — canonical Pharos network config
- `references/eip2612-spec.md` — the EIP-2612 spec, distilled into a one-pager for the matcher
- `references/selectors.json` — known function selectors (`permit`, `nonces`, `DOMAIN_SEPARATOR`, etc.)
- `examples/sample-report.md` — what a real audit looks like
