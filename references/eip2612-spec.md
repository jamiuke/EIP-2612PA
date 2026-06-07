# EIP-2612 spec, distilled

A one-page distillation of [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612) for the auditor. If you've already read EIP-2612, skip this.

## The interface

```solidity
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external;

function nonces(address owner) external view returns (uint256);
function DOMAIN_SEPARATOR() external view returns (bytes32);
```

## How permit works (the high level)

1. The user signs a typed-data hash off-chain (EIP-712) containing (owner, spender, value, nonce, deadline).
2. Anyone calls `permit(...)` with that signature, paying the gas.
3. The contract verifies the signature against `ecrecover(typedDataHash, v, r, s)`, checks the deadline, checks the recovered address == owner, increments the nonce, and sets the allowance.

## The exact spec function (canonical)

```solidity
function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(block.timestamp <= deadline, "PERMIT_DEADLINE_EXPIRED");
    // (optional) require(owner != address(0));
    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        DOMAIN_SEPARATOR(),
        keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            owner,
            spender,
            value,
            nonces[owner]++,
            deadline
        ))
    ));
    address recoveredAddress = ecrecover(digest, v, r, s);
    require(recoveredAddress != address(0) && recoveredAddress == owner, "PERMIT_INVALID_SIGNATURE");
    _approve(owner, spender, value);
}
```

## The 4-byte function selectors

| Selector | Function |
|---|---|
| `0xd505accf` | `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` |
| `0x7ecebe00` | `nonces(address)` |
| `0x3644e515` | `DOMAIN_SEPARATOR()` |
| `0x06fdde03` | `name()` |
| `0x95d89b41` | `symbol()` |
| `0x18160ddd` | `totalSupply()` |
| `0x70a08231` | `balanceOf(address)` |
| `0xa9059cbb` | `transfer(address,uint256)` |
| `0x23b872dd` | `transferFrom(address,address,uint256)` |
| `0x095ea7b3` | `approve(address,uint256)` |
| `0xdd62ed3e` | `allowance(address,address)` |

## The Permit type-hash (56 bytes)

```
Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)
```

Solidity emits this as 2 PUSH-N opcodes (PUSH32 + PUSH24).

## The ecrecover precompile

`ecrecover` is precompile 0x01. It's called with:

```
STATICCALL
  gas
  addr=0x0000000000000000000000000000000000000001   <-- the precompile address
  argOffset=0x00, argSize=0x80
  retOffset=0x00, retSize=0x20
```

So the auditor looks for a `STATICCALL` (0xfa) with a `PUSH20 0x01...001` on the stack.

## Common pitfalls the auditor flags

1. **Missing nonce increment** — signatures can be replayed indefinitely. CRITICAL.
2. **No deadline check** — old signatures are valid forever. HIGH.
3. **No `ecrecover` call** — not actually a permit. CRITICAL.
4. **Hardcoded chainId in DOMAIN_SEPARATOR** — permits replayable across chains. CRITICAL.
5. **No owner check after ecrecover** — anyone can submit any signature. CRITICAL.
6. **Missing `nonces()` getter** — off-chain tooling can't predict the next nonce. MEDIUM.

## The interaction with EIP-712

`permit` is the canonical use case of EIP-712 typed-data hashing. The signature is over:

```
keccak256("\x19\x01" || DOMAIN_SEPARATOR || keccak256(abi.encode(
  PERMIT_TYPEHASH, owner, spender, value, nonces[owner], deadline
)))
```

So before auditing `permit()`, you should audit the `DOMAIN_SEPARATOR()` first using **eip712dsa** — they're complementary.

## References

- [EIP-2612: permit extension for ERC-20](https://eips.ethereum.org/EIPS/eip-2612) — the canonical spec
- [EIP-712: typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712) — required companion spec
- [OpenZeppelin: ERC20Permit.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC20Permit.sol) — reference implementation
- [Uniswap V2: permit](https://docs.uniswap.org/contracts/v2/api/periphery/IERC20Permit) — popular usage
