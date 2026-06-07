#!/usr/bin/env python3
"""
eip2612pa/test_audit.py — unit tests for the EIP-2612 auditor.
Run: python3 tests/test_audit.py
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
from audit import (
    audit, extract_string_literals, find_selectors,
    has_opcode_near, has_ecrecover_near, has_nonce_increment_near, _iter_opcodes,
    EIP2612_TYPEHASH,
    SEL_PERMIT, SEL_NONCES, SEL_DOMAIN_SEPARATOR,
    ADDRESS, ORIGIN, JUMPDEST, RETURN, STOP, JUMPI, REVERT,
    SLOAD, SSTORE, TIMESTAMP, EQ, STATICCALL, PUSH20, PUSH32,
)  # noqa


# ----- helpers -----

def hex_of(s: str) -> bytes:
    return s.encode("ascii")

def PUSH1(v: int) -> bytes:
    return bytes([0x60, v])

def PUSH4(v: int) -> bytes:
    return bytes([0x63]) + v.to_bytes(4, "big")

def PUSH20(v_hex: str) -> bytes:
    return bytes([0x73]) + bytes.fromhex(v_hex)

def JUMPDEST() -> bytes:
    return bytes([0x5b])

def RETURN_() -> bytes:
    return bytes([RETURN])

def function_body(*parts) -> bytes:
    return JUMPDEST() + b"".join(parts) + RETURN_()


# ============== tests ==============

def test_extract_string_literal_permit_typehash():
    """The 82-byte Permit type-hash string should be extractable, even when split
    across multiple PUSH-N opcodes (which is how Solidity emits long string literals)."""
    s = EIP2612_TYPEHASH.encode("ascii")
    assert len(s) == 82, f"expected 82 chars, got {len(s)}"
    bc = (
        bytes([0x7f]) + s[0:32]      # PUSH32 first 32 bytes
        + bytes([0x7f]) + s[32:64]   # PUSH32 next 32 bytes
        + bytes([0x71]) + s[64:82]   # PUSH18 last 18 bytes (0x71 = 0x5f + 18)
    )
    literals = extract_string_literals(bc)
    found = [x for _, x in literals if x == EIP2612_TYPEHASH]
    assert found, f"type-hash literal not extracted; got: {literals}"
    print("  ✓ test_extract_string_literal_permit_typehash")


def test_extract_skips_non_printable_push():
    """A PUSH-N whose payload contains non-printable bytes should NOT be extracted."""
    bc = JUMPDEST() + bytes([0x63]) + b"\xde\xad\xbe\xef" + RETURN_()
    literals = extract_string_literals(bc)
    assert all(not s.startswith("\xde") for _, s in literals), f"non-printable PUSH wrongly extracted: {literals}"
    print("  ✓ test_extract_skips_non_printable_push")


def test_find_selectors():
    """Selectors should be found in the bytecode."""
    bc = JUMPDEST() + PUSH4(int(SEL_PERMIT, 16)) + RETURN_()
    sels = find_selectors(bc)
    assert SEL_PERMIT in sels, f"permit selector not found; got: {list(sels.keys())}"
    print("  ✓ test_find_selectors")


def test_has_ecrecover_near():
    """ecrecover precompile (PUSH20 0x00...01 followed by STATICCALL) should be detected."""
    # Build: PUSH20(0x01) + PUSH1 0x00 + PUSH1 0x00 + STATICCALL
    bc = (
        PUSH20("0000000000000000000000000000000000000001")
        + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0)
        + bytes([STATICCALL])
    )
    found, off = has_ecrecover_near(bc, 0, 200)
    assert found, f"ecrecover not detected; raw hex: {bc.hex()}"
    print("  ✓ test_has_ecrecover_near")


def test_has_nonce_increment_near():
    """An SLOAD followed by SSTORE within the window should be detected as nonce increment."""
    # Build: SLOAD + SSTORE within 50 bytes
    bc = JUMPDEST() + bytes([SLOAD]) + bytes([0x00] * 10) + bytes([SSTORE]) + RETURN_()
    found, sload_off, sstore_off = has_nonce_increment_near(bc, 0, 200)
    assert found, f"SLOAD→SSTORE not detected"
    assert sstore_off > sload_off
    print("  ✓ test_has_nonce_increment_near")


def test_no_nonce_increment():
    """If there's no SLOAD→SSTORE pair, the check should fail."""
    # Just a SSTORE without a preceding SLOAD
    bc = JUMPDEST() + bytes([SSTORE]) + RETURN_()
    found, _, _ = has_nonce_increment_near(bc, 0, 200)
    assert not found, f"SSTORE without SLOAD wrongly detected as nonce increment"
    print("  ✓ test_no_nonce_increment")


def test_audit_permit_correct():
    """A correct EIP-2612 implementation should pass all 8 checks."""
    s = EIP2612_TYPEHASH.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x71]) + s[64:82]
    )
    # Build the ecrecover call: PUSH20 0x01 + stack setup + STATICCALL
    ecrecover_call = (
        PUSH20("0000000000000000000000000000000000000001")
        + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0)
        + bytes([STATICCALL])
    )
    # Build the permit function: PUSH4 permit selector + nonces++ + ecrecover + EQ + TIMESTAMP
    bc = (
        bytes([0x63]) + b"\xd5\x05\xac\xcf"  # PUSH4 permit selector
        + bytes([SLOAD]) + bytes([0x60, 0x01]) + bytes([0x01]) + bytes([SSTORE])
        + ecrecover_call
        + bytes([EQ])
        + bytes([TIMESTAMP])
        + RETURN_()
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c1 = next(c for c in result["checks"] if c["id"] == 1)
    assert c1["verdict"] == "PASS", f"check 1 should PASS, got {c1['verdict']}: {c1['evidence']}"
    c4 = next(c for c in result["checks"] if c["id"] == 4)
    assert c4["verdict"] == "PASS", f"check 4 should PASS, got {c4['verdict']}: {c4['evidence']}"
    c5 = next(c for c in result["checks"] if c["id"] == 5)
    assert c5["verdict"] == "PASS", f"check 5 should PASS, got {c5['verdict']}: {c5['evidence']}"
    print("  ✓ test_audit_permit_correct")


def test_audit_no_permit():
    """A contract without permit() should be NOT_FOUND for check 1."""
    bc = JUMPDEST() + bytes([STOP])
    result = audit("0x" + bc.hex(), contract="0xtest")
    c1 = next(c for c in result["checks"] if c["id"] == 1)
    assert c1["verdict"] == "NOT_FOUND", f"check 1 should NOT_FOUND, got {c1['verdict']}"
    assert result["verdict"] == "NOT_EIP2612"
    assert result["overall_score"] == 0
    print("  ✓ test_audit_no_permit")


def test_audit_missing_ecrecover():
    """A permit() function without ecrecover should FAIL check 5."""
    bc = (
        bytes([0x63]) + b"\xd5\x05\xac\xcf"  # PUSH4 permit selector
        + bytes([SLOAD]) + bytes([SSTORE])
        + RETURN_()
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c5 = next(c for c in result["checks"] if c["id"] == 5)
    assert c5["verdict"] == "FAIL", f"check 5 should FAIL, got {c5['verdict']}: {c5['evidence']}"
    print("  ✓ test_audit_missing_ecrecover")


def test_audit_no_nonce_increment():
    """A permit() function without nonce increment should FAIL check 6."""
    ecrecover_call = (
        PUSH20("0000000000000000000000000000000000000001")
        + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0)
        + bytes([STATICCALL])
    )
    bc = (
        bytes([0x63]) + b"\xd5\x05\xac\xcf"
        + ecrecover_call
        + bytes([EQ]) + bytes([TIMESTAMP])
        + RETURN_()
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c6 = next(c for c in result["checks"] if c["id"] == 6)
    assert c6["verdict"] == "FAIL", f"check 6 should FAIL, got {c6['verdict']}: {c6['evidence']}"
    print("  ✓ test_audit_no_nonce_increment")


def test_audit_no_deadline_check():
    """A permit() function without TIMESTAMP should FAIL check 7."""
    bc = (
        bytes([0x63]) + b"\xd5\x05\xac\xcf"
        + bytes([SLOAD]) + bytes([SSTORE])
        + bytes([EQ])
        + RETURN_()
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c7 = next(c for c in result["checks"] if c["id"] == 7)
    assert c7["verdict"] == "FAIL", f"check 7 should FAIL, got {c7['verdict']}: {c7['evidence']}"
    print("  ✓ test_audit_no_deadline_check")


def test_overall_score_all_pass():
    """When all critical checks PASS, overall should be 100."""
    s = EIP2612_TYPEHASH.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x71]) + s[64:82]
    )
    ecrecover_call = (
        PUSH20("0000000000000000000000000000000000000001")
        + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0) + PUSH1(0)
        + bytes([STATICCALL])
    )
    # Build the bytecode in a way that avoids PUSH-data hiding critical opcodes.
    # Selectors are emitted as PUSH4 <4 bytes> by Solidity, NOT raw 4 bytes.
    bc = (
        bytes([0x63]) + b"\xd5\x05\xac\xcf"  # PUSH4 permit selector
        + bytes([0x63]) + b"\x7e\xce\xbe\x00"  # PUSH4 nonces selector
        + bytes([0x63]) + b"\x36\x44\xe5\x15"  # PUSH4 DOMAIN_SEPARATOR selector
        # JUMPDEST marks the actual function start
        + JUMPDEST()
        # nonces[owner]++ pattern: SLOAD + ADD + SSTORE
        + bytes([SLOAD]) + bytes([0x60, 0x01]) + bytes([0x01]) + bytes([SSTORE])
        # ecrecover call
        + ecrecover_call
        # owner EQ check
        + bytes([EQ])
        # TIMESTAMP for deadline check
        + bytes([TIMESTAMP])
        + RETURN_()
        # The Permit type-hash literal
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    assert result["overall_score"] == 100, f"expected 100, got {result['overall_score']}; checks: {[(c['id'], c['verdict']) for c in result['checks']]}"
    print("  ✓ test_overall_score_all_pass")


def test_severity_label_thresholds():
    from audit import sev_label
    assert sev_label(0)   == "NOT EIP-2612"
    assert sev_label(30)  == "LOW"
    assert sev_label(31)  == "MEDIUM"
    assert sev_label(60)  == "MEDIUM"
    assert sev_label(61)  == "HIGH"
    assert sev_label(80)  == "HIGH"
    assert sev_label(81)  == "CRITICAL"
    assert sev_label(100) == "CRITICAL"
    print("  ✓ test_severity_label_thresholds")


# ----- runner -----

if __name__ == "__main__":
    tests = [
        test_extract_string_literal_permit_typehash,
        test_extract_skips_non_printable_push,
        test_find_selectors,
        test_has_ecrecover_near,
        test_has_nonce_increment_near,
        test_no_nonce_increment,
        test_audit_permit_correct,
        test_audit_no_permit,
        test_audit_missing_ecrecover,
        test_audit_no_nonce_increment,
        test_audit_no_deadline_check,
        test_overall_score_all_pass,
        test_severity_label_thresholds,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {t.__name__} — {e}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {t.__name__} — EXCEPTION: {e}")
    print(f"\n{len(tests) - failed} test(s) passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
