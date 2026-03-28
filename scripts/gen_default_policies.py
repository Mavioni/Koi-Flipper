#!/usr/bin/env python3
"""Generate default Koi governance policy files (.trit binary format).

Usage:
    python3 scripts/gen_default_policies.py assets/default_policies/
"""

import struct
import sys
import os

# Policy file format constants
MAGIC   = b'TRIT'
VERSION = 1

# Domain indices (match koi_trit.h)
DOMAIN_RF    = 0
DOMAIN_BLE   = 1
DOMAIN_VAULT = 2
DOMAIN_MESH  = 3
DOMAIN_APP   = 4

# Combining algorithms
DENY_OVERRIDE    = 0
PERMIT_OVERRIDE  = 1
FIRST_APPLICABLE = 2
CONSENSUS        = 3

# koi_state_t field indices
F_NETWORK_TRUST  = 0
F_VAULT_ACCESS   = 1
F_RADIO_POLICY   = 2
F_APP_PERMISSION = 3
F_INFERENCE_MODE = 4
F_MESH_RELAY     = 5
F_DATA_CLASS     = 6
F_POWER_STATE    = 7
F_IDENTITY       = 8

TRIT_DENY    = -1
TRIT_NEUTRAL =  0
TRIT_ALLOW   =  1


def encode_trit(t: int) -> int:
    """Encode a trit value to 2-bit field encoding (01=DENY, 10=NEUTRAL, 11=ALLOW)."""
    if t < 0:  return 0b01
    if t > 0:  return 0b11
    return      0b10


def build_rule(domain, result, combining, priority=0, conditions=None, flags=0):
    """
    Build an 11-byte packed TritRule.

    conditions: dict mapping field_index -> trit_value for required state fields.
    """
    conditions = conditions or {}
    input_mask = 0
    input_trits = bytearray(3)

    for field_idx, trit_val in conditions.items():
        input_mask |= (1 << field_idx)
        bit_pos  = field_idx * 2
        byte_idx = bit_pos // 8
        bit_idx  = bit_pos % 8
        input_trits[byte_idx] |= encode_trit(trit_val) << bit_idx

    # TritRule packed struct (11 bytes):
    # uint16_t input_mask
    # uint8_t  input_trits[3]
    # uint16_t flags
    # uint8_t  domain
    # uint8_t  combining
    # int8_t   result
    # uint8_t  priority
    return struct.pack('<H3sHBBbB',
        input_mask,
        bytes(input_trits),
        flags,
        domain,
        combining,
        result,
        priority,
    )


def crc32(data: bytes) -> int:
    """Standard IEEE 802.3 CRC32 (same polynomial as zlib/koi_policy_file.c)."""
    crc = 0xFFFFFFFF
    for byte in data:
        for _ in range(8):
            if (crc ^ byte) & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
            byte >>= 1
    return crc ^ 0xFFFFFFFF


def write_policy(path: str, domain: int, rules: list):
    rule_count = len(rules)
    rule_data  = b''.join(rules)
    header = struct.pack('<4sBBH', MAGIC, VERSION, domain, rule_count)
    footer = struct.pack('<I', crc32(header + rule_data))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(header + rule_data + footer)
    total = len(header) + len(rule_data) + len(footer)
    print(f"  {path}: {rule_count} rule(s), {total} bytes")


def main(out_dir: str):
    print(f"Generating default Koi policies -> {out_dir}")

    # -------------------------------------------------------------------------
    # RF Domain — DenyOverride
    # Suppress on power-shed; allow on explicit radio_policy=+1; else listen.
    # -------------------------------------------------------------------------
    write_policy(os.path.join(out_dir, 'rf.trit'), DOMAIN_RF, [
        build_rule(DOMAIN_RF, TRIT_DENY,    DENY_OVERRIDE, priority=0,
                   conditions={F_POWER_STATE: TRIT_DENY}),
        build_rule(DOMAIN_RF, TRIT_ALLOW,   DENY_OVERRIDE, priority=1,
                   conditions={F_RADIO_POLICY: TRIT_ALLOW}),
        build_rule(DOMAIN_RF, TRIT_NEUTRAL, DENY_OVERRIDE, priority=2),
    ])

    # -------------------------------------------------------------------------
    # BLE Domain — FirstApplicable
    # Hostile → deny. Trusted tailscale peer → allow. Unknown → neutral.
    # -------------------------------------------------------------------------
    write_policy(os.path.join(out_dir, 'ble.trit'), DOMAIN_BLE, [
        build_rule(DOMAIN_BLE, TRIT_DENY,    FIRST_APPLICABLE, priority=0,
                   conditions={F_NETWORK_TRUST: TRIT_DENY}),
        build_rule(DOMAIN_BLE, TRIT_ALLOW,   FIRST_APPLICABLE, priority=1,
                   conditions={F_NETWORK_TRUST: TRIT_ALLOW}),
        build_rule(DOMAIN_BLE, TRIT_NEUTRAL, FIRST_APPLICABLE, priority=2),
    ])

    # -------------------------------------------------------------------------
    # Vault Domain — DenyOverride (unanimous permit required)
    # Locked → deny. Full access + active power → allow. Else deny.
    # -------------------------------------------------------------------------
    write_policy(os.path.join(out_dir, 'vault.trit'), DOMAIN_VAULT, [
        build_rule(DOMAIN_VAULT, TRIT_DENY,  DENY_OVERRIDE, priority=0,
                   conditions={F_VAULT_ACCESS: TRIT_DENY}),
        build_rule(DOMAIN_VAULT, TRIT_ALLOW, DENY_OVERRIDE, priority=1,
                   conditions={F_VAULT_ACCESS: TRIT_ALLOW, F_POWER_STATE: TRIT_ALLOW}),
        build_rule(DOMAIN_VAULT, TRIT_DENY,  DENY_OVERRIDE, priority=2),
    ])

    # -------------------------------------------------------------------------
    # Mesh Domain — Consensus
    # Relay only if both network_trust=+1 AND mesh_relay=+1.
    # -------------------------------------------------------------------------
    write_policy(os.path.join(out_dir, 'mesh.trit'), DOMAIN_MESH, [
        build_rule(DOMAIN_MESH, TRIT_ALLOW,   CONSENSUS, priority=0,
                   conditions={F_NETWORK_TRUST: TRIT_ALLOW, F_MESH_RELAY: TRIT_ALLOW}),
        build_rule(DOMAIN_MESH, TRIT_DENY,    CONSENSUS, priority=1,
                   conditions={F_NETWORK_TRUST: TRIT_DENY}),
        build_rule(DOMAIN_MESH, TRIT_DENY,    CONSENSUS, priority=2,
                   conditions={F_MESH_RELAY: TRIT_DENY}),
        build_rule(DOMAIN_MESH, TRIT_NEUTRAL, CONSENSUS, priority=3),
    ])

    # -------------------------------------------------------------------------
    # App Domain — FirstApplicable
    # Blocked → deny. Privileged → allow. Default → sandboxed (neutral).
    # -------------------------------------------------------------------------
    write_policy(os.path.join(out_dir, 'app.trit'), DOMAIN_APP, [
        build_rule(DOMAIN_APP, TRIT_DENY,    FIRST_APPLICABLE, priority=0,
                   conditions={F_APP_PERMISSION: TRIT_DENY}),
        build_rule(DOMAIN_APP, TRIT_ALLOW,   FIRST_APPLICABLE, priority=1,
                   conditions={F_APP_PERMISSION: TRIT_ALLOW}),
        build_rule(DOMAIN_APP, TRIT_NEUTRAL, FIRST_APPLICABLE, priority=2),
    ])

    print("Done. Deploy to Flipper SD: /ext/governance/*.trit")


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else 'assets/default_policies'
    main(out_dir)
