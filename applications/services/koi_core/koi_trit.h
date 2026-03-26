// applications/services/koi_core/koi_trit.h
#pragma once

#include <stdint.h>
#include <stdbool.h>

// ---------------------------------------------------------------------------
// Ternary trit type: {-1, 0, +1}
// ---------------------------------------------------------------------------
typedef int8_t trit_t;

#define TRIT_DENY    ((trit_t)-1)
#define TRIT_NEUTRAL ((trit_t) 0)
#define TRIT_ALLOW   ((trit_t)+1)

// ---------------------------------------------------------------------------
// Device state vector — 9 trit_t fields, 9 bytes total
// Field order is canonical: changing it breaks policy files and bit-packing.
// ---------------------------------------------------------------------------
typedef struct {
    trit_t network_trust;  // -1=hostile,       0=unknown,   +1=tailscale_peer
    trit_t vault_access;   // -1=locked,         0=read_only, +1=full
    trit_t radio_policy;   // -1=suppress,       0=listen,    +1=transmit
    trit_t app_permission; // -1=blocked,        0=sandboxed, +1=privileged
    trit_t inference_mode; // -1=reject,         0=cache,     +1=process
    trit_t mesh_relay;     // -1=drop,           0=buffer,    +1=forward
    trit_t data_class;     // -1=private,        0=internal,  +1=public
    trit_t power_state;    // -1=shed,           0=idle,      +1=active
    trit_t identity;       // -1=anonymous,      0=pseudonymous,+1=identified
} koi_state_t;

#define KOI_STATE_FIELD_COUNT 9

// Field indices — use these instead of magic numbers
#define KOI_FIELD_NETWORK_TRUST  0
#define KOI_FIELD_VAULT_ACCESS   1
#define KOI_FIELD_RADIO_POLICY   2
#define KOI_FIELD_APP_PERMISSION 3
#define KOI_FIELD_INFERENCE_MODE 4
#define KOI_FIELD_MESH_RELAY     5
#define KOI_FIELD_DATA_CLASS     6
#define KOI_FIELD_POWER_STATE    7
#define KOI_FIELD_IDENTITY       8

// ---------------------------------------------------------------------------
// Policy domains
// ---------------------------------------------------------------------------
#define KOI_DOMAIN_RF    0
#define KOI_DOMAIN_BLE   1
#define KOI_DOMAIN_VAULT 2
#define KOI_DOMAIN_MESH  3
#define KOI_DOMAIN_APP   4
#define KOI_DOMAIN_COUNT 5

// ---------------------------------------------------------------------------
// Policy rule combining algorithms
// ---------------------------------------------------------------------------
#define KOI_COMBINING_DENY_OVERRIDE    0  // MIN — any DENY overrides
#define KOI_COMBINING_PERMIT_OVERRIDE  1  // MAX — any ALLOW overrides
#define KOI_COMBINING_FIRST_APPLICABLE 2  // First matching rule wins
#define KOI_COMBINING_CONSENSUS        3  // sign(sum of results)

// ---------------------------------------------------------------------------
// Policy rule — 11 bytes packed.
// input_trits packs 2 bits per koi_state_t field (fields 0..8).
// Encoding: 00=unused, 01=DENY(-1), 10=NEUTRAL(0), 11=ALLOW(+1)
// input_mask: bit i = 1 means field i is required to match.
// ---------------------------------------------------------------------------
typedef struct __attribute__((packed)) {
    uint16_t input_mask;     // 9-bit bitmask over koi_state_t fields
    uint8_t  input_trits[3]; // 2 bits × 12 capacity (9 used)
    uint16_t flags;          // reserved for time-conditions, user-override
    uint8_t  domain;         // KOI_DOMAIN_*
    uint8_t  combining;      // KOI_COMBINING_*
    int8_t   result;         // TRIT_DENY, TRIT_NEUTRAL, or TRIT_ALLOW
    uint8_t  priority;       // evaluation order (lower = first)
} TritRule; // 11 bytes
