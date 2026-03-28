#pragma once

#include "koi_trit.h"
#include <stdint.h>
#include <stdbool.h>

#define KOI_AUDIT_CAPACITY 128

typedef struct {
    uint32_t tick;       // furi_get_tick() at decision time
    uint8_t  domain;     // KOI_DOMAIN_*
    int8_t   result;     // TRIT_DENY, TRIT_NEUTRAL, or TRIT_ALLOW
    uint8_t  state_hash; // XOR fold of koi_state_t bytes for quick diffing
    uint8_t  _pad;       // padding to 8 bytes
} AuditEntry; // 8 bytes exactly

typedef struct KoiAudit KoiAudit;

/** Allocate an empty audit ring buffer. Returns NULL on OOM. */
KoiAudit* koi_audit_alloc(void);

/** Free the audit ring buffer. */
void koi_audit_free(KoiAudit* audit);

/** Append a decision to the ring buffer. Overwrites oldest entry if full. */
void koi_audit_append(KoiAudit* audit, uint8_t domain, trit_t result, const koi_state_t* state);

/** Number of entries currently stored (0..KOI_AUDIT_CAPACITY). */
uint8_t koi_audit_count(const KoiAudit* audit);

/**
 * Get an entry by recency index. Index 0 = most recent, 1 = second-most recent, etc.
 * Returns NULL if index >= count.
 */
const AuditEntry* koi_audit_get(const KoiAudit* audit, uint8_t index);

/**
 * Flush all entries oldest-first to an append-only log file on SD card.
 * Clears the ring buffer after successful flush. Returns true on success.
 */
bool koi_audit_flush(KoiAudit* audit, const char* path);
