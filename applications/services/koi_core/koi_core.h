#pragma once

#include "koi_trit.h"
#include "koi_audit.h"
#include <furi.h>

#define RECORD_KOI_CORE "koi_core"

#define KOI_GOVERNANCE_DIR "/ext/governance"
#define KOI_AUDIT_LOG_PATH "/ext/governance/audit.log"
#define KOI_RULE_CAPACITY  256

typedef struct KoiCore KoiCore;

/**
 * Evaluate a governance decision for the given domain against the
 * service's current state. Returns TRIT_DENY if koi_core is unavailable.
 * Thread-safe (uses a FuriMutex).
 */
trit_t koi_core_evaluate(KoiCore* core, uint8_t domain);

/**
 * Get a snapshot of the current koi_state_t.
 * Thread-safe.
 */
koi_state_t koi_core_get_state(KoiCore* core);

/**
 * Update a single state field and broadcast a FuriPubSub event.
 * Thread-safe.
 */
void koi_core_set_state_field(KoiCore* core, uint8_t field_index, trit_t value);

/**
 * Subscribe to governance events (state changes, policy reloads).
 * Callback is called from the koi_core service thread — keep it fast.
 */
FuriPubSub* koi_core_get_pubsub(KoiCore* core);

/**
 * Reload policy for a single domain from a .trit file.
 * Replaces existing rules for that domain atomically.
 * Fails-closed on CRC error.
 */
bool koi_core_reload_policy(KoiCore* core, uint8_t domain, const char* path);

/** Get the audit log handle for read access from the governance FAP. */
const KoiAudit* koi_core_get_audit(KoiCore* core);
