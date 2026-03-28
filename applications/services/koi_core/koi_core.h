#pragma once

#include "koi_trit.h"
#include "koi_audit.h"
#include <furi.h>

#define RECORD_KOI_CORE "koi_core"

#define KOI_GOVERNANCE_DIR  "/ext/governance"
#define KOI_AUDIT_LOG_PATH  "/ext/governance/audit.log"
#define KOI_RULE_CAPACITY   256

/**
 * KoiCoreApi — vtable for the koi_core service.
 *
 * External FAPs access the governance engine through this struct:
 *   KoiCoreApi* api = furi_record_open(RECORD_KOI_CORE);
 *   trit_t result = api->evaluate(api, KOI_DOMAIN_RF);
 *
 * Function pointers avoid SDK symbol export issues with the
 * RogueMaster build system.
 */
typedef struct KoiCoreApi KoiCoreApi;

struct KoiCoreApi {
    /** Evaluate governance decision for a domain. Thread-safe. */
    trit_t (*evaluate)(KoiCoreApi* api, uint8_t domain);

    /** Get snapshot of current state vector. Thread-safe. */
    koi_state_t (*get_state)(KoiCoreApi* api);

    /** Update a single state field. Thread-safe. Broadcasts on PubSub. */
    void (*set_state_field)(KoiCoreApi* api, uint8_t field_index, trit_t value);

    /** Get PubSub handle for governance events. */
    FuriPubSub* (*get_pubsub)(KoiCoreApi* api);

    /** Reload policy for a domain from a .trit file. */
    bool (*reload_policy)(KoiCoreApi* api, uint8_t domain, const char* path);

    /** Get the audit log handle (read-only). */
    const KoiAudit* (*get_audit)(KoiCoreApi* api);

    /** Get audit entry count. */
    uint8_t (*audit_count)(KoiCoreApi* api);

    /** Get audit entry by recency index (0 = newest). */
    const AuditEntry* (*audit_get)(KoiCoreApi* api, uint8_t index);

    // Private — do not access from external FAPs
    void* _private;
};
