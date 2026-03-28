#include "koi_core.h"
#include "koi_policy.h"
#include "koi_policy_file.h"
#include "koi_audit.h"

#include <furi.h>
#include <storage/storage.h>
#include <string.h>
#include <stdio.h>

#define TAG "KoiCore"

static const char* KOI_POLICY_PATHS[KOI_DOMAIN_COUNT] = {
    KOI_GOVERNANCE_DIR "/rf.trit",
    KOI_GOVERNANCE_DIR "/ble.trit",
    KOI_GOVERNANCE_DIR "/vault.trit",
    KOI_GOVERNANCE_DIR "/mesh.trit",
    KOI_GOVERNANCE_DIR "/app.trit",
};

typedef struct {
    TritRule    rules[KOI_RULE_CAPACITY];
    uint8_t     rule_count;
    koi_state_t state;
    FuriMutex*  mutex;
    FuriPubSub* pubsub;
    KoiAudit*   audit;
} KoiCore;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static void koi_core_load_all_policies(KoiCore* core) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(storage, KOI_GOVERNANCE_DIR);
    furi_record_close(RECORD_STORAGE);

    core->rule_count = 0;
    for(uint8_t domain = 0; domain < KOI_DOMAIN_COUNT; domain++) {
        uint8_t loaded = 0;
        KoiPolicyFileError err = koi_policy_file_load(
            KOI_POLICY_PATHS[domain],
            domain,
            core->rules + core->rule_count,
            (uint8_t)(KOI_RULE_CAPACITY - core->rule_count),
            &loaded);

        if(err == KOI_POLICY_FILE_OK) {
            core->rule_count += loaded;
            FURI_LOG_I(TAG, "Loaded %d rules for domain %d", loaded, domain);
        } else if(err == KOI_POLICY_FILE_IO_ERROR) {
            // No file yet — fail-closed by default
            FURI_LOG_W(TAG, "No policy file for domain %d (fail-closed)", domain);
        } else {
            // CRC fail, bad magic, etc. — log loudly, fail-closed
            FURI_LOG_E(TAG, "Policy domain %d integrity error: %d (fail-closed)", domain, err);
        }
    }
}

// ---------------------------------------------------------------------------
// Vtable function implementations
// ---------------------------------------------------------------------------

static trit_t koi_core_api_evaluate(KoiCoreApi* api, uint8_t domain) {
    KoiCore* core = (KoiCore*)api->_private;
    furi_mutex_acquire(core->mutex, FuriWaitForever);
    trit_t result = koi_policy_evaluate(core->rules, core->rule_count, domain, &core->state);
    koi_audit_append(core->audit, domain, result, &core->state);
    furi_mutex_release(core->mutex);
    return result;
}

static koi_state_t koi_core_api_get_state(KoiCoreApi* api) {
    KoiCore* core = (KoiCore*)api->_private;
    furi_mutex_acquire(core->mutex, FuriWaitForever);
    koi_state_t s = core->state;
    furi_mutex_release(core->mutex);
    return s;
}

static void koi_core_api_set_state_field(KoiCoreApi* api, uint8_t field_index, trit_t value) {
    KoiCore* core = (KoiCore*)api->_private;
    if(field_index >= KOI_STATE_FIELD_COUNT) return;
    furi_mutex_acquire(core->mutex, FuriWaitForever);
    ((trit_t*)&core->state)[field_index] = value;
    furi_pubsub_publish(core->pubsub, &core->state);
    furi_mutex_release(core->mutex);
}

static FuriPubSub* koi_core_api_get_pubsub(KoiCoreApi* api) {
    KoiCore* core = (KoiCore*)api->_private;
    return core->pubsub;
}

static bool koi_core_api_reload_policy(KoiCoreApi* api, uint8_t domain, const char* path) {
    KoiCore* core = (KoiCore*)api->_private;
    TritRule new_rules[64];
    uint8_t new_count = 0;
    KoiPolicyFileError err = koi_policy_file_load(path, domain, new_rules, 64, &new_count);
    if(err != KOI_POLICY_FILE_OK) return false;

    furi_mutex_acquire(core->mutex, FuriWaitForever);
    // Compact out old rules for this domain
    uint16_t write = 0;
    for(uint8_t i = 0; i < core->rule_count; i++) {
        if(core->rules[i].domain != domain) {
            core->rules[write++] = core->rules[i];
        }
    }
    // Append new rules
    for(uint8_t i = 0; i < new_count && write < (uint16_t)KOI_RULE_CAPACITY; i++) {
        core->rules[write++] = new_rules[i];
    }
    core->rule_count = write;
    furi_mutex_release(core->mutex);
    return true;
}

static const KoiAudit* koi_core_api_get_audit(KoiCoreApi* api) {
    KoiCore* core = (KoiCore*)api->_private;
    return core->audit;
}

static uint8_t koi_core_api_audit_count(KoiCoreApi* api) {
    KoiCore* core = (KoiCore*)api->_private;
    return koi_audit_count(core->audit);
}

static const AuditEntry* koi_core_api_audit_get(KoiCoreApi* api, uint8_t index) {
    KoiCore* core = (KoiCore*)api->_private;
    return koi_audit_get(core->audit, index);
}

// ---------------------------------------------------------------------------
// Static vtable instance
// ---------------------------------------------------------------------------

static KoiCoreApi koi_api;

// ---------------------------------------------------------------------------
// Service task
// ---------------------------------------------------------------------------

static int32_t koi_core_task(void* p) {
    UNUSED(p);

    KoiCore* core = malloc(sizeof(KoiCore));
    furi_check(core != NULL);

    core->rule_count = 0;
    memset(&core->state, 0, sizeof(koi_state_t));
    core->mutex  = furi_mutex_alloc(FuriMutexTypeNormal);
    core->pubsub = furi_pubsub_alloc();
    core->audit  = koi_audit_alloc();

    koi_core_load_all_policies(core);

    // Wire up vtable
    koi_api.evaluate        = koi_core_api_evaluate;
    koi_api.get_state       = koi_core_api_get_state;
    koi_api.set_state_field = koi_core_api_set_state_field;
    koi_api.get_pubsub      = koi_core_api_get_pubsub;
    koi_api.reload_policy   = koi_core_api_reload_policy;
    koi_api.get_audit       = koi_core_api_get_audit;
    koi_api.audit_count     = koi_core_api_audit_count;
    koi_api.audit_get       = koi_core_api_audit_get;
    koi_api._private        = core;

    furi_record_create(RECORD_KOI_CORE, &koi_api);
    FURI_LOG_I(TAG, "koi_core ready: %d rules loaded", core->rule_count);

    // Flush audit log every 60 seconds
    while(true) {
        furi_delay_ms(60000);
        furi_mutex_acquire(core->mutex, FuriWaitForever);
        koi_audit_flush(core->audit, KOI_AUDIT_LOG_PATH);
        furi_mutex_release(core->mutex);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Service entry point
// ---------------------------------------------------------------------------

void koi_core_on_system_start(void) {
    FuriThread* thread = furi_thread_alloc_ex(
        "KoiCoreSrv", 3 * 1024, koi_core_task, NULL);
    furi_thread_set_priority(thread, FuriThreadPriorityLow);
    furi_thread_start(thread);
}
