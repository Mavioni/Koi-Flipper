#include "koi_audit.h"

#include <furi.h>
#include <storage/storage.h>
#include <stdlib.h>

struct KoiAudit {
    AuditEntry entries[KOI_AUDIT_CAPACITY];
    uint8_t head;   // index of the NEXT write slot
    uint8_t count;  // 0..KOI_AUDIT_CAPACITY
};

KoiAudit* koi_audit_alloc(void) {
    KoiAudit* a = malloc(sizeof(KoiAudit));
    if(a) {
        a->head = 0;
        a->count = 0;
    }
    return a;
}

void koi_audit_free(KoiAudit* audit) {
    free(audit);
}

static uint8_t koi_state_hash(const koi_state_t* state) {
    const uint8_t* b = (const uint8_t*)state;
    uint8_t h = 0;
    for(uint8_t i = 0; i < KOI_STATE_FIELD_COUNT; i++) h ^= b[i];
    return h;
}

void koi_audit_append(KoiAudit* audit, uint8_t domain, trit_t result, const koi_state_t* state) {
    furi_assert(audit != NULL);
    furi_assert(state != NULL);
    AuditEntry* e = &audit->entries[audit->head];
    e->tick       = (uint32_t)furi_get_tick();
    e->domain     = domain;
    e->result     = result;
    e->state_hash = koi_state_hash(state);
    e->_pad       = 0;
    audit->head = (uint8_t)((audit->head + 1u) % KOI_AUDIT_CAPACITY);
    if(audit->count < KOI_AUDIT_CAPACITY) audit->count++;
}

uint8_t koi_audit_count(const KoiAudit* audit) {
    furi_assert(audit != NULL);
    return audit->count;
}

const AuditEntry* koi_audit_get(const KoiAudit* audit, uint8_t index) {
    furi_assert(audit != NULL);
    if(index >= audit->count) return NULL;
    // head points to next write slot = oldest slot when full
    // index 0 (newest) = head-1, index 1 = head-2, etc.
    int16_t raw = (int16_t)audit->head - 1 - (int16_t)index;
    if(raw < 0) raw += KOI_AUDIT_CAPACITY;
    return &audit->entries[(uint8_t)raw];
}

bool koi_audit_flush(KoiAudit* audit, const char* path) {
    furi_assert(audit != NULL);
    furi_assert(path != NULL);
    if(audit->count == 0) return true;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);
    bool ok = false;

    if(storage_file_open(f, path, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        uint8_t written = 0;
        // Write oldest-first (highest recency index first)
        for(uint8_t i = audit->count; i > 0; i--) {
            const AuditEntry* e = koi_audit_get(audit, (uint8_t)(i - 1));
            if(storage_file_write(f, e, sizeof(AuditEntry)) == sizeof(AuditEntry)) written++;
        }
        ok = (written == audit->count);
    }

    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    if(ok) {
        audit->head = 0;
        audit->count = 0;
    }
    return ok;
}
