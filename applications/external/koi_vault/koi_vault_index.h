#pragma once
#include "koi_vault_crypto.h"
#include "koi_vault_storage.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KOI_INDEX_NAME_MAX    32
#define KOI_INDEX_MAX_ENTRIES 195
#define KOI_INDEX_CACHE_SIZE  8192
#define KOI_INDEX_ENTRY_SIZE  42
#define KOI_INDEX_START_SECTOR 0
#define KOI_INDEX_MAX_SECTORS  16

typedef struct {
    char     name[KOI_INDEX_NAME_MAX];
    uint16_t chunk_index;
    uint32_t offset;
    uint32_t size;
} KoiVaultIndexEntry;

typedef struct {
    KoiVaultIndexEntry entries[KOI_INDEX_MAX_ENTRIES];
    uint16_t count;
    bool dirty;
} KoiVaultIndex;

void koi_vault_index_init(KoiVaultIndex* index);
bool koi_vault_index_load(KoiVaultIndex* index, KoiVaultStorage* store, KoiVaultCrypto* crypto, uint8_t vault_id);
bool koi_vault_index_save(KoiVaultIndex* index, KoiVaultStorage* store, KoiVaultCrypto* crypto, uint8_t vault_id);
const KoiVaultIndexEntry* koi_vault_index_find(const KoiVaultIndex* index, const char* name);
KoiVaultIndexEntry* koi_vault_index_add(KoiVaultIndex* index, const char* name);
bool koi_vault_index_remove(KoiVaultIndex* index, const char* name);
uint16_t koi_vault_index_count(const KoiVaultIndex* index);
const KoiVaultIndexEntry* koi_vault_index_get(const KoiVaultIndex* index, uint16_t pos);

#ifdef __cplusplus
}
#endif
