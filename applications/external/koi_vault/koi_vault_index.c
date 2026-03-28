#include "koi_vault_index.h"
#include "lib/crypto/memzero.h"
#include <string.h>
#include <furi.h>

#define TAG "KoiVaultIndex"

void koi_vault_index_init(KoiVaultIndex* index) {
    memset(index, 0, sizeof(KoiVaultIndex));
    index->count = 0;
    index->dirty = false;
}

static size_t koi_vault_index_serialize(const KoiVaultIndex* index, uint8_t* buf, size_t buf_len) {
    if(buf_len < 2) return 0;
    buf[0] = (uint8_t)(index->count & 0xFF);
    buf[1] = (uint8_t)((index->count >> 8) & 0xFF);
    size_t pos = 2;
    for(uint16_t i = 0; i < index->count; i++) {
        if(pos + KOI_INDEX_ENTRY_SIZE > buf_len) break;
        const KoiVaultIndexEntry* e = &index->entries[i];
        memcpy(buf + pos, e->name, KOI_INDEX_NAME_MAX); pos += KOI_INDEX_NAME_MAX;
        buf[pos++] = (uint8_t)(e->chunk_index & 0xFF);
        buf[pos++] = (uint8_t)((e->chunk_index >> 8) & 0xFF);
        buf[pos++] = (uint8_t)(e->offset & 0xFF);
        buf[pos++] = (uint8_t)((e->offset >> 8) & 0xFF);
        buf[pos++] = (uint8_t)((e->offset >> 16) & 0xFF);
        buf[pos++] = (uint8_t)((e->offset >> 24) & 0xFF);
        buf[pos++] = (uint8_t)(e->size & 0xFF);
        buf[pos++] = (uint8_t)((e->size >> 8) & 0xFF);
        buf[pos++] = (uint8_t)((e->size >> 16) & 0xFF);
        buf[pos++] = (uint8_t)((e->size >> 24) & 0xFF);
    }
    return pos;
}

static bool koi_vault_index_deserialize(KoiVaultIndex* index, const uint8_t* buf, size_t buf_len) {
    if(buf_len < 2) return false;
    uint16_t count = (uint16_t)(buf[0] | (buf[1] << 8));
    if(count > KOI_INDEX_MAX_ENTRIES) return false;
    size_t pos = 2;
    for(uint16_t i = 0; i < count; i++) {
        if(pos + KOI_INDEX_ENTRY_SIZE > buf_len) return false;
        KoiVaultIndexEntry* e = &index->entries[i];
        memcpy(e->name, buf + pos, KOI_INDEX_NAME_MAX);
        e->name[KOI_INDEX_NAME_MAX - 1] = '\0';
        pos += KOI_INDEX_NAME_MAX;
        e->chunk_index = (uint16_t)(buf[pos] | (buf[pos+1] << 8)); pos += 2;
        e->offset = (uint32_t)(buf[pos] | (buf[pos+1]<<8) | (buf[pos+2]<<16) | (buf[pos+3]<<24)); pos += 4;
        e->size = (uint32_t)(buf[pos] | (buf[pos+1]<<8) | (buf[pos+2]<<16) | (buf[pos+3]<<24)); pos += 4;
    }
    index->count = count;
    index->dirty = false;
    return true;
}

bool koi_vault_index_load(KoiVaultIndex* index, KoiVaultStorage* store, KoiVaultCrypto* crypto, uint8_t vault_id) {
    uint8_t cache[KOI_INDEX_CACHE_SIZE];
    memset(cache, 0, sizeof(cache));
    for(uint8_t s = 0; s < KOI_INDEX_MAX_SECTORS; s++) {
        uint8_t encrypted[KOI_VAULT_SECTOR_SIZE];
        if(!koi_vault_storage_read_sector(store, vault_id, (uint64_t)(KOI_INDEX_START_SECTOR + s), encrypted)) {
            if(s == 0) { koi_vault_index_init(index); return true; }
            break;
        }
        if(!koi_vault_crypto_decrypt_sector(crypto, (uint64_t)(KOI_INDEX_START_SECTOR + s), encrypted, cache + s * KOI_VAULT_SECTOR_SIZE)) {
            FURI_LOG_E(TAG, "Failed to decrypt index sector %d", s);
            return false;
        }
    }
    bool ok = koi_vault_index_deserialize(index, cache, sizeof(cache));
    memzero(cache, sizeof(cache));
    return ok;
}

bool koi_vault_index_save(KoiVaultIndex* index, KoiVaultStorage* store, KoiVaultCrypto* crypto, uint8_t vault_id) {
    uint8_t cache[KOI_INDEX_CACHE_SIZE];
    memset(cache, 0, sizeof(cache));
    size_t used = koi_vault_index_serialize(index, cache, sizeof(cache));
    uint8_t sectors_needed = (uint8_t)((used + KOI_VAULT_SECTOR_SIZE - 1) / KOI_VAULT_SECTOR_SIZE);
    if(sectors_needed > KOI_INDEX_MAX_SECTORS) sectors_needed = KOI_INDEX_MAX_SECTORS;
    for(uint8_t s = 0; s < sectors_needed; s++) {
        uint8_t encrypted[KOI_VAULT_SECTOR_SIZE];
        if(!koi_vault_crypto_encrypt_sector(crypto, (uint64_t)(KOI_INDEX_START_SECTOR + s), cache + s * KOI_VAULT_SECTOR_SIZE, encrypted)) {
            memzero(cache, sizeof(cache)); return false;
        }
        if(!koi_vault_storage_write_sector(store, vault_id, (uint64_t)(KOI_INDEX_START_SECTOR + s), encrypted)) {
            memzero(cache, sizeof(cache)); return false;
        }
    }
    memzero(cache, sizeof(cache));
    index->dirty = false;
    return true;
}

const KoiVaultIndexEntry* koi_vault_index_find(const KoiVaultIndex* index, const char* name) {
    for(uint16_t i = 0; i < index->count; i++) {
        if(strncmp(index->entries[i].name, name, KOI_INDEX_NAME_MAX) == 0) return &index->entries[i];
    }
    return NULL;
}

KoiVaultIndexEntry* koi_vault_index_add(KoiVaultIndex* index, const char* name) {
    if(index->count >= KOI_INDEX_MAX_ENTRIES) return NULL;
    if(koi_vault_index_find(index, name) != NULL) return NULL;
    KoiVaultIndexEntry* e = &index->entries[index->count];
    memset(e, 0, sizeof(KoiVaultIndexEntry));
    strncpy(e->name, name, KOI_INDEX_NAME_MAX - 1);
    index->count++;
    index->dirty = true;
    return e;
}

bool koi_vault_index_remove(KoiVaultIndex* index, const char* name) {
    for(uint16_t i = 0; i < index->count; i++) {
        if(strncmp(index->entries[i].name, name, KOI_INDEX_NAME_MAX) == 0) {
            if(i + 1 < index->count) {
                memmove(&index->entries[i], &index->entries[i+1], (index->count - i - 1) * sizeof(KoiVaultIndexEntry));
            }
            index->count--;
            memset(&index->entries[index->count], 0, sizeof(KoiVaultIndexEntry));
            index->dirty = true;
            return true;
        }
    }
    return false;
}

uint16_t koi_vault_index_count(const KoiVaultIndex* index) { return index->count; }

const KoiVaultIndexEntry* koi_vault_index_get(const KoiVaultIndex* index, uint16_t pos) {
    if(pos >= index->count) return NULL;
    return &index->entries[pos];
}
