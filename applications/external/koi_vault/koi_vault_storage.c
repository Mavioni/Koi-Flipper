#include "koi_vault_storage.h"
#include <furi.h>
#include <storage/storage.h>
#include <string.h>
#include <stdio.h>

#define TAG "KoiVaultStorage"

struct KoiVaultStorage {
    Storage* storage;
};

KoiVaultStorage* koi_vault_storage_alloc(void) {
    KoiVaultStorage* store = malloc(sizeof(KoiVaultStorage));
    if(store) {
        store->storage = furi_record_open(RECORD_STORAGE);
    }
    return store;
}

void koi_vault_storage_free(KoiVaultStorage* store) {
    if(store) {
        furi_record_close(RECORD_STORAGE);
        free(store);
    }
}

const char* koi_vault_storage_get_dir(uint8_t vault_id) {
    return (vault_id == KOI_VAULT_ID_ALPHA) ? KOI_VAULT_ALPHA_DIR : KOI_VAULT_BETA_DIR;
}

bool koi_vault_storage_create_vault(KoiVaultStorage* store, uint8_t vault_id) {
    storage_simply_mkdir(store->storage, KOI_VAULT_BASE_DIR);
    const char* dir = koi_vault_storage_get_dir(vault_id);
    storage_simply_mkdir(store->storage, dir);
    char path[64];
    snprintf(path, sizeof(path), "%s/chunk_000.koi", dir);
    File* f = storage_file_alloc(store->storage);
    if(!storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_NEW)) {
        if(!storage_file_open(f, path, FSAM_WRITE, FSOM_OPEN_EXISTING)) {
            storage_file_free(f);
            return false;
        }
    }
    KoiVaultChunkHeader header;
    memcpy(header.magic, KOI_VAULT_CHUNK_MAGIC, 4);
    header.version = KOI_VAULT_CHUNK_VERSION;
    header.vault_id = vault_id;
    header.chunk_index = 0;
    memset(header.reserved, 0, 8);
    bool ok = (storage_file_write(f, &header, sizeof(header)) == sizeof(header));
    storage_file_close(f);
    storage_file_free(f);
    FURI_LOG_I(TAG, "Created vault %s chunk 0: %s", vault_id == 0 ? "alpha" : "beta", ok ? "ok" : "fail");
    return ok;
}

bool koi_vault_storage_write_meta(const KoiVaultMeta* meta) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(storage, KOI_VAULT_BASE_DIR);
    File* f = storage_file_alloc(storage);
    storage_simply_remove(storage, KOI_VAULT_META_PATH);
    bool ok = false;
    if(storage_file_open(f, KOI_VAULT_META_PATH, FSAM_WRITE, FSOM_CREATE_NEW)) {
        ok = (storage_file_write(f, meta, sizeof(KoiVaultMeta)) == sizeof(KoiVaultMeta));
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

bool koi_vault_storage_read_meta(KoiVaultMeta* meta) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);
    bool ok = false;
    if(storage_file_open(f, KOI_VAULT_META_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        if(storage_file_read(f, meta, sizeof(KoiVaultMeta)) == sizeof(KoiVaultMeta)) {
            ok = (memcmp(meta->magic, KOI_VAULT_META_MAGIC, 4) == 0);
        }
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static void sector_to_chunk_offset(uint64_t sector_num, uint16_t* chunk_idx, uint32_t* byte_offset) {
    uint64_t sectors_per_chunk = KOI_VAULT_SECTORS_PER_CHUNK;
    *chunk_idx = (uint16_t)(sector_num / sectors_per_chunk);
    uint64_t sector_in_chunk = sector_num % sectors_per_chunk;
    *byte_offset = (uint32_t)(KOI_VAULT_CHUNK_HEADER_SIZE + sector_in_chunk * KOI_VAULT_SECTOR_SIZE);
}

static void make_chunk_path(uint8_t vault_id, uint16_t chunk_idx, char* path, size_t path_len) {
    snprintf(path, path_len, "%s/chunk_%03u.koi",
        koi_vault_storage_get_dir(vault_id), (unsigned)chunk_idx);
}

bool koi_vault_storage_read_sector(
    KoiVaultStorage* store, uint8_t vault_id,
    uint64_t sector_num, uint8_t output[512])
{
    uint16_t chunk_idx; uint32_t byte_offset;
    sector_to_chunk_offset(sector_num, &chunk_idx, &byte_offset);
    char path[64];
    make_chunk_path(vault_id, chunk_idx, path, sizeof(path));
    File* f = storage_file_alloc(store->storage);
    bool ok = false;
    if(storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        if(storage_file_seek(f, byte_offset, true)) {
            ok = (storage_file_read(f, output, KOI_VAULT_SECTOR_SIZE) == KOI_VAULT_SECTOR_SIZE);
        }
    }
    storage_file_close(f);
    storage_file_free(f);
    return ok;
}

bool koi_vault_storage_write_sector(
    KoiVaultStorage* store, uint8_t vault_id,
    uint64_t sector_num, const uint8_t input[512])
{
    uint16_t chunk_idx; uint32_t byte_offset;
    sector_to_chunk_offset(sector_num, &chunk_idx, &byte_offset);
    char path[64];
    make_chunk_path(vault_id, chunk_idx, path, sizeof(path));
    File* f = storage_file_alloc(store->storage);
    bool ok = false;
    if(!storage_file_open(f, path, FSAM_READ_WRITE, FSOM_OPEN_EXISTING)) {
        if(!storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_NEW)) {
            storage_file_free(f);
            return false;
        }
        KoiVaultChunkHeader header;
        memcpy(header.magic, KOI_VAULT_CHUNK_MAGIC, 4);
        header.version = KOI_VAULT_CHUNK_VERSION;
        header.vault_id = vault_id;
        header.chunk_index = chunk_idx;
        memset(header.reserved, 0, 8);
        storage_file_write(f, &header, sizeof(header));
        storage_file_close(f);
        if(!storage_file_open(f, path, FSAM_READ_WRITE, FSOM_OPEN_EXISTING)) {
            storage_file_free(f);
            return false;
        }
    }
    if(storage_file_seek(f, byte_offset, true)) {
        ok = (storage_file_write(f, input, KOI_VAULT_SECTOR_SIZE) == KOI_VAULT_SECTOR_SIZE);
    }
    storage_file_close(f);
    storage_file_free(f);
    return ok;
}
