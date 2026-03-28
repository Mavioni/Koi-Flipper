#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KOI_VAULT_BASE_DIR       "/ext/vault"
#define KOI_VAULT_ALPHA_DIR      "/ext/vault/alpha"
#define KOI_VAULT_BETA_DIR       "/ext/vault/beta"
#define KOI_VAULT_META_PATH      "/ext/vault/meta.koi"
#define KOI_VAULT_CHUNK_MAGIC    "KOIV"
#define KOI_VAULT_CHUNK_VERSION  1
#define KOI_VAULT_CHUNK_HEADER_SIZE 16
#define KOI_VAULT_SECTOR_SIZE    512
#define KOI_VAULT_CHUNK_MAX_SIZE (1024 * 1024 * 1024)
#define KOI_VAULT_SECTORS_PER_CHUNK \
    ((KOI_VAULT_CHUNK_MAX_SIZE - KOI_VAULT_CHUNK_HEADER_SIZE) / KOI_VAULT_SECTOR_SIZE)
#define KOI_VAULT_ID_ALPHA  0
#define KOI_VAULT_ID_BETA   1

typedef struct __attribute__((packed)) {
    uint8_t  magic[4];
    uint8_t  version;
    uint8_t  vault_id;
    uint16_t chunk_index;
    uint8_t  reserved[8];
} KoiVaultChunkHeader;

#define KOI_VAULT_META_MAGIC "KOIM"

typedef struct __attribute__((packed)) {
    uint8_t  magic[4];
    uint8_t  version;
    uint8_t  salt[16];
    uint32_t pbkdf2_iters;
    uint8_t  alpha_verify[32];
    uint8_t  beta_verify[32];
    uint8_t  duress_active;
    uint8_t  _pad[2];
} KoiVaultMeta;

typedef struct KoiVaultStorage KoiVaultStorage;

KoiVaultStorage* koi_vault_storage_alloc(void);
void koi_vault_storage_free(KoiVaultStorage* store);
bool koi_vault_storage_create_vault(KoiVaultStorage* store, uint8_t vault_id);
bool koi_vault_storage_write_meta(const KoiVaultMeta* meta);
bool koi_vault_storage_read_meta(KoiVaultMeta* meta);
bool koi_vault_storage_read_sector(KoiVaultStorage* store, uint8_t vault_id, uint64_t sector_num, uint8_t output[512]);
bool koi_vault_storage_write_sector(KoiVaultStorage* store, uint8_t vault_id, uint64_t sector_num, const uint8_t input[512]);
const char* koi_vault_storage_get_dir(uint8_t vault_id);

#ifdef __cplusplus
}
#endif
