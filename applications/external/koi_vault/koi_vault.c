// applications/external/koi_vault/koi_vault.c
#include "koi_vault.h"
#include "lib/crypto/memzero.h"

#include <furi.h>
#include <furi_hal_random.h>
#include <koi_core/koi_core.h>
#include <koi_core/koi_trit.h>
#include <string.h>

#define TAG "KoiVault"

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

KoiVault* koi_vault_alloc(void) {
    KoiVault* vault = malloc(sizeof(KoiVault));
    furi_check(vault != NULL);
    memset(vault, 0, sizeof(KoiVault));

    vault->state = KoiVaultStateUninitialized;
    vault->storage = koi_vault_storage_alloc();
    koi_vault_index_init(&vault->index);
    vault->active_vault_id = KOI_VAULT_ID_ALPHA;
    vault->pin_attempts = 0;

    // Open governance service
    vault->koi_core = furi_record_open(RECORD_KOI_CORE);

    // Check if vault already exists
    if(koi_vault_storage_read_meta(&vault->meta)) {
        vault->state = KoiVaultStateLocked;
    }

    return vault;
}

void koi_vault_free(KoiVault* vault) {
    if(!vault) return;

    // Always wipe crypto on free
    koi_vault_crypto_wipe(&vault->crypto);
    memzero(&vault->index, sizeof(vault->index));

    koi_vault_storage_free(vault->storage);
    furi_record_close(RECORD_KOI_CORE);
    free(vault);
}

bool koi_vault_exists(KoiVault* vault) {
    return vault->state != KoiVaultStateUninitialized;
}

// ---------------------------------------------------------------------------
// Vault creation
// ---------------------------------------------------------------------------

bool koi_vault_create(
    KoiVault* vault,
    const char* pin,
    const char* duress_pin)
{
    // Check governance
    trit_t gov = vault->koi_core->evaluate(vault->koi_core, KOI_DOMAIN_VAULT);
    if(gov == TRIT_DENY) {
        FURI_LOG_W(TAG, "Governance denied vault creation");
        return false;
    }

    // Generate random salt
    KoiVaultMeta meta;
    memset(&meta, 0, sizeof(meta));
    memcpy(meta.magic, KOI_VAULT_META_MAGIC, 4);
    meta.version = 1;
    meta.pbkdf2_iters = KOI_VAULT_PBKDF2_ITERS;
    furi_hal_random_fill_buf(meta.salt, KOI_VAULT_SALT_LEN);

    // Derive alpha key and compute verify token
    uint8_t alpha_key[KOI_VAULT_XTS_KEY_LEN];
    koi_vault_crypto_derive_key(pin, strlen(pin), meta.salt, meta.pbkdf2_iters, alpha_key);
    koi_vault_crypto_compute_verify_token(alpha_key, meta.alpha_verify);

    // Create alpha vault directory
    if(!koi_vault_storage_create_vault(vault->storage, KOI_VAULT_ID_ALPHA)) {
        memzero(alpha_key, sizeof(alpha_key));
        return false;
    }

    // Write empty index for alpha
    koi_vault_index_init(&vault->index);
    if(!koi_vault_crypto_init(&vault->crypto, alpha_key)) {
        memzero(alpha_key, sizeof(alpha_key));
        return false;
    }
    koi_vault_index_save(&vault->index, vault->storage, &vault->crypto, KOI_VAULT_ID_ALPHA);
    koi_vault_crypto_wipe(&vault->crypto);
    memzero(alpha_key, sizeof(alpha_key));

    // Handle duress/beta vault
    if(duress_pin && strlen(duress_pin) > 0) {
        uint8_t beta_key[KOI_VAULT_XTS_KEY_LEN];
        koi_vault_crypto_derive_key(duress_pin, strlen(duress_pin),
            meta.salt, meta.pbkdf2_iters, beta_key);
        koi_vault_crypto_compute_verify_token(beta_key, meta.beta_verify);

        if(!koi_vault_storage_create_vault(vault->storage, KOI_VAULT_ID_BETA)) {
            memzero(beta_key, sizeof(beta_key));
            return false;
        }

        // Write empty index for beta
        KoiVaultIndex beta_index;
        koi_vault_index_init(&beta_index);
        KoiVaultCrypto beta_crypto;
        koi_vault_crypto_init(&beta_crypto, beta_key);
        koi_vault_index_save(&beta_index, vault->storage, &beta_crypto, KOI_VAULT_ID_BETA);
        koi_vault_crypto_wipe(&beta_crypto);
        memzero(beta_key, sizeof(beta_key));

        meta.duress_active = 1;
    } else {
        memset(meta.beta_verify, 0, sizeof(meta.beta_verify));
        meta.duress_active = 0;
    }

    // Write metadata
    if(!koi_vault_storage_write_meta(&meta)) return false;

    vault->meta = meta;
    vault->state = KoiVaultStateLocked;
    FURI_LOG_I(TAG, "Vault created (duress=%d)", meta.duress_active);
    return true;
}

// ---------------------------------------------------------------------------
// Open / Lock
// ---------------------------------------------------------------------------

KoiVaultState koi_vault_open(KoiVault* vault, const char* pin) {
    // Check governance first
    trit_t gov = vault->koi_core->evaluate(vault->koi_core, KOI_DOMAIN_VAULT);
    if(gov == TRIT_DENY) {
        FURI_LOG_W(TAG, "Governance denied vault open");
        return KoiVaultStateLocked;
    }

    // Check lockout
    if(vault->state == KoiVaultStateLockout) {
        if(furi_get_tick() < vault->lockout_until_tick) {
            return KoiVaultStateLockout;
        }
        vault->state = KoiVaultStateLocked;
        vault->pin_attempts = 0;
    }

    // Derive key from entered PIN
    uint8_t derived_key[KOI_VAULT_XTS_KEY_LEN];
    koi_vault_crypto_derive_key(pin, strlen(pin),
        vault->meta.salt, vault->meta.pbkdf2_iters, derived_key);

    // Compute verify token and check against alpha
    uint8_t verify_token[KOI_VAULT_VERIFY_TOKEN_LEN];
    koi_vault_crypto_compute_verify_token(derived_key, verify_token);

    if(memcmp(verify_token, vault->meta.alpha_verify, KOI_VAULT_VERIFY_TOKEN_LEN) == 0) {
        // Alpha PIN — normal unlock
        vault->active_vault_id = KOI_VAULT_ID_ALPHA;
        koi_vault_crypto_init(&vault->crypto, derived_key);
        memzero(derived_key, sizeof(derived_key));

        koi_vault_index_load(&vault->index, vault->storage, &vault->crypto, KOI_VAULT_ID_ALPHA);

        vault->state = KoiVaultStateUnlocked;
        vault->pin_attempts = 0;
        vault->last_activity_tick = furi_get_tick();

        // Set governance state
        vault->koi_core->set_state_field(vault->koi_core, KOI_FIELD_VAULT_ACCESS, TRIT_ALLOW);
        FURI_LOG_I(TAG, "Vault unlocked (alpha)");
        return KoiVaultStateUnlocked;
    }

    // Check duress PIN
    if(vault->meta.duress_active &&
       memcmp(verify_token, vault->meta.beta_verify, KOI_VAULT_VERIFY_TOKEN_LEN) == 0) {
        // Duress PIN detected!
        FURI_LOG_W(TAG, "DURESS PIN entered — opening beta, wiping alpha keys");

        vault->active_vault_id = KOI_VAULT_ID_BETA;
        koi_vault_crypto_init(&vault->crypto, derived_key);
        memzero(derived_key, sizeof(derived_key));

        koi_vault_index_load(&vault->index, vault->storage, &vault->crypto, KOI_VAULT_ID_BETA);

        vault->state = KoiVaultStateDuress;
        vault->pin_attempts = 0;
        vault->last_activity_tick = furi_get_tick();

        // Governance: deny vault access for alpha (duress state)
        vault->koi_core->set_state_field(vault->koi_core, KOI_FIELD_VAULT_ACCESS, TRIT_DENY);

        // Log duress event to governance audit
        // (koi_core_evaluate will record the DENY in audit log)
        vault->koi_core->evaluate(vault->koi_core, KOI_DOMAIN_VAULT);

        return KoiVaultStateDuress;
    }

    // Wrong PIN
    memzero(derived_key, sizeof(derived_key));
    vault->pin_attempts++;
    FURI_LOG_W(TAG, "Wrong PIN (attempt %d/%d)", vault->pin_attempts, KOI_VAULT_MAX_PIN_ATTEMPTS);

    if(vault->pin_attempts >= KOI_VAULT_MAX_PIN_ATTEMPTS) {
        vault->state = KoiVaultStateLockout;
        vault->lockout_until_tick = furi_get_tick() + KOI_VAULT_LOCKOUT_MS;
        return KoiVaultStateLockout;
    }

    return KoiVaultStateLocked;
}

void koi_vault_lock(KoiVault* vault) {
    if(vault->state == KoiVaultStateUnlocked || vault->state == KoiVaultStateDuress) {
        // Flush index if dirty
        if(vault->index.dirty) {
            koi_vault_index_save(&vault->index, vault->storage,
                &vault->crypto, vault->active_vault_id);
        }
    }

    // Wipe everything
    koi_vault_crypto_wipe(&vault->crypto);
    memzero(&vault->index, sizeof(vault->index));
    vault->state = KoiVaultStateLocked;

    // Governance: lock
    vault->koi_core->set_state_field(vault->koi_core, KOI_FIELD_VAULT_ACCESS, TRIT_DENY);
    FURI_LOG_I(TAG, "Vault locked");
}

bool koi_vault_check_timeout(KoiVault* vault) {
    if(vault->state != KoiVaultStateUnlocked && vault->state != KoiVaultStateDuress) {
        return false;
    }
    if(furi_get_tick() - vault->last_activity_tick > KOI_VAULT_LOCK_TIMEOUT_MS) {
        koi_vault_lock(vault);
        return true;
    }
    return false;
}

void koi_vault_touch(KoiVault* vault) {
    vault->last_activity_tick = furi_get_tick();
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

uint16_t koi_vault_file_count(KoiVault* vault) {
    if(vault->state != KoiVaultStateUnlocked && vault->state != KoiVaultStateDuress) return 0;
    return koi_vault_index_count(&vault->index);
}

const KoiVaultIndexEntry* koi_vault_file_get(KoiVault* vault, uint16_t pos) {
    if(vault->state != KoiVaultStateUnlocked && vault->state != KoiVaultStateDuress) return NULL;
    return koi_vault_index_get(&vault->index, pos);
}

uint32_t koi_vault_file_read(KoiVault* vault, const char* name, uint8_t* buf, uint32_t buf_size) {
    if(vault->state != KoiVaultStateUnlocked && vault->state != KoiVaultStateDuress) return 0;
    koi_vault_touch(vault);

    const KoiVaultIndexEntry* entry = koi_vault_index_find(&vault->index, name);
    if(!entry) return 0;
    if(entry->size > buf_size) return 0;

    uint32_t bytes_read = 0;
    uint64_t sector = KOI_VAULT_DATA_START_SECTOR + entry->offset;
    uint32_t remaining = entry->size;

    while(remaining > 0) {
        uint8_t encrypted_sector[KOI_VAULT_SECTOR_SIZE];
        uint8_t decrypted_sector[KOI_VAULT_SECTOR_SIZE];

        if(!koi_vault_storage_read_sector(vault->storage, vault->active_vault_id,
            sector, encrypted_sector)) break;
        if(!koi_vault_crypto_decrypt_sector(&vault->crypto, sector,
            encrypted_sector, decrypted_sector)) break;

        uint32_t to_copy = (remaining < KOI_VAULT_SECTOR_SIZE) ? remaining : KOI_VAULT_SECTOR_SIZE;
        memcpy(buf + bytes_read, decrypted_sector, to_copy);
        bytes_read += to_copy;
        remaining -= to_copy;
        sector++;
    }

    return bytes_read;
}

bool koi_vault_file_write(KoiVault* vault, const char* name, const uint8_t* data, uint32_t size) {
    if(vault->state != KoiVaultStateUnlocked && vault->state != KoiVaultStateDuress) return false;
    koi_vault_touch(vault);

    // Check governance
    trit_t gov = vault->koi_core->evaluate(vault->koi_core, KOI_DOMAIN_VAULT);
    if(gov == TRIT_DENY) return false;

    // Remove existing file if present (overwrite)
    koi_vault_index_remove(&vault->index, name);

    // Allocate sectors: find the next free sector offset
    uint64_t next_sector = 0;
    for(uint16_t i = 0; i < vault->index.count; i++) {
        const KoiVaultIndexEntry* e = &vault->index.entries[i];
        uint64_t end = e->offset + ((e->size + KOI_VAULT_SECTOR_SIZE - 1) / KOI_VAULT_SECTOR_SIZE);
        if(end > next_sector) next_sector = end;
    }

    // Add index entry
    KoiVaultIndexEntry* entry = koi_vault_index_add(&vault->index, name);
    if(!entry) return false;

    entry->chunk_index = 0; // simplified: single chunk for now
    entry->offset = (uint32_t)next_sector;
    entry->size = size;

    // Write encrypted sectors
    uint32_t written = 0;
    uint64_t sector = KOI_VAULT_DATA_START_SECTOR + next_sector;

    while(written < size) {
        uint8_t plaintext_sector[KOI_VAULT_SECTOR_SIZE];
        memset(plaintext_sector, 0, KOI_VAULT_SECTOR_SIZE);

        uint32_t to_copy = (size - written < KOI_VAULT_SECTOR_SIZE) ?
            size - written : KOI_VAULT_SECTOR_SIZE;
        memcpy(plaintext_sector, data + written, to_copy);

        uint8_t encrypted_sector[KOI_VAULT_SECTOR_SIZE];
        if(!koi_vault_crypto_encrypt_sector(&vault->crypto, sector,
            plaintext_sector, encrypted_sector)) {
            koi_vault_index_remove(&vault->index, name);
            return false;
        }
        if(!koi_vault_storage_write_sector(vault->storage, vault->active_vault_id,
            sector, encrypted_sector)) {
            koi_vault_index_remove(&vault->index, name);
            return false;
        }

        written += to_copy;
        sector++;
    }

    // Save index
    return koi_vault_index_save(&vault->index, vault->storage,
        &vault->crypto, vault->active_vault_id);
}

bool koi_vault_file_delete(KoiVault* vault, const char* name) {
    if(vault->state != KoiVaultStateUnlocked && vault->state != KoiVaultStateDuress) return false;
    koi_vault_touch(vault);

    if(!koi_vault_index_remove(&vault->index, name)) return false;
    return koi_vault_index_save(&vault->index, vault->storage,
        &vault->crypto, vault->active_vault_id);
}

// ---------------------------------------------------------------------------
// PIN management
// ---------------------------------------------------------------------------

bool koi_vault_change_pin(KoiVault* vault, const char* new_pin) {
    if(vault->state != KoiVaultStateUnlocked) return false;
    koi_vault_touch(vault);

    uint8_t new_key[KOI_VAULT_XTS_KEY_LEN];
    koi_vault_crypto_derive_key(new_pin, strlen(new_pin),
        vault->meta.salt, vault->meta.pbkdf2_iters, new_key);
    koi_vault_crypto_compute_verify_token(new_key, vault->meta.alpha_verify);

    // Re-initialize crypto with new key
    koi_vault_crypto_wipe(&vault->crypto);
    koi_vault_crypto_init(&vault->crypto, new_key);
    memzero(new_key, sizeof(new_key));

    // Re-encrypt and save index with new key
    koi_vault_index_save(&vault->index, vault->storage,
        &vault->crypto, KOI_VAULT_ID_ALPHA);

    // Update metadata
    return koi_vault_storage_write_meta(&vault->meta);
}

bool koi_vault_set_duress_pin(KoiVault* vault, const char* duress_pin) {
    if(vault->state != KoiVaultStateUnlocked) return false;
    koi_vault_touch(vault);

    uint8_t beta_key[KOI_VAULT_XTS_KEY_LEN];
    koi_vault_crypto_derive_key(duress_pin, strlen(duress_pin),
        vault->meta.salt, vault->meta.pbkdf2_iters, beta_key);
    koi_vault_crypto_compute_verify_token(beta_key, vault->meta.beta_verify);

    // Create beta vault if needed
    koi_vault_storage_create_vault(vault->storage, KOI_VAULT_ID_BETA);

    // Write empty index for beta
    KoiVaultIndex beta_index;
    koi_vault_index_init(&beta_index);
    KoiVaultCrypto beta_crypto;
    koi_vault_crypto_init(&beta_crypto, beta_key);
    koi_vault_index_save(&beta_index, vault->storage, &beta_crypto, KOI_VAULT_ID_BETA);
    koi_vault_crypto_wipe(&beta_crypto);
    memzero(beta_key, sizeof(beta_key));

    vault->meta.duress_active = 1;
    return koi_vault_storage_write_meta(&vault->meta);
}
