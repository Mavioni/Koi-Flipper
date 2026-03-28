// applications/external/koi_vault/koi_vault.h
#pragma once

#include "koi_vault_crypto.h"
#include "koi_vault_storage.h"
#include "koi_vault_index.h"

#include <koi_core/koi_core.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define KOI_VAULT_LOCK_TIMEOUT_MS   (5 * 60 * 1000)  // 5 minutes auto-lock
#define KOI_VAULT_MAX_PIN_ATTEMPTS  5
#define KOI_VAULT_LOCKOUT_MS        (30 * 1000)       // 30 seconds after max attempts

// Data sectors start after the index sectors
#define KOI_VAULT_DATA_START_SECTOR (KOI_INDEX_START_SECTOR + KOI_INDEX_MAX_SECTORS)

// ---------------------------------------------------------------------------
// Vault state
// ---------------------------------------------------------------------------

typedef enum {
    KoiVaultStateUninitialized = 0,  // No vault created yet
    KoiVaultStateLocked,             // Vault exists but PIN not entered
    KoiVaultStateUnlocked,           // Vault open, alpha or beta active
    KoiVaultStateDuress,             // Duress mode: beta open, alpha wiped
    KoiVaultStateLockout,            // Too many PIN attempts
} KoiVaultState;

// ---------------------------------------------------------------------------
// Vault context
// ---------------------------------------------------------------------------

typedef struct {
    KoiVaultState     state;
    KoiVaultCrypto    crypto;         // 1KB: AES-XTS contexts + key
    KoiVaultStorage*  storage;        // heap-allocated
    KoiVaultIndex     index;          // 8KB: in-memory index cache
    KoiVaultMeta      meta;           // 92B: vault metadata

    uint8_t active_vault_id;          // KOI_VAULT_ID_ALPHA or KOI_VAULT_ID_BETA
    uint32_t last_activity_tick;      // for auto-lock timeout
    uint8_t  pin_attempts;            // failed PIN attempts since last success
    uint32_t lockout_until_tick;      // tick when lockout expires

    KoiCoreApi* koi_core;             // governance service handle (vtable)
} KoiVault;

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/** Allocate and initialize vault context. */
KoiVault* koi_vault_alloc(void);

/** Free vault context, wiping all key material. */
void koi_vault_free(KoiVault* vault);

/** Check if a vault has been created (meta.koi exists). */
bool koi_vault_exists(KoiVault* vault);

// ---------------------------------------------------------------------------
// Vault creation
// ---------------------------------------------------------------------------

/**
 * Create a new vault pair (alpha + beta).
 * @param pin         Primary PIN for alpha vault
 * @param duress_pin  Duress PIN for beta vault (NULL to skip)
 * @return true on success
 */
bool koi_vault_create(
    KoiVault* vault,
    const char* pin,
    const char* duress_pin);

// ---------------------------------------------------------------------------
// Open / Lock
// ---------------------------------------------------------------------------

/**
 * Attempt to open the vault with the given PIN.
 * Checks governance (KOI_DOMAIN_VAULT) first.
 * On duress PIN: opens beta, wipes alpha keys from SRAM, logs audit event.
 *
 * @return KoiVaultStateUnlocked on success,
 *         KoiVaultStateDuress on duress,
 *         KoiVaultStateLocked on wrong PIN,
 *         KoiVaultStateLockout on too many attempts
 */
KoiVaultState koi_vault_open(KoiVault* vault, const char* pin);

/**
 * Lock the vault: flush index, wipe crypto keys from SRAM.
 * Sets vault_access state to TRIT_DENY.
 */
void koi_vault_lock(KoiVault* vault);

/**
 * Check auto-lock timeout. Call periodically from the app loop.
 * Returns true if the vault was locked due to timeout.
 */
bool koi_vault_check_timeout(KoiVault* vault);

/** Touch the activity timer (call on any user interaction). */
void koi_vault_touch(KoiVault* vault);

// ---------------------------------------------------------------------------
// File operations (require unlocked state)
// ---------------------------------------------------------------------------

/** Get the number of files in the active vault. */
uint16_t koi_vault_file_count(KoiVault* vault);

/** Get file entry at position (for browsing UI). */
const KoiVaultIndexEntry* koi_vault_file_get(KoiVault* vault, uint16_t pos);

/**
 * Read a file from the vault into a buffer.
 * @param name      Filename
 * @param buf       Output buffer (caller allocates, at least entry->size bytes)
 * @param buf_size  Buffer size
 * @return bytes read, or 0 on failure
 */
uint32_t koi_vault_file_read(KoiVault* vault, const char* name, uint8_t* buf, uint32_t buf_size);

/**
 * Write a file into the vault.
 * @param name   Filename (max 31 chars)
 * @param data   File data
 * @param size   Data size in bytes
 * @return true on success
 */
bool koi_vault_file_write(KoiVault* vault, const char* name, const uint8_t* data, uint32_t size);

/** Delete a file from the vault. */
bool koi_vault_file_delete(KoiVault* vault, const char* name);

// ---------------------------------------------------------------------------
// PIN management
// ---------------------------------------------------------------------------

/** Change the primary (alpha) PIN. Requires current PIN verified. */
bool koi_vault_change_pin(KoiVault* vault, const char* new_pin);

/** Set or change the duress (beta) PIN. */
bool koi_vault_set_duress_pin(KoiVault* vault, const char* duress_pin);

#ifdef __cplusplus
}
#endif
