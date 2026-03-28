#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mbedtls/aes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KOI_VAULT_XTS_KEY_LEN     64
#define KOI_VAULT_SECTOR_SIZE     512
#define KOI_VAULT_SALT_LEN        16
#define KOI_VAULT_PIN_MAX_LEN     32
#define KOI_VAULT_PBKDF2_ITERS    100000
#define KOI_VAULT_VERIFY_TOKEN_LEN 32

typedef struct {
    uint8_t xts_key[KOI_VAULT_XTS_KEY_LEN];
    mbedtls_aes_xts_context enc_ctx;
    mbedtls_aes_xts_context dec_ctx;
    bool initialized;
} KoiVaultCrypto;

void koi_vault_crypto_derive_key(
    const char* pin, size_t pin_len,
    const uint8_t salt[KOI_VAULT_SALT_LEN],
    uint32_t iterations,
    uint8_t out_key[KOI_VAULT_XTS_KEY_LEN]);

void koi_vault_crypto_compute_verify_token(
    const uint8_t key[KOI_VAULT_XTS_KEY_LEN],
    uint8_t token[KOI_VAULT_VERIFY_TOKEN_LEN]);

bool koi_vault_crypto_init(KoiVaultCrypto* crypto, const uint8_t key[KOI_VAULT_XTS_KEY_LEN]);
void koi_vault_crypto_wipe(KoiVaultCrypto* crypto);

bool koi_vault_crypto_encrypt_sector(
    KoiVaultCrypto* crypto, uint64_t sector_num,
    const uint8_t input[KOI_VAULT_SECTOR_SIZE],
    uint8_t output[KOI_VAULT_SECTOR_SIZE]);

bool koi_vault_crypto_decrypt_sector(
    KoiVaultCrypto* crypto, uint64_t sector_num,
    const uint8_t input[KOI_VAULT_SECTOR_SIZE],
    uint8_t output[KOI_VAULT_SECTOR_SIZE]);

#ifdef __cplusplus
}
#endif
