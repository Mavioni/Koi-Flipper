#include "koi_vault_crypto.h"
#include "lib/crypto/pbkdf2.h"
#include "lib/crypto/memzero.h"
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <string.h>

#define TAG "KoiVaultCrypto"

void koi_vault_crypto_derive_key(
    const char* pin, size_t pin_len,
    const uint8_t salt[KOI_VAULT_SALT_LEN],
    uint32_t iterations,
    uint8_t out_key[KOI_VAULT_XTS_KEY_LEN])
{
    pbkdf2_hmac_sha256(
        (const uint8_t*)pin, (int)pin_len,
        salt, KOI_VAULT_SALT_LEN,
        iterations,
        out_key, KOI_VAULT_XTS_KEY_LEN);
}

void koi_vault_crypto_compute_verify_token(
    const uint8_t key[KOI_VAULT_XTS_KEY_LEN],
    uint8_t token[KOI_VAULT_VERIFY_TOKEN_LEN])
{
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md_info, key, 32,
        (const uint8_t*)"koi-vault-verify", 16, token);
}

bool koi_vault_crypto_init(KoiVaultCrypto* crypto, const uint8_t key[KOI_VAULT_XTS_KEY_LEN]) {
    memcpy(crypto->xts_key, key, KOI_VAULT_XTS_KEY_LEN);
    mbedtls_aes_xts_init(&crypto->enc_ctx);
    mbedtls_aes_xts_init(&crypto->dec_ctx);
    int ret = mbedtls_aes_xts_setkey_enc(&crypto->enc_ctx, key, 512);
    if(ret != 0) { koi_vault_crypto_wipe(crypto); return false; }
    ret = mbedtls_aes_xts_setkey_dec(&crypto->dec_ctx, key, 512);
    if(ret != 0) { koi_vault_crypto_wipe(crypto); return false; }
    crypto->initialized = true;
    return true;
}

void koi_vault_crypto_wipe(KoiVaultCrypto* crypto) {
    mbedtls_aes_xts_free(&crypto->enc_ctx);
    mbedtls_aes_xts_free(&crypto->dec_ctx);
    memzero(crypto->xts_key, KOI_VAULT_XTS_KEY_LEN);
    crypto->initialized = false;
}

static void sector_num_to_data_unit(uint64_t sector_num, uint8_t data_unit[16]) {
    memset(data_unit, 0, 16);
    data_unit[0] = (uint8_t)(sector_num & 0xFF);
    data_unit[1] = (uint8_t)((sector_num >> 8) & 0xFF);
    data_unit[2] = (uint8_t)((sector_num >> 16) & 0xFF);
    data_unit[3] = (uint8_t)((sector_num >> 24) & 0xFF);
    data_unit[4] = (uint8_t)((sector_num >> 32) & 0xFF);
    data_unit[5] = (uint8_t)((sector_num >> 40) & 0xFF);
    data_unit[6] = (uint8_t)((sector_num >> 48) & 0xFF);
    data_unit[7] = (uint8_t)((sector_num >> 56) & 0xFF);
}

bool koi_vault_crypto_encrypt_sector(
    KoiVaultCrypto* crypto, uint64_t sector_num,
    const uint8_t input[KOI_VAULT_SECTOR_SIZE],
    uint8_t output[KOI_VAULT_SECTOR_SIZE])
{
    if(!crypto->initialized) return false;
    uint8_t data_unit[16];
    sector_num_to_data_unit(sector_num, data_unit);
    return mbedtls_aes_crypt_xts(&crypto->enc_ctx, MBEDTLS_AES_ENCRYPT,
        KOI_VAULT_SECTOR_SIZE, data_unit, input, output) == 0;
}

bool koi_vault_crypto_decrypt_sector(
    KoiVaultCrypto* crypto, uint64_t sector_num,
    const uint8_t input[KOI_VAULT_SECTOR_SIZE],
    uint8_t output[KOI_VAULT_SECTOR_SIZE])
{
    if(!crypto->initialized) return false;
    uint8_t data_unit[16];
    sector_num_to_data_unit(sector_num, data_unit);
    return mbedtls_aes_crypt_xts(&crypto->dec_ctx, MBEDTLS_AES_DECRYPT,
        KOI_VAULT_SECTOR_SIZE, data_unit, input, output) == 0;
}
