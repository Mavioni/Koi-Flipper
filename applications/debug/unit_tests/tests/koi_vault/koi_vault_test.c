#include "../test.h" // IWYU pragma: keep
#include <furi.h>
#include <string.h>

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

// RFC 6070 / draft-josefsson-scrypt-kdf-01 PBKDF2-HMAC-SHA256 test vectors

// Vector 1: password="password", salt="salt", iterations=1, dkLen=32
static const uint8_t pbkdf2_tv1_password[] = "password";
static const uint8_t pbkdf2_tv1_salt[] = "salt";
static const uint32_t pbkdf2_tv1_iterations = 1;
static const uint8_t pbkdf2_tv1_expected[32] = {
    0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
    0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
    0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
    0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
};

// Vector 2: password="password", salt="salt", iterations=4096, dkLen=32
static const uint8_t pbkdf2_tv2_password[] = "password";
static const uint8_t pbkdf2_tv2_salt[] = "salt";
static const uint32_t pbkdf2_tv2_iterations = 4096;
static const uint8_t pbkdf2_tv2_expected[32] = {
    0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
    0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
    0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
    0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
};

// Reference PBKDF2-HMAC-SHA256 using exported mbedtls
static void pbkdf2_hmac_sha256_ref(
    const uint8_t* password, size_t pass_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t* output, size_t dk_len)
{
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint32_t block_count = (uint32_t)((dk_len + 31) / 32);

    for(uint32_t block = 1; block <= block_count; block++) {
        uint8_t u[32], f[32];
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, md_info, 1);
        mbedtls_md_hmac_starts(&ctx, password, pass_len);
        mbedtls_md_hmac_update(&ctx, salt, salt_len);
        uint8_t be_block[4] = {
            (uint8_t)(block >> 24), (uint8_t)(block >> 16),
            (uint8_t)(block >> 8),  (uint8_t)(block)
        };
        mbedtls_md_hmac_update(&ctx, be_block, 4);
        mbedtls_md_hmac_finish(&ctx, u);
        memcpy(f, u, 32);

        for(uint32_t i = 1; i < iterations; i++) {
            mbedtls_md_hmac_reset(&ctx);
            mbedtls_md_hmac_update(&ctx, u, 32);
            mbedtls_md_hmac_finish(&ctx, u);
            for(int j = 0; j < 32; j++) f[j] ^= u[j];
        }
        mbedtls_md_free(&ctx);

        size_t offset = (block - 1) * 32;
        size_t to_copy = (offset + 32 > dk_len) ? dk_len - offset : 32;
        memcpy(output + offset, f, to_copy);
    }
}

MU_TEST(test_pbkdf2_sha256_vector1) {
    uint8_t derived[32];
    pbkdf2_hmac_sha256_ref(
        pbkdf2_tv1_password, 8,
        pbkdf2_tv1_salt, 4,
        pbkdf2_tv1_iterations,
        derived, 32);
    mu_assert_mem_eq(pbkdf2_tv1_expected, derived, 32);
}

MU_TEST(test_pbkdf2_sha256_vector2) {
    uint8_t derived[32];
    pbkdf2_hmac_sha256_ref(
        pbkdf2_tv2_password, 8,
        pbkdf2_tv2_salt, 4,
        pbkdf2_tv2_iterations,
        derived, 32);
    mu_assert_mem_eq(pbkdf2_tv2_expected, derived, 32);
}

MU_TEST(test_pbkdf2_sha256_64byte_output) {
    uint8_t derived[64];
    pbkdf2_hmac_sha256_ref(
        (const uint8_t*)"testpin", 7,
        (const uint8_t*)"koivault", 8,
        1000,
        derived, 64);
    mu_check(memcmp(derived, derived + 32, 32) != 0);
    uint8_t derived2[64];
    pbkdf2_hmac_sha256_ref(
        (const uint8_t*)"testpin", 7,
        (const uint8_t*)"koivault", 8,
        1000,
        derived2, 64);
    mu_assert_mem_eq(derived, derived2, 64);
}

#include <mbedtls/aes.h>

MU_TEST(test_aes_xts_roundtrip_512b_sector) {
    uint8_t xts_key[64];
    for(int i = 0; i < 64; i++) xts_key[i] = (uint8_t)(i ^ 0xAB);

    mbedtls_aes_xts_context enc_ctx, dec_ctx;
    mbedtls_aes_xts_init(&enc_ctx);
    mbedtls_aes_xts_init(&dec_ctx);

    int ret = mbedtls_aes_xts_setkey_enc(&enc_ctx, xts_key, 512);
    mu_assert_int_eq(0, ret);
    ret = mbedtls_aes_xts_setkey_dec(&dec_ctx, xts_key, 512);
    mu_assert_int_eq(0, ret);

    uint8_t plaintext[512];
    for(int i = 0; i < 512; i++) plaintext[i] = (uint8_t)(i & 0xFF);

    uint8_t data_unit[16] = {0};
    data_unit[0] = 42;

    uint8_t ciphertext[512];
    ret = mbedtls_aes_crypt_xts(&enc_ctx, MBEDTLS_AES_ENCRYPT, 512, data_unit, plaintext, ciphertext);
    mu_assert_int_eq(0, ret);
    mu_check(memcmp(plaintext, ciphertext, 512) != 0);

    uint8_t decrypted[512];
    ret = mbedtls_aes_crypt_xts(&dec_ctx, MBEDTLS_AES_DECRYPT, 512, data_unit, ciphertext, decrypted);
    mu_assert_int_eq(0, ret);
    mu_assert_mem_eq(plaintext, decrypted, 512);

    uint8_t wrong_unit[16] = {0};
    wrong_unit[0] = 99;
    ret = mbedtls_aes_crypt_xts(&dec_ctx, MBEDTLS_AES_DECRYPT, 512, wrong_unit, ciphertext, decrypted);
    mu_assert_int_eq(0, ret);
    mu_check(memcmp(plaintext, decrypted, 512) != 0);

    mbedtls_aes_xts_free(&enc_ctx);
    mbedtls_aes_xts_free(&dec_ctx);
}

MU_TEST(test_crypto_key_derive_deterministic) {
    uint8_t key1[64], key2[64];
    const uint8_t pin[] = "1234";
    const uint8_t salt[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                               0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    pbkdf2_hmac_sha256_ref(pin, 4, salt, 16, 1000, key1, 64);
    pbkdf2_hmac_sha256_ref(pin, 4, salt, 16, 1000, key2, 64);
    mu_assert_mem_eq(key1, key2, 64);
}

MU_TEST(test_crypto_different_pin_different_key) {
    uint8_t key1[64], key2[64];
    const uint8_t salt[16] = {0};
    pbkdf2_hmac_sha256_ref((const uint8_t*)"1234", 4, salt, 16, 1000, key1, 64);
    pbkdf2_hmac_sha256_ref((const uint8_t*)"5678", 4, salt, 16, 1000, key2, 64);
    mu_check(memcmp(key1, key2, 64) != 0);
}

MU_TEST(test_crypto_different_salt_different_key) {
    uint8_t key1[64], key2[64];
    uint8_t salt1[16] = {0x01};
    uint8_t salt2[16] = {0x02};
    pbkdf2_hmac_sha256_ref((const uint8_t*)"1234", 4, salt1, 16, 1000, key1, 64);
    pbkdf2_hmac_sha256_ref((const uint8_t*)"1234", 4, salt2, 16, 1000, key2, 64);
    mu_check(memcmp(key1, key2, 64) != 0);
}

MU_TEST(test_crypto_xts_different_sectors_different_ciphertext) {
    uint8_t xts_key[64];
    for(int i = 0; i < 64; i++) xts_key[i] = (uint8_t)i;
    mbedtls_aes_xts_context ctx;
    mbedtls_aes_xts_init(&ctx);
    mbedtls_aes_xts_setkey_enc(&ctx, xts_key, 512);
    uint8_t plaintext[512] = {0};
    memset(plaintext, 0xAA, 512);
    uint8_t ct_sector0[512], ct_sector1[512];
    uint8_t du0[16] = {0}, du1[16] = {0};
    du0[0] = 0; du1[0] = 1;
    mbedtls_aes_crypt_xts(&ctx, MBEDTLS_AES_ENCRYPT, 512, du0, plaintext, ct_sector0);
    mbedtls_aes_crypt_xts(&ctx, MBEDTLS_AES_ENCRYPT, 512, du1, plaintext, ct_sector1);
    mu_check(memcmp(ct_sector0, ct_sector1, 512) != 0);
    mbedtls_aes_xts_free(&ctx);
}

void test_setup(void) {}
void test_teardown(void) {}

MU_TEST_SUITE(test_koi_vault) {
    MU_SUITE_CONFIGURE(&test_setup, &test_teardown);
    MU_RUN_TEST(test_pbkdf2_sha256_vector1);
    MU_RUN_TEST(test_pbkdf2_sha256_vector2);
    MU_RUN_TEST(test_pbkdf2_sha256_64byte_output);
    MU_RUN_TEST(test_aes_xts_roundtrip_512b_sector);
    MU_RUN_TEST(test_crypto_key_derive_deterministic);
    MU_RUN_TEST(test_crypto_different_pin_different_key);
    MU_RUN_TEST(test_crypto_different_salt_different_key);
    MU_RUN_TEST(test_crypto_xts_different_sectors_different_ciphertext);
}
