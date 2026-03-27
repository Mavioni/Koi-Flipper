#pragma once

#include "koi_trit.h"
#include <stdint.h>

#define KOI_POLICY_MAGIC    "TRIT"
#define KOI_POLICY_VERSION  1

typedef enum {
    KOI_POLICY_FILE_OK          = 0,
    KOI_POLICY_FILE_BAD_MAGIC   = 1,
    KOI_POLICY_FILE_BAD_VERSION = 2,
    KOI_POLICY_FILE_CRC_FAIL    = 3,
    KOI_POLICY_FILE_IO_ERROR    = 4,
    KOI_POLICY_FILE_TOO_MANY    = 5,
} KoiPolicyFileError;

/**
 * Load a .trit policy binary file from the SD card.
 * Verifies magic bytes, version, and CRC32 before returning.
 * On CRC_FAIL, caller must default to DENY (fail-closed).
 *
 * @param path       Absolute path e.g. "/ext/governance/rf.trit"
 * @param rules      Output buffer for parsed rules
 * @param capacity   Maximum number of rules the buffer can hold
 * @param out_count  Set to actual number of rules loaded
 * @return KoiPolicyFileError code
 */
KoiPolicyFileError koi_policy_file_load(
    const char* path,
    TritRule* rules,
    uint8_t capacity,
    uint8_t* out_count);

// CRC32 helpers exposed for tests
uint32_t koi_policy_file_crc32_init(void);
uint32_t koi_policy_file_crc32_update(uint32_t crc, const uint8_t* data, uint32_t len);
uint32_t koi_policy_file_crc32_finalize(uint32_t crc);
