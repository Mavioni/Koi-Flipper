#include "koi_policy_file.h"

#include <furi.h>
#include <storage/storage.h>
#include <string.h>

#define KOI_POLICY_HEADER_SIZE 8

// Nibble-based CRC32 (IEEE 802.3 polynomial, same as zlib)
uint32_t koi_policy_file_crc32_init(void) {
    return 0xFFFFFFFFu;
}

uint32_t koi_policy_file_crc32_update(uint32_t crc, const uint8_t* data, uint32_t len) {
    static const uint32_t table[16] = {
        0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu,
        0x76DC4190u, 0x6B6B51F4u, 0x4DB26158u, 0x5005713Cu,
        0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
        0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu,
    };
    for(uint32_t i = 0; i < len; i++) {
        crc = (crc >> 4) ^ table[(crc ^ (data[i] >> 0)) & 0x0Fu];
        crc = (crc >> 4) ^ table[(crc ^ (data[i] >> 4)) & 0x0Fu];
    }
    return crc;
}

uint32_t koi_policy_file_crc32_finalize(uint32_t crc) {
    return crc ^ 0xFFFFFFFFu;
}

KoiPolicyFileError koi_policy_file_load(
    const char* path,
    uint8_t expected_domain,
    TritRule* rules,
    uint8_t capacity,
    uint8_t* out_count)
{
    furi_assert(out_count != NULL);
    *out_count = 0;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);

    KoiPolicyFileError result = KOI_POLICY_FILE_IO_ERROR;

    do {
        if(!storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) break;

        uint8_t header[KOI_POLICY_HEADER_SIZE];
        if(storage_file_read(f, header, sizeof(header)) != sizeof(header)) break;

        if(memcmp(header, KOI_POLICY_MAGIC, 4) != 0) {
            result = KOI_POLICY_FILE_BAD_MAGIC;
            break;
        }
        if(header[4] != KOI_POLICY_VERSION) {
            result = KOI_POLICY_FILE_BAD_VERSION;
            break;
        }
        if(header[5] != expected_domain) {
            result = KOI_POLICY_FILE_BAD_DOMAIN;
            break;
        }

        uint16_t rule_count = (uint16_t)(header[6] | ((uint16_t)header[7] << 8));
        if(rule_count > capacity) {
            result = KOI_POLICY_FILE_TOO_MANY;
            break;
        }

        uint32_t crc = koi_policy_file_crc32_init();
        crc = koi_policy_file_crc32_update(crc, header, sizeof(header));

        for(uint16_t i = 0; i < rule_count; i++) {
            if(storage_file_read(f, &rules[i], sizeof(TritRule)) != sizeof(TritRule)) goto done;
            crc = koi_policy_file_crc32_update(crc, (const uint8_t*)&rules[i], sizeof(TritRule));
        }
        crc = koi_policy_file_crc32_finalize(crc);

        uint32_t file_crc = 0;
        if(storage_file_read(f, &file_crc, sizeof(file_crc)) != sizeof(file_crc)) goto done;
        if(file_crc != crc) {
            result = KOI_POLICY_FILE_CRC_FAIL;
            break;
        }

        *out_count = (uint8_t)rule_count;
        result = KOI_POLICY_FILE_OK;
    } while(0);

done:
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return result;
}
