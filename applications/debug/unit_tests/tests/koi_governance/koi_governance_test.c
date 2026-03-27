#include "../test.h" // IWYU pragma: keep
#include <furi.h>
#include <storage/storage.h>
#include <koi_core/koi_trit.h>
#include <koi_core/koi_policy.h>
#include <koi_core/koi_policy_file.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static uint8_t trit_enc(trit_t t) {
    if(t < 0) return KOI_TRIT_BITS_DENY;
    if(t > 0) return KOI_TRIT_BITS_ALLOW;
    return KOI_TRIT_BITS_NEUTRAL;
}

static TritRule make_rule(
    uint8_t domain,
    uint8_t field_index,
    trit_t required,
    trit_t result,
    uint8_t combining)
{
    TritRule r = {0};
    r.domain = domain;
    r.combining = combining;
    r.result = result;
    r.priority = 0;
    r.flags = 0;

    if(field_index < KOI_STATE_FIELD_COUNT) {
        r.input_mask = (uint16_t)(1u << field_index);
        uint8_t bit_pos   = KOI_TRIT_BITS_SHIFT(field_index);
        uint8_t byte_idx  = bit_pos / 8u;
        uint8_t bit_idx   = bit_pos % 8u;
        r.input_trits[byte_idx] |= (uint8_t)(trit_enc(required) << bit_idx);
    }
    return r;
}

static TritRule make_unconditional_rule(uint8_t domain, trit_t result, uint8_t combining) {
    TritRule r = {0};
    r.domain = domain;
    r.combining = combining;
    r.result = result;
    return r;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

MU_TEST(test_no_rules_returns_deny) {
    koi_state_t state = {0};
    trit_t result = koi_policy_evaluate(NULL, 0, KOI_DOMAIN_RF, &state);
    mu_assert_int_eq(TRIT_DENY, result);
}

MU_TEST(test_deny_override_any_deny_wins) {
    koi_state_t state = {0};
    TritRule rules[3];
    rules[0] = make_unconditional_rule(KOI_DOMAIN_RF, TRIT_ALLOW,   KOI_COMBINING_DENY_OVERRIDE);
    rules[1] = make_unconditional_rule(KOI_DOMAIN_RF, TRIT_DENY,    KOI_COMBINING_DENY_OVERRIDE);
    rules[2] = make_unconditional_rule(KOI_DOMAIN_RF, TRIT_ALLOW,   KOI_COMBINING_DENY_OVERRIDE);
    trit_t result = koi_policy_evaluate(rules, 3, KOI_DOMAIN_RF, &state);
    mu_assert_int_eq(TRIT_DENY, result);
}

MU_TEST(test_deny_override_all_allow_returns_allow) {
    koi_state_t state = {0};
    TritRule rules[2];
    rules[0] = make_unconditional_rule(KOI_DOMAIN_RF, TRIT_ALLOW, KOI_COMBINING_DENY_OVERRIDE);
    rules[1] = make_unconditional_rule(KOI_DOMAIN_RF, TRIT_ALLOW, KOI_COMBINING_DENY_OVERRIDE);
    trit_t result = koi_policy_evaluate(rules, 2, KOI_DOMAIN_RF, &state);
    mu_assert_int_eq(TRIT_ALLOW, result);
}

MU_TEST(test_permit_override_any_allow_wins) {
    koi_state_t state = {0};
    TritRule rules[3];
    rules[0] = make_unconditional_rule(KOI_DOMAIN_BLE, TRIT_DENY,    KOI_COMBINING_PERMIT_OVERRIDE);
    rules[1] = make_unconditional_rule(KOI_DOMAIN_BLE, TRIT_ALLOW,   KOI_COMBINING_PERMIT_OVERRIDE);
    rules[2] = make_unconditional_rule(KOI_DOMAIN_BLE, TRIT_DENY,    KOI_COMBINING_PERMIT_OVERRIDE);
    trit_t result = koi_policy_evaluate(rules, 3, KOI_DOMAIN_BLE, &state);
    mu_assert_int_eq(TRIT_ALLOW, result);
}

MU_TEST(test_first_applicable_returns_first_match) {
    koi_state_t state = {0};
    state.network_trust = TRIT_ALLOW;
    TritRule rules[2];
    rules[0] = make_rule(KOI_DOMAIN_MESH, KOI_FIELD_NETWORK_TRUST, TRIT_ALLOW, TRIT_ALLOW,
                         KOI_COMBINING_FIRST_APPLICABLE);
    rules[1] = make_unconditional_rule(KOI_DOMAIN_MESH, TRIT_DENY, KOI_COMBINING_FIRST_APPLICABLE);
    trit_t result = koi_policy_evaluate(rules, 2, KOI_DOMAIN_MESH, &state);
    mu_assert_int_eq(TRIT_ALLOW, result);
}

MU_TEST(test_first_applicable_falls_through_to_default) {
    koi_state_t state = {0};
    state.network_trust = TRIT_DENY;
    TritRule rules[2];
    rules[0] = make_rule(KOI_DOMAIN_MESH, KOI_FIELD_NETWORK_TRUST, TRIT_ALLOW, TRIT_ALLOW,
                         KOI_COMBINING_FIRST_APPLICABLE);
    rules[1] = make_unconditional_rule(KOI_DOMAIN_MESH, TRIT_DENY, KOI_COMBINING_FIRST_APPLICABLE);
    trit_t result = koi_policy_evaluate(rules, 2, KOI_DOMAIN_MESH, &state);
    mu_assert_int_eq(TRIT_DENY, result);
}

MU_TEST(test_consensus_majority_allow) {
    koi_state_t state = {0};
    TritRule rules[3];
    rules[0] = make_unconditional_rule(KOI_DOMAIN_MESH, TRIT_ALLOW,   KOI_COMBINING_CONSENSUS);
    rules[1] = make_unconditional_rule(KOI_DOMAIN_MESH, TRIT_ALLOW,   KOI_COMBINING_CONSENSUS);
    rules[2] = make_unconditional_rule(KOI_DOMAIN_MESH, TRIT_DENY,    KOI_COMBINING_CONSENSUS);
    trit_t result = koi_policy_evaluate(rules, 3, KOI_DOMAIN_MESH, &state);
    mu_assert_int_eq(TRIT_ALLOW, result);
}

MU_TEST(test_consensus_tie_returns_neutral) {
    koi_state_t state = {0};
    TritRule rules[2];
    rules[0] = make_unconditional_rule(KOI_DOMAIN_MESH, TRIT_ALLOW, KOI_COMBINING_CONSENSUS);
    rules[1] = make_unconditional_rule(KOI_DOMAIN_MESH, TRIT_DENY,  KOI_COMBINING_CONSENSUS);
    trit_t result = koi_policy_evaluate(rules, 2, KOI_DOMAIN_MESH, &state);
    mu_assert_int_eq(TRIT_NEUTRAL, result);
}

MU_TEST(test_rule_not_matching_skips_rule) {
    koi_state_t state = {0};
    state.power_state = TRIT_ALLOW;
    TritRule rules[1];
    rules[0] = make_rule(KOI_DOMAIN_RF, KOI_FIELD_POWER_STATE, TRIT_DENY, TRIT_DENY,
                         KOI_COMBINING_DENY_OVERRIDE);
    trit_t result = koi_policy_evaluate(rules, 1, KOI_DOMAIN_RF, &state);
    mu_assert_int_eq(TRIT_DENY, result); // no match → fail-closed
}

MU_TEST(test_domain_filtering_ignores_other_domains) {
    koi_state_t state = {0};
    TritRule rules[1];
    rules[0] = make_unconditional_rule(KOI_DOMAIN_BLE, TRIT_ALLOW, KOI_COMBINING_DENY_OVERRIDE);
    trit_t result = koi_policy_evaluate(rules, 1, KOI_DOMAIN_RF, &state);
    mu_assert_int_eq(TRIT_DENY, result); // no RF rules → fail-closed
}

MU_TEST(test_multi_field_condition_all_must_match) {
    koi_state_t state = {0};
    state.network_trust = TRIT_ALLOW;
    state.mesh_relay    = TRIT_ALLOW;

    TritRule r = {0};
    r.domain    = KOI_DOMAIN_MESH;
    r.combining = KOI_COMBINING_PERMIT_OVERRIDE;
    r.result    = TRIT_ALLOW;
    // Set field 0 (network_trust) = ALLOW
    r.input_mask |= (1u << KOI_FIELD_NETWORK_TRUST);
    uint8_t bit0 = KOI_TRIT_BITS_SHIFT(KOI_FIELD_NETWORK_TRUST);
    r.input_trits[bit0 / 8u] |= (uint8_t)(KOI_TRIT_BITS_ALLOW << (bit0 % 8u));
    // Set field 5 (mesh_relay) = ALLOW
    r.input_mask |= (1u << KOI_FIELD_MESH_RELAY);
    uint8_t bit5 = KOI_TRIT_BITS_SHIFT(KOI_FIELD_MESH_RELAY);
    r.input_trits[bit5 / 8u] |= (uint8_t)(KOI_TRIT_BITS_ALLOW << (bit5 % 8u));

    TritRule rules[1] = {r};
    trit_t result = koi_policy_evaluate(rules, 1, KOI_DOMAIN_MESH, &state);
    mu_assert_int_eq(TRIT_ALLOW, result);

    state.mesh_relay = TRIT_DENY; // break one condition
    result = koi_policy_evaluate(rules, 1, KOI_DOMAIN_MESH, &state);
    mu_assert_int_eq(TRIT_DENY, result); // no match → fail-closed
}

// ---------------------------------------------------------------------------
// Policy file tests — helpers
// ---------------------------------------------------------------------------

#define KOI_TEST_POLICY_PATH EXT_PATH(".tmp/unit_tests/test_policy.trit")

static void write_test_policy_file(uint8_t domain, const TritRule* rule) {
    Storage* storage = furi_record_open(RECORD_STORAGE);

    uint8_t header[8];
    header[0] = 'T'; header[1] = 'R'; header[2] = 'I'; header[3] = 'T';
    header[4] = 1;
    header[5] = domain;
    header[6] = 1; header[7] = 0; // rule_count = 1, little-endian

    uint32_t crc = koi_policy_file_crc32_init();
    crc = koi_policy_file_crc32_update(crc, header, sizeof(header));
    crc = koi_policy_file_crc32_update(crc, (const uint8_t*)rule, sizeof(TritRule));
    crc = koi_policy_file_crc32_finalize(crc);

    storage_simply_remove(storage, KOI_TEST_POLICY_PATH);
    File* f = storage_file_alloc(storage);
    mu_check(storage_file_open(f, KOI_TEST_POLICY_PATH, FSAM_WRITE, FSOM_CREATE_NEW));
    mu_check(storage_file_write(f, header, sizeof(header)) == sizeof(header));
    mu_check(storage_file_write(f, rule, sizeof(TritRule)) == sizeof(TritRule));
    mu_check(storage_file_write(f, &crc, sizeof(crc)) == sizeof(crc));
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

// ---------------------------------------------------------------------------
// Policy file tests
// ---------------------------------------------------------------------------

MU_TEST(test_policy_file_parse_valid) {
    TritRule rule = make_unconditional_rule(KOI_DOMAIN_RF, TRIT_ALLOW, KOI_COMBINING_DENY_OVERRIDE);
    write_test_policy_file(KOI_DOMAIN_RF, &rule);

    TritRule out_rules[4];
    uint8_t out_count = 0;
    KoiPolicyFileError err = koi_policy_file_load(
        KOI_TEST_POLICY_PATH, KOI_DOMAIN_RF, out_rules, 4, &out_count);

    mu_assert_int_eq(KOI_POLICY_FILE_OK, err);
    mu_assert_int_eq(1, out_count);
    mu_assert_int_eq(KOI_DOMAIN_RF, out_rules[0].domain);
    mu_assert_int_eq(TRIT_ALLOW, out_rules[0].result);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, KOI_TEST_POLICY_PATH);
    furi_record_close(RECORD_STORAGE);
}

MU_TEST(test_policy_file_bad_magic_fails) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, KOI_TEST_POLICY_PATH);
    File* f = storage_file_alloc(storage);
    mu_check(storage_file_open(f, KOI_TEST_POLICY_PATH, FSAM_WRITE, FSOM_CREATE_NEW));
    uint8_t junk[] = {'X','X','X','X',1,0,0,0, 0,0,0,0};
    storage_file_write(f, junk, sizeof(junk));
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    TritRule out[4]; uint8_t count = 0;
    KoiPolicyFileError err = koi_policy_file_load(KOI_TEST_POLICY_PATH, KOI_DOMAIN_RF, out, 4, &count);
    mu_assert_int_eq(KOI_POLICY_FILE_BAD_MAGIC, err);

    storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, KOI_TEST_POLICY_PATH);
    furi_record_close(RECORD_STORAGE);
}

MU_TEST(test_policy_file_crc_mismatch_fails) {
    TritRule rule = make_unconditional_rule(KOI_DOMAIN_RF, TRIT_ALLOW, KOI_COMBINING_DENY_OVERRIDE);
    write_test_policy_file(KOI_DOMAIN_RF, &rule);

    // Corrupt the last byte of the file (part of the CRC footer)
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);
    mu_check(storage_file_open(f, KOI_TEST_POLICY_PATH, FSAM_READ_WRITE, FSOM_OPEN_EXISTING));
    uint32_t size = (uint32_t)storage_file_size(f);
    storage_file_seek(f, size - 1, true);
    uint8_t bad = 0xFF;
    storage_file_write(f, &bad, 1);
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    TritRule out[4]; uint8_t count = 0;
    KoiPolicyFileError err = koi_policy_file_load(KOI_TEST_POLICY_PATH, KOI_DOMAIN_RF, out, 4, &count);
    mu_assert_int_eq(KOI_POLICY_FILE_CRC_FAIL, err);

    storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, KOI_TEST_POLICY_PATH);
    furi_record_close(RECORD_STORAGE);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

void test_setup(void)    {}
void test_teardown(void) {}

MU_TEST_SUITE(test_koi_governance) {
    MU_SUITE_CONFIGURE(&test_setup, &test_teardown);
    MU_RUN_TEST(test_no_rules_returns_deny);
    MU_RUN_TEST(test_deny_override_any_deny_wins);
    MU_RUN_TEST(test_deny_override_all_allow_returns_allow);
    MU_RUN_TEST(test_permit_override_any_allow_wins);
    MU_RUN_TEST(test_first_applicable_returns_first_match);
    MU_RUN_TEST(test_first_applicable_falls_through_to_default);
    MU_RUN_TEST(test_consensus_majority_allow);
    MU_RUN_TEST(test_consensus_tie_returns_neutral);
    MU_RUN_TEST(test_rule_not_matching_skips_rule);
    MU_RUN_TEST(test_domain_filtering_ignores_other_domains);
    MU_RUN_TEST(test_multi_field_condition_all_must_match);
    MU_RUN_TEST(test_policy_file_parse_valid);
    MU_RUN_TEST(test_policy_file_bad_magic_fails);
    MU_RUN_TEST(test_policy_file_crc_mismatch_fails);
}

int run_minunit_test_koi_governance(void) {
    MU_RUN_SUITE(test_koi_governance);
    return MU_EXIT_CODE;
}

TEST_API_DEFINE(run_minunit_test_koi_governance)
