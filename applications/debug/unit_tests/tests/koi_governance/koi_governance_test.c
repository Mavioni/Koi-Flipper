#include "../test.h" // IWYU pragma: keep
#include <furi.h>
#include <koi_core/koi_trit.h>
#include <koi_core/koi_policy.h>

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
}

int run_minunit_test_koi_governance(void) {
    MU_RUN_SUITE(test_koi_governance);
    return MU_EXIT_CODE;
}

TEST_API_DEFINE(run_minunit_test_koi_governance)
