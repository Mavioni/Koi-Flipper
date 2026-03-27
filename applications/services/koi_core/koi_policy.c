#include "koi_policy.h"
#include <stdbool.h>

bool koi_rule_matches(const TritRule* rule, const koi_state_t* state) {
    const int8_t* fields = (const int8_t*)state;
    for(uint8_t i = 0; i < KOI_STATE_FIELD_COUNT; i++) {
        if(!(rule->input_mask & (uint16_t)(1u << i))) continue;
        uint8_t bit_pos  = KOI_TRIT_BITS_SHIFT(i);
        uint8_t byte_idx = bit_pos / 8u;
        uint8_t bit_idx  = bit_pos % 8u;
        uint8_t enc = (rule->input_trits[byte_idx] >> bit_idx) & 0x3u;
        trit_t required;
        switch(enc) {
        case KOI_TRIT_BITS_DENY:    required = TRIT_DENY;    break;
        case KOI_TRIT_BITS_NEUTRAL: required = TRIT_NEUTRAL; break;
        case KOI_TRIT_BITS_ALLOW:   required = TRIT_ALLOW;   break;
        default: continue; // KOI_TRIT_BITS_UNUSED — skip field
        }
        if(fields[i] != required) return false;
    }
    return true;
}

trit_t koi_policy_evaluate(
    const TritRule* rules,
    uint8_t rule_count,
    uint8_t domain,
    const koi_state_t* state)
{
    if(!rules || rule_count == 0 || !state) return TRIT_DENY;

    uint8_t combining = KOI_COMBINING_DENY_OVERRIDE;
    bool any_match = false;
    int16_t consensus_sum = 0;
    trit_t result = TRIT_DENY; // fail-closed default

    for(uint8_t i = 0; i < rule_count; i++) {
        if(rules[i].domain != domain) continue;
        if(!koi_rule_matches(&rules[i], state)) continue;

        if(!any_match) {
            combining = rules[i].combining;
            result = rules[i].result;
            any_match = true;
            consensus_sum = rules[i].result;
            if(combining == KOI_COMBINING_FIRST_APPLICABLE) return result;
            continue;
        }

        switch(combining) {
        case KOI_COMBINING_DENY_OVERRIDE:
            if(rules[i].result < result) result = rules[i].result;
            break;
        case KOI_COMBINING_PERMIT_OVERRIDE:
            if(rules[i].result > result) result = rules[i].result;
            break;
        case KOI_COMBINING_FIRST_APPLICABLE:
            break; // already returned on first match above
        case KOI_COMBINING_CONSENSUS:
            consensus_sum += rules[i].result;
            result = (consensus_sum > 0) ? TRIT_ALLOW :
                     (consensus_sum < 0) ? TRIT_DENY  : TRIT_NEUTRAL;
            break;
        }
    }

    return result;
}
