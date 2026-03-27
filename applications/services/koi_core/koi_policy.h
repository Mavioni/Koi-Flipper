#pragma once
#include "koi_trit.h"
#include <stdbool.h>

/**
 * Evaluate policy rules for a domain against the current device state.
 *
 * Filtering: only rules with rule->domain == domain are evaluated.
 * Combining: determined by the first matching rule's `combining` field.
 *            All subsequent rules in the same evaluation use the same algorithm.
 * Default: TRIT_DENY if no rules match (fail-closed).
 *
 * @param rules      Pointer to rule array (may be NULL if rule_count == 0)
 * @param rule_count Number of rules in the array
 * @param domain     KOI_DOMAIN_* constant
 * @param state      Current device state vector
 * @return TRIT_DENY (-1), TRIT_NEUTRAL (0), or TRIT_ALLOW (+1)
 */
trit_t koi_policy_evaluate(
    const TritRule* rules,
    uint8_t rule_count,
    uint8_t domain,
    const koi_state_t* state);

/**
 * Check whether a single rule's field conditions match the given state.
 * Exported for testing; prefer koi_policy_evaluate() in production code.
 */
bool koi_rule_matches(const TritRule* rule, const koi_state_t* state);
