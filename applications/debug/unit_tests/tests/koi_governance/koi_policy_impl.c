/* Compile koi_policy implementation directly into the test plugin.
 * Temporary until koi_core is wired into the firmware SDK in Task 5/6.
 */
#include <koi_core/koi_policy.c>      // NOLINT(bugprone-suspicious-include)
#include <koi_core/koi_policy_file.c> // NOLINT(bugprone-suspicious-include)
