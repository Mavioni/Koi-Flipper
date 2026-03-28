# Koi Firmware Changelog

All notable Koi-specific changes are documented here.
For upstream RogueMaster changes, see [CHANGELOG.md](CHANGELOG.md).

## [0.2.0] - 2026-03-28

### Added
- **koi_core service** — Furi RTOS service providing ternary governance engine
  - `koi_trit.h`: canonical type definitions (`trit_t`, `koi_state_t` 9-field vector, `TritRule` 11B packed)
  - `koi_policy.c`: evaluation engine with 4 combining algorithms (DenyOverride, PermitOverride, FirstApplicable, Consensus)
  - `koi_policy_file.c`: binary `.trit` file parser with CRC32 integrity verification
  - `koi_audit.c`: 128-entry ring buffer with SD card append-only flush
  - `koi_core.c`: Furi service task, policy loading, FuriRecord registration, thread-safe API
- **koi_governance FAP** — UI application for browsing governance state
  - State view: scrollable 9-field `koi_state_t` display
  - Policy view: per-domain rule browser with live decision evaluation
  - Audit view: scrollable 128-entry decision log (newest first)
- **Default policies** for 5 domains (RF, BLE, Vault, Mesh, App)
  - `gen_default_policies.py` generator script
  - Binary `.trit` files deployed to `/ext/governance/` on SD card
- 17 on-device MinUnit tests covering evaluation engine, file parser, and audit buffer

### Planned
- Encrypted knowledge vaults (Phase 3)
- WireGuard/Tailscale networking (Phase 4)
- Sub-GHz mesh protocol (Phase 5)

## [0.1.0] - 2026-03-25

### Added
- Forked from RogueMaster firmware (branch 420)
- Koi branding (firmware origin, build artifacts, boot animations)
- Custom build script (buildKoi.sh)
- Koi README with install and build instructions

### Planned (at time of release)
- Ternary governance engine (delivered in 0.2.0)
- Encrypted knowledge vaults (delivered in future)
- WireGuard/Tailscale networking (delivered in future)
- Sub-GHz mesh protocol (delivered in future)
