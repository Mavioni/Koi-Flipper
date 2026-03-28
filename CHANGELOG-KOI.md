# Koi Firmware Changelog

All notable Koi-specific changes are documented here.
For upstream RogueMaster changes, see [CHANGELOG.md](CHANGELOG.md).

## [0.3.0] - 2026-03-28

### Added
- **koi_vault FAP** — Encrypted knowledge vault with dual-vault architecture
  - AES-256-XTS sector-level encryption (mbedtls, exported to SDK)
  - PBKDF2-HMAC-SHA256 key derivation (100K iterations, bundled trezor-crypto)
  - Chunked 1GB storage files at `/ext/vault/{alpha,beta}/chunk_NNN.koi`
  - Encrypted key-value index (195 entries max, 8KB RAM cache)
  - Dual vault: Alpha (primary) + Beta (decoy/secondary)
  - Duress PIN: opens Beta vault, wipes Alpha keys from SRAM, logs audit event
  - Governance integration: all operations gated by `koi_core_evaluate(KOI_DOMAIN_VAULT)`
  - PIN entry view: numeric keypad on 128x64, lockout after 5 failed attempts
  - File browser view: scrollable list with add/delete operations
  - Settings view: create vault, change PIN, configure duress PIN
  - Auto-lock after 5 minutes of inactivity
  - 15 on-device unit tests (PBKDF2 vectors, AES-XTS roundtrip, storage, index)
- **SDK symbol exports**: mbedtls AES-XTS (5), SHA-256 (8), MD/HMAC (20) now available to external FAPs
- **Koi Build CI**: GitHub Actions workflow on `ubuntu-latest` with firmware artifact upload

### Planned
- Encrypted vault file import/export (Phase 3b)
- WireGuard/Tailscale networking (Phase 4)
- Sub-GHz mesh protocol (Phase 5)

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
