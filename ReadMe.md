# Koi Firmware

**Sovereign intelligence firmware for Flipper Zero.**

Built on [RogueMaster](https://github.com/RogueMaster/flipperzero-firmware-wPlugins) with all 611+ community apps, plus:

- **LUMINA** — Sovereign AI companion with tiered ternary inference
- **Ternary Governance Engine** — {-1, 0, +1} policy decisions for all device operations
- **Encrypted Knowledge Vaults** — AES-256 hardware-accelerated storage with PBKDF2 key derivation
- **Tailscale Networking** — WireGuard tunnels via ESP32 WiFi devboard
- **Mesh Communications** — Sub-GHz and LoRa peer-to-peer with NFC identity exchange

## Install

1. Download the latest release from [Releases](https://github.com/Mavioni/Koi-Flipper/releases)
2. Extract the `.tgz` file
3. Copy the extracted folder to your Flipper Zero's SD card `/update/` directory
4. On the Flipper: press down on Desktop → Archive → Browser → navigate to update folder → run update

## Build from Source

```bash
git clone --recurse-submodules https://github.com/Mavioni/Koi-Flipper.git
cd Koi-Flipper
./fbt updater_package
```

Build output: `dist/f7-C/f7-update-Koi420FAP/`

## Credits

- [RogueMaster](https://github.com/RogueMaster/flipperzero-firmware-wPlugins) — upstream firmware
- [Flipper Devices](https://github.com/flipperdevices/flipperzero-firmware) — official firmware
- All community plugin authors (see individual app READMEs)

## License

GPL-3.0 (inherited from upstream)
