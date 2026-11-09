# Molcer OS — Xiaomi 15 Ultra

Experimental build for global `xuanyuan`, based on the manufacturer-authenticated China HyperOS 4 / Android 17 OTA `OS4.0.0.18.XOACNXM`.

The current candidate is **Molcer OS 0.2.0-experimental.1**. It includes KernelSU Next 3.4.2, Google Play Store, standalone Chrome 157.0.8103.38, Turkish resource overlays, OLED defaults and removal of reviewed optional applications. Stock camera, IMS, carrier configuration, security services and thermal limits are preserved. No speculative performance properties are added.

**A fully assembled offline candidate now exists, but it is not a production-ready or device-verified ROM.** [Final assembly run 42615835833](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42615835833) passed AVB, super and complete image-hash verification. Boot acceptance, camera, modem/IMS, Play certification, Turkish coverage and installer execution on real hardware remain unverified. See [BUILD-STATUS.md](BUILD-STATUS.md).

## Candidate evidence

- Persistent manifest: `reports/assembled-candidate-manifest.json`.
- Local image directory: `work/final-package/images/` (39 images, 12,487,875,188 bytes in total).
- Product: 4,374,233,088 bytes; SHA256 `a68b03f20928e00ea6f93af43605e79bf7976127abd29001667b3d01d7f93c81`.
- KernelSU Next init_boot: SHA256 `2fc66cc4166c4775184f6d56353227825adafc1fa137aad58f1931470ee39188`.
- Sparse super: 11,728,374,388 bytes; SHA256 `6f722e24977850a31fb792ea50ac97e4ad2722764290e5c27e14eda63d6dcce7`.
- AVB flags are zero; the complete descriptor chain and both local metadata signatures passed offline verification. This does not prove acceptance by the phone's bootloader trust root.
- All nine logical images were re-extracted from the built super and matched their source hashes. Actual device GPT capacity has not been checked.

The owner-selected Xiaomi.eu OS3.0.314.0.WOACNXM `modem.img` and global `modemfirmware_ww.img` are integrated unchanged. Their Android 16-to-Android 17 interoperability is not proven. Device-unique NV/calibration partitions and China `countrycode` are excluded. See [RADIO-STATUS.md](RADIO-STATUS.md).

## Local verification without phone access

Run from the repository root:

```bash
py -3 verify_installation_package.py \
  --manifest reports/assembled-candidate-manifest.json \
  --images work/final-package/images \
  --output work/local-installation-verification.json

py -3 install_candidate.py \
  --manifest reports/assembled-candidate-manifest.json \
  --images work/final-package/images
```

The first command rehashes every local image. The second prints the reviewed installation plan and does not access a phone. The verification report deliberately retains conservative `ready_to_flash=false` and `installation_order_defined=false` fields; the separate installer owns the installation plan and optional execution path.

## Owner-run manual installation

Only the owner should run this command, after making a complete backup, unlocking the bootloader and entering fastboot mode:

```bash
py -3 install_candidate.py \
  --manifest reports/assembled-candidate-manifest.json \
  --images work/final-package/images \
  --execute --reboot
```

The installer checks the `xuanyuan` model, unlocked state, active slot and every real target partition's capacity before any write. It requires the exact confirmation `XUANYUAN-INSTALL`, flashes both A/B physical slots plus one sparse super, then activates slot A. It does not erase userdata or touch the protected partitions listed in `install_candidate.py`. No data wipe does not mean no risk of data loss or an unbootable device.

The release assets remain individually named `NOT-INSTALLABLE`: **never flash a separate chunk or an isolated product/init_boot asset**. Use only the complete, locally verified 39-image directory with the installer. The manifest's conservative `installable_rom_produced=false` and `installation_allowed=false` fields describe release policy, not a substitute for the owner's explicit installation decision.

There is no Android OTA updater, automatic installer or recovery-installable OTA ZIP. The signed manual-package index is `updates/experimental-0.2.0.json`, with its detached signature in `updates/experimental-0.2.0.signature.json`. See [OTA-STATUS.md](OTA-STATUS.md).

Project automation never accesses, flashes, wipes or reboots a phone. All source downloads are pinned and authenticated; no application or private partition is extracted from the owner's device.
