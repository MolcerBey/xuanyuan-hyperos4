# Molcer OS build status

**Current state: a complete offline-assembled experimental candidate, awaiting owner-controlled device and installer validation.** It is not a production release. Individual draft assets retain their `NOT-INSTALLABLE` names and must never be flashed independently; the only installation path is the complete verified 39-image local package plus `install_candidate.py`.

## Latest verified assembly

[Assembly run 42615835833](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42615835833) completed successfully on 2026-11-09. Assembly tooling commit: `8573d0d58843b008b2a94c79bc18346d1c436d16`. Customized product/init_boot source commit: `f6e13aba5442361c0247f28c6d203c368a7433b4`.

- Candidate: `0.2.0-experimental.1`, version code `2026110601`.
- Base: authenticated China HyperOS 4 / Android 17 `OS4.0.0.18.XOACNXM` for `xuanyuan`; target hardware variant is global.
- Owner-visible draft tag: `molcer-assembled-8573d0d58843-42615835833-1`.
- Persistent manifest: `reports/assembled-candidate-manifest.json`.
- Signed manual-package metadata: `updates/experimental-0.2.0.json` and `updates/experimental-0.2.0.signature.json`; public RSA verification passed. This is not an Android OTA or public release.

| Component | Bytes | SHA256 |
| --- | ---: | --- |
| Final AVB-footered product | 4,374,233,088 | `a68b03f20928e00ea6f93af43605e79bf7976127abd29001667b3d01d7f93c81` |
| KernelSU Next init_boot | 8,388,608 | `2fc66cc4166c4775184f6d56353227825adafc1fa137aad58f1931470ee39188` |
| Sparse super | 11,728,374,388 | `6f722e24977850a31fb792ea50ac97e4ad2722764290e5c27e14eda63d6dcce7` |
| vbmeta | 12,288 | `0f0ce6d72f36b660fa40c4ccb446e1629abccd167d6ac0cd12d1e8bc53559a7c` |
| vbmeta_system | 4,096 | `445a6f57f0758a57ecbb43c1556051990f4ef84b6daa9c0ee3443f4c47ca23b1` |
| EU modem | 172,568,576 | `abdb08bc80e2b9c837b40f54df5c34c1ea929b5d1c14e7cfebfc0b433b9a6d69` |
| EU global modemfirmware | 140,234,752 | `bfab29aac6a9337cb168bbc76455fda068c59be899b917b0038af2c88a7a1fe6` |

The complete local upload set totals 12,487,875,188 bytes. Every chunk and reconstructed image is checked against its pinned size and SHA256. The manifest covers 47 authenticated source partition records, the final super and 39 uploaded physical/super images.

## Completed offline gates

- The exact base archive passed its pinned SHA256 and Xiaomi whole-file CMS signature checks. The original download index's incorrect MD5 is not used.
- The two AVB metadata signatures were created with the local DPAPI-protected RSA4096 identity and verified with public material. `avb_flags=0`; the boot/recovery/vbmeta/vbmeta_system descriptor chain passed with OEM child keys preserved.
- The signed product and init_boot bindings were checked before AVB application and again in the final image inventory.
- Real pinned Linux `lpmake` produced a virtual-A/B sparse super. Geometry, all six metadata copies, group limits, sparse bounds and source hashes passed. Nine logical image payloads, including padding and AVB tails, were independently rehashed from super and matched exactly.
- The selected EU radio pair replaced the China base radio in the package. `countrycode`, userdata and device-unique NV/calibration partitions are excluded.
- The local suite passes 147 tests on Windows, with only the pinned-Linux FEC test skipped. [Linux run 42670599492](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42670599492) passed all 147 tests, including real FEC/lpmake/super checks.

Offline verification does not establish bootloader trust-root acceptance, real GPT capacity, successful fastboot execution or runtime behavior.

## Integrated customization

- Google Play Store 51.8.09-29 from the pinned MindTheGapps Android 17 ARM64 package replaces the China updater stub. Existing Google runtime APEX and Google Services Framework match the selected release byte-for-byte. The full GApps installer is not run.
- Official KernelSU Next 3.4.2 manager and a patched init_boot using the stock kernel's detected `android15-6.6` KMI. The stock kernel is preserved.
- Standalone Chrome 157.0.8103.38 ARM64, with its APK v3 signature and Turkish locale verified. No Trichrome dependency is required by this standalone package. Default-browser role activation still requires runtime testing.
- Five Turkish overlays contain 16,163 reviewed strings; a separate signed OLED-defaults overlay and black wallpaper are included. Default locale is `tr-TR`, timezone Europe/Istanbul, and Molcer OS version/branding metadata is included. Overlay runtime activation and complete Turkish coverage are not established.
- Sixteen reviewed optional packages were removed, including the Xiaomi browser and China Play updater. Stock camera, gallery, media editing, modem/IMS/carrier configuration and thermal controls are retained. The product build verified 2,270 retained entries and 285 protected camera/media paths; these static checks do not prove camera or IMS operation.

See `reports/product-preview-latest.json`, `reports/translations.json`, `reports/signed-overlays.json` and `reports/camera-preservation.json` for build-scope evidence. The product-stage report's `ready_to_flash=false` applies to the isolated product image, not to the later assembled package.

## Installation package and remaining device work

The local package is `work/final-package/images/`; the persistent manifest is `reports/assembled-candidate-manifest.json`. `verify_installation_package.py` verifies all bytes without phone access. Its conservative report intentionally keeps `ready_to_flash=false` and does not claim to implement installation.

`install_candidate.py` separately defines the reviewed 39-image order and an owner-invoked fastboot path. It checks model, unlocked bootloader, current slot and every target's real capacity before writes, requests `XUANYUAN-INSTALL`, flashes A/B physical partitions and sparse super, then selects slot A. It never erases userdata and excludes `countrycode`, `metadata`, `persist`, `modemst1/2`, `fsg`, `fsc`, `frp`, `logfs`, `storsec`, `toolsfv`, `misc` and `rescue`. Only mock/offline installer tests have run; no actual phone has been accessed.

Before any production claim, the owner must verify: successful flash and boot, slot state, AVB acceptance, KernelSU Next, Play Store sign-in and Play certification, Chrome default role, Turkish overlays and OLED defaults, all camera modes, SIM/data/SMS/calls, Turk Telekom VoLTE/VoWiFi, Wi-Fi, Bluetooth, NFC, GPS, fingerprint/face unlock, audio, charging and reboot stability. Preserve a full backup and a known-good recovery path.

Small reports are retained as Actions artifacts; large image chunks remain in an owner-visible private draft. The release is not public, and no automatic update or phone operation is enabled by project policy.
