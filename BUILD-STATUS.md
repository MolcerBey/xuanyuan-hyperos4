# Molcer OS build status

**An audited product image preview has been produced, not an installable ROM.** Complete installation packaging, AVB integration and boot validation remain unfinished. Draft assets are explicitly named `NOT-INSTALLABLE`; do not flash them independently.

## Latest successful preview

[Build 42022961429](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42022961429) succeeded for commit `4591cf49c0c9c88b50bbb7b5fc2b1f8c83758214`. All ten assets are uploaded in the [owner-visible draft release](https://github.com/MolcerBey/xuanyuan-hyperos4/releases/tag/untagged-ec2b439672af0ec463e9). APK package inspection also passed in [run 42024352099](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42024352099).

- Google Play Store 51.8.09-29 from MindTheGapps Android 17 ARM64 replaces the China Play updater stub. The retained Google runtime APEX and Google Services Framework are byte-identical to the selected release; both SHA256 comparisons passed.
- Official KernelSU Next 3.4.2 manager; a separate patched `init_boot` candidate uses the stock kernel's detected `android15-6.6` KMI.
- Chrome and its matching Trichrome library. The pinned NikGapps catalog build is 134.0.6998.135; it is **not current Chrome**. A current browser package or verified Play update path is still needed before release.
- Eleven reviewed optional packages removed; Xiaomi browser replaced. Camera, gallery, editing dependencies, modem, IMS, carrier and thermal configuration are retained.
- Molcer OS branding, `tr-TR` default locale and Europe/Istanbul timezone. Six resource-only overlays compiled and passed APK signature verification: five Turkish overlays contain 16,163 strings, and one sets the framework's default-browser resource to Chrome. Runtime activation and full Turkish coverage are not established.

The latest product image is 4,521,066,496 bytes, compared with the stock image's 5,208,166,400 bytes. SHA256: `d0acdf531ecb428823c52c782704f39d180cb29ce79b0be5758f62ec8d83c0c1`. The build checked 2,277 retained filesystem entries, then remounted the generated EROFS image and compared its content, ownership, permissions, extended attributes and symlinks with the staged tree. This is a size measurement, not a performance or battery-life benchmark.

| Turkish resource target | Compiled strings |
| --- | ---: |
| Android framework | 2,106 |
| Setup | 795 |
| Launcher | 88 |
| System UI | 1,958 |
| Settings | 11,216 |

See `reports/translations.json` for skipped strings and `reports/product-preview-latest.json` for exact Google core hashes. The draft's generic NOT-INSTALLABLE note still lists Google runtime assessment; the accompanying build report resolves that item through byte-for-byte equality. The installation and runtime limitations remain.

## Google package source

No application is extracted from the phone. As checked on 2026-11-05, the latest published stable [MindTheGapps Android 17 ARM64 release](https://github.com/MindTheGapps/17.0.0-arm64/releases/tag/MindTheGapps-17.0.0-arm64-20261022_132445) is dated 2026-10-22. `gapps-assets.json` pins its URL, size and SHA256. APK/APEX signatures were inspected with Android SDK Build Tools 37.0.0.

Integration is selective: the Play Store and its privileged permission entry are installed, while existing core services are preserved because they match exactly. The entire GApps installer is not run against HyperOS. The unrequested Exchange component fails signature verification and is excluded. Android version and architecture matching do not establish runtime compatibility or Play certification.

## Validation and remaining work

Global-device radio evidence and the authenticated Android17 `modem` + `modemfirmware` candidate are recorded in [RADIO-STATUS.md](RADIO-STATUS.md). The Turk Telekom MBN exists in both sources but differs between China and global. Runtime compatibility remains pending; no modem change has been applied to the phone.

The owner confirmed GLOBAL hardware and a currently working Turk Telekom connection on Xiaomi.eu. This changes the radio integration assumptions: the China base's modem must not be automatically included in a global-device flash plan. [Xiaomi.eu maintainer documentation](https://miuipolska.pl/xiaomi-15-ultra-xiaomi-eu/) records loss of coverage with the China modem on global Xiaomi 15 Ultra hardware, but its linked Android15 modem is not evidence of compatibility with this Android17 beta. `radio-policy.json` records the requirement to preserve the known-working global modem pending identification and compatibility checks. This is a packaging constraint, not a modem modification already applied to the phone. Device-unique NV/calibration partitions remain untouched. Current source modem/MBN and IMS inspection runs separately in `inspect-radio.yml`.

The source archive must pass its pinned SHA256 and Xiaomi whole-file CMS signature checks before extraction. Full-OTA operation hashes and resulting partition hashes are checked. Nineteen unit checks cover identity, extraction, kernel KMI detection, retained filesystem data and overlay policy selection.

Static inspection found Turkish MCC 286 APNs, including Turkcell, Vodafone, Türk Telekom and Netgsm. Calls, data, SMS, VoLTE and VoWiFi remain untested. Camera runtime tests were waived by the owner; preserved camera files do not prove flawless operation.

Turkish overlays only use resources permitted by the target application's overlay policy. They preserve OEM APKs and signatures and skip missing or format-sensitive strings. Preview signing keys are temporary and are not a production update-signing setup.

Builds use GitHub's standard public-repository Ubuntu runner. Small reports have seven-day artifact retention; large preview images are split into files below 2 GiB and saved in a draft release for owner review. No phone flashing, wiping or rebooting is performed.

See [Actions](https://github.com/MolcerBey/xuanyuan-hyperos4/actions) and [draft releases](https://github.com/MolcerBey/xuanyuan-hyperos4/releases) for observed build results.
