# Molcer OS build status

**An audited product image preview has been produced, not an installable ROM.** Complete installation packaging, AVB integration and boot validation remain unfinished. Draft assets are explicitly named `NOT-INSTALLABLE`; do not flash them independently.

## First successful preview

- Google Play Store 51.8.09-29 from MindTheGapps Android 17 ARM64 replaces the China Play updater stub. Existing Google runtime and framework are preserved and compared against the selected release.
- Official KernelSU Next 3.4.2 manager; a separate patched `init_boot` candidate uses the stock kernel's detected `android15-6.6` KMI.
- Chrome and its matching Trichrome library. The pinned NikGapps catalog build is 134.0.6998.135; it is **not current Chrome**. A current browser package or verified Play update path is still needed before release.
- Eleven reviewed optional packages removed; Xiaomi browser replaced. Camera, gallery, editing dependencies, modem, IMS, carrier and thermal configuration are retained.
- Molcer OS branding and the `tr-TR` default locale. Resource-only Turkish overlays are under build validation; full Turkish coverage is not established.

The first product image shrank from 5,208,166,400 to 4,519,911,424 bytes. The build checked 2,277 retained filesystem entries, then remounted the generated EROFS image and compared its content, ownership, permissions, extended attributes and symlinks with the staged tree. This is a size measurement, not a performance or battery-life benchmark.

## Google package source

No application is extracted from the phone. As checked on 2026-11-05, the latest published stable [MindTheGapps Android 17 ARM64 release](https://github.com/MindTheGapps/17.0.0-arm64/releases/tag/MindTheGapps-17.0.0-arm64-20261022_132445) is dated 2026-10-22. `gapps-assets.json` pins its URL, size and SHA256. APK/APEX signatures were inspected with Android SDK Build Tools 37.0.0.

Integration is selective: the Play Store and its privileged permission entry are installed, while existing core services are compared before replacement is considered. The entire GApps installer is not run against HyperOS. The unrequested Exchange component fails signature verification and is excluded. Android version and architecture matching do not establish runtime compatibility or Play certification.

## Validation and remaining work

The source archive must pass its pinned SHA256 and Xiaomi whole-file CMS signature checks before extraction. Full-OTA operation hashes and resulting partition hashes are checked. Nineteen unit checks cover identity, extraction, kernel KMI detection, retained filesystem data and overlay policy selection.

Static inspection found Turkish MCC 286 APNs, including Turkcell, Vodafone, Türk Telekom and Netgsm. Calls, data, SMS, VoLTE and VoWiFi remain untested. Camera runtime tests were waived by the owner; preserved camera files do not prove flawless operation.

Turkish overlays only use resources permitted by the target application's overlay policy. They preserve OEM APKs and signatures and skip missing or format-sensitive strings. Preview signing keys are temporary and are not a production update-signing setup.

Builds use GitHub's standard public-repository Ubuntu runner. Small reports have seven-day artifact retention; large preview images are split into files below 2 GiB and saved in a draft release for owner review. No phone flashing, wiping or rebooting is performed.

See [Actions](https://github.com/MolcerBey/xuanyuan-hyperos4/actions) and [draft releases](https://github.com/MolcerBey/xuanyuan-hyperos4/releases) for observed build results.
