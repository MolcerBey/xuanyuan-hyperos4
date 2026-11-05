# Molcer OS — Xiaomi 15 Ultra

Work in progress for `xuanyuan`, based on the manufacturer-signed China HyperOS 4 / Android 17 OTA `OS4.0.0.18.XOACNXM`.

Requested configuration: KernelSU Next, Google Play, Turkish UI, Chrome as default browser, and removal of reviewed optional applications. Preserve stock camera, modem, IMS, carrier configuration and security services. No speculative performance properties or thermal-limit changes.

**No installable Molcer OS ROM has been produced yet.** An audited modified product image and an offline KernelSU Next init_boot candidate have been built. AVB, complete packaging and boot validation remain pending. See [BUILD-STATUS.md](BUILD-STATUS.md) for the current Google package selection, completed checks and remaining limitations.

The original download index contained an incorrect MD5. The exact source archive was independently authenticated with its valid whole-file CMS signature and the Xiaomi certificate also present in the stock HyperOS 3 OTA. `base.json` pins the authenticated archive SHA256 and certificate. Downloads must pass both checks.

Downloads have transfer-speed and duration limits and use the manufacturer's alternate OTA endpoint when appropriate. All APK inputs come from pinned public packages; applications are not extracted from the phone.

Camera runtime tests were waived by the owner. Camera, Turkish carrier/VoLTE/VoWiFi operation, Play certification and full Turkish coverage are not verified. No phone flashing, wiping or rebooting is performed by this project.

The target is GLOBAL hardware on Turk Telekom. At the owner's request, the global hardware branch inside their exact Xiaomi.eu OS3.0.314.0.WOACNXM release (`modem.img` plus `modemfirmware_ww.img`) is staged and wired into preview packaging by `integrate_radio.py`. See the [output manifest](reports/rom-radio-integration.json) and [RADIO-STATUS.md](RADIO-STATUS.md) for release verification and Android16-to-Android17 integration limits. All phone access is prohibited; work uses downloaded packages only.

See [Actions](https://github.com/MolcerBey/xuanyuan-hyperos4/actions) for actual results. Reports and offline candidates must not be mistaken for a finished ROM.
