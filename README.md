# Molcer OS — Xiaomi 15 Ultra

Work in progress for `xuanyuan`, based on the manufacturer-signed China HyperOS 4 / Android 17 OTA `OS4.0.0.18.XOACNXM`.

Requested configuration: KernelSU Next, Google Play, Turkish UI, Chrome as default browser, and removal of reviewed optional applications. Preserve stock camera, modem, IMS, carrier configuration and security services. No speculative performance properties or thermal-limit changes.

**No installable Molcer OS ROM has been produced yet.** Source authentication and extraction tools are implemented. The Actions workflow inventories product/system/system_ext packages and locale resources, then prepares an offline KernelSU Next init_boot candidate. That candidate is not an installation package: AVB, complete packaging and boot validation are pending.

The original download index contained an incorrect MD5. The exact source archive was independently authenticated with its valid whole-file CMS signature and the Xiaomi certificate also present in the stock HyperOS 3 OTA. `base.json` pins the authenticated archive SHA256 and certificate. Downloads must pass both checks.

The previous inspection run timed out during download. Downloads now have transfer-speed and duration limits and try the manufacturer's alternate OTA endpoint.

Camera runtime tests were waived by the owner. Camera, Turkish carrier/VoLTE/VoWiFi operation, Play certification and full Turkish coverage are not verified. No phone flashing, wiping or rebooting is performed by this project.

See [Actions](https://github.com/MolcerBey/xuanyuan-hyperos4/actions) for actual results. Reports and offline candidates must not be mistaken for a finished ROM.
