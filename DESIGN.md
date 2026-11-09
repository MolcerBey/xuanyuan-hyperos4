# HyperOS 4 customization scope

Target: Xiaomi 15 Ultra, device `xuanyuan`; requested China HyperOS 4 / Android 17 base.

## Current stage

Authenticated source and a complete offline-assembled experimental candidate have been produced. See [BUILD-STATUS.md](BUILD-STATUS.md) for current implementation and validation results; the scope below is architectural background. No production-ready or device-verified ROM and no measured performance improvement have been produced. No phone flash, wipe, reboot, root installation, or bootloader change has been performed by project automation.

Camera runtime testing is mandatory for a production release and has not been performed. Structural checks of downloaded files and generated images remain required and do not constitute a compatibility guarantee.

## Base evidence

- Candidate public release name: `OS4.0.0.18.XOACNXM`.
- Internal OTA incremental: `17OS4.0.261014.195958428.QCPECN.S`.
- Metadata: Android 17, SDK 37, xuanyuan, AB full OTA.
- Download size: 10,321,978,949 bytes.
- Partition image total: 13,340,323,840 bytes.
- Product image: 5,208,166,400 bytes.
- Published MD5 from the download index: `bfc6faa7f2b6d205e3fa76f1f0438b6d`.
- The published MD5 was incorrect. Complete length matched. Actual MD5 is `bfc6faa7f25124b3352b7fb6e80d8e02`; authenticated SHA256 is `bd19c93fa7c1cb90ed194c5cc2ebfe786f55f1382b172e344522ca805c63f1ea`.
- OTA signer certificate DER SHA256: `d45f076fe23a1a5b7f486e3ff41547a2023dbfe1fe73353b1e48ebdfed72cc6f`.
- The signer certificate was independently extracted from the CMS signature and matches the OTA certificate in HyperOS 3.0.314.0 obtained from Xiaomi's `bigota.d.miui.com` CDN.
- Whole-file CMS verification succeeded in run 41927267094. Strict verification now pins both the archive SHA256 and the signer certificate; embedded certificates alone are not trusted.

## Planned changes after source approval

1. Inventory APK package IDs and system configuration from the base image.
2. Identify optional analytics/advertising components by exact package ID and review dependencies before removal. No blanket system-app removal.
3. Keep stock camera applications, camera framework services, processing libraries, lens configuration, vendor/ODM/DSP components and their permissions intact.
4. Keep stock thermal limits, CPU/GPU policies, encryption and SELinux. No speculative build.prop performance flags or forced refresh-rate settings.
5. Preserve filesystem owners, modes, capabilities, SELinux labels and symlinks during repacking; compare retained file contents and metadata before accepting an output.
6. Verify partition sizes and AVB/installation requirements before producing installation artifacts. Do not call an inspection report, module or stock ZIP a custom ROM.
7. Owner requested Turkish UI, Google Play, Chrome, KernelSU Next, OLED defaults and Molcer OS branding. Verify actual locale and Google dependencies before claiming support. Root uses the stock kernel KMI and an official pinned KernelSU Next release. Stock IMS/carrier configuration is preserved; the owner-selected EU global radio pair replaces the China radio, but Turkish network runtime compatibility remains unverified.

## Workflows

- `Verify HyperOS 4 base`: unit checks, bounded metadata inspection, full source download, checksum verification, quarantine diagnostics on failure.
- `Inspect product partition`: verifies the source before extracting the product image; checks operation hashes and final partition SHA256; generates a read-only APK inventory.
- Inspection and build jobs run on GitHub's standard public-repository Linux runner with short report-artifact retention. Product image previews are saved separately in draft releases. No phone data is collected.

## Validation

The discovery suite contains 147 unit tests covering identity, wrong device, delta rejection, truncated protobuf, partition reconstruction, corruption rejection, kernel KMI detection, filesystem preservation, resource overlay policy, AVB/super packaging, deterministic radio archives, bounded asset-download timeouts and offline installation-bundle verification. `test-all.yml` runs the complete suite and real Linux packaging smoke tests on every push and pull request.

## Sources

- https://hyperosfirmware.com/model/xuanyuan/recovery/OS4.0.0.18.XOACNXM
- https://bigota.d.miui.com/OS4.0.0.18.XOACNXM/xuanyuan-ota_full-OS4.0.0.18.XOACNXM-user-17.0-bfc6faa7f2.zip
- https://bigota.d.miui.com/OS3.0.314.0.WOACNXM/xuanyuan-ota_full-OS3.0.314.0.WOACNXM-user-16.0-9f74d1725b.zip
- https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto
- https://erofs.docs.kernel.org/en/latest/mkfs.html
