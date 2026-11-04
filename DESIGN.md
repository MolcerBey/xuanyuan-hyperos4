# HyperOS 4 customization scope

Target: Xiaomi 15 Ultra, device `xuanyuan`; requested China HyperOS 4 / Android 17 base.

## Current stage

Source investigation only. No flashable custom ROM, modified partition, or performance improvement has been produced. No phone flash, wipe, reboot, root installation, or bootloader change has been performed.

The owner explicitly waived camera runtime testing. This does not constitute a compatibility guarantee. Structural checks of downloaded files and generated images remain required.

## Base evidence

- Candidate public release name: `OS4.0.0.18.XOACNXM`.
- Internal OTA incremental: `17OS4.0.261014.195958428.QCPECN.S`.
- Metadata: Android 17, SDK 37, xuanyuan, AB full OTA.
- Download size: 10,321,978,949 bytes.
- Partition image total: 13,340,323,840 bytes.
- Product image: 5,208,166,400 bytes.
- Published MD5 from the download index: `bfc6faa7f2b6d205e3fa76f1f0438b6d`.
- First complete GitHub download failed the published MD5/length gate. The follow-up job records both actual values and verifies the embedded whole-file signature.
- OTA signer certificate DER SHA256: `d45f076fe23a1a5b7f486e3ff41547a2023dbfe1fe73353b1e48ebdfed72cc6f`.
- The signer certificate was independently extracted from the CMS signature and matches the OTA certificate in HyperOS 3.0.314.0 obtained from Xiaomi's `bigota.d.miui.com` CDN.
- Certificate equality alone does not prove a valid signature over this archive. A failed checksum must not be replaced with a newly measured value without independently authenticating the exact content.

## Planned changes after source approval

1. Inventory APK package IDs and system configuration from the base image.
2. Identify optional analytics/advertising components by exact package ID and review dependencies before removal. No blanket system-app removal.
3. Keep stock camera applications, camera framework services, processing libraries, lens configuration, vendor/ODM/DSP components and their permissions intact.
4. Keep stock thermal limits, CPU/GPU policies, encryption and SELinux. No speculative build.prop performance flags or forced refresh-rate settings.
5. Preserve filesystem owners, modes, capabilities, SELinux labels and symlinks during repacking; compare retained file contents and metadata before accepting an output.
6. Verify partition sizes and AVB/installation requirements before producing installation artifacts. Do not call an inspection report, module or stock ZIP a custom ROM.
7. Treat Turkish UI, Google Play/Android Auto and root as explicit product choices; support depends on the inspected base and user preferences.

## Workflows

- `Verify HyperOS 4 base`: unit checks, bounded metadata inspection, full source download, checksum verification, quarantine diagnostics on failure.
- `Inspect product partition`: verifies the source before extracting the product image; checks operation hashes and final partition SHA256; generates a read-only APK inventory.
- Both jobs run on GitHub's standard public-repository Linux runner with short artifact retention. Artifacts currently contain reports only, not the ROM or phone data.

## Validation

Eight local unit checks cover valid identity, wrong device, delta rejection, truncated protobuf, raw/bzip2/xz partition reconstruction and corruption rejection.

## Sources

- https://hyperosfirmware.com/model/xuanyuan/recovery/OS4.0.0.18.XOACNXM
- https://bigota.d.miui.com/OS4.0.0.18.XOACNXM/xuanyuan-ota_full-OS4.0.0.18.XOACNXM-user-17.0-bfc6faa7f2.zip
- https://bigota.d.miui.com/OS3.0.314.0.WOACNXM/xuanyuan-ota_full-OS3.0.314.0.WOACNXM-user-16.0-9f74d1725b.zip
- https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto
- https://erofs.docs.kernel.org/en/latest/mkfs.html
