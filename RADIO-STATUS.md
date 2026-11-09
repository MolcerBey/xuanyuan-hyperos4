# Global Xiaomi 15 Ultra / Turk Telekom radio work

The owner confirmed global hardware, Xiaomi.eu OS3.0.314.0.WOACNXM (Android16), and a working Turk Telekom connection. All phone access, including read-only ADB, is prohibited by the owner. Work uses downloaded ROM files only; no active-device radio contents are claimed to have been read.

## Selected source: exact owner-specified Xiaomi.eu ROM

The selected Molcer OS radio integration source is now `eu-radio-source.json`, built by `prepare_eu_radio.py`. It uses `images/modem.img` and `images/modemfirmware_ww.img` from `xiaomi.eu_XUANYUAN_OS3.0.314.0.WOACNXM_16_343f98d215.zip`. Direct inspection of this package's Windows and Linux installers confirmed that `HwCountry=CN` selects the ordinary `modemfirmware.img`, while other hardware selects `modemfirmware_ww.img`. The installer scripts are read and hashed as evidence; they are never executed.

The official Xiaomi.eu SourceForge download page publishes full archive SHA256 `9c1eced1591d5ad28998e7731a0555ce824074fdfe2061e7cad43b59da835157`. The builder verifies the complete archive before extracting either radio file, checks installer hashes and ZIP member sizes/CRCs, then records each extracted file's SHA256. This is verification against Xiaomi.eu's published release checksum, not a claim of Xiaomi whole-file signing for the customized EU ZIP.

These files are selected because the owner explicitly requested the radio branch supplied with their working EU version. Matching that release does not prove that a later manual modem change was never made, or establish Android16-to-Android17 vendor/radio compatibility. Full Molcer OS installation and runtime validation remain pending. No phone connection is requested or required for source preparation.

Preparation succeeded in [run 42067682905](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42067682905). The [verified EU radio artifact](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42067682905/artifacts/13433824127) contains the selected pair with checksums and provenance; artifact retention is three days. `reports/eu-radio-reference.json` records:

- Common `modem.img`: 172,568,576 bytes; SHA256 `abdb08bc80e2b9c837b40f54df5c34c1ea929b5d1c14e7cfebfc0b433b9a6d69`.
- Global `modemfirmware_ww.img`: 140,234,752 bytes; SHA256 `bfab29aac6a9337cb168bbc76455fda068c59be899b917b0038af2c88a7a1fe6`.

The common/global distinction comes from the exact EU release's installer, not from guessing that all radio partitions must come from a separate stock Global ROM. No downloaded installer was executed.

## Integrated into Molcer OS build staging

At the owner's explicit request, `integrate_radio.py` now stages the selected pair into `out/rom-radio/images/modem.img` and `out/rom-radio/images/modemfirmware.img`. The latter contains the unchanged **WW** image, despite using the destination partition name. The [integration manifest](reports/rom-radio-integration.json) records both actual output hashes. Both source hashes must pass before any output is created, and the copies are checked again. China/global substitutions, a mixed pair, duplicate ZIP names and unexpected archive paths are rejected.

The full preview workflow includes these two images and their manifest alongside the product and KernelSU Next assets. The lightweight `integrate-radio.yml` workflow packages the same inputs and attaches them to the existing owner draft preview, allowing radio integration without rebuilding an unchanged product image. An expired source artifact falls back to downloading and authenticating the exact EU archive; it never silently chooses a different donor.

[Integration run 42076078828](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42076078828) passed all nine tests, staged both pinned images, and uploaded `NOT-INSTALLABLE-Molcer-OS-EU-radio.zip` plus its manifest to the existing draft release. [Run 42112450003](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42112450003) later refreshed that draft with the same verified image manifest. The current release ZIP SHA256 is `1a68e21b1f0a7edaec9b458e9035cf9f5b393658cdcd169a4de7a01a93454665`; the earlier ZIP hash `584801c068786147ba555da355b64d758aa73e2a50edf2426b29f7726e49d15e` in [build evidence](reports/rom-radio-preview-build.json) is historical. New archive tooling uses fixed ZIP metadata and verifies the staged images before packaging.

This is actual inclusion in build staging and preview packaging, **not completion of a flashable ROM**. The integration workflow never accesses a device and does not provide a flashing script. Full packaging, AVB and Android17 runtime compatibility remain pending.

## Completed offline compatibility comparison

**Verdict: full Android17 compatibility is not proven.** This does not mean that definite incompatibility has been established. [Run 42071526692](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42071526692) successfully compared the exact selected EU pair with the original radio pair from the authenticated OS4.0.0.18.XOACNXM Molcer OS base. All four images were mounted read-only in GitHub Actions; no phone was accessed.

The permanent [assessment](reports/eu-radio-compatibility-assessment.json) records source hashes and the full report's SHA256. The [full report artifact](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42071526692/artifacts/13436542038) expires on 2026-11-12; a local copy is retained in `reports/eu-molcer-radio-compatibility.json`.

- EU contains 1,134 files and the target 1,151, with no inventory read errors or omissions. Of 1,131 shared paths, 339 files are identical and 792 differ. Three paths exist only in EU and twenty only in the target. These counts are not a compatibility score.
- All 71 shared ELF headers match in the inspected class, endianness, machine, ELF type and ABI-version fields. Segment layout and proprietary protocols were not validated.
- Both pairs declare the same FAT logical volume lengths: 211,812,352 bytes for `modem` and 257,949,696 for `modemfirmware`. Stored image lengths are shorter. This does not prove corruption or actual GPT partition fit; allocated-file reads succeeded, but a full FAT allocation check was not performed.
- The selected EU global firmware contains and indexes the Turk Telekom profile in both `mbn_sw.txt` and `oem_sw.txt`. Its size is 51,008 bytes and SHA256 is `e48dcc969890d95fc66d458fbf8a1ad0c81d198df1d69c6a7b0e37584a279030`. The target China profile is 52,432 bytes with SHA256 `823ad8435f85f110ce7d203b95db7042bf7e2269d09d747dfb96ee9d59b98f06`. Profile availability does not prove active selection or IMS registration.
- EU `qdsp6_oemsw.mbn` contains the literal identifier `MPSS.DE.7.0.c5-00035-PAKALA_GEN_PACK-1.115597.42.123326.19`. No equivalent core modem version string was recovered from the target by this scanner, so an exact core baseband-version comparison cannot be claimed. The ADSP/CDSP/SOCCP literal identifiers match. Literal identifiers do not establish protocol interoperability.

The unresolved issue is pairing an Android16 radio release with the Android17 vendor/RIL/IMS implementation. [Android's IMS documentation](https://source.android.com/docs/core/connect/ims) describes vendor-specific interfaces for work offloaded to the modem; matching public interfaces alone cannot establish that pairing. Active carrier selection, calls/data/VoLTE/VoWiFi, boot acceptance, firmware rollback and device partition capacity remain unverified. The exact EU source remains selected as requested, but it has not been integrated into an installable Molcer OS package, and `installation_allowed` remains false. No alternative modem was silently substituted.

## Previously prepared Android17 alternative

- China base: OS4.0.0.18.XOACNXM, Android17, device xuanyuan.
- Global donor: OS4.0.0.6.XOAMIXM, Android17, device xuanyuan, downloaded from Xiaomi's own CDN. The whole-file CMS signature passed verification against the independently pinned Xiaomi certificate.
- Global archive SHA256: `46ad76b094e037d3fd51d20ccdf3353c6b1a58a9630dcbe9f05b0ee18e3f5251`.
- Global modem SHA256: `900280a03b7285f9b3495829d5564bd34aed0f128ba275fb59f193e66b627b07`.
- Global modemfirmware SHA256: `7fc1fdbed91049c0beca5aa66d7977f431c2bb458efc89e8f8ecd8bbe57cdb51`.

These are separate partitions. A modem-only candidate does not constitute the complete radio pair. Candidate artifacts are labelled NOT-INSTALLABLE and contain no flashing script, personal NV state, IMEI data or calibration data.

The complete global pair was produced successfully in [run 42030383376](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42030383376) and saved as [artifact 13415767407](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42030383376/artifacts/13415767407), with three-day retention. This supersedes the earlier modem-only candidate.

## What the carrier comparison established

Ten inspected CarrierStudio XML assets containing Turk Telekom or xuanyuan settings are byte-identical between China and global sources. The Turk Telekom MCC286/MNC03 entries in the default configuration files already set `carrier_volte_available_bool`, `carrier_wfc_ims_available_bool` and `carrier_vt_available_bool` to true. The xuanyuan-specific XML also contains the 286-03 entry. The selected configuration and IMS registration on a running phone remain unverified.

The vendor property `ro.vendor.radio.build_region` is `cn` in the China source and `global` in the global source. The China ODM also declares `ro.vendor.radio.ntn_chip_type=1`, absent from the global report. These differences are evidence to investigate, not justification for changing radio properties blindly. We have not applied property overrides or carrier-provisioning bypasses.

The dedicated modemfirmware inspection succeeded for both sources in [run 42030383737](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42030383737). It found 529 MBN files in China and 531 in global, with no scan errors or omitted entries. Both ship and index `image/modem_pr/mcfg/configs/mcfg_sw/generic/EU/TurkTelekom/Commercial/TR/mcfg_sw.mbn`, but the 52,432-byte profiles differ:

- China profile SHA256: `823ad8435f85f110ce7d203b95db7042bf7e2269d09d747dfb96ee9d59b98f06`.
- Global profile SHA256: `3e9633c05cd956644236ff0e7d9fd2b76b2398ded730bd2168cd0347eb1e3a0d`.

The global profile is already included unchanged inside the authenticated global modemfirmware candidate. A file hash difference does not explain the semantic differences or prove that the phone selects that profile. No MBN is force-selected. See `reports/radio-assessment.json` for the precise static evidence and remaining limits.

## Integration constraints

`radio-policy.json` excludes the China `modem`, `modemfirmware` and `countrycode` partitions from any future global-device flash plan. The working global radio should be preserved until its identity and Android17 pairing are understood. Device-unique `modemst1`, `modemst2`, `fsg`, `fsc` and `persist` must remain untouched.

Pending: validate the selected EU radio pair with the Android17 target vendor/IMS implementation, finish full ROM/AVB packaging, and verify runtime behavior if the owner later explicitly authorizes device testing. Source signature and checksum success do not establish runtime compatibility. Do not request or perform phone access under the current instruction.

`collect_radio_baseline.ps1` is disabled by `phone_access_allowed=false` in `radio-policy.json`; it exits before any ADB call.

## Primary references

- [Xiaomi.eu maintainer: global Xiaomi 15 Ultra requires global modem with China-based ROM](https://miuipolska.pl/xiaomi-15-ultra-xiaomi-eu/). Its Android15 download is historical evidence, not the donor used here.
- [Turk Telekom supported devices and HD+/Wi-Fi calling requirements](https://bireysel.turktelekom.com.tr/dijital-servisler/hd-gorusme-volte-ve-wifi-arama).
- [Android carrier configuration precedence](https://source.android.com/docs/core/connect/carrier).
- [Authenticated source and carrier inspection run](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42028731281).
