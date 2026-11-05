# Global Xiaomi 15 Ultra / Turk Telekom radio work

The owner confirmed global hardware and a working Turk Telekom connection on the current Xiaomi.eu installation. No phone radio settings or firmware have been changed. The phone is not currently available through ADB, so its working baseband version is not yet known.

## Confirmed source evidence

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

Pending: identify the working baseband, validate the global radio pair with the target vendor/IMS implementation, finish full ROM/AVB packaging, and check registration, calls, SMS, data, VoLTE and Wi-Fi calling. Source signature and checksum success do not establish runtime compatibility.

`collect_radio_baseline.ps1` reads a fixed list of non-personal software/model properties. It does not extract applications or read SIM identifiers and writes its report only under the ignored local `work/` directory.

## Primary references

- [Xiaomi.eu maintainer: global Xiaomi 15 Ultra requires global modem with China-based ROM](https://miuipolska.pl/xiaomi-15-ultra-xiaomi-eu/). Its Android15 download is historical evidence, not the donor used here.
- [Turk Telekom supported devices and HD+/Wi-Fi calling requirements](https://bireysel.turktelekom.com.tr/dijital-servisler/hd-gorusme-volte-ve-wifi-arama).
- [Android carrier configuration precedence](https://source.android.com/docs/core/connect/carrier).
- [Authenticated source and carrier inspection run](https://github.com/MolcerBey/xuanyuan-hyperos4/actions/runs/42028731281).
