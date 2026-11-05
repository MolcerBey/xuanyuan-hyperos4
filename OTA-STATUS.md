# Molcer OS version and update metadata

The current identity is **0.2.0-experimental.1**, version code **2026110601**, for global `xuanyuan`, Android 17, base `OS4.0.0.18.XOACNXM`. `version.json` is the version source.

This project now has an offline update-index preparation and signature-verification format. **It does not have an Android OTA updater, an automatic installer, or a recovery-installable OTA ZIP.** The intended future distribution is a manually reviewed full package. The existing assembled candidate has no installer and is not approved for installation.

## Current index states

- An empty index has `updates: []`. It communicates the project/version identity without claiming that a ROM download or an update is available.
- A candidate entry can be prepared only from the completed final assembly manifest. The validator requires its exact device/base identity, all offline AVB/super/hash gates, AVB flags zero, the complete 47-partition inventory and all 39 uploaded physical/super images. The selected EU modem pair is pinned by size and SHA256.
- Four verification reports must have digests matching their uploaded assets: AVB signatures, super geometry, independent hashes of the nine logical images inside super, and radio integration.
- Every image has bounded, contiguous, hashed chunks. URLs must be exact HTTPS download paths under `github.com/MolcerBey/xuanyuan-hyperos4/releases/download/` for the manifest's release tag. Device-unique partitions and the China `countrycode` image are excluded.
- Generated indices have `public_release_available: false`, `automatic_installation: false` and `android_ota_updater_implemented: false`. A draft release is not a public download. This tool never publishes or promotes a release. Publication and any future availability-enabled schema require a separate review; the current validator deliberately rejects an availability claim.

## Signature format

Public verification uses only the committed `keys/avb-public.xml` RSA4096/exponent65537 parameters. The key identifier is the SHA256 of the public key encoded in the same AVB format used by the image-signing tools.

Canonical JSON is UTF-8, with sorted object keys, no insignificant separators and no floating-point numbers. Duplicate input keys and oversized documents are rejected. The signing input is:

```text
b"Molcer OS update index v1\0" + canonical_json_bytes
```

The request contains the SHA256 of that complete domain-separated input. A separate local signer must first validate the request, then sign its digest using RSA4096 PKCS#1 v1.5 with SHA256. `release_metadata.py` never reads private keys. The response JSON contains `schema`, `algorithm`, `digest_sha256`, `public_key_avb_sha256` and a 512-byte lowercase `signature_hex`.

These detached metadata signatures are not Xiaomi OTA signatures and do not establish OEM recovery/update-engine trust. They do not prove bootloader acceptance, actual device GPT capacity, camera operation or modem/IMS interoperability.

## Commands

Prepare an empty index, without a candidate:

```bash
python3 release_metadata.py empty --output out/update-index.json --request out/update-signing-request.json
```

Prepare an unavailable experimental candidate entry after final assembly succeeds:

```bash
python3 release_metadata.py prepare --manifest reports/assembled-candidate-manifest.json --output out/update-index.json --request out/update-signing-request.json
```

Validate the exact request before separate local signing:

```bash
python3 release_metadata.py validate-request --index out/update-index.json --request out/update-signing-request.json
```

Verify the detached signature using public material only:

```bash
python3 release_metadata.py verify --index out/update-index.json --signature out/update-signature.json --minimum-version-code 2026110601
```

Outputs are never overwritten. When preparing a later version, supply `--previous-index` and `--previous-signature` together. The prior signature is verified and the new version code must strictly increase. A consumer must retain its highest accepted version code and pass it as `--minimum-version-code`; a signature alone cannot prevent replay of an older valid index.

No command in this workflow accesses, flashes, wipes or reboots a phone.
