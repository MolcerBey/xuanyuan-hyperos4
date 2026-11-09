import base64
import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from release_metadata import (ALGORITHM, BASE_SHA256, DOMAIN, LOGICAL_PARTITIONS, MANIFEST_STATUS,
    RADIO, REPOSITORY, REPORT_NAMES, SOURCE_PARTITIONS, canonical_bytes, make_index, public_key,
    read_json, sha256, signing_request, validate_asset_url, validate_assembly, validate_index,
    validate_signing_request, verify_detached)


def version():
    return {'schema': 1, 'product': 'Molcer OS', 'version_name': '0.2.0-experimental.1',
            'version_code': 2026110601, 'channel': 'experimental', 'device': 'xuanyuan',
            'hardware_variant': 'global', 'base': 'OS4.0.0.18.XOACNXM', 'android': 17,
            'update_mechanism': 'manual-full-package', 'automatic_installation': False,
            'android_ota_updater_implemented': False, 'public_release_available': False}


def manifest():
    tag = 'molcer-test-assembly'
    images = []
    for name in sorted(SOURCE_PARTITIONS | {'super'}):
        record = {'name': name, 'size': 1024, 'sha256': sha256(name.encode())}
        record.update(RADIO.get(name, {}))
        if name not in LOGICAL_PARTITIONS:
            asset = 'NOT-INSTALLABLE-' + name + '.img.part-00000'
            record['chunks'] = [{'index': 0, 'offset': 0, 'size': record['size'],
                'sha256': record['sha256'], 'asset_name': asset,
                'download_url': f'https://github.com/{REPOSITORY}/releases/download/{tag}/{asset}'}]
        images.append(record)
    reports = {name: sha256(name.encode()) for name in REPORT_NAMES}
    small = [{'asset_name': name, 'size': 120, 'sha256': digest,
              'download_url': f'https://github.com/{REPOSITORY}/releases/download/{tag}/{name}'}
             for name, digest in reports.items()]
    return {'schema': 1, 'repository': REPOSITORY, 'status': MANIFEST_STATUS,
        'device': 'xuanyuan', 'hardware_variant': 'global', 'rom_name': 'Molcer OS',
        'base_archive_sha256': BASE_SHA256, 'full_partition_chain_verified': True,
        'avb_flags': 0, 'release_tag': tag, 'release_draft': True, 'installer_included': False,
        'installation_allowed': False, 'installable_rom_produced': False, 'runtime_verified': False,
        'device_gpt_capacity_verified': False, 'offline_validation': {'avb': True, 'super': True, 'hashes': True},
        'validation_report_sha256': reports, 'small_assets': small,
        'all_partition_images': [{k: image[k] for k in ('name', 'size', 'sha256')} for image in images if image['name'] != 'super'],
        'super': {'name': 'super', 'size': 1024, 'sha256': sha256(b'super')},
        'uploaded_images': [image for image in images if image['name'] not in LOGICAL_PARTITIONS]}


class UpdateMetadataTests(unittest.TestCase):
    def setUp(self):
        self.key = public_key(pathlib.Path(__file__).parent / 'keys/avb-public.xml')

    def test_empty_index_is_not_an_available_or_implemented_ota(self):
        index = make_index(version(), self.key)
        self.assertEqual(index['updates'], [])
        self.assertFalse(index['public_release_available'])
        self.assertFalse(index['automatic_installation'])
        self.assertFalse(index['android_ota_updater_implemented'])
        self.assertTrue(validate_index(index, self.key))

    def test_verified_candidate_is_recorded_but_unavailable(self):
        index = make_index(version(), self.key, manifest())
        self.assertEqual(len(index['updates']), 1)
        self.assertEqual(len(index['updates'][0]['images']), 39)
        self.assertFalse(index['updates'][0]['public_release_available'])
        self.assertFalse(index['updates'][0]['installation_allowed'])

    def test_draft_asset_urls_are_identity_bound_and_normalized(self):
        item = manifest()
        tag = item['release_tag']
        draft = 'untagged-0123456789abcdef0123'
        item['release_url'] = f'https://github.com/{REPOSITORY}/releases/tag/{draft}'
        for image in item['uploaded_images']:
            for chunk in image['chunks']:
                chunk['download_url'] = chunk['download_url'].replace('/' + tag + '/', '/' + draft + '/')
        for asset in item['small_assets']:
            asset['download_url'] = asset['download_url'].replace('/' + tag + '/', '/' + draft + '/')
        images = validate_assembly(item)
        self.assertTrue(all('/' + tag + '/' in chunk['download_url']
                            for image in images for chunk in image['chunks']))
        index = make_index(version(), self.key, item)
        self.assertTrue(all('/' + tag + '/' in chunk['download_url']
                            for image in index['updates'][0]['images'] for chunk in image['chunks']))
        item['uploaded_images'][0]['chunks'][0]['download_url'] = item['uploaded_images'][0]['chunks'][0]['download_url'].replace(
            draft, 'untagged-1234567890abcdef0123')
        with self.assertRaisesRegex(ValueError, 'exact release download'):
            validate_assembly(item)

    def test_wrong_device_or_failed_offline_gate_is_rejected(self):
        for field, value in [('device', 'other'), ('hardware_variant', 'cn'),
                             ('full_partition_chain_verified', False), ('avb_flags', 2),
                             ('installer_included', True), ('release_draft', False)]:
            with self.subTest(field=field):
                item = manifest(); item[field] = value
                with self.assertRaises(ValueError):
                    make_index(version(), self.key, item)
        item = manifest(); item['offline_validation']['hashes'] = 1
        with self.assertRaises(ValueError):
            validate_assembly(item)

    def test_radio_substitution_and_missing_full_partition_rejected(self):
        item = manifest()
        next(x for x in item['uploaded_images'] if x['name'] == 'modemfirmware')['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'radio pair'):
            validate_assembly(item)
        item = manifest(); item['all_partition_images'].pop()
        with self.assertRaisesRegex(ValueError, 'inventory'):
            validate_assembly(item)

    def test_urls_reject_other_owner_query_redirect_and_traversal(self):
        good = f'https://github.com/{REPOSITORY}/releases/download/release/image.img'
        self.assertEqual(validate_asset_url(good, 'release', 'image.img'), good)
        bad = [good.replace('MolcerBey', 'someone'), good + '?redirect=evil', good + '#fragment',
               good.replace('https:', 'http:'), good.replace('github.com', 'github.com.evil'),
               good.replace('/release/image.img', '/release/../image.img')]
        for url in bad:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_asset_url(url, 'release', 'image.img')

    def test_monotonic_versions_and_minimum_version_enforced(self):
        old = make_index(version(), self.key)
        with self.assertRaisesRegex(ValueError, 'increase'):
            make_index(version(), self.key, previous=old)
        new_version = version(); new_version['version_code'] += 1
        new_version['version_name'] = '0.2.0-experimental.2'
        newer = make_index(new_version, self.key, previous=old)
        self.assertTrue(validate_index(newer, self.key, 2026110602))
        with self.assertRaisesRegex(ValueError, 'downgrade'):
            validate_index(old, self.key, 2026110602)

    def test_canonical_domain_bound_request_and_tamper_rejection(self):
        index = make_index(version(), self.key)
        request = signing_request(index, self.key)
        self.assertEqual(request['digest_sha256'], sha256(DOMAIN + canonical_bytes(index)))
        self.assertNotEqual(request['digest_sha256'], sha256(canonical_bytes(index)))
        self.assertTrue(validate_signing_request(index, request, self.key))
        changed = copy.deepcopy(index); changed['version']['version_code'] += 1
        with self.assertRaises(ValueError):
            validate_signing_request(changed, request, self.key)
        signature = {k: request[k] for k in ('schema', 'algorithm', 'digest_sha256', 'public_key_avb_sha256')}
        signature['signature_hex'] = '00' * 512
        with self.assertRaisesRegex(ValueError, 'signature verification'):
            verify_detached(index, signature, self.key)

    def test_chunk_overlap_excessive_size_and_report_hash_mismatch_rejected(self):
        item = manifest(); item['uploaded_images'][0]['chunks'][0]['offset'] = 1
        with self.assertRaisesRegex(ValueError, 'contiguous'):
            validate_assembly(item)
        item = manifest(); item['uploaded_images'][0]['chunks'][0]['size'] = 3 * 1024**3
        with self.assertRaisesRegex(ValueError, 'size'):
            validate_assembly(item)
        item = manifest(); item['small_assets'][0]['sha256'] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'report'):
            validate_assembly(item)

    def test_duplicate_keys_and_floats_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'duplicate.json'; path.write_text('{"schema":1,"schema":2}')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                read_json(path)
        with self.assertRaisesRegex(ValueError, 'integer'):
            canonical_bytes({'size': 1.5})

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL needed only for an ephemeral RSA test fixture')
    def test_ephemeral_rsa4096_roundtrip_and_tampered_index(self):
        # This creates a disposable test identity; it never opens project private keys.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); private = root / 'test-only.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096',
                            '-out', str(private)], check=True, capture_output=True)
            modulus = subprocess.check_output(['openssl', 'rsa', '-in', str(private), '-modulus', '-noout'], text=True).strip().split('=', 1)[1]
            xml = root / 'test-public.xml'
            xml.write_text('<RSAKeyValue><Modulus>' + base64.b64encode(bytes.fromhex(modulus)).decode() +
                           '</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>')
            key = public_key(xml); index = make_index(version(), key); request = signing_request(index, key)
            data = root / 'data'; data.write_bytes(DOMAIN + canonical_bytes(index))
            sigpath = root / 'signature'
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(private), '-out', str(sigpath), str(data)],
                           check=True, capture_output=True)
            signature = {k: request[k] for k in ('schema', 'algorithm', 'digest_sha256', 'public_key_avb_sha256')}
            signature['signature_hex'] = sigpath.read_bytes().hex()
            self.assertTrue(verify_detached(index, signature, key)['signature_verified'])
            index['version']['version_code'] += 1
            with self.assertRaises(ValueError):
                verify_detached(index, signature, key)


if __name__ == '__main__':
    unittest.main()
