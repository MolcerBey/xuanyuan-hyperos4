import copy
import hashlib
import pathlib
import tempfile
import unittest
import warnings
import zipfile
from integrate_radio import integrate, APPROVED, SOURCE_ROM, SOURCE_SHA256


class RadioIntegrationTests(unittest.TestCase):
    def fixture(self, root):
        source = root / 'source'; source.mkdir()
        policy = {'device': 'xuanyuan', 'hardware_variant': 'global', 'phone_access_allowed': False,
                  'selected_integration_radio_source': 'eu-radio-source.json',
                  'selected_radio_report': 'reports/eu-radio-reference.json', 'baseline_rom_version': SOURCE_ROM}
        config = {'device': 'xuanyuan', 'hardware_variant': 'global', 'rom': SOURCE_ROM,
                  'android': '16', 'sha256': SOURCE_SHA256, 'members': []}
        reference = {'device': 'xuanyuan', 'hardware_variant': 'global', 'source_rom': SOURCE_ROM,
                     'source_android': '16', 'source_archive_sha256': SOURCE_SHA256,
                     'official_release_checksum_verified': True, 'files': []}
        for member, (name, partition) in APPROVED.items():
            data = ('global EU fixture ' + partition).encode()
            (source / name).write_bytes(data)
            config['members'].append({'path': member, 'output': name, 'size': len(data)})
            reference['files'].append({'source_member': member, 'output': name, 'size': len(data),
                                       'sha256': hashlib.sha256(data).hexdigest(), 'zip_crc_verified': True})
        return source, policy, config, reference

    def test_correct_pair_staged_with_ww_partition_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            report = integrate(policy, config, ref, root / 'out', source_dir=source)
            self.assertEqual((root / 'out/images/modemfirmware.img').read_bytes(),
                             (source / 'NOT-INSTALLABLE-modemfirmware.img').read_bytes())
            self.assertEqual({f['partition'] for f in report['files']}, {'modem', 'modemfirmware'})
            self.assertTrue(report['radio_pair_included_in_build_staging'])
            self.assertFalse(report['phone_accessed'])
            self.assertFalse(report['installers_executed'])
            self.assertFalse(report['ready_to_flash'])
            self.assertFalse(report['installable_rom_produced'])

    def test_deterministic_archive_repeats_exact_bytes(self):
        from integrate_radio import package_archive
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            integrate(policy, config, ref, root / 'out', source_dir=source)
            archive = root / 'radio.zip'
            first = package_archive(root / 'out', archive)
            contents = archive.read_bytes()
            archive.unlink()
            second = package_archive(root / 'out', archive)
            self.assertEqual(archive.read_bytes(), contents)
            self.assertEqual(first, second)
            with zipfile.ZipFile(archive) as packaged:
                self.assertEqual(set(packaged.namelist()), {'NOT-INSTALLABLE.txt', 'radio-integration.json',
                    'SHA256SUMS.txt', 'images/modem.img', 'images/modemfirmware.img'})
                self.assertTrue(all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in packaged.infolist()))

    def test_archive_rejects_overwrite_and_changed_image(self):
        from integrate_radio import package_archive
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            integrate(policy, config, ref, root / 'out', source_dir=source)
            archive = root / 'radio.zip'
            package_archive(root / 'out', archive)
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                package_archive(root / 'out', archive)
            archive.unlink()
            with (root / 'out/images/modem.img').open('ab') as stream:
                stream.write(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed'):
                package_archive(root / 'out', archive)
            self.assertFalse(archive.exists())

    def test_bad_second_image_hash_rejects_before_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            path = source / 'NOT-INSTALLABLE-modemfirmware.img'
            path.write_bytes(b'x' * path.stat().st_size)
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                integrate(policy, config, ref, root / 'out', source_dir=source)
            self.assertFalse((root / 'out').exists())

    def test_china_name_and_policy_substitution_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            wrong = copy.deepcopy(config)
            wrong['members'][1]['path'] = 'images/modemfirmware.img'
            with self.assertRaisesRegex(ValueError, 'WW radio pair'):
                integrate(policy, wrong, ref, root / 'out', source_dir=source)
            policy['selected_integration_radio_source'] = 'global-donor.json'
            with self.assertRaisesRegex(ValueError, 'exact reviewed EU source'):
                integrate(policy, config, ref, root / 'out', source_dir=source)
            self.assertFalse((root / 'out').exists())

    def test_zip_pair_accepted_but_path_injection_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            archive = root / 'artifact.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                for path in source.iterdir():
                    z.write(path, path.name)
            report = integrate(policy, config, ref, root / 'valid', artifact=archive)
            self.assertEqual(report['source_mode'], 'artifact-zip')
            with zipfile.ZipFile(archive, 'a') as z:
                z.writestr('../escape.img', b'not permitted')
            with self.assertRaisesRegex(ValueError, 'allowlist'):
                integrate(policy, config, ref, root / 'invalid', artifact=archive)
            self.assertFalse((root / 'invalid').exists())
            self.assertFalse((root / 'escape.img').exists())

    def test_duplicate_zip_member_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            archive = root / 'artifact.zip'
            with zipfile.ZipFile(archive, 'w') as z, warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                for path in source.iterdir():
                    z.write(path, path.name)
                z.writestr('NOT-INSTALLABLE-modem.img', b'duplicate')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                integrate(policy, config, ref, root / 'out', artifact=archive)
            self.assertFalse((root / 'out').exists())

    def test_missing_pair_and_existing_output_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); source, policy, config, ref = self.fixture(root)
            out = root / 'out'; out.mkdir(); (out / 'keep.txt').write_text('preserve')
            with self.assertRaisesRegex(ValueError, 'fresh'):
                integrate(policy, config, ref, out, source_dir=source)
            self.assertEqual((out / 'keep.txt').read_text(), 'preserve')
            (source / 'NOT-INSTALLABLE-modemfirmware.img').unlink()
            with self.assertRaisesRegex(ValueError, 'Missing'):
                integrate(policy, config, ref, root / 'new', source_dir=source)
            self.assertFalse((root / 'new').exists())


if __name__ == '__main__':
    unittest.main()
