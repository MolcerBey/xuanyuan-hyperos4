import base64
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from sign_oled_overlay import PACKAGE, sign_overlay, validated_input


class OLEDSigningTests(unittest.TestCase):
    def fixture(self, root):
        unsigned = root / 'unsigned'
        source = unsigned / 'overlay/MolcerTurkish' / (PACKAGE + '.apk')
        source.parent.mkdir(parents=True)
        source.write_bytes(b'synthetic unsigned OLED APK')
        report = {'schema': 1, 'original_apks_modified': False, 'preview_signing_key': False,
                  'signing_status': 'unsigned-local-signing-required', 'runtime_verified': False,
                  'credit': 'Molcer OS original black wallpaper',
                  'targets': [{'package': 'android', 'target_apk': 'system/system/framework/framework-res.apk',
                               'target_apk_sha256': '11' * 32, 'overlays': [PACKAGE],
                               'compiled_resources': ['integer/config_defaultNightMode',
                                                      'drawable/default_wallpaper']}]}
        report_path = root / 'report.json'
        report_path.write_text(json.dumps(report), encoding='utf-8')
        return unsigned, source, report_path

    def test_signed_manifest_is_bound_to_unsigned_apk_and_framework(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            unsigned, source, report_path = self.fixture(root)
            private = root / 'private.json'
            private.write_text(json.dumps({'schema': 1, 'pfx': base64.b64encode(b'x' * 256).decode(),
                                           'password': 'synthetic-test-password'}))
            output = root / 'assets/oled-overlays'

            def run(command, **kwargs):
                target = pathlib.Path(command[command.index('--out') + 1] if '--out' in command else command[-1])
                target.write_bytes(source.read_bytes() + b'signed')
                return mock.Mock(returncode=0)

            def output_of(command, **kwargs):
                if command[1] == 'verify':
                    return 'synthetic certificate evidence'
                if command[2] == 'xmltree':
                    return 'E: application\n A: hasCode=(type 0x12)0x0\n'
                return "package: name='" + PACKAGE + "' versionCode='1'\n"

            with mock.patch('sign_oled_overlay.subprocess.run', side_effect=run), \
                    mock.patch('sign_oled_overlay.subprocess.check_output', side_effect=output_of), \
                    mock.patch('sign_oled_overlay.parse_apk_signers') as verify_signer, \
                    mock.patch('sign_oled_overlay.file_digest', side_effect=lambda path: '22' * 32):
                manifest = sign_overlay(unsigned, report_path, output, private, root / 'tools')
            self.assertEqual(manifest['overlays'][0]['unsigned_sha256'], '22' * 32)
            self.assertEqual(manifest['overlays'][0]['target_apk_sha256'], '11' * 32)
            self.assertTrue(manifest['permanent_local_signature'])
            self.assertFalse(manifest['runtime_verified'])
            self.assertTrue((output / 'manifest.json').is_file())
            self.assertTrue((output / (PACKAGE + '.apk')).is_file())
            verify_signer.assert_called_once()

    def test_changed_resource_scope_is_rejected_before_key_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            unsigned, _, report_path = self.fixture(root)
            report = json.loads(report_path.read_text())
            report['targets'][0]['compiled_resources'].append('string/unapproved')
            report_path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'resource scope'):
                validated_input(unsigned, report_path)


if __name__ == '__main__':
    unittest.main()
