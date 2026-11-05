import hashlib
import pathlib
import tempfile
import unittest
import zipfile
from prepare_eu_radio import extract_verified


class ExactEUSourceTests(unittest.TestCase):
    def fixture(self, root):
        path = root / 'source.zip'
        script = b'CN chooses modemfirmware.img; global chooses modemfirmware_ww.img'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('linux_install_upgrade.sh', script)
            z.writestr('images/modem.img', b'common modem')
            z.writestr('images/modemfirmware.img', b'China firmware')
            z.writestr('images/modemfirmware_ww.img', b'Global firmware')
        cfg = {'size': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'device': 'xuanyuan', 'hardware_variant': 'global', 'rom': 'test', 'android': '16', 'url': 'https://example.test/source.zip', 'selection_evidence': 'test', 'installer_sha256': {'linux_install_upgrade.sh': hashlib.sha256(script).hexdigest()}, 'members': []}
        with zipfile.ZipFile(path) as z:
            for name, output in [('images/modem.img', 'NOT-INSTALLABLE-modem.img'), ('images/modemfirmware_ww.img', 'NOT-INSTALLABLE-modemfirmware.img')]:
                info = z.getinfo(name)
                cfg['members'].append({'path': name, 'output': output, 'size': info.file_size, 'crc32': format(info.CRC, '08x')})
        return path, cfg

    def test_extracts_global_branch_without_installers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); archive, cfg = self.fixture(root)
            report = extract_verified(archive, cfg, root / 'out')
            self.assertEqual((root / 'out/NOT-INSTALLABLE-modemfirmware.img').read_bytes(), b'Global firmware')
            self.assertEqual(len(list((root / 'out').iterdir())), 2)
            self.assertFalse(report['installers_executed'])
            self.assertFalse(report['ready_to_flash'])

    def test_wrong_archive_hash_stops_before_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); archive, cfg = self.fixture(root)
            cfg['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                extract_verified(archive, cfg, root / 'out')
            self.assertFalse((root / 'out').exists())

    def test_china_firmware_substitution_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); archive, cfg = self.fixture(root)
            cfg['members'][1]['path'] = 'images/modemfirmware.img'
            with self.assertRaisesRegex(ValueError, 'global radio pair'):
                extract_verified(archive, cfg, root / 'out')
            self.assertFalse((root / 'out').exists())


if __name__ == '__main__':
    unittest.main()
