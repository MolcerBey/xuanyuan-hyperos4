import pathlib
import tempfile
import unittest
from unittest import mock

from release_metadata import RADIO, sha256
from test_release_metadata import manifest
from verify_installation_package import verify_package


class InstallationPackageTests(unittest.TestCase):
    def fixture(self, root):
        document = manifest()
        image_root = root / 'images'; image_root.mkdir()
        inventory = {item['name']: item for item in document['all_partition_images']}
        radio = {}
        for image in document['uploaded_images']:
            data = ('verified image ' + image['name']).encode()
            (image_root / (image['name'] + '.img')).write_bytes(data)
            image['size'] = len(data); image['sha256'] = sha256(data)
            image['chunks'][0]['size'] = len(data); image['chunks'][0]['sha256'] = image['sha256']
            if image['name'] == 'super':
                document['super']['size'] = len(data); document['super']['sha256'] = image['sha256']
            else:
                inventory[image['name']]['size'] = len(data)
                inventory[image['name']]['sha256'] = image['sha256']
            if image['name'] in RADIO:
                radio[image['name']] = {'size': len(data), 'sha256': image['sha256']}
        return document, image_root, radio

    def test_exact_complete_bundle_is_verified_without_device_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            document, images, radio = self.fixture(pathlib.Path(tmp))
            with mock.patch('release_metadata.RADIO', radio):
                report = verify_package(document, images)
            self.assertEqual(report['image_count'], 39)
            self.assertTrue(report['all_image_bytes_verified'])
            self.assertFalse(report['ready_to_flash'])
            self.assertFalse(report['fastboot_execution_implemented'])
            self.assertFalse(report['phone_accessed'])

    def test_changed_image_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); document, images, radio = self.fixture(root)
            (images / 'super.img').write_bytes(b'changed')
            with mock.patch('release_metadata.RADIO', radio):
                with self.assertRaisesRegex(ValueError, 'super'):
                    verify_package(document, images)

    def test_missing_and_extra_images_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); document, images, radio = self.fixture(root)
            (images / 'unexpected.img').write_bytes(b'unexpected')
            with mock.patch('release_metadata.RADIO', radio):
                with self.assertRaisesRegex(ValueError, 'Unexpected'):
                    verify_package(document, images)
            (images / 'unexpected.img').unlink(); (images / 'super.img').unlink()
            with mock.patch('release_metadata.RADIO', radio):
                with self.assertRaisesRegex(ValueError, 'exact'):
                    verify_package(document, images)

    def test_unapproved_manifest_is_rejected_before_image_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); document, images, radio = self.fixture(root)
            document['device'] = 'other'
            with mock.patch('release_metadata.RADIO', radio):
                with self.assertRaisesRegex(ValueError, 'device'):
                    verify_package(document, images)


if __name__ == '__main__':
    unittest.main()
