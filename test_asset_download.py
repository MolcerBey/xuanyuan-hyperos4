import os
import unittest
from unittest import mock

from assemble_candidate import asset_download_timeout


class AssetDownloadTimeoutTests(unittest.TestCase):
    def test_default_and_bounded_override(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(asset_download_timeout(), 1200)
        for value in ('60', '3600', '7200'):
            with self.subTest(value=value), mock.patch.dict(
                    os.environ, {'MOLCER_ASSET_DOWNLOAD_TIMEOUT': value}):
                self.assertEqual(asset_download_timeout(), int(value))

    def test_invalid_timeout_is_rejected(self):
        for value in ('', 'abc', '1.5', '59', '7201'):
            with self.subTest(value=value), mock.patch.dict(
                    os.environ, {'MOLCER_ASSET_DOWNLOAD_TIMEOUT': value}):
                with self.assertRaises(ValueError):
                    asset_download_timeout()


if __name__ == '__main__':
    unittest.main()
