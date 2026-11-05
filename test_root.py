import gzip
import pathlib
import struct
import tempfile
import unittest

from prepare_root import kernel_kmi


class KernelIdentityTests(unittest.TestCase):
    def check_image(self, kernel, expected=None):
        header = bytearray(4096)
        header[:8] = b"ANDROID!"
        struct.pack_into("<I", header, 8, len(kernel))
        struct.pack_into("<I", header, 40, 4)
        with tempfile.TemporaryDirectory() as tmp:
            image = pathlib.Path(tmp, "boot.img")
            image.write_bytes(header + kernel)
            if expected:
                self.assertEqual(kernel_kmi(image), expected)
            else:
                with self.assertRaises(ValueError):
                    kernel_kmi(image)

    def test_stock_android15_kmi_on_newer_system(self):
        self.check_image(b"Linux version 6.6.118-android15-11-example\x00", "android15-6.6")

    def test_compressed_kernel(self):
        self.check_image(gzip.compress(b"Linux version 6.12.42-android16-3-example\x00"), "android16-6.12")

    def test_unknown_kernel_rejected(self):
        self.check_image(b"unknown kernel")

    def test_ambiguous_kernel_rejected(self):
        self.check_image(b"Linux version 6.6.118-android15-x\x00Linux version 6.12.42-android16-x\x00")
