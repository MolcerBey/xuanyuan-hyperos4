import bz2
import hashlib
import lzma
import os
import pathlib
import struct
import tempfile
import unittest
import zipfile

from extract_partition import extract
from test_inspection import pb, vi


class ExtractionTests(unittest.TestCase):
    def run_case(self, kind, corrupt=False):
        raw = b"X" * 4096
        encoded = {0: lambda x: x, 1: bz2.compress, 8: lzma.compress}[kind](raw)
        extent = vi(8) + vi(0) + vi(16) + vi(1)
        op = vi(8) + vi(kind) + vi(16) + vi(0) + vi(24) + vi(len(encoded)) + pb(6, extent) + pb(8, hashlib.sha256(encoded).digest())
        info = vi(8) + vi(len(raw)) + pb(2, hashlib.sha256(raw).digest())
        part = pb(1, b"product") + pb(7, info) + pb(8, op)
        manifest = pb(13, part)
        payload = b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0) + manifest + encoded
        if corrupt:
            payload = payload[:-1] + bytes([payload[-1] ^ 1])
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            try:
                os.chdir(tmp)
                with zipfile.ZipFile("base.zip", "w") as z:
                    z.writestr("payload.bin", payload)
                if corrupt:
                    with self.assertRaisesRegex(ValueError, "checksum"):
                        extract("base.zip", ["product"], "images")
                else:
                    extract("base.zip", ["product"], "images")
                    self.assertEqual(pathlib.Path("images/product.img").read_bytes(), raw)
            finally:
                os.chdir(old)

    def test_raw(self):
        self.run_case(0)

    def test_bzip(self):
        self.run_case(1)

    def test_xz(self):
        self.run_case(8)

    def test_corruption_rejected(self):
        self.run_case(8, corrupt=True)


if __name__ == "__main__":
    unittest.main()
