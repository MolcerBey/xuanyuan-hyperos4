import io
import struct
import unittest
import zipfile

from inspect_ota import fields, inspect


def vi(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def pb(n, value):
    return vi(n * 8 + 2) + vi(len(value)) + value


class InspectionTests(unittest.TestCase):
    def fixture(self, device="xuanyuan", delta=False):
        buffer = io.BytesIO()
        info = vi(8) + vi(4096) + pb(2, b"a" * 32)
        part = pb(1, b"system") + pb(7, info)
        manifest = pb(13, part) + vi(96) + vi(int(delta))
        with zipfile.ZipFile(buffer, "w") as z:
            z.writestr("META-INF/com/android/metadata", f"pre-device={device}\npost-build=Xiaomi/xuanyuan/xuanyuan:17/CP2A/internal:user/release-keys\npost-build-incremental=internal\npost-sdk-level=37\nota-type=AB\n")
            z.writestr("META-INF/com/android/otacert", b"test certificate")
            z.writestr("payload.bin", b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0) + manifest)
        buffer.seek(0)
        return buffer

    def expected(self):
        return {"device": "xuanyuan", "android": "17", "sdk": "37", "incremental": "internal"}

    def test_valid_full_ota(self):
        self.assertTrue(all(inspect(self.fixture(), self.expected())["checks"].values()))

    def test_other_device_rejected(self):
        self.assertFalse(inspect(self.fixture("dada"), self.expected())["checks"]["device"])

    def test_delta_rejected(self):
        self.assertFalse(inspect(self.fixture(delta=True), self.expected())["checks"]["full_payload"])

    def test_truncated_protobuf_rejected(self):
        with self.assertRaises(ValueError):
            fields(b"\x0a\x05a")


if __name__ == "__main__":
    unittest.main()
