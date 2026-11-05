import hashlib
import pathlib
import struct
import tempfile
import unittest

from inspect_packaging import parse_payload_manifest, read_vbmeta_blob, verify_image_source


def varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def manifest(maximum=4096, duplicate=False):
    info = field(1, 4096) + field(2, b'0' * 32)
    part = field(1, b'product') + field(7, info)
    group = field(1, b'qti_dynamic_partitions') + field(2, maximum) + field(3, b'product')
    if duplicate:
        group += field(3, b'product')
    dynamic = field(1, group) + field(2, 1) + field(9, field(1, b'super') + field(2, 8192))
    return field(13, part) + field(15, dynamic)


class PackagingInspectionTests(unittest.TestCase):
    def test_group_bounds_and_unknown_extensions_preserved(self):
        result = parse_payload_manifest(manifest())
        self.assertEqual(result['dynamic_groups'][0]['stock_image_total_bytes'], 4096)
        self.assertIn('9', result['uninterpreted_dynamic_fields'])
        self.assertFalse(result['super_geometry_verified'])
        with self.assertRaisesRegex(ValueError, 'exceed'):
            parse_payload_manifest(manifest(maximum=4095))
        with self.assertRaisesRegex(ValueError, 'membership'):
            parse_payload_manifest(manifest(duplicate=True))

    def test_partial_and_delta_payload_rejected(self):
        for extension in (field(12, 1), field(16, 1)):
            with self.assertRaisesRegex(ValueError, 'full'):
                parse_payload_manifest(manifest() + extension)

    def test_footer_outside_file_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = pathlib.Path(temp) / 'image.img'
            footer = struct.pack('>4s2I3Q28s', b'AVBf', 1, 0, 128, 256, 4096, b'\0' * 28)
            p.write_bytes(b'\0' * 512 + footer)
            with self.assertRaisesRegex(ValueError, 'footer bounds'):
                read_vbmeta_blob(p)

    def test_unsigned_filesystem_is_not_misreported_as_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            p = pathlib.Path(temp) / 'image.img'
            p.write_bytes(b'example filesystem' * 30)
            self.assertEqual(read_vbmeta_blob(p), (None, None))

    def test_source_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = pathlib.Path(temp) / 'product.img'
            expected = {'size': 4, 'sha256': hashlib.sha256(b'good').hexdigest()}
            p.write_bytes(b'evil')
            with self.assertRaisesRegex(ValueError, 'authenticated payload'):
                verify_image_source(p, expected)


if __name__ == '__main__':
    unittest.main()
