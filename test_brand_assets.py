import io
import pathlib
import struct
import tempfile
import unittest
import zipfile
import zlib

from build_brand_assets import (BASE_SHA256, MAX_BOOT_ZIP, boot_archive, build,
                                digest, encode_png, parse_stock_desc,
                                render_boot_frame, validate_evidence)


def decode_own_png(data):
    """Independent PNG structure/CRC check for the generated RGB8 filter-zero data."""
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise AssertionError('PNG signature')
    offset, payload = 8, bytearray()
    width = height = None
    while offset < len(data):
        length = struct.unpack_from('>I', data, offset)[0]
        kind = data[offset + 4:offset + 8]
        content = data[offset + 8:offset + 8 + length]
        crc = struct.unpack_from('>I', data, offset + 8 + length)[0]
        if zlib.crc32(kind + content) & 0xffffffff != crc:
            raise AssertionError('PNG CRC')
        if kind == b'IHDR':
            width, height, bits, color, compression, filter_method, interlace = struct.unpack('>2I5B', content)
            if (bits, color, compression, filter_method, interlace) != (8, 2, 0, 0, 0):
                raise AssertionError('PNG format')
        elif kind == b'IDAT':
            payload.extend(content)
        offset += 12 + length
    raw = zlib.decompress(payload)
    stride = 1 + 3 * width
    if len(raw) != stride * height or any(raw[y * stride] for y in range(height)):
        raise AssertionError('PNG row sizes/filters')
    pixels = b''.join(raw[y * stride + 1:(y + 1) * stride] for y in range(height))
    return width, height, pixels


class BrandAssetTests(unittest.TestCase):
    def evidence(self):
        desc = '720 1600 30\np 1 0 part0\np 0 0 part1\n'
        return {'schema': 1, 'phone_accessed': False, 'source_archive_hash_verified': True,
                'source_archive_sha256': BASE_SHA256,
                'bootanimation': {'path': 'product/media/bootanimation.zip', 'sha256': '1' * 64,
                                  'desc': desc, 'desc_sha256': digest(desc.encode())}}

    def test_evidence_requires_exact_hash_and_safe_path(self):
        self.assertEqual(validate_evidence(self.evidence())['fps'], 30)
        for key, value in [('desc_sha256', '0' * 64), ('path', '../../bootanimation.zip')]:
            evidence = self.evidence()
            evidence['bootanimation'][key] = value
            with self.assertRaises(ValueError):
                validate_evidence(evidence)

    def test_unbounded_dimensions_and_invalid_desc_are_rejected(self):
        for desc in ('99999 3200 30\np 0 0 part0', '1440 3200 0\np 0 0 part0',
                     '1440 3200 30', '1440 3200 30\n$SYSTEM',
                     '1440 3200 30\np 0 0 ../part0'):
            with self.subTest(desc=desc), self.assertRaises(ValueError):
                parse_stock_desc(desc)

    def test_black_wallpaper_pixels_are_exact_rgb_zero(self):
        width, height, pixels = decode_own_png(encode_png(64, 128, bytes(64 * 128)))
        self.assertEqual((width, height), (64, 128))
        self.assertEqual(pixels, bytes(64 * 128 * 3))

    def test_brand_frame_has_opaque_black_edges_and_small_white_mark(self):
        width, height = 360, 800
        gray = render_boot_frame(width, height)
        self.assertEqual(max(gray), 255)
        self.assertGreater(gray.count(0) / len(gray), 0.98)
        self.assertEqual(gray[:width], bytes(width))
        self.assertEqual(gray[-width:], bytes(width))
        self.assertTrue(all(gray[y * width] == gray[(y + 1) * width - 1] == 0 for y in range(height)))
        _, _, rgb = decode_own_png(encode_png(width, height, gray))
        self.assertEqual(rgb[::3], gray)
        self.assertEqual(rgb[1::3], gray)
        self.assertEqual(rgb[2::3], gray)

    def test_zip_is_stored_single_static_frame_and_deterministic(self):
        frame = encode_png(360, 800, render_boot_frame(360, 800))
        first, desc = boot_archive(360, 800, frame)
        second, _ = boot_archive(360, 800, frame)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), MAX_BOOT_ZIP)
        self.assertEqual(desc, '360 800 1\np 0 0 part0 #000000\n')
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertEqual(archive.namelist(), ['desc.txt', 'part0/00000.png'])
            self.assertTrue(all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist()))
            self.assertEqual(archive.read('part0/00000.png'), frame)

    def test_missing_stock_evidence_cannot_produce_boot_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / 'assets'
            with self.assertRaisesRegex(ValueError, 'evidence is required'):
                build(output)
            self.assertFalse(output.exists())

    def test_evidence_drives_candidate_geometry_and_report_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / 'assets'
            report = build(output, self.evidence())
            self.assertEqual(report['boot_dimensions'], {'width': 720, 'height': 1600})
            self.assertEqual(report['stock_desc_parameters']['fps'], 30)
            self.assertEqual(report['output_fps'], 1)
            self.assertFalse(report['installed_into_rom'])
            for name, record in report['assets'].items():
                data = (output / name).read_bytes()
                self.assertEqual((len(data), digest(data)), (record['size'], record['sha256']))
            with zipfile.ZipFile(output / 'bootanimation.zip') as archive:
                self.assertEqual(archive.read('desc.txt'), b'720 1600 1\np 0 0 part0 #000000\n')
            width, height, pixels = decode_own_png((output / 'wallpaper.png').read_bytes())
            self.assertEqual((width, height), (1440, 3200))
            self.assertEqual(pixels.count(0), len(pixels))

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'fresh'):
                build(directory, self.evidence())


if __name__ == '__main__':
    unittest.main()
