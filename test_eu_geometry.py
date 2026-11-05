import hashlib
import io
import struct
import unittest

from inspect_eu_geometry import geometry, metadata, read_sparse_window, checked_slice


def valid_geometry():
    data = bytearray(struct.pack('<2I32s3I', 0x616c4467, 52, b'\0' * 32, 65536, 3, 4096))
    data[8:40] = hashlib.sha256(data).digest()
    return bytes(data)


def valid_metadata():
    group = struct.pack('<36sIQ', b'qti_dynamic_partitions_a', 0, 8 * 1024**2)
    block = struct.pack('<Q2IQ36sI', 2048, 1024**2, 0, 16 * 1024**2, b'super', 0)
    tables = group + block
    header = bytearray(256)
    struct.pack_into('<I2HI', header, 0, 0x414c5030, 10, 2, 256)
    struct.pack_into('<I', header, 44, len(tables))
    header[48:80] = hashlib.sha256(tables).digest()
    for at, start, count, size in [(80, 0, 0, 52), (92, 0, 0, 24), (104, 0, 1, 48), (116, 48, 1, 64)]:
        struct.pack_into('<3I', header, at, start, count, size)
    header[12:44] = hashlib.sha256(header).digest()
    return bytes(header) + tables


class EUGeometryTests(unittest.TestCase):
    def test_geometry_checksum_corruption_rejected(self):
        data = valid_geometry()
        self.assertEqual(geometry(data, b'\1' * len(data), 0)['metadata_slot_count'], 3)
        damaged = bytearray(data); damaged[8] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):
            geometry(damaged, b'\1' * len(data), 0)

    def test_metadata_checksums_and_group_budget(self):
        data = valid_metadata()
        result = metadata(data, b'\1' * len(data), 0, 65536)
        self.assertEqual(result['groups'][0]['maximum_size_bytes'], 8 * 1024**2)
        for index, message in [(12, 'header checksum'), (300, 'table checksum')]:
            damaged = bytearray(data); damaged[index] ^= 1
            with self.assertRaisesRegex(ValueError, message):
                metadata(damaged, b'\1' * len(data), 0, 65536)

    def test_sparse_large_raw_chunk_reads_only_requested_window(self):
        window = 4096
        header = struct.pack('<I4H4I', 0xed26ff3a, 1, 0, 28, 12, 4096, 1024, 1, 0)
        chunk = struct.pack('<2H2I', 0xcac1, 0, 1024, 12 + 1024 * 4096)
        source = io.BytesIO(header + chunk + b'x' * window)
        data, known, info = read_sparse_window(source, window_size=window)
        self.assertEqual(data, b'x' * window)
        self.assertEqual(known, b'\1' * window)
        self.assertEqual(info['member_uncompressed_bytes_read'], 28 + 12 + window)
        self.assertFalse(info['whole_sparse_crc_verified'])

    def test_dont_care_metadata_not_assumed_zero(self):
        header = struct.pack('<I4H4I', 0xed26ff3a, 1, 0, 28, 12, 4096, 1, 1, 0)
        chunk = struct.pack('<2H2I', 0xcac3, 0, 1, 12)
        data, known, _ = read_sparse_window(io.BytesIO(header + chunk), window_size=4096)
        with self.assertRaisesRegex(ValueError, 'dont-care'):
            checked_slice(data, known, 0, 52)

    def test_metadata_window_bounds_rejected(self):
        data = valid_geometry()
        with self.assertRaisesRegex(ValueError, 'bounded prefix'):
            checked_slice(data, b'\1' * len(data), len(data) - 1, 10)


if __name__ == '__main__':
    unittest.main()
