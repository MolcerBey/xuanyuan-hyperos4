import pathlib
import struct
import tempfile
import unittest
from compare_radio_static import compare, fat_header, version_strings


class RadioCompatibilityEvidenceTests(unittest.TestCase):
    def test_bpb_logical_volume_is_not_gpt_capacity(self):
        data = bytearray(512)
        struct.pack_into('<H', data, 11, 4096)
        data[13] = 4
        struct.pack_into('<H', data, 14, 1)
        data[16] = 2
        struct.pack_into('<H', data, 17, 512)
        struct.pack_into('<H', data, 22, 16)
        struct.pack_into('<I', data, 32, 62976)
        data[54:62] = b'FAT16   '
        data[510:512] = b'\x55\xaa'
        result = fat_header(data, 140234752)
        self.assertEqual(result['declared_logical_volume_bytes'], 257949696)
        self.assertTrue(result['image_shorter_than_declared_volume'])
        self.assertIsNone(result['gpt_partition_capacity_bytes'])
        self.assertFalse(result['partition_size_fit_verified'])
        self.assertFalse(result['filesystem_allocation_integrity_verified'])

    def test_binary_difference_does_not_prove_incompatibility(self):
        eu = {'files': {'modem/a': {'size': 1, 'sha256': 'a'}}, 'turk_telekom_profiles': []}
        target = {'files': {'modem/a': {'size': 1, 'sha256': 'b'}}, 'turk_telekom_profiles': []}
        result = compare(eu, target)
        self.assertEqual(result['changed_shared_file_count'], 1)
        self.assertEqual(result['conclusion'], 'not-proven-full-compatible')
        self.assertFalse(result['runtime_verified'])
        self.assertFalse(result['vendor_modem_protocol_compatibility_verified'])

    def test_version_identifier_crosses_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, 'modem.b01')
            path.write_bytes(b'\0' * (1024**2 - 8) + b'MPSS.DE.5.0.test-123\0')
            result = version_strings(path)
            self.assertIn('MPSS.DE.5.0.test-123', result['identifiers'])
            self.assertFalse(result['scan_size_limit_reached'])


if __name__ == '__main__':
    unittest.main()
