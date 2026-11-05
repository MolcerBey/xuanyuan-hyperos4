import copy
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch

from build_super import (BASE_SHA256, GROUP, PARTITIONS, Geometry, build_image,
                         check_disk_space, collect_images, geometry_from_report,
                         image_record, inspect_sparse_file, lpmake_command,
                         plan_layout, read_json, sha256, source_records)


class SuperBuilderTests(unittest.TestCase):
    def sizes(self):
        return dict.fromkeys(PARTITIONS, 4096)

    def test_exact_group_budget_is_accepted(self):
        sizes = self.sizes()
        sizes['odm'] = Geometry().group_size - 8 * 4096
        result = plan_layout(sizes)
        self.assertEqual(result['group_remaining_bytes'], 0)
        self.assertGreaterEqual(result['physical_remaining_bytes'], 0)
        self.assertEqual(result['allocated_b_slot_bytes'], 0)

    def test_one_block_over_group_budget_is_rejected(self):
        sizes = self.sizes()
        sizes['odm'] = Geometry().group_size - 7 * 4096
        with self.assertRaisesRegex(ValueError, 'group budget'):
            plan_layout(sizes)

    def test_physical_alignment_overflow_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'alignment exceed'):
            plan_layout(self.sizes(), Geometry(super_size=3 * 1024**2, group_size=2 * 1024**2))

    def test_uint64_overflow_and_invalid_lengths_are_rejected(self):
        for value in (2**64, 0, -4096, True, 4097):
            with self.subTest(value=value):
                sizes = self.sizes()
                sizes['product'] = value
                with self.assertRaises(ValueError):
                    plan_layout(sizes)

    def test_unknown_and_missing_partitions_are_rejected(self):
        for name in ('unknown', None):
            sizes = self.sizes()
            del sizes['mi_product']
            if name:
                sizes[name] = 4096
            with self.assertRaisesRegex(ValueError, 'Missing or unknown'):
                plan_layout(sizes)

    def test_missing_image_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, 'Missing'):
                image_record('system', pathlib.Path(root) / 'missing.img',
                             {'size': 4096, 'sha256': '0' * 64}, 'test')

    def test_source_manifest_unknown_partition_is_rejected(self):
        inspection = {'source_archive_hash_verified': True, 'source_archive_sha256': BASE_SHA256,
                      'payload': {'snapshot_enabled': True, 'block_size': 4096,
                                  'dynamic_groups': [{'name': GROUP, 'partition_names': list(PARTITIONS)}],
                                  'partitions': [{'name': name} for name in PARTITIONS]}}
        source_records(inspection)
        inspection['payload']['dynamic_groups'][0]['partition_names'][-1] = 'unrecognized'
        with self.assertRaisesRegex(ValueError, 'unknown'):
            source_records(inspection)

    def test_rebuilt_product_requires_footer_and_uses_final_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stock = root / 'stock'
            stock.mkdir()
            payload_records = []
            for name in PARTITIONS:
                path = stock / (name + '.img')
                path.write_bytes(b'x' * 4096)
                payload_records.append({'name': name, 'size': 4096, 'sha256': sha256(path)})
            product = root / 'product.img'
            # Synthetic structural footer/header fixture; this is not signed AVB.
            data = bytearray(8192)
            data[4096:4100] = b'AVB0'
            data[-64:] = struct.pack('>4s2I3Q28s', b'AVBf', 1, 0, 2048, 4096, 256, b'\0' * 28)
            product.write_bytes(data)
            inspection = {'source_archive_hash_verified': True, 'source_archive_sha256': BASE_SHA256,
                          'payload': {'snapshot_enabled': True, 'block_size': 4096,
                                      'dynamic_groups': [{'name': GROUP, 'partition_names': list(PARTITIONS)}],
                                      'partitions': payload_records}}
            record = {'schema': 1, 'product_hashtree_verified': True,
                      'prepared_images': [{'partition': 'product', 'size': 8192, 'sha256': sha256(product)}]}
            images, footer = collect_images(stock, product, inspection, record)
            self.assertEqual(footer['original_image_size'], 2048)
            self.assertEqual(images['product']['size'], 8192)
            self.assertEqual(plan_layout({n: r['size'] for n, r in images.items()})['image_total_bytes'],
                             8 * 4096 + 8192)
            product.write_bytes(b'x' * 8192)
            record['prepared_images'][0]['sha256'] = sha256(product)
            with self.assertRaisesRegex(ValueError, 'AVB footer'):
                collect_images(stock, product, inspection, record)

    def test_launch_virtual_ab_command_has_no_retrofit_suffixing(self):
        records = {name: {'size': 4096, 'path': '/source/' + name + '.img'} for name in PARTITIONS}
        command = lpmake_command('/pinned/lpmake', records, Geometry(), '/output/super.img')
        self.assertIn('--virtual-ab', command)
        self.assertIn('--sparse', command)
        self.assertNotIn('--auto-slot-suffixing', command)
        self.assertIn('super:11811160064:1048576:0', command)
        self.assertEqual(command[command.index('--metadata-slots') + 1], '3')
        for name in PARTITIONS:
            self.assertIn(f'{name}_a:readonly:4096:{GROUP}_a', command)
            self.assertIn(f'{name}_b:readonly:0:{GROUP}_b', command)
            self.assertIn(f'{name}_a=/source/{name}.img', command)
            self.assertFalse(any(arg.startswith(name + '_b=') for arg in command))

    def test_disk_guard_rejects_before_lpmake(self):
        with patch('build_super.shutil.disk_usage') as usage:
            usage.return_value.free = 1024
            with self.assertRaisesRegex(ValueError, 'free disk space'):
                check_disk_space('.', Geometry())

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            output = pathlib.Path(root) / 'super.img'
            output.write_bytes(b'KEEP')
            records = {name: {'size': 4096, 'path': str(pathlib.Path(root) / (name + '.img'))}
                       for name in PARTITIONS}
            with patch('build_super.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'fresh'):
                    build_image(records, Geometry(), '/unused/lpmake', {}, output)
                run.assert_not_called()
            self.assertEqual(output.read_bytes(), b'KEEP')

    def test_sparse_truncation_and_expanded_size_are_rejected(self):
        geometry = Geometry(super_size=16 * 1024**2, group_size=12 * 1024**2)
        blocks = geometry.super_size // 4096
        header = struct.pack('<I4H4I', 0xed26ff3a, 1, 0, 28, 12, 4096, blocks, 1, 0)
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / 'super.img'
            path.write_bytes(header + struct.pack('<2H2I', 0xcac3, 0, blocks, 12))
            self.assertTrue(inspect_sparse_file(path, geometry)['all_chunk_bounds_verified'])
            path.write_bytes(header + struct.pack('<2H2I', 0xcac1, 0, blocks, 12 + geometry.super_size))
            with self.assertRaisesRegex(ValueError, 'out-of-bounds'):
                inspect_sparse_file(path, geometry)

    def test_reference_report_is_pinned_and_requires_checksums(self):
        path = pathlib.Path('reports/eu-super-geometry.json')
        if not path.is_file():
            self.skipTest('Authenticated reference fixture absent')
        original = read_json(path)
        self.assertEqual(geometry_from_report(original), Geometry())
        for field in ('full_archive_sha256_verified',):
            modified = copy.deepcopy(original)
            modified[field] = False
            with self.assertRaises(ValueError):
                geometry_from_report(modified)
        modified = copy.deepcopy(original)
        modified['reference_super_declared_size_bytes'] += 4096
        with self.assertRaises(ValueError):
            geometry_from_report(modified)


if __name__ == '__main__':
    unittest.main()
