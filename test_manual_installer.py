import pathlib
import tempfile
import unittest
from unittest import mock

from install_candidate import (FLASH_ORDER, FORBIDDEN, installation_plan, parse_getvar,
                               parse_partition_size, preflight)
from release_metadata import LOGICAL_PARTITIONS, SOURCE_PARTITIONS


class ManualInstallerTests(unittest.TestCase):
    def test_exact_oem_subset_and_no_protected_partitions(self):
        plan = installation_plan()
        self.assertEqual(len(plan), 39)
        self.assertEqual(set(FLASH_ORDER), SOURCE_PARTITIONS - LOGICAL_PARTITIONS | {'super'})
        self.assertFalse(FORBIDDEN.intersection(FLASH_ORDER))
        self.assertEqual(sum(item['target'] == 'super' for item in plan), 1)
        self.assertEqual(plan[-2:], [{'image': 'recovery', 'target': 'recovery_ab'},
                                    {'image': 'boot', 'target': 'boot_ab'}])

    def test_getvar_and_capacity_parsing(self):
        self.assertEqual(parse_getvar('product: xuanyuan\nFinished.', 'product'), 'xuanyuan')
        self.assertEqual(parse_partition_size('partition-size:super: 0x2c0000000\n', 'super'),
                         0x2c0000000)
        with self.assertRaisesRegex(ValueError, 'required variable'):
            parse_getvar('FAILED: remote variable not found', 'product')

    def test_capacity_and_identity_checks_precede_all_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for item in installation_plan():
                (root / (item['image'] + '.img')).write_bytes(b'x')

            def query(fastboot, variable):
                if variable == 'product':
                    return 'product: xuanyuan\n'
                if variable == 'unlocked':
                    return 'unlocked: yes\n'
                if variable == 'current-slot':
                    return 'current-slot: b\n'
                return 'partition-size:' + variable.split(':', 1)[1] + ': 0x1000\n'

            with mock.patch('install_candidate.run_query', side_effect=query), \
                    mock.patch('install_candidate.subprocess.run') as run:
                evidence = preflight('fastboot', root, installation_plan())
            self.assertTrue(evidence['bootloader_unlocked'])
            self.assertEqual(evidence['previous_slot'], 'b')
            run.assert_not_called()
            (root / 'super.img').write_bytes(b'x' * 4097)
            with mock.patch('install_candidate.run_query', side_effect=query):
                with self.assertRaisesRegex(ValueError, 'capacity'):
                    preflight('fastboot', root, installation_plan())


if __name__ == '__main__':
    unittest.main()
