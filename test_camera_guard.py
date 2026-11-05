import copy
import hashlib
import unittest

from camera_guard import (prepare_product_guard, verify_product_guard, REQUIRED_CAMERA_PACKAGES,
                          APPROVED_REMOVALS)


class CameraGuardTests(unittest.TestCase):
    def fixture(self):
        paths = dict(REQUIRED_CAMERA_PACKAGES)
        paths['com.miui.analytics'] = 'app/AnalyticsCore/AnalyticsCore.apk'
        snapshot, packages = {}, []
        for identity, path in paths.items():
            snapshot[path] = {'sha256': hashlib.sha256(path.encode()).hexdigest(), 'size': len(path),
                              'mode': 33188, 'uid': 0, 'gid': 0, 'xattrs': {'security.selinux': 'abcd'}}
            packages.append({'path': path, 'package': "package: name='" + identity + "' versionCode='1'"})
        snapshot['lib64/libcodec.so'] = copy.deepcopy(snapshot[next(iter(snapshot))])
        snapshot['etc/thermal_config.xml'] = copy.deepcopy(snapshot[next(iter(snapshot))])
        config = {'device': 'xuanyuan', 'base': 'OS4.0.0.18.XOACNXM',
                  'remove': {'app/AnalyticsCore': 'com.miui.analytics'}, 'replace': {}}
        return snapshot, config, {'apk_packages': packages}

    def test_exact_optional_removal_preserves_real_product_evidence(self):
        before, config, inventory = self.fixture()
        plan = prepare_product_guard(before, config, inventory)
        after = copy.deepcopy(before); del after['app/AnalyticsCore/AnalyticsCore.apk']
        report = verify_product_guard(plan, after)
        self.assertTrue(report['camera_dependency_preserved'])
        self.assertFalse(report['runtime_verified'])
        self.assertFalse(report['cross_partition_compatibility_verified'])
        self.assertEqual(len(report['required_camera_packages']), len(REQUIRED_CAMERA_PACKAGES))

    def test_camera_deletion_cannot_be_approved_in_debloat_config(self):
        before, config, inventory = self.fixture()
        config['remove']['priv-app/MiuiCamera'] = 'com.android.camera'
        with self.assertRaisesRegex(ValueError, 'Unreviewed'):
            prepare_product_guard(before, config, inventory)

    def test_broad_parent_or_glob_removal_rejected(self):
        for path in ['data-app', 'app/*', '../product/app/AnalyticsCore']:
            with self.subTest(path=path):
                before, config, inventory = self.fixture()
                config['remove'] = {path: 'com.miui.analytics'}
                with self.assertRaises(ValueError):
                    prepare_product_guard(before, config, inventory)

    def test_missing_camera_and_fake_identity_fail_before_changes(self):
        before, config, inventory = self.fixture()
        inventory['apk_packages'][0]['package'] = "package: name='wrong.identity'"
        with self.assertRaisesRegex(ValueError, 'Required camera'):
            prepare_product_guard(before, config, inventory)
        before, config, inventory = self.fixture()
        inventory['apk_packages'][-1]['package'] = "package: name='com.android.camera'"
        with self.assertRaisesRegex(ValueError, 'exact removal identity'):
            prepare_product_guard(before, config, inventory)

    def test_hash_mode_selinux_and_thermal_changes_are_rejected(self):
        cases = [('priv-app/MiuiCamera/MiuiCamera.apk', 'sha256', '0' * 64),
                 ('data-app/MIUIGallery/MIUIGallery.apk', 'mode', 33279),
                 ('data-app/MiMediaEditor/MiMediaEditor.apk', 'xattrs', {}),
                 ('etc/thermal_config.xml', 'sha256', '1' * 64),
                 ('lib64/libcodec.so', 'uid', 1000)]
        for path, key, value in cases:
            with self.subTest(path=path, field=key):
                before, config, inventory = self.fixture()
                plan = prepare_product_guard(before, config, inventory)
                after = copy.deepcopy(before); after[path][key] = value
                with self.assertRaisesRegex(ValueError, 'Protected dependency'):
                    verify_product_guard(plan, after)

    def test_optional_new_candidate_requires_complete_reverse_dependency_evidence(self):
        before, config, inventory = self.fixture()
        path = 'data-app/Health/Health.apk'
        before[path] = copy.deepcopy(before['app/AnalyticsCore/AnalyticsCore.apk'])
        config['remove']['data-app/Health'] = APPROVED_REMOVALS['data-app/Health']
        inventory['apk_packages'].append({'path': path, 'package': "package: name='com.mi.health'"})
        with self.assertRaisesRegex(ValueError, 'Complete dependency'):
            prepare_product_guard(before, config, inventory)
        deps = {'dependency_scan_complete': True, 'candidates': {'com.mi.health': {
            'exact_candidate_found': True, 'expected_path': 'product/' + path,
            'hard_dependency_findings': [{'consumer': 'com.android.systemui'}]}}}
        with self.assertRaisesRegex(ValueError, 'Unresolved declared dependency'):
            prepare_product_guard(before, config, inventory, deps)
        deps['candidates']['com.mi.health']['hard_dependency_findings'] = []
        plan = prepare_product_guard(before, config, inventory, deps)
        self.assertEqual(plan['new_optional_dependencies_checked'], ['com.mi.health'])


if __name__ == '__main__':
    unittest.main()
