import pathlib
import tempfile
import unittest
import xml.etree.ElementTree as ET

from inspect_app_dependencies import (CANDIDATES, build_reverse_dependencies,
                                      inspect_xml, parse_manifest, parse_xml_reference)


# Reduced, verbatim attribute/indentation format from the actual SDK37
# Health.apk candidate dump in customization-audit's app-dependencies.json.
HEALTH_SDK37 = '''N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: package="com.mi.health" (Raw: "com.mi.health")
      E: uses-permission (line=15)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.BLUETOOTH_ADMIN" (Raw: "android.permission.BLUETOOTH_ADMIN")
      E: permission (line=34)
        A: http://schemas.android.com/apk/res/android:label(0x01010001)="read device status permission" (Raw: "read device status permission")
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.mi.health.provider.device.read" (Raw: "com.mi.health.provider.device.read")
        A: http://schemas.android.com/apk/res/android:protectionLevel(0x01010009)=0x00000003
      E: application (line=300)
          E: provider (line=400)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.xiaomi.fitness.device.manager.provider.DeviceProvider" (Raw: "com.xiaomi.fitness.device.manager.provider.DeviceProvider")
            A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="com.mi.health.provider.device" (Raw: "com.mi.health.provider.device")
'''
PREFIX = 'http://schemas.android.com/apk/res/android:'


def consumer_manifest():
    return f'''E: manifest
  A: package="com.example.consumer"
  A: {PREFIX}sharedUserId(0x0101000b)="com.example.shared"
  E: uses-permission
    A: {PREFIX}name(0x01010003)="com.mi.health.provider.device.read"
  E: application
    E: uses-library
      A: {PREFIX}name(0x01010003)="health.required.library"
      A: {PREFIX}required(0x0101028e)=true
    E: uses-library
      A: {PREFIX}name(0x01010003)="health.optional.library"
      A: {PREFIX}required(0x0101028e)=false
  E: queries
    E: package
      A: {PREFIX}name(0x01010003)="com.mi.health"
'''


class AppDependenciesTests(unittest.TestCase):
    def test_actual_sdk37_candidate_attributes_normalize(self):
        app = parse_manifest(HEALTH_SDK37)
        self.assertEqual(app['package'], 'com.mi.health')
        self.assertEqual(app['defined_permissions'][0]['android:name'], 'com.mi.health.provider.device.read')
        self.assertEqual(app['used_permissions'][0]['android:name'], 'android.permission.BLUETOOTH_ADMIN')
        self.assertEqual(app['providers'][0]['android:authorities'], 'com.mi.health.provider.device')

    def test_shared_uid_nested_libraries_permissions_and_query_reverse_counts(self):
        candidate_text = HEALTH_SDK37.replace('    A: package=',
            f'    A: {PREFIX}sharedUserId(0x0101000b)="com.example.shared"\n    A: package=')
        candidate_text += f'''          E: library
            A: {PREFIX}name="health.required.library"
          E: library
            A: {PREFIX}name="health.optional.library"
'''
        candidate = {**parse_manifest(candidate_text), 'path': CANDIDATES['com.mi.health']}
        consumer = {**parse_manifest(consumer_manifest()), 'path': 'system/app/Consumer/Consumer.apk'}
        self.assertEqual(candidate['shared_user_id'], 'com.example.shared')
        self.assertEqual(consumer['shared_user_id'], 'com.example.shared')
        result = build_reverse_dependencies([candidate, consumer])['com.mi.health']
        self.assertEqual(len(result['hard_dependency_findings']), 3)
        self.assertEqual({r['kind'] for r in result['hard_dependency_findings']},
                         {'shared-user-id', 'uses-library', 'permission-defined-by-candidate'})
        self.assertEqual(len(result['soft_reference_findings']), 2)
        self.assertEqual({r['kind'] for r in result['soft_reference_findings']}, {'uses-library', 'package-query'})
        self.assertEqual(result['provider_authorities'], ['com.mi.health.provider.device'])

    def test_overlay_full_uri_target_name_and_priority_are_preserved(self):
        app = parse_manifest(f'''E: manifest
  A: package="com.example.overlay"
  E: overlay
    A: {PREFIX}targetPackage="android"
    A: {PREFIX}targetName="ThemeResources"
    A: {PREFIX}priority=999
    A: {PREFIX}isStatic=true
''')
        self.assertEqual(app['overlays'], [{'tag': 'overlay', 'android:targetPackage': 'android',
                                          'android:targetName': 'ThemeResources', 'android:priority': '999',
                                          'android:isStatic': 'true'}])

    def test_only_exact_android_uri_prefix_is_normalized(self):
        app = parse_manifest('''E: manifest
  A: package="com.example.app"
  E: application
    A: http://schemas.android.com/apk/res/androidx:name="keep-this-key"
    A: android:name="legacy.Name"
''')
        attrs = app['application'][0]
        self.assertEqual(attrs['http://schemas.android.com/apk/res/androidx:name'], 'keep-this-key')
        self.assertEqual(attrs['android:name'], 'legacy.Name')

    def test_duplicate_normalized_attributes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate normalized'):
            parse_manifest(f'''E: manifest
  A: package="com.example.app"
  A: android:sharedUserId="first"
  A: {PREFIX}sharedUserId="second"
''')

    def test_fragment_xml_preserves_all_roots_and_full_raw_evidence(self):
        text = ('<?xml version="1.0" encoding="utf-8"?>\n'
                '<packages><group><apk name="com.mi.health"/></group></packages>\n'
                '<removable package="com.mi.health"/>\n')
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc').mkdir()
            (root / 'etc/removable_apk_info.xml').write_bytes(text.encode('utf-8'))
            candidates = {'com.mi.health': {'expected_path': CANDIDATES['com.mi.health']}}
            result = inspect_xml({'product': root}, candidates)
        self.assertEqual(result['errors'], [])
        item = result['candidate_references'][0]
        self.assertEqual(item['parse_mode'], 'xml-fragments-wrapped')
        self.assertEqual(item['fragment_root_count'], 2)
        self.assertEqual(item['raw_text'], text)
        self.assertFalse(item['raw_text_truncated'])
        self.assertIn('junk after document element', item['initial_parse_error'])
        self.assertEqual({e['tag'] for e in item['entries']}, {'apk', 'removable'})

    def test_normal_xml_is_not_wrapped(self):
        root, evidence = parse_xml_reference('<packages><apk name="com.mi.health"/></packages>')
        self.assertEqual(root.tag, 'packages')
        self.assertEqual(evidence['parse_mode'], 'xml-document')

    def test_malformed_xml_and_non_xml_trailing_junk_remain_errors(self):
        for text in ('<packages><apk></packages>', '<packages/> garbage',
                     '<packages/><second>unclosed', '<packages/><broken></wrong>'):
            with self.subTest(text=text), self.assertRaises((ValueError, ET.ParseError)):
                parse_xml_reference(text)
        text = '<packages name="com.mi.health"/> trailing-junk'
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'etc').mkdir()
            (root / 'etc/broken.xml').write_bytes(text.encode('utf-8'))
            result = inspect_xml({'product': root}, {'com.mi.health': {'expected_path': CANDIDATES['com.mi.health']}})
        self.assertEqual(len(result['errors']), 1)
        self.assertEqual(result['errors'][0]['parse_mode'], 'failed')
        self.assertEqual(result['errors'][0]['raw_text'], text)
        self.assertEqual(result['candidate_references'], [])


if __name__ == '__main__':
    unittest.main()
