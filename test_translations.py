import unittest
from build_translations import allowed_resources, target_strings


class TranslationPolicyTests(unittest.TestCase):
    def test_signature_only_resources_excluded(self):
        text = 'name="Theme" actor=""\n  policies="signature"\n    string/private\n  policies="product|signature"\n    string/allowed\n  policies="public"\n    string/public_label\n'
        self.assertEqual(allowed_resources(text), {"string/allowed": "Theme", "string/public_label": "Theme"})

    def test_group_policy_does_not_allow_vendor(self):
        text = 'name="Vendor" actor=""\n policies="vendor"\n string/label\n'
        self.assertEqual(allowed_resources(text), {})

    def test_resource_blocks_preserve_format_markers(self):
        text = 'resource 0x7f010000 string/title\n () "Hello"\nresource 0x7f010001 string/count\n () "%1$d items"\nresource 0x7f020000 bool/flag\n () true\n'
        resources = target_strings(text)
        self.assertNotIn("bool/flag", resources)
        self.assertIn("%1$d", resources["string/count"])
        self.assertNotIn("%", resources["string/title"])
