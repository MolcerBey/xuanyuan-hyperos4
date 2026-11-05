import unittest
from policy_audit import validate_product_properties


class PolicyAuditTests(unittest.TestCase):
    def fixture(self):
        original = '# source\nro.product.locale=zh-CN\nro.build.display.id=Stock\npersist.sys.power=true\nduplicate=a\nduplicate=b\n'
        modified = original.replace('zh-CN', 'tr-TR').replace('ro.build.display.id=Stock', 'ro.build.display.id=Molcer OS 0.2.0')
        modified += 'ro.molcer.os.name=Molcer OS\nro.molcer.os.version=0.2.0\npersist.sys.timezone=Europe/Istanbul\n'
        return original, modified

    def test_preserves_even_existing_duplicate_oem_lines(self):
        old, new = self.fixture()
        self.assertTrue(validate_product_properties(old, new, '0.2.0')['other_oem_property_lines_unchanged'])

    def test_unapproved_power_property_rejected(self):
        old, new = self.fixture()
        with self.assertRaisesRegex(ValueError, 'Unapproved'):
            validate_product_properties(old, new.replace('power=true', 'power=false'), '0.2.0')

    def test_duplicate_custom_property_rejected(self):
        old, new = self.fixture()
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            validate_product_properties(old, new + 'ro.product.locale=zh-CN\n', '0.2.0')
