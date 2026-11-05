import copy
import unittest
from tree_audit import compare_retained


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.original = {"camera.apk": {"mode": 33188, "uid": 0, "gid": 0, "xattrs": {"security.selinux": "abc"}, "sha256": "camera", "size": 8}, "ads.apk": {"sha256": "ads"}, "etc/build.prop": {"sha256": "stock", "size": 2, "mode": 33188}}

    def test_approved_changes(self):
        after = copy.deepcopy(self.original)
        del after["ads.apk"]
        after["etc/build.prop"]["sha256"] = "molcer"
        after["chrome.apk"] = {"sha256": "chrome"}
        self.assertEqual(compare_retained(self.original, after, ["ads.apk"], {"etc/build.prop"}, {"chrome.apk"}), 1)

    def test_camera_change_rejected(self):
        after = copy.deepcopy(self.original)
        after["camera.apk"]["sha256"] = "changed"
        with self.assertRaises(ValueError):
            compare_retained(self.original, after, [], set(), set())

    def test_selinux_loss_rejected(self):
        after = copy.deepcopy(self.original)
        after["camera.apk"]["xattrs"] = {}
        with self.assertRaises(ValueError):
            compare_retained(self.original, after, [], set(), set())

    def test_unexpected_file_rejected(self):
        after = copy.deepcopy(self.original)
        after["unexpected.apk"] = {}
        with self.assertRaises(ValueError):
            compare_retained(self.original, after, [], set(), set())
