import pathlib
import tempfile
import unittest
import zipfile

from inspect_radio import inspect, path_hints, xml_evidence


class RadioInspectionTests(unittest.TestCase):
    def test_vodafone_name_does_not_establish_turkey(self):
        self.assertEqual(path_hints("generic/Europe/Vodafone/UK/mcfg_sw.mbn"), ["vodafone_name_country_not_established"])
        self.assertIn("turkey_or_turkish_operator_name", path_hints("generic/Turkey/Turkcell/mcfg_sw.mbn"))

    def test_arbitrary_286_number_is_not_country_evidence(self):
        evidence = xml_evidence(b'<carrier_config><int name="timeout" value="286"/></carrier_config>', "config.xml")
        self.assertEqual(evidence["mcc_286_elements"], [])
        self.assertEqual(evidence["filename_hints"], [])

    def test_mcc_attribute_and_mccmnc_filename_are_distinct_evidence(self):
        evidence = xml_evidence(b'<carrier_config mcc="286" mnc="01"><boolean name="carrier_volte_available_bool" value="true"/></carrier_config>', "config.xml")
        self.assertEqual(len(evidence["mcc_286_elements"]), 1)
        filename = xml_evidence(b'<carrier_config/>', "assets/carrier_config_mccmnc_28602.xml")
        self.assertEqual(filename["filename_hints"], ["mcc_286_filename"])
        self.assertEqual(filename["mcc_286_elements"], [])

    def test_static_inventory_never_claims_activation_and_keeps_input(self):
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            profile = work / "mounted_modem/image/modem_pr/mcfg/configs/mcfg_sw/generic/Turkey/Turkcell/mcfg_sw.mbn"
            profile.parent.mkdir(parents=True)
            original = b'\x00Turkcell test profile\x00'
            profile.write_bytes(original)
            apk = work / "mounted_product/app/CarrierConfig/CarrierConfig.apk"
            apk.parent.mkdir(parents=True)
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("assets/carrier_config_mccmnc_28601.xml", '<carrier_config><boolean name="carrier_volte_available_bool" value="true"/></carrier_config>')
            report = inspect(work)
            self.assertEqual(report["mbn_candidate_count"], 1)
            self.assertEqual(len(report["carrier_apk_assets"]), 1)
            self.assertFalse(report["active_mbn_profile_verified"])
            self.assertFalse(report["turkey_compatibility_verified"])
            self.assertFalse(report["source_files_modified"])
            self.assertEqual(profile.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
