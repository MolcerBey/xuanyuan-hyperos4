import unittest
from build_translations import (allowed_resources, target_strings, default_string,
                                format_signature, format_check, positional_format, select_entries)


class TranslationPolicyTests(unittest.TestCase):
    def test_signature_only_resources_excluded(self):
        text = 'name="Theme" actor=""\n  policies="signature"\n    string/private\n  policies="product|signature"\n    string/allowed\n  policies="public"\n    string/public_label\n'
        self.assertEqual(allowed_resources(text), {"string/allowed": "Theme", "string/public_label": "Theme"})

    def test_group_policy_does_not_allow_vendor(self):
        text = 'name="Vendor" actor=""\n policies="vendor"\n string/label\n'
        self.assertEqual(allowed_resources(text), {})

    def test_new_group_does_not_inherit_previous_public_policy(self):
        text = 'name="First"\n policies="public"\n string/ok\nname="Second"\n string/not_explicitly_allowed\n'
        self.assertEqual(allowed_resources(text), {'string/ok': 'First'})

    def test_resource_blocks_preserve_format_markers(self):
        text = 'resource 0x7f010000 string/title\n () "Hello"\nresource 0x7f010001 string/count\n () "%1$d items"\nresource 0x7f020000 bool/flag\n () true\n'
        resources = target_strings(text)
        self.assertNotIn("bool/flag", resources)
        self.assertIn("%1$d", resources["string/count"])
        self.assertNotIn("%", resources["string/title"])


class TranslationFormatTests(unittest.TestCase):
    def test_only_unambiguous_default_literal_establishes_contract(self):
        block = ' () "%1$d items"\n (tr) "%1$s local text"\n'
        self.assertEqual(default_string(block), ('%1$d items', 'literal'))
        self.assertIsNone(format_check('%1$d oge', block)[0])
        self.assertEqual(format_check('%1$s oge', block)[0], 'format_signature_mismatch')

    def test_missing_ambiguous_and_reference_defaults_are_rejected(self):
        for block, reason in [
            (' (en) "%s"', 'missing'),
            (' () "%s"\n () "%s"', 'ambiguous'),
            (' () @string/other\n (en) "%s"', 'non_literal'),
            (' () "%s" (styled)', 'non_literal'),
        ]:
            with self.subTest(reason=reason):
                self.assertEqual(format_check('%s', block)[0], 'format_default_' + reason)

    def test_default_quoted_escapes_are_decoded_without_evaluation(self):
        self.assertEqual(default_string(r' () "Say \"%s\"\nnow"'), ('Say "%s"\nnow', 'literal'))
        self.assertEqual(default_string(r' () "\u0025s"')[1], 'unknown_escape')

    def test_localized_percent_does_not_override_clean_default(self):
        reason, evidence = format_check('Temiz metin', ' () "Plain text"\n (fr) "100%"')
        self.assertIsNone(reason)
        self.assertTrue(evidence['format_checked'])

    def test_positional_translation_preserves_implicit_argument_types(self):
        self.assertEqual(format_signature('%d items for %s'), format_signature('%2$s icin %1$d oge'))
        self.assertNotEqual(format_signature('%d items for %s'), format_signature('%1$s icin %2$d oge'))

    def test_explicit_indices_do_not_advance_implicit_counter(self):
        self.assertEqual(format_signature('%2$s %s %s'), format_signature('%2$s %1$s %2$s'))

    def test_reuse_date_time_and_non_argument_tokens(self):
        self.assertEqual(format_signature('%tH:%<tM %% %n %s'),
                         format_signature('%1$tM:%1$tH %% %n %2$s'))
        self.assertEqual(positional_format('%tH:%<tM %% %n %s'), '%1$tH:%1$tM %% %n %2$s')

    def test_normalization_keeps_flags_precision_and_argument_contract(self):
        source = '%02d / %.2f / %<.2f'
        normalized = '%1$02d / %2$.2f / %2$.2f'
        self.assertEqual(positional_format(source), normalized)
        self.assertEqual(format_signature(source), format_signature(normalized))

    def test_type_count_and_literal_controls_must_match(self):
        for target, translated in [('%d', '%s'), ('%1$s %1$s', '%1$s'),
                                   ('%s', '%s %s'), ('%s %%', '%s'),
                                   ('%s%n', '%s'), ('%tH', '%tM')]:
            with self.subTest(target=target, translated=translated):
                block = ' () "' + target + '"'
                self.assertEqual(format_check(translated, block)[0], 'format_signature_mismatch')

    def test_invalid_or_unsupported_formats_are_not_silently_accepted(self):
        invalid = ['100%', '%q', '%tq', '%0$s', '%--5s', '%0s', '%-s', '%+ s',
                   '%1$.2d', '%<s', '%1$<s', '%1$n', '%5n', '%#s', '%F', '%10001s']
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                format_signature(value)

    def test_invalid_source_and_translation_are_distinguished(self):
        self.assertEqual(format_check('%s', ' () "100%"')[0], 'format_invalid_target_default')
        self.assertEqual(format_check('%q', ' () "%s"')[0], 'format_invalid_translation')

    def test_selection_reports_each_rejected_resource_without_fuzzy_mapping(self):
        xml = '<resources><string name="safe">%d oge</string><string name="bad">%s oge</string><string name="missing">Baslik</string><string name="private">%d oge</string></resources>'
        names = {'string/safe': ' () "%d items"', 'string/bad': ' () "%d items"',
                 'string/private': ' () "%d items"'}
        groups, skipped, details, verified = select_entries(
            xml, names, {'string/safe': 'Public', 'string/bad': 'Public'}, True)
        self.assertEqual([entry.get('name') for entry in groups['Public']], ['safe'])
        self.assertEqual(groups['Public'][0].text, '%1$d oge')
        self.assertEqual(verified, ['safe'])
        self.assertEqual(dict(skipped), {'format_signature_mismatch': 1, 'not_in_this_base': 1,
                                         'not_product_overlayable': 1})
        self.assertEqual({d['name'] for d in details}, {'bad', 'missing', 'private'})
        bad = next(d for d in details if d['name'] == 'bad')
        self.assertEqual(bad['target_default_text'], '%d items')
        self.assertEqual(bad['target_default_status'], 'literal')

    def test_styled_and_non_translatable_strings_still_require_review(self):
        xml = '<resources><string name="styled"><b>Metin</b></string><string name="fixed" translatable="false">Value</string></resources>'
        groups, skipped, details, _ = select_entries(xml, {}, {}, False)
        self.assertFalse(groups)
        self.assertEqual(skipped['non_plain_string'], 2)
        self.assertEqual(len(details), 2)
