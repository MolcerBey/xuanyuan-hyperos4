import unittest
from fetch_chrome_candidate import parse_apk_signers


class ChromeSignerTests(unittest.TestCase):
    def test_sdk37_v3_signer_with_separate_source_stamp(self):
        output = 'Number of signers: 1\nV3.0 Signer: certificate SHA-256 digest: ' + 'a'*64 + '\nSource Stamp Signer: certificate SHA-256 digest: ' + 'b'*64 + '\n'
        self.assertEqual(parse_apk_signers(output, 'a'*64), ['a'*64])

    def test_legacy_output(self):
        self.assertEqual(parse_apk_signers('Number of signers: 1\nSigner #1 certificate SHA-256 digest: ' + 'a'*64, 'a'*64), ['a'*64])

    def test_source_stamp_cannot_substitute_for_apk_signer(self):
        output = 'Number of signers: 1\nV3.0 Signer: certificate SHA-256 digest: ' + 'b'*64 + '\nSource Stamp Signer: certificate SHA-256 digest: ' + 'a'*64
        with self.assertRaisesRegex(ValueError, 'pinned'):
            parse_apk_signers(output, 'a'*64)

    def test_multiple_missing_or_unknown_signers_rejected(self):
        for output in ['Number of signers: 2\nSigner #1 certificate SHA-256 digest: ' + 'a'*64,
                       'Number of signers: 1\nSource Stamp Signer: certificate SHA-256 digest: ' + 'a'*64,
                       'Number of signers: 1\nUnknown Signer: certificate SHA-256 digest: ' + 'a'*64]:
            with self.assertRaises(ValueError):
                parse_apk_signers(output, 'a'*64)


if __name__ == '__main__':
    unittest.main()
