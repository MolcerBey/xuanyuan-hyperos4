import base64
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from prepare_avb import read_json
from release_metadata import make_index, public_key, signing_request, verify_detached
from sign_update_index import sign_index


class UpdateSigningTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for the disposable signing identity')
    def test_domain_separated_index_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            private, xml = root / 'private.pem', root / 'public.xml'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                            'rsa_keygen_bits:4096', '-out', str(private)], check=True, capture_output=True)
            modulus = subprocess.check_output(['openssl', 'rsa', '-in', str(private), '-modulus', '-noout'],
                                              text=True).strip().split('=', 1)[1]
            xml.write_text('<RSAKeyValue><Modulus>' + base64.b64encode(bytes.fromhex(modulus)).decode() +
                           '</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>')
            key = public_key(xml)
            index = make_index(read_json('version.json'), key)
            request = signing_request(index, key)
            signature = sign_index(index, request, private, xml)
            self.assertTrue(verify_detached(index, signature, key)['signature_verified'])
            signature['digest_sha256'] = '00' * 32
            with self.assertRaisesRegex(ValueError, 'identity or digest'):
                verify_detached(index, signature, key)


if __name__ == '__main__':
    unittest.main()
