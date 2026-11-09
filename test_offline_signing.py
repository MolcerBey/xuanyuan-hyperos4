import copy
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from prepare_avb import ALGORITHM, apply_signature, digest, load_tool, public_only_key, unsigned_blob
from sign_avb_requests import sign_requests


class OfflineSigningTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for the disposable signing identity')
    def test_local_signatures_match_their_requests_and_public_key(self):
        module = load_tool('.tools/avbtool.py')
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            private, public = root / 'private.pem', root / 'public.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                            'rsa_keygen_bits:4096', '-out', str(private)], check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)],
                           check=True, capture_output=True)
            encoded_public = public_only_key(module, public)
            descriptor = module.AvbPropertyDescriptor()
            descriptor.key, descriptor.value = 'test', b'offline'
            requests = []
            for name in ('vbmeta', 'vbmeta_system'):
                header = module.AvbVBMetaHeader()
                blob, request = unsigned_blob(module, public, header, [descriptor])
                request.update(partition=name, algorithm=ALGORITHM, unsigned_blob_hex=blob.hex(),
                               unsigned_blob_sha256=digest(blob), partition_image_size=12288,
                               unsigned_image_sha256=digest(blob.ljust(12288, b'\0')))
                requests.append(request)
            requests_path = root / 'requests.json'
            requests_path.write_bytes(b'validated synthetic request fixture')
            bundle = {'schema': 1, 'algorithm': ALGORITHM,
                      'public_key_avb_sha256': digest(encoded_public), 'requests': requests}
            result = sign_requests(bundle, requests_path, private, public, '.tools/avbtool.py')
            self.assertEqual(len(result['signatures']), 2)
            for request, response in zip(requests, result['signatures']):
                signed = apply_signature(module, request, response, encoded_public, public)
                self.assertTrue(module.verify_vbmeta_signature(module.AvbVBMetaHeader(signed[:256]), signed))
            changed = copy.deepcopy(result['signatures'][0])
            changed['digest_sha256'] = '00' * 32
            with self.assertRaisesRegex(ValueError, 'different request'):
                apply_signature(module, requests[0], changed, encoded_public, public)


if __name__ == '__main__':
    unittest.main()
