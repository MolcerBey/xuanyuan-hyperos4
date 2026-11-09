import copy
import hashlib
import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from prepare_avb import (ALGORITHM, apply_signature, check_chain_key, descriptor_key, digest,
                         exact_descriptor, init_boot_body_size, load_tool,
                         parse_blob, public_only_key, replace_descriptors, run_tool,
                         unsigned_blob, validate_request, verify_full_chain)
from inspect_packaging import read_vbmeta_blob


class AVBRebuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_tool('.tools/avbtool.py')

    def descriptors(self):
        m = self.module
        init = m.AvbHashDescriptor(); init.partition_name = 'init_boot'; init.image_size = 4096
        init.hash_algorithm = 'sha256'; init.digest = b'\0' * 32
        country = m.AvbHashDescriptor(); country.partition_name = 'countrycode'; country.image_size = 32
        country.hash_algorithm = 'sha256'; country.digest = b'\0' * 32
        boot = m.AvbChainPartitionDescriptor(); boot.partition_name = 'boot'; boot.rollback_index_location = 3; boot.public_key = b'original'
        prop = m.AvbPropertyDescriptor(); prop.key = 'test'; prop.value = b'keep'
        return [init, country, boot, prop]

    def test_only_selected_descriptors_change(self):
        original = self.descriptors()
        replacement = copy.deepcopy(original[0]); replacement.digest = b'\x01' * 32
        result, kept = replace_descriptors(original, {('AvbHashDescriptor', 'init_boot'): replacement},
                                           {('AvbHashDescriptor', 'countrycode')})
        self.assertEqual([d.encode() for d in result[1:]], [d.encode() for d in original[2:]])
        self.assertEqual(len(kept), 2)
        self.assertFalse(any(getattr(d, 'partition_name', None) == 'countrycode' for d in result))
        self.assertEqual(original[0].digest, b'\0' * 32)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            replace_descriptors(original + [copy.deepcopy(original[0])], {('AvbHashDescriptor', 'init_boot'): replacement})

    def test_replacement_cannot_retarget_another_partition(self):
        original = self.descriptors()
        with self.assertRaisesRegex(ValueError, 'identity'):
            replace_descriptors(original, {('AvbHashDescriptor', 'init_boot'): original[1]})

    def test_pinned_aosp_builder_api_runs_without_openssl(self):
        # Only public-key loading is stubbed. Execute the real pinned builder so
        # API/class regressions are caught even where OpenSSL is unavailable.
        class SyntheticPublicKey:
            def __init__(self, path):
                self.num_bits = 4096

            def encode(self):
                return struct.pack('>II', 4096, 0) + b'\x01' * 1024

        m = self.module
        header = m.AvbVBMetaHeader()
        header.rollback_index = 123
        with mock.patch.object(m, 'RSAPublicKey', SyntheticPublicKey):
            blob, request = unsigned_blob(m, 'synthetic-test-public.pem', header, self.descriptors())
        parsed, descriptors, auth, aux, _ = parse_blob(m, blob)
        self.assertEqual(parsed.rollback_index, 123)
        self.assertEqual([d.encode() for d in descriptors], [d.encode() for d in self.descriptors()])
        self.assertEqual(request['digest_sha256'], digest(blob[:256] + aux))
        self.assertEqual(auth[parsed.signature_offset:parsed.signature_offset + parsed.signature_size], b'\0' * 512)

    def test_init_boot_uses_updated_header_not_stale_footer(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'init_boot.img'
            data = bytearray(32768); data[:8] = b'ANDROID!'
            struct.pack_into('<2I', data, 8, 0, 12000)
            struct.pack_into('<I', data, 20, 1584); struct.pack_into('<I', data, 40, 4)
            data[-64:] = struct.pack('>4s2I3Q28s', b'AVBf', 1, 0, 8192, 8192, 256, b'\0' * 28)
            path.write_bytes(data)
            self.assertEqual(init_boot_body_size(path), 16384)
            struct.pack_into('<I', data, 12, 999999)
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'truncated'):
                init_boot_body_size(path)

    def test_oem_child_key_is_bound_to_parent_not_custom_root(self):
        m = self.module
        descriptor = m.AvbChainPartitionDescriptor()
        descriptor.partition_name = 'boot'
        descriptor.public_key = b'OEM boot test key'
        header = m.AvbVBMetaHeader()
        header.algorithm_type = 2
        header.auxiliary_data_block_size = 64
        header.public_key_offset = 0
        header.public_key_size = len(descriptor.public_key)
        blob = header.encode() + descriptor.public_key.ljust(64, b'\0')
        self.assertEqual(check_chain_key(m, descriptor, blob), descriptor.public_key)
        wrong = copy.deepcopy(descriptor); wrong.public_key = b'custom root key'
        with self.assertRaisesRegex(ValueError, 'parent descriptor'):
            check_chain_key(m, wrong, blob)
        header.flags = 2
        with self.assertRaisesRegex(ValueError, 'parent descriptor'):
            check_chain_key(m, descriptor, header.encode() + descriptor.public_key.ljust(64, b'\0'))

    def test_full_chain_verifier_keeps_oem_keys_and_rejects_key_substitution(self):
        # Synthetic metadata exercises graph/key routing; real signature checking
        # is separately exercised by the OpenSSL roundtrip below.
        m = self.module

        def metadata(key, descriptors=()):
            encoded = b''.join(d.encode() for d in descriptors)
            header = m.AvbVBMetaHeader()
            header.algorithm_type = 2
            header.descriptors_size = len(encoded)
            header.public_key_offset = len(encoded)
            header.public_key_size = len(key)
            auxiliary = encoded + key
            auxiliary = auxiliary.ljust((len(auxiliary) + 63) // 64 * 64, b'\0')
            header.auxiliary_data_block_size = len(auxiliary)
            return header.encode() + auxiliary

        keys = {'boot': b'OEM boot key', 'recovery': b'OEM recovery key',
                'vbmeta_system': b'custom root key'}
        chains = []
        for location, (name, key) in enumerate(keys.items(), 1):
            chain = m.AvbChainPartitionDescriptor()
            chain.partition_name = name
            chain.rollback_index_location = location
            chain.public_key = key
            chains.append(chain)
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'vbmeta.img').write_bytes(metadata(b'custom root key', chains))
            for name, key in keys.items():
                (root / (name + '.img')).write_bytes(metadata(key))
            with mock.patch('prepare_avb.run_tool') as verifier:
                nodes = verify_full_chain(m, 'avbtool.py', root, 'root.pem')
            self.assertEqual(nodes, ['boot', 'recovery', 'vbmeta', 'vbmeta_system'])
            calls = [list(call.args) for call in verifier.call_args_list]
            self.assertEqual(sum('--key' in call for call in calls), 1)
            self.assertIn('--key', calls[0])
            self.assertNotIn('--follow_chain_partitions', sum(calls, []))
            self.assertEqual(calls[0].count('--expected_chain_partition'), 3)
            self.assertEqual((root / '.expected-vbmeta-boot.avbpubkey').read_bytes(), keys['boot'])
            (root / 'boot.img').write_bytes(metadata(b'custom root key'))
            with mock.patch('prepare_avb.run_tool') as verifier:
                with self.assertRaisesRegex(ValueError, 'parent descriptor'):
                    verify_full_chain(m, 'avbtool.py', root, 'root.pem')
                verifier.assert_not_called()

    @unittest.skipUnless(shutil.which('fec'), 'Pinned Linux fec required for the real FEC2 footer regression')
    def test_real_fec2_footer_generation_and_data_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'product.img'
            body = hashlib.shake_256(b'Molcer AVB FEC integration fixture').digest(1024**2)
            path.write_bytes(body)
            run_tool('.tools/avbtool.py', 'add_hashtree_footer', '--image', path,
                     '--partition_name', 'product', '--hash_algorithm', 'sha256',
                     '--block_size', 4096, '--salt', '00' * 32,
                     '--algorithm', 'NONE', '--fec_num_roots', 2)
            footer, blob = read_vbmeta_blob(path)
            header, descriptors, _, _, _ = parse_blob(self.module, blob)
            descriptor = exact_descriptor(descriptors, 'AvbHashtreeDescriptor', 'product')
            self.assertEqual(header.flags, 0)
            self.assertEqual(header.algorithm_type, 0)
            self.assertEqual(footer['original_image_size'], len(body))
            self.assertEqual(descriptor.fec_num_roots, 2)
            self.assertGreater(descriptor.fec_size, 0)
            self.assertEqual(descriptor.fec_offset, descriptor.tree_offset + descriptor.tree_size)
            run_tool('.tools/avbtool.py', 'verify_image', '--image', path)
            with path.open('r+b') as stream:
                stream.write(bytes([body[0] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'avbtool failed'):
                run_tool('.tools/avbtool.py', 'verify_image', '--image', path)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required; cryptographic roundtrip runs in Linux CI')
    def test_signature_roundtrip_and_tamper_rejection(self):
        m = self.module
        from validate_signing_requests import avb_public_from_xml, verify_public_signature
        self.assertEqual(avb_public_from_xml('keys/avb-public.xml'),
                         public_only_key(m, 'keys/avb-public.pem'))
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); private = root / 'ephemeral-test-key.pem'; public = root / 'public.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096', '-out', str(private)], check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
            key = public_only_key(m, public)
            header = m.AvbVBMetaHeader(); header.rollback_index = 123; header.rollback_index_location = 2
            blob, request = unsigned_blob(m, public, header, self.descriptors())
            request.update({'partition': 'vbmeta', 'algorithm': ALGORITHM, 'unsigned_blob_hex': blob.hex(),
                            'unsigned_blob_sha256': digest(blob), 'partition_image_size': 12288,
                            'unsigned_image_sha256': digest(blob.ljust(12288, b'\0'))})
            parsed, _, _, aux, _ = parse_blob(m, blob)
            self.assertEqual(parsed.rollback_index, 123)
            self.assertEqual(parsed.flags, 0)
            (root / 'data').write_bytes(blob[:256] + aux)
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(private), '-out', str(root / 'signature'), str(root / 'data')], check=True, capture_output=True)
            response = {k: request[k] for k in ('partition', 'unsigned_blob_sha256', 'digest_sha256')}
            response['signature_hex'] = (root / 'signature').read_bytes().hex()
            signed = apply_signature(m, request, response, key, public)
            self.assertTrue(m.verify_vbmeta_signature(m.AvbVBMetaHeader(signed[:256]), signed))
            tampered = bytearray(signed)
            tampered[256 + parsed.signature_offset] ^= 1
            self.assertFalse(m.verify_vbmeta_signature(m.AvbVBMetaHeader(tampered[:256]), tampered))
            verify_public_signature(m, signed)
            bad = copy.deepcopy(request); b = bytearray(blob); b[-1] ^= 1; bad['unsigned_blob_hex'] = b.hex()
            with self.assertRaisesRegex(ValueError, 'blob hash'):
                validate_request(m, bad, key)
            bad = dict(response); bad['digest_sha256'] = '00' * 32
            with self.assertRaisesRegex(ValueError, 'different request'):
                apply_signature(m, request, bad, key, public)
            bad = dict(response); sig = bytearray.fromhex(bad['signature_hex']); sig[0] ^= 1; bad['signature_hex'] = sig.hex()
            with self.assertRaisesRegex(ValueError, 'verification failed'):
                apply_signature(m, request, bad, key, public)


if __name__ == '__main__':
    unittest.main()
