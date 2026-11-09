"""Sign a validated update index with the local AVB identity and verify it publicly."""
import argparse
import json
import pathlib
import subprocess
import tempfile

from prepare_avb import file_digest, read_json
from release_metadata import (ALGORITHM, DOMAIN, canonical_bytes, public_key,
                              validate_signing_request, verify_detached)
from sign_avb_requests import private_material, rsa_xml_to_pem


def sign_index(index, request, private_key, public_xml):
    key = public_key(public_xml)
    validate_signing_request(index, request, key)
    material = private_material(private_key, b'Molcer OS AVB signing identity v1')
    if b'PRIVATE KEY' not in material:
        material = rsa_xml_to_pem(material)
    with tempfile.TemporaryDirectory(prefix='molcer-index-local-signer-') as directory:
        root = pathlib.Path(directory)
        key_path, data_path, signature_path = root / 'key.pem', root / 'index.data', root / 'signature'
        key_path.write_bytes(material)
        key_path.chmod(0o600)
        data_path.write_bytes(DOMAIN + canonical_bytes(index))
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key_path),
                                 '-out', str(signature_path), str(data_path)],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise ValueError('OpenSSL rejected the update-index signing input or key')
        response = {name: request[name] for name in
                    ('schema', 'algorithm', 'digest_sha256', 'public_key_avb_sha256')}
        response['signature_hex'] = signature_path.read_bytes().hex()
    verify_detached(index, response, key)
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', required=True)
    parser.add_argument('--request', required=True)
    parser.add_argument('--private-key', default='.private/avb-key.dpapi')
    parser.add_argument('--public-key', default='keys/avb-public.xml')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    index, request = read_json(args.index), read_json(args.request)
    signature = sign_index(index, request, args.private_key, args.public_key)
    output = pathlib.Path(args.output)
    if output.exists():
        raise ValueError('Refusing to overwrite an existing detached signature')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(signature, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'signature_verified': True, 'algorithm': ALGORITHM,
                      'request_sha256': file_digest(args.request), 'private_key_in_output': False}))


if __name__ == '__main__':
    main()
