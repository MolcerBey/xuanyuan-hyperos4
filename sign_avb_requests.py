"""Sign only validated AVB requests with a local PEM or Current-User DPAPI key."""
import argparse
import base64
import ctypes
from ctypes import wintypes
import json
import os
import pathlib
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from prepare_avb import (ALGORITHM, NAMES, apply_signature, digest, file_digest,
                         load_tool, public_only_key, read_json, validate_request)


def decrypt_dpapi(path, entropy):
    if os.name != 'nt':
        raise ValueError('DPAPI private keys require the original Windows user account')
    encrypted = pathlib.Path(path).read_bytes()
    if not 64 <= len(encrypted) <= 16384:
        raise ValueError('Unexpected encrypted private-key size')

    class DataBlob(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

    source = (ctypes.c_byte * len(encrypted)).from_buffer_copy(encrypted)
    extra = (ctypes.c_byte * len(entropy)).from_buffer_copy(entropy)
    input_blob = DataBlob(len(encrypted), source)
    entropy_blob = DataBlob(len(entropy), extra)
    output_blob = DataBlob()
    crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    if not crypt32.CryptUnprotectData(ctypes.byref(input_blob), None, ctypes.byref(entropy_blob),
                                      None, None, 0, ctypes.byref(output_blob)):
        raise ValueError('Windows could not decrypt the key for the current user')
    try:
        plaintext = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        if len(plaintext) > 16384:
            raise ValueError('Decrypted private-key material exceeds its limit')
        return plaintext
    finally:
        kernel32.LocalFree(output_blob.pbData)


def private_material(path, entropy=b''):
    path = pathlib.Path(path)
    if path.suffix.lower() == '.dpapi':
        return decrypt_dpapi(path, entropy)
    data = path.read_bytes()
    if len(data) > 16384:
        raise ValueError('Private-key material exceeds its size limit')
    return data


def der_field(tag, value):
    length = len(value)
    if length < 128:
        encoded = bytes([length])
    else:
        octets = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        encoded = bytes([0x80 | len(octets)]) + octets
    return bytes([tag]) + encoded + value


def der_integer(value):
    if value < 0:
        raise ValueError('Negative RSA parameter')
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    return der_field(2, b'\0' + raw if raw[0] & 0x80 else raw)


def rsa_xml_to_pem(material):
    root = ET.fromstring(material)
    names = ('Modulus', 'Exponent', 'P', 'Q', 'DP', 'DQ', 'InverseQ', 'D')
    if root.tag != 'RSAKeyValue' or len(root) != 8 or {item.tag for item in root} != set(names):
        raise ValueError('Unexpected private RSA XML structure')
    values = {}
    for name in names:
        raw = base64.b64decode(root.findtext(name), validate=True)
        if not raw:
            raise ValueError('Empty RSA parameter')
        values[name] = int.from_bytes(raw, 'big')
    if (values['Modulus'].bit_length() != 4096 or values['Exponent'] != 65537
            or values['P'] * values['Q'] != values['Modulus']):
        raise ValueError('Unexpected private RSA identity')
    pkcs1 = der_field(0x30, b''.join(der_integer(value) for value in
        (0, values['Modulus'], values['Exponent'], values['D'], values['P'], values['Q'],
         values['DP'], values['DQ'], values['InverseQ'])))
    algorithm = bytes.fromhex('300d06092a864886f70d0101010500')
    pkcs8 = der_field(0x30, der_integer(0) + algorithm + der_field(4, pkcs1))
    encoded = base64.b64encode(pkcs8).decode('ascii')
    return ('-----BEGIN PRIVATE KEY-----\n' + '\n'.join(encoded[index:index + 64]
            for index in range(0, len(encoded), 64)) + '\n-----END PRIVATE KEY-----\n').encode('ascii')


def sign_requests(bundle, requests_path, private_key, public_key_path, avbtool):
    module = load_tool(avbtool)
    public = public_only_key(module, public_key_path)
    requests = bundle['requests']
    if (bundle.get('schema') != 1 or bundle.get('algorithm') != ALGORITHM
            or bundle.get('public_key_avb_sha256') != digest(public)
            or len(requests) != 2 or {r['partition'] for r in requests} != NAMES):
        raise ValueError('Unexpected AVB signing bundle identity')
    material = private_material(private_key, b'Molcer OS AVB signing identity v1')
    if b'PRIVATE KEY' not in material:
        material = rsa_xml_to_pem(material)
    responses = []
    try:
        with tempfile.TemporaryDirectory(prefix='molcer-avb-local-signer-') as directory:
            key_path = pathlib.Path(directory) / 'key.pem'
            key_path.write_bytes(material)
            key_path.chmod(0o600)
            for request in requests:
                _, _, _, data = validate_request(module, request, public)
                data_path = pathlib.Path(directory) / (request['partition'] + '.data')
                signature_path = pathlib.Path(directory) / (request['partition'] + '.sig')
                data_path.write_bytes(data)
                result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key_path),
                                         '-out', str(signature_path), str(data_path)],
                                        capture_output=True, text=True, timeout=60)
                if result.returncode:
                    raise ValueError('OpenSSL rejected the local private key or signing request')
                response = {key: request[key] for key in
                            ('partition', 'unsigned_blob_sha256', 'digest_sha256')}
                response['signature_hex'] = signature_path.read_bytes().hex()
                apply_signature(module, request, response, public, public_key_path)
                responses.append(response)
    finally:
        if isinstance(material, bytearray):
            material[:] = b'\0' * len(material)
    return {'schema': 1, 'algorithm': ALGORITHM, 'requests_sha256': file_digest(requests_path),
            'public_key_avb_sha256': digest(public), 'signatures': responses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', required=True)
    parser.add_argument('--private-key', default='.private/avb-key.dpapi')
    parser.add_argument('--public-key', default='keys/avb-public.pem')
    parser.add_argument('--avbtool', default='.tools/avbtool.py')
    parser.add_argument('--output', required=True)
    parser.add_argument('--stock-avb', default='work/stock-avb')
    args = parser.parse_args()
    from validate_signing_requests import validate_bundle
    validate_bundle(args.requests, stock_dir=args.stock_avb, public_pem=args.public_key,
                    avbtool=args.avbtool)
    result = sign_requests(read_json(args.requests), args.requests, args.private_key,
                           args.public_key, args.avbtool)
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'signatures_created': len(result['signatures']),
                      'public_verification_passed': True, 'output': str(output)}))


if __name__ == '__main__':
    main()
