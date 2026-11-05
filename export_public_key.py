"""Encode public RSA parameters as standard SPKI PEM; never read private keys."""
import base64
import hashlib
import pathlib
import xml.etree.ElementTree as ET


def tlv(tag, data):
    size = len(data)
    length = bytes([size]) if size < 128 else bytes([128 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + data


def integer(raw):
    raw = raw.lstrip(b'\0') or b'\0'
    if raw[0] & 128:
        raw = b'\0' + raw
    return tlv(2, raw)


def main():
    root = ET.fromstring(pathlib.Path('keys/avb-public.xml').read_bytes())
    if root.tag != 'RSAKeyValue' or {e.tag for e in root} != {'Modulus', 'Exponent'}:
        raise ValueError('Expected public RSA parameters only')
    modulus = base64.b64decode(root.findtext('Modulus'), validate=True)
    exponent = base64.b64decode(root.findtext('Exponent'), validate=True)
    if len(modulus) != 512 or int.from_bytes(exponent, 'big') != 65537:
        raise ValueError('Expected RSA4096 with exponent65537')
    rsa = tlv(0x30, integer(modulus) + integer(exponent))
    algorithm = bytes.fromhex('300d06092a864886f70d0101010500')
    spki = tlv(0x30, algorithm + tlv(3, b'\0' + rsa))
    encoded = base64.b64encode(spki).decode()
    pem = '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(encoded[i:i+64] for i in range(0,len(encoded),64)) + '\n-----END PUBLIC KEY-----\n'
    pathlib.Path('keys/avb-public.pem').write_text(pem, encoding='ascii')
    print('Public-key SPKI SHA256:', hashlib.sha256(spki).hexdigest())


if __name__ == '__main__':
    main()
