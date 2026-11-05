"""Validate offline AVB signing scope using only public material, including on Windows."""
import argparse
import base64
import copy
import hashlib
import json
import pathlib
import struct
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from prepare_avb import (digest, exact_descriptor, file_digest, load_tool, parse_blob,
                         read_json, replace_descriptors, validate_request)
from inspect_packaging import read_vbmeta_blob

STOCK = {
    'vbmeta': ('d8f12f9a865a9d88db54cc1e8bb7e009e6b7ef37944d78ea02c7362e0ce7df27', 12288),
    'vbmeta_system': ('8e611970fc95288ceb2cac1f24ca8d69eb730dd6547afbc73b54eaa1064295f0', 4096),
}


def avb_public_from_xml(path):
    root = ET.fromstring(pathlib.Path(path).read_bytes())
    if root.tag != 'RSAKeyValue' or len(root) != 2 or {e.tag for e in root} != {'Modulus', 'Exponent'}:
        raise ValueError('Expected public RSA XML only')
    modulus = base64.b64decode(root.findtext('Modulus'), validate=True)
    exponent = int.from_bytes(base64.b64decode(root.findtext('Exponent'), validate=True), 'big')
    n = int.from_bytes(modulus, 'big')
    if n.bit_length() != 4096 or exponent != 65537 or len(modulus) != 512:
        raise ValueError('Expected RSA4096 exponent65537')
    n0inv = -pow(n, -1, 2**32) % 2**32
    rr = pow(2, 8192, n).to_bytes(512, 'big')
    return struct.pack('>II', 4096, n0inv) + modulus + rr


def verify_public_signature(module, blob):
    header, _, auth, aux, blob = parse_blob(module, blob)
    if header.algorithm_type != 2 or header.hash_size != 32 or header.signature_size != 512 or header.flags:
        raise ValueError('Unexpected stock AVB signature parameters')
    key = aux[header.public_key_offset:header.public_key_offset + header.public_key_size]
    if len(key) != 1032 or struct.unpack_from('>I', key)[0] != 4096:
        raise ValueError('Unexpected stock RSA key')
    signature = auth[header.signature_offset:header.signature_offset + 512]
    expected = hashlib.sha256(blob[:256] + aux).digest()
    if expected != auth[header.hash_offset:header.hash_offset + 32]:
        raise ValueError('Stock AVB hash mismatch')
    n = int.from_bytes(key[8:520], 'big')
    s = int.from_bytes(signature, 'big')
    if s >= n or pow(s, 65537, n).to_bytes(512, 'big') != module.ALGORITHMS['SHA256_RSA4096'].padding + expected:
        raise ValueError('Stock AVB signature mismatch')


def check_descriptor_unchanged_fields(old, new, permitted):
    candidate = copy.deepcopy(new)
    for field in permitted:
        setattr(candidate, field, getattr(old, field))
    if candidate.encode() != old.encode():
        raise ValueError('Modified image descriptor changes unapproved parameters')


def validate_bundle(request_path, stock_dir='work/stock-avb', public_xml='keys/avb-public.xml',
                    public_pem='keys/avb-public.pem', avbtool='.tools/avbtool.py'):
    bundle = read_json(request_path)
    module = load_tool(avbtool)
    public = avb_public_from_xml(public_xml)
    if (bundle.get('schema') != 1 or bundle.get('algorithm') != 'SHA256_RSA4096'
            or bundle.get('status') != 'UNSIGNED-NOT-INSTALLABLE'
            or bundle.get('public_key_avb_sha256') != digest(public)
            or bundle.get('public_key_pem_sha256') != file_digest(public_pem)
            or bundle.get('avbtool_sha256') != file_digest(avbtool)
            or bundle.get('source_vbmeta_sha256s') != {n: h for n, (h, _) in STOCK.items()}):
        raise ValueError('Signing bundle identity differs from approved source/key')
    requests = bundle['requests']
    if len(requests) != 2 or {r['partition'] for r in requests} != set(STOCK):
        raise ValueError('Exactly two AVB signing requests required')
    original, updated = {}, {}
    for request in requests:
        name = request['partition']
        path = pathlib.Path(stock_dir, name + '.img')
        if file_digest(path) != STOCK[name][0] or path.stat().st_size != STOCK[name][1]:
            raise ValueError('Authenticated local stock AVB image differs')
        _, stock_blob = read_vbmeta_blob(path)
        verify_public_signature(module, stock_blob)
        old_header, old_descriptors, _, _, _ = parse_blob(module, stock_blob)
        header, descriptors, _, _ = validate_request(module, request, public)
        for field in ('required_libavb_version_major', 'required_libavb_version_minor',
                      'rollback_index', 'rollback_index_location', 'release_string'):
            if getattr(header, field) != getattr(old_header, field):
                raise ValueError('Unapproved AVB header change: ' + field)
        if header.public_key_metadata_size or request['partition_image_size'] != STOCK[name][1]:
            raise ValueError('Unexpected public-key metadata or vbmeta capacity')
        original[name], updated[name] = old_descriptors, descriptors
    old_product = exact_descriptor(original['vbmeta_system'], 'AvbHashtreeDescriptor', 'product')
    product = exact_descriptor(updated['vbmeta_system'], 'AvbHashtreeDescriptor', 'product')
    old_init = exact_descriptor(original['vbmeta'], 'AvbHashDescriptor', 'init_boot')
    init = exact_descriptor(updated['vbmeta'], 'AvbHashDescriptor', 'init_boot')
    check_descriptor_unchanged_fields(old_product, product, ('image_size', 'tree_offset', 'tree_size', 'fec_offset', 'fec_size', 'root_digest'))
    check_descriptor_unchanged_fields(old_init, init, ('image_size', 'digest'))
    if (len(product.root_digest) != 32 or len(init.digest) != 32
            or not 4096 <= init.image_size < 8388608 or init.image_size % 4096
            or product.image_size <= 0 or product.image_size % 4096
            or product.tree_offset != product.image_size or product.tree_size <= 0
            or product.fec_offset != product.tree_offset + product.tree_size or product.fec_size <= 0):
        raise ValueError('Invalid product hashtree/FEC or init_boot geometry')
    chain = copy.deepcopy(exact_descriptor(original['vbmeta'], 'AvbChainPartitionDescriptor', 'vbmeta_system'))
    chain.public_key = public
    expected_root, _ = replace_descriptors(original['vbmeta'], {
        ('AvbHashDescriptor', 'init_boot'): init, ('AvbChainPartitionDescriptor', 'vbmeta_system'): chain},
        {('AvbHashDescriptor', 'countrycode')})
    expected_system, _ = replace_descriptors(original['vbmeta_system'], {('AvbHashtreeDescriptor', 'product'): product})
    for name, expected in [('vbmeta', expected_root), ('vbmeta_system', expected_system)]:
        if [d.encode() for d in updated[name]] != [d.encode() for d in expected]:
            raise ValueError('Unapproved descriptor addition, removal, reordering or mutation')
    records = bundle['prepared_images']
    if len(records) != 2 or {r['partition'] for r in records} != {'product', 'init_boot'}:
        raise ValueError('Unexpected prepared image bindings')
    by_name = {r['partition']: r for r in records}
    for name, record in by_name.items():
        if (record.get('path') != 'images/' + name + '.img' or type(record.get('size')) is not int
                or not isinstance(record.get('sha256'), str) or len(bytes.fromhex(record['sha256'])) != 32):
            raise ValueError('Invalid prepared image record')
    if by_name['init_boot']['size'] != 8388608 or by_name['product']['size'] < product.fec_offset + product.fec_size + 64:
        raise ValueError('Prepared image size does not cover signed contents')
    inspection = read_json('reports/packaging-inspection.json')
    group = inspection['payload']['dynamic_groups'][0]
    parts = {p['name']: p for p in inspection['payload']['partitions']}
    other = sum(parts[n]['size'] for n in group['partition_names'] if n != 'product')
    # Require room for conservative per-partition 1MiB alignment before signing.
    aligned = sum((parts[n]['size'] + 1048575) // 1048576 * 1048576 for n in group['partition_names'] if n != 'product')
    aligned += (by_name['product']['size'] + 1048575) // 1048576 * 1048576
    if aligned > 11800674304:
        raise ValueError('Prepared dynamic images exceed verified EU group budget')
    if (bundle.get('product_fec_mode') != 'preserve' or bundle.get('product_fec_num_roots') != 2
            or bundle.get('avb_flags') != 0 or bundle.get('phone_accessed') is not False
            or bundle.get('product_hashtree_verified') is not True or bundle.get('init_boot_hash_verified') is not True):
        raise ValueError('Required build checks or no-phone policy missing')
    return {'schema': 1, 'requests_sha256': file_digest(request_path),
            'scope_verified': True, 'stock_signatures_verified': True,
            'preserved_oem_descriptors_verified': True, 'avb_flags': 0,
            'dynamic_images_aligned_bytes': aligned, 'group_budget_bytes': 11800674304,
            'prepared_images': records, 'requests': [{k: r[k] for k in
            ('partition', 'unsigned_blob_sha256', 'digest_sha256')} for r in requests]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('requests')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = validate_bundle(args.requests)
    path = pathlib.Path(args.output)
    if path.exists():
        raise ValueError('Refusing to overwrite previous validation')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'scope_verified': True, 'requests_sha256': result['requests_sha256']}))


if __name__ == '__main__':
    main()
