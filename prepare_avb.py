"""Prepare AVB signing requests and apply public signatures; never read private keys."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

from inspect_packaging import read_vbmeta_blob

ALGORITHM = 'SHA256_RSA4096'
NAMES = {'vbmeta', 'vbmeta_system'}
MAX_JSON = 1024**2


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_JSON:
        raise ValueError('Metadata JSON exceeds size limit')
    return json.loads(path.read_text(encoding='utf-8'))


def load_tool(path, config='packaging-tools.json'):
    pin = read_json(config)['avbtool']
    path = pathlib.Path(path)
    if path.stat().st_size != pin['size'] or file_digest(path) != pin['sha256']:
        raise ValueError('AVB tool differs from pinned AOSP source')
    spec = importlib.util.spec_from_file_location('molcer_avbtool', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_blob(module, blob):
    if len(blob) < 256 or len(blob) > 256 * 1024:
        raise ValueError('Invalid vbmeta blob size')
    header = module.AvbVBMetaHeader(blob[:256])
    auth_size, aux_size = header.authentication_data_block_size, header.auxiliary_data_block_size
    total = 256 + auth_size + aux_size
    if total > len(blob) or auth_size % 64 or aux_size % 64:
        raise ValueError('Invalid vbmeta block bounds')
    auth = blob[256:256 + auth_size]
    aux = blob[256 + auth_size:total]
    for prefix in ('hash', 'signature'):
        if getattr(header, prefix + '_offset') + getattr(header, prefix + '_size') > len(auth):
            raise ValueError('Invalid vbmeta authentication bounds')
    for prefix in ('public_key', 'public_key_metadata', 'descriptors'):
        if getattr(header, prefix + '_offset') + getattr(header, prefix + '_size') > len(aux):
            raise ValueError('Invalid vbmeta auxiliary bounds')
    descriptors = module.parse_descriptors(aux[header.descriptors_offset:header.descriptors_offset + header.descriptors_size])
    return header, descriptors, auth, aux, blob[:total]


def descriptor_key(descriptor):
    return type(descriptor).__name__, getattr(descriptor, 'partition_name', None)


def replace_descriptors(original, replacements, removals=()):
    """Replace only named descriptor types, preserving all other encoded bytes."""
    replacements = dict(replacements)
    removals = set(removals)
    if replacements.keys() & removals:
        raise ValueError('Descriptor cannot be replaced and removed')
    counts = {key: 0 for key in set(replacements) | removals}
    result, preserved = [], []
    for descriptor in original:
        key = descriptor_key(descriptor)
        if key in counts:
            counts[key] += 1
        if key in removals:
            continue
        if key in replacements:
            replacement = replacements[key]
            if descriptor_key(replacement) != key:
                raise ValueError('Replacement descriptor identity differs')
            result.append(copy.deepcopy(replacement))
        else:
            copied = copy.deepcopy(descriptor)
            if copied.encode() != descriptor.encode():
                raise ValueError('Preserved descriptor changed')
            result.append(copied)
            preserved.append(digest(descriptor.encode()))
    if any(count != 1 for count in counts.values()):
        raise ValueError('Missing or duplicate selected descriptor')
    return result, preserved


def exact_descriptor(descriptors, kind, name):
    matches = [d for d in descriptors if descriptor_key(d) == (kind, name)]
    if len(matches) != 1:
        raise ValueError('Missing or duplicate ' + name + ' descriptor')
    return matches[0]


def input_blob(module, path, expected_hash):
    if file_digest(path) != expected_hash:
        raise ValueError('Stock AVB input hash differs from authenticated inspection')
    _, blob = read_vbmeta_blob(path)
    if blob is None:
        raise ValueError('Stock AVB input has no metadata')
    header, descriptors, _, _, blob = parse_blob(module, blob)
    if header.flags != 0 or header.algorithm_type != 2 or header.public_key_metadata_size:
        raise ValueError('Unexpected stock AVB flags, algorithm or public-key metadata')
    if not module.verify_vbmeta_signature(header, blob):
        raise ValueError('Stock AVB metadata signature failed')
    return header, descriptors


def init_boot_body_size(path):
    """Derive used boot-v4 bytes, independent of any stale footer after patching."""
    with pathlib.Path(path).open('rb') as stream:
        header = stream.read(4096)
    if len(header) != 4096 or header[:8] != b'ANDROID!':
        raise ValueError('Expected Android init_boot header')
    kernel, ramdisk = struct.unpack_from('<2I', header, 8)
    version = struct.unpack_from('<I', header, 40)[0]
    header_size = struct.unpack_from('<I', header, 20)[0]
    if kernel or version != 4 or header_size != 1584 or not ramdisk:
        raise ValueError('Unexpected init_boot v4 header layout')
    signature_size = struct.unpack_from('<I', header, 1580)[0]
    rounded = lambda size: (size + 4095) // 4096 * 4096
    used = 4096 + rounded(ramdisk) + rounded(signature_size)
    if used > pathlib.Path(path).stat().st_size:
        raise ValueError('init_boot header references truncated contents')
    return used


def run_tool(tool, *args):
    result = subprocess.run([sys.executable, str(tool), *map(str, args)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=1800)
    if result.returncode:
        raise ValueError('avbtool failed: ' + result.stderr[-2000:])
    return result.stdout


def public_only_key(module, path):
    content = pathlib.Path(path).read_text(encoding='ascii')
    if 'PRIVATE KEY' in content or '-----BEGIN PUBLIC KEY-----' not in content:
        raise ValueError('Only an SPKI public PEM key may be supplied')
    public = module.RSAPublicKey(str(path)).encode()
    if len(public) != 1032 or struct.unpack_from('>I', public)[0] != 4096:
        raise ValueError('Expected RSA4096 public key')
    return public


def unsigned_blob(module, key_path, stock_header, descriptors):
    """Official vbmeta builder with an in-process public-only recording signer."""
    recorded = []
    original_class = module.RSAPublicKey

    class RecordingPublicKey(original_class):
        def sign(self, algorithm_name, data_to_sign, signing_helper=None, signing_helper_with_files=None):
            if algorithm_name != ALGORITHM or self.num_bits != 4096:
                raise ValueError('Unexpected signing algorithm')
            data_hash = hashlib.sha256(data_to_sign).digest()
            padded = module.ALGORITHMS[algorithm_name].padding + data_hash
            if len(padded) != 512:
                raise ValueError('Unexpected PKCS1 encoded block length')
            recorded.append({'digest_sha256': data_hash.hex(), 'pkcs1_v1_5_encoded_hex': padded.hex()})
            return b'\0' * 512

    module.RSAPublicKey = RecordingPublicKey
    try:
        blob = module.AvbTool()._generate_vbmeta_blob(
            algorithm_name=ALGORITHM, key_path=str(key_path), public_key_metadata_path=None,
            descriptors=copy.deepcopy(descriptors), chain_partitions_use_ab=None,
            chain_partitions_do_not_use_ab=None, rollback_index=stock_header.rollback_index,
            flags=0, rollback_index_location=stock_header.rollback_index_location,
            props=None, props_from_file=None, kernel_cmdlines=None,
            setup_rootfs_from_kernel=None, ht_desc_to_setup=None,
            include_descriptors_from_image=None, signing_helper=None,
            signing_helper_with_files=None, release_string=stock_header.release_string,
            append_to_release_string=None,
            required_libavb_version_minor=stock_header.required_libavb_version_minor)
    finally:
        module.RSAPublicKey = original_class
    if len(recorded) != 1:
        raise ValueError('Expected exactly one signing request')
    header, generated, auth, aux, blob = parse_blob(module, blob)
    if (header.flags or header.rollback_index != stock_header.rollback_index
            or header.rollback_index_location != stock_header.rollback_index_location
            or [d.encode() for d in generated] != [d.encode() for d in descriptors]):
        raise ValueError('Generated metadata failed descriptor/rollback preservation')
    if auth[header.signature_offset:header.signature_offset + header.signature_size] != b'\0' * 512:
        raise ValueError('Unsigned stage unexpectedly contains a signature')
    if digest(blob[:256] + aux) != recorded[0]['digest_sha256']:
        raise ValueError('Signing request digest differs from generated blob')
    return blob, recorded[0]


def prepare(args):
    tool = pathlib.Path(args.avbtool)
    module = load_tool(tool)
    public_key = public_only_key(module, args.public_key)
    inspection = read_json(args.inspection)
    policy = read_json('radio-policy.json')
    if policy.get('phone_access_allowed') is not False or 'countrycode' not in policy['exclude_base_partitions_from_future_flash_plan']:
        raise ValueError('Expected offline policy preserving device countrycode')
    source = pathlib.Path(args.stock_avb)
    stocks = {name: input_blob(module, source / (name + '.img'), inspection['images'][name]['sha256']) for name in NAMES}
    product_record, root_record = read_json(args.product_report), read_json(args.root_report)
    if (file_digest(args.product) != product_record['product_sha256']
            or file_digest(args.init_boot) != root_record['init_boot_sha256']):
        raise ValueError('Modified input differs from its audited product/root report')
    original_product = exact_descriptor(stocks['vbmeta_system'][1], 'AvbHashtreeDescriptor', 'product')
    original_init = exact_descriptor(stocks['vbmeta'][1], 'AvbHashDescriptor', 'init_boot')
    if (original_product.flags or original_init.flags or original_product.dm_verity_version != 1
            or original_product.data_block_size != original_product.hash_block_size):
        raise ValueError('Unsupported source descriptor flags/verity geometry')
    if args.fec_mode == 'preserve' and original_product.fec_num_roots and not shutil.which('fec'):
        raise ValueError('Preserving stock FEC requires the pinned AOSP fec executable')
    out = pathlib.Path(args.output)
    if out.exists():
        raise ValueError('Use a fresh AVB output directory')
    out.mkdir(parents=True)
    (out / 'NOT-INSTALLABLE.txt').write_text('UNSIGNED AVB staging. Zero signature placeholders must be replaced by verified offline signatures. No installation or boot compatibility is established.\n', encoding='utf-8')
    images = out / 'images'; images.mkdir()
    product, init_boot = images / 'product.img', images / 'init_boot.img'
    shutil.copyfile(args.product, product)
    if read_vbmeta_blob(product)[1] is not None:
        raise ValueError('Audited product input unexpectedly already has AVB metadata')
    used = init_boot_body_size(args.init_boot)
    with pathlib.Path(args.init_boot).open('rb') as src, init_boot.open('xb') as dst:
        remaining = used
        while remaining:
            data = src.read(min(8 * 1024**2, remaining))
            if not data:
                raise ValueError('Truncated init_boot during copy')
            dst.write(data); remaining -= len(data)
    product_args = ['add_hashtree_footer', '--image', product, '--partition_name', 'product',
                    '--hash_algorithm', original_product.hash_algorithm, '--block_size', original_product.data_block_size,
                    '--salt', original_product.salt.hex(), '--algorithm', 'NONE']
    if args.fec_mode == 'omit' or not original_product.fec_num_roots:
        product_args += ['--do_not_generate_fec']
    else:
        product_args += ['--fec_num_roots', original_product.fec_num_roots]
    for descriptor in inspection['images']['product']['avb']['descriptors']:
        if descriptor['type'] == 'AvbPropertyDescriptor':
            product_args += ['--prop', descriptor['key'] + ':' + bytes.fromhex(descriptor['value']['hex']).decode('utf-8')]
    run_tool(tool, *product_args)
    init_args = ['add_hash_footer', '--image', init_boot, '--partition_size', inspection['images']['init_boot']['size'],
                 '--partition_name', 'init_boot', '--hash_algorithm', original_init.hash_algorithm,
                 '--salt', original_init.salt.hex(), '--algorithm', 'NONE']
    for descriptor in inspection['images']['init_boot']['avb']['descriptors']:
        if descriptor['type'] == 'AvbPropertyDescriptor':
            init_args += ['--prop', descriptor['key'] + ':' + bytes.fromhex(descriptor['value']['hex']).decode('utf-8')]
    run_tool(tool, *init_args)
    new_product = exact_descriptor(parse_blob(module, read_vbmeta_blob(product)[1])[1], 'AvbHashtreeDescriptor', 'product')
    new_init = exact_descriptor(parse_blob(module, read_vbmeta_blob(init_boot)[1])[1], 'AvbHashDescriptor', 'init_boot')
    for image in (product, init_boot):
        run_tool(tool, 'verify_image', '--image', image)
    rebuilt_system, kept_system = replace_descriptors(stocks['vbmeta_system'][1], {('AvbHashtreeDescriptor', 'product'): new_product})
    new_chain = copy.deepcopy(exact_descriptor(stocks['vbmeta'][1], 'AvbChainPartitionDescriptor', 'vbmeta_system'))
    new_chain.public_key = public_key
    rebuilt_root, kept_root = replace_descriptors(stocks['vbmeta'][1], {
        ('AvbHashDescriptor', 'init_boot'): new_init,
        ('AvbChainPartitionDescriptor', 'vbmeta_system'): new_chain},
        removals={('AvbHashDescriptor', 'countrycode')})
    requests = []
    for name, descriptors in [('vbmeta_system', rebuilt_system), ('vbmeta', rebuilt_root)]:
        blob, request = unsigned_blob(module, args.public_key, stocks[name][0], descriptors)
        capacity = inspection['images'][name]['size']
        if len(blob) > capacity:
            raise ValueError('Rebuilt vbmeta exceeds stock image size')
        unsigned_image = blob.ljust(capacity, b'\0')
        (out / ('UNSIGNED-' + name + '.img')).write_bytes(unsigned_image)
        requests.append({'partition': name, 'algorithm': ALGORITHM, **request,
                         'unsigned_blob_hex': blob.hex(), 'unsigned_blob_sha256': digest(blob),
                         'unsigned_image_sha256': digest(unsigned_image), 'partition_image_size': capacity})
    bundle = {'schema': 1, 'status': 'UNSIGNED-NOT-INSTALLABLE', 'algorithm': ALGORITHM,
              'public_key_avb_sha256': digest(public_key), 'public_key_pem_sha256': file_digest(args.public_key),
              'avbtool_sha256': file_digest(tool),
              'source_vbmeta_sha256s': {n: inspection['images'][n]['sha256'] for n in sorted(NAMES)},
              'prepared_images': [{'partition': n, 'path': 'images/' + n + '.img',
                                   'size': (images / (n + '.img')).stat().st_size,
                                   'sha256': file_digest(images / (n + '.img'))} for n in ('product', 'init_boot')],
              'preserved_descriptor_sha256s': {'vbmeta': kept_root, 'vbmeta_system': kept_system},
              'removed_descriptors': [{'type': 'AvbHashDescriptor', 'partition_name': 'countrycode',
                                      'reason': 'Global device countrycode is preserved and excluded from the flash plan; no CN countrycode is bundled.'}],
              'product_fec_mode': args.fec_mode, 'product_fec_num_roots': new_product.fec_num_roots,
              'product_hashtree_verified': True, 'init_boot_hash_verified': True,
              'avb_flags': 0, 'stock_boot_recovery_chain_keys_preserved': True,
              'phone_accessed': False, 'private_key_accessed': False,
              'installable_rom_produced': False, 'runtime_verified': False, 'requests': requests}
    (out / 'signing-requests.json').write_text(json.dumps(bundle, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': bundle['status'], 'requests': len(requests), 'images': bundle['prepared_images']}))
    return bundle


def validate_request(module, request, expected_public):
    if request['partition'] not in NAMES or request['algorithm'] != ALGORITHM:
        raise ValueError('Unexpected signing request identity')
    blob = bytes.fromhex(request['unsigned_blob_hex'])
    if digest(blob) != request['unsigned_blob_sha256']:
        raise ValueError('Unsigned blob hash mismatch')
    header, descriptors, auth, aux, canonical = parse_blob(module, blob)
    if (canonical != blob or header.algorithm_type != 2 or header.flags != 0
            or header.signature_size != 512 or header.hash_size != 32):
        raise ValueError('Unexpected unsigned AVB structure or flags')
    key = aux[header.public_key_offset:header.public_key_offset + header.public_key_size]
    if key != expected_public:
        raise ValueError('Signing request public key differs from pinned public key')
    data = blob[:256] + aux
    wanted = hashlib.sha256(data).digest()
    if (wanted.hex() != request['digest_sha256']
            or auth[header.hash_offset:header.hash_offset + 32] != wanted
            or request['pkcs1_v1_5_encoded_hex'] != (module.ALGORITHMS[ALGORITHM].padding + wanted).hex()
            or auth[header.signature_offset:header.signature_offset + 512] != b'\0' * 512):
        raise ValueError('Signing request digest/padding/placeholder mismatch')
    capacity = request['partition_image_size']
    if (type(capacity) is not int or not len(blob) <= capacity <= 256 * 1024
            or digest(blob.ljust(capacity, b'\0')) != request['unsigned_image_sha256']):
        raise ValueError('Unsigned image size/hash mismatch')
    return header, descriptors, blob, data


def apply_signature(module, request, response, public_key, public_key_path):
    header, _, blob, data = validate_request(module, request, public_key)
    for name in ('partition', 'unsigned_blob_sha256', 'digest_sha256'):
        if response.get(name) != request[name]:
            raise ValueError('Signature response is for a different request')
    signature = bytes.fromhex(response['signature_hex'])
    if len(signature) != 512 or signature == b'\0' * 512:
        raise ValueError('Invalid RSA4096 signature length/value')
    with tempfile.TemporaryDirectory(prefix='molcer-avb-verify-') as temp:
        root = pathlib.Path(temp)
        (root / 'data').write_bytes(data)
        (root / 'signature').write_bytes(signature)
        verified = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_key_path),
                                   '-signature', str(root / 'signature'), str(root / 'data')],
                                  capture_output=True, text=True, timeout=30)
        if verified.returncode:
            raise ValueError('Offline RSA signature verification failed')
    signed = bytearray(blob)
    start = 256 + header.signature_offset
    signed[start:start + 512] = signature
    if not module.verify_vbmeta_signature(header, bytes(signed)):
        raise ValueError('Official AVB signature verification failed')
    return bytes(signed).ljust(request['partition_image_size'], b'\0')


def check_chain_key(module, descriptor, child_blob):
    """Bind each signed child to its parent's key; OEM keys may differ from root."""
    header, _, _, aux, _ = parse_blob(module, child_blob)
    key = aux[header.public_key_offset:header.public_key_offset + header.public_key_size]
    if header.flags or not header.algorithm_type or not key or key != descriptor.public_key:
        raise ValueError('Chained image key/flags do not match parent descriptor: ' + descriptor.partition_name)
    return key


def verify_full_chain(module, tool, image_root, root_public_pem):
    """Verify every image with its own parent-approved key, including OEM children.

    avbtool --follow_chain_partitions forwards --key to children, which is wrong
    when custom vbmeta chains to unchanged OEM-signed boot/recovery images.
    Explicitly bind every edge, and invoke the official verifier per node.
    """
    image_root = pathlib.Path(image_root)
    visited, active = set(), set()

    def visit(name, expected_key=None):
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in active or len(visited | active) >= 16:
            raise ValueError('Invalid or cyclic AVB chain')
        path = image_root / (name + '.img')
        _, blob = read_vbmeta_blob(path)
        if blob is None:
            raise ValueError('Chained partition lacks AVB metadata: ' + name)
        header, descriptors, _, aux, _ = parse_blob(module, blob)
        embedded_key = aux[header.public_key_offset:header.public_key_offset + header.public_key_size]
        if header.flags or not header.algorithm_type or (expected_key is not None and embedded_key != expected_key):
            raise ValueError('Unexpected chain key/flags: ' + name)
        if name in visited:
            return
        active.add(name)
        command = ['verify_image', '--image', path]
        if name == 'vbmeta':
            command += ['--key', root_public_pem]
        children, child_names, locations = [], set(), set()
        for descriptor in descriptors:
            if type(descriptor).__name__ != 'AvbChainPartitionDescriptor':
                continue
            child = descriptor.partition_name
            if (not re.fullmatch(r'[A-Za-z0-9_-]+', child) or child in child_names
                    or descriptor.rollback_index_location < 1
                    or descriptor.rollback_index_location in locations):
                raise ValueError('Invalid duplicate chain name/rollback location')
            _, child_blob = read_vbmeta_blob(image_root / (child + '.img'))
            if child_blob is None:
                raise ValueError('Chained partition lacks AVB metadata: ' + child)
            expected = check_chain_key(module, descriptor, child_blob)
            expected_file = image_root / ('.expected-' + name + '-' + child + '.avbpubkey')
            expected_file.write_bytes(expected)
            command += ['--expected_chain_partition', f'{child}:{descriptor.rollback_index_location}:{expected_file}']
            children.append((child, expected))
            child_names.add(child); locations.add(descriptor.rollback_index_location)
        run_tool(tool, *command)
        for child, expected in children:
            visit(child, expected)
        active.remove(name)
        visited.add(name)

    visit('vbmeta')
    return sorted(visited)


def apply(args):
    module = load_tool(args.avbtool)
    public_key = public_only_key(module, args.public_key)
    bundle, responses = read_json(args.requests), read_json(args.signatures)
    if (bundle.get('schema') != 1 or responses.get('schema') != 1
            or responses.get('requests_sha256') != file_digest(args.requests)
            or bundle.get('public_key_avb_sha256') != digest(public_key)):
        raise ValueError('Signing bundle identity mismatch')
    requests, signatures = bundle['requests'], responses['signatures']
    if (len(requests) != 2 or len(signatures) != 2
            or {r['partition'] for r in requests} != NAMES
            or {r['partition'] for r in signatures} != NAMES):
        raise ValueError('Expected exactly both AVB signature responses')
    by_name = {r['partition']: r for r in signatures}
    signed = {r['partition']: apply_signature(module, r, by_name[r['partition']], public_key, args.public_key) for r in requests}
    root_desc = parse_blob(module, signed['vbmeta'])[1]
    chain = exact_descriptor(root_desc, 'AvbChainPartitionDescriptor', 'vbmeta_system')
    if chain.public_key != public_key or any(descriptor_key(d) == ('AvbHashDescriptor', 'countrycode') for d in root_desc):
        raise ValueError('Rebuilt AVB chain or countrycode exclusion differs')
    out = pathlib.Path(args.output)
    if out.exists():
        raise ValueError('Use a fresh signed AVB output directory')
    full_chain = False
    verified_nodes = []
    if args.images:
        image_root = pathlib.Path(args.images)
        if (len(bundle['prepared_images']) != 2
                or {r['partition'] for r in bundle['prepared_images']} != {'product', 'init_boot'}):
            raise ValueError('Expected exactly both modified image bindings')
        for record in bundle['prepared_images']:
            if record['partition'] not in ('product', 'init_boot'):
                raise ValueError('Unexpected prepared partition')
            p = image_root / (record['partition'] + '.img')
            if p.stat().st_size != record['size'] or file_digest(p) != record['sha256']:
                raise ValueError('Prepared image differs from signed request bindings')
        with tempfile.TemporaryDirectory(prefix='molcer-avb-chain-', dir=image_root.parent) as temp:
            verify_root = pathlib.Path(temp)
            for p in image_root.glob('*.img'):
                if p.stem not in NAMES and p.is_file():
                    os.link(p, verify_root / p.name)
            for name, data in signed.items():
                (verify_root / (name + '.img')).write_bytes(data)
            verified_nodes = verify_full_chain(module, args.avbtool, verify_root, args.public_key)
        full_chain = True
    out.mkdir(parents=True)
    for name, data in signed.items():
        (out / (name + '.img')).write_bytes(data)
    report = {'schema': 1, 'metadata_signatures_verified': True,
              'full_partition_chain_verified': full_chain,
              'verified_avb_nodes': verified_nodes,
              'requests_sha256': file_digest(args.requests),
              'public_key_avb_sha256': digest(public_key),
              'images': {n: {'sha256': digest(v), 'size': len(v)} for n, v in signed.items()},
              'avb_flags': 0, 'phone_accessed': False, 'private_key_accessed': False,
              'runtime_verified': False, 'installable_rom_produced': False}
    (out / 'avb-signature-verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (out / 'NOT-INSTALLABLE.txt').write_text('AVB metadata signatures verified. This alone is not a complete ROM or proof of boot, rollback, camera or network compatibility.\n', encoding='utf-8')
    print(json.dumps(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare')
    p.add_argument('--product', default='out/product-preview/product.img')
    p.add_argument('--init-boot', default='out/root-candidate/init_boot.img')
    p.add_argument('--product-report', default='reports/product-preview.json')
    p.add_argument('--root-report', default='reports/root-candidate.json')
    p.add_argument('--stock-avb', default='work/images')
    p.add_argument('--inspection', default='reports/packaging-inspection.json')
    p.add_argument('--fec-mode', choices=('preserve', 'omit'), default='preserve')
    p.add_argument('--output', default='out/avb-prepared')
    a = commands.add_parser('apply')
    a.add_argument('--requests', required=True)
    a.add_argument('--signatures', required=True)
    a.add_argument('--images', help='Complete image directory for full offline AVB chain verification')
    a.add_argument('--output', default='out/avb-signed')
    for command in (p, a):
        command.add_argument('--avbtool', default='.tools/avbtool.py')
        command.add_argument('--public-key', default='keys/avb-public.pem')
    args = parser.parse_args()
    prepare(args) if args.command == 'prepare' else apply(args)


if __name__ == '__main__':
    main()
