"""Prepare/verify signed manual-package metadata; no private keys, OTA or flashing."""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import struct
import urllib.parse
import xml.etree.ElementTree as ET

DOMAIN = b'Molcer OS update index v1\0'
ALGORITHM = 'RSA4096-SHA256-PKCS1-v1_5'
REPOSITORY = 'MolcerBey/xuanyuan-hyperos4'
BASE = 'OS4.0.0.18.XOACNXM'
BASE_SHA256 = 'bd19c93fa7c1cb90ed194c5cc2ebfe786f55f1382b172e344522ca805c63f1ea'
MAX_ASSET_SIZE = 1900 * 1024**2
MAX_IMAGE_SIZE = 32 * 1024**3
MAX_TOTAL_SIZE = 64 * 1024**3
MAX_JSON_SIZE = 4 * 1024**2
MANIFEST_STATUS = 'offline-assembled-candidate-awaiting-device-and-installer-validation'
REPORT_NAMES = {'avb-signature-verification.json', 'super-build.json',
                'super-payload-verification.json', 'rom-radio-integration.json'}
RADIO = {
    'modem': {'size': 172568576, 'sha256': 'abdb08bc80e2b9c837b40f54df5c34c1ea929b5d1c14e7cfebfc0b433b9a6d69'},
    'modemfirmware': {'size': 140234752, 'sha256': 'bfab29aac6a9337cb168bbc76455fda068c59be899b917b0038af2c88a7a1fe6'},
}
FORBIDDEN_PARTITIONS = {'userdata', 'metadata', 'persist', 'modemst1', 'modemst2', 'fsg', 'fsc', 'frp', 'countrycode'}
LOGICAL_PARTITIONS = frozenset({'odm', 'product', 'system', 'system_dlkm', 'system_ext',
                                'vendor', 'vendor_dlkm', 'mi_product', 'mi_ext'})
SOURCE_PARTITIONS = frozenset(('abl aop aop_config bluetooth boot cpucp cpucp_dtb devcfg dsp dtbo '
    'featenabler hyp idmanager imagefv init_boot keymaster modem modemfirmware multiimgqti odm pdp '
    'pdp_cdb product pvmfw qupfw recovery shrm soccp_dcd soccp_debug spuservice system system_dlkm '
    'system_ext tz uefi uefisecapp vbmeta vbmeta_system vendor vendor_boot vendor_dlkm vm-bootsys '
    'xbl xbl_config xbl_ramdump mi_product mi_ext').split())


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path):
    raw = pathlib.Path(path).read_bytes()
    if len(raw) > MAX_JSON_SIZE:
        raise ValueError('JSON document exceeds the metadata limit')
    return json.loads(raw, object_pairs_hook=no_duplicate_keys,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON number')))


def canonical_bytes(value):
    def check(item):
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ValueError('JSON keys must be strings')
            for child in item.values():
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
        elif item is not None and type(item) not in (str, int, bool):
            raise ValueError('Metadata only permits integer JSON numbers')
        elif type(item) is int and not -(2**63) <= item < 2**63:
            raise ValueError('Metadata integer exceeds signed 64-bit range')
    check(value)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(raw) > MAX_JSON_SIZE:
        raise ValueError('Canonical metadata exceeds the size limit')
    return raw


def public_key(path='keys/avb-public.xml'):
    raw = pathlib.Path(path).read_bytes()
    if len(raw) > 16384 or b'<!' in raw:
        raise ValueError('Expected bounded public RSA XML')
    root = ET.fromstring(raw)
    if root.tag != 'RSAKeyValue' or len(root) != 2 or {x.tag for x in root} != {'Modulus', 'Exponent'}:
        raise ValueError('Only public Modulus/Exponent parameters are accepted')
    modulus = base64.b64decode(root.findtext('Modulus'), validate=True)
    exponent = base64.b64decode(root.findtext('Exponent'), validate=True)
    n, e = int.from_bytes(modulus, 'big'), int.from_bytes(exponent, 'big')
    if len(modulus) != 512 or n.bit_length() != 4096 or not n & 1 or e != 65537:
        raise ValueError('Expected the pinned RSA4096 exponent65537 public key')
    avb = struct.pack('>II', 4096, -pow(n, -1, 2**32) % 2**32) + modulus + pow(2, 8192, n).to_bytes(512, 'big')
    return {'n': n, 'e': e, 'avb_sha256': sha256(avb)}


def require_hash(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('Expected a lowercase SHA256 digest')
    return value


def require_size(value, maximum=MAX_IMAGE_SIZE):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError('Invalid or excessive metadata size')
    return value


def safe_tag(tag):
    if not isinstance(tag, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,159}', tag):
        raise ValueError('Unsupported release tag')
    return tag


def validate_asset_url(url, tag, asset_name):
    safe_tag(tag)
    if not isinstance(asset_name, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,199}', asset_name):
        raise ValueError('Unsafe asset filename')
    expected = f'https://github.com/{REPOSITORY}/releases/download/{tag}/{asset_name}'
    parsed = urllib.parse.urlsplit(url)
    if (url != expected or parsed.scheme != 'https' or parsed.netloc != 'github.com'
            or parsed.query or parsed.fragment):
        raise ValueError('Only exact release download URLs from the project repository are allowed')
    return url


def validate_version(version):
    expected = {'schema': 1, 'product': 'Molcer OS', 'channel': 'experimental', 'device': 'xuanyuan',
                'hardware_variant': 'global', 'base': BASE, 'android': 17,
                'update_mechanism': 'manual-full-package', 'automatic_installation': False,
                'android_ota_updater_implemented': False, 'public_release_available': False}
    for key, value in expected.items():
        if type(version.get(key)) is not type(value) or version[key] != value:
            raise ValueError('Unexpected version metadata: ' + key)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-experimental\.[1-9][0-9]*', version.get('version_name', '')):
        raise ValueError('Expected an explicit experimental semantic version')
    code = version.get('version_code')
    if type(code) is not int or not 1 <= code <= 2**31 - 1:
        raise ValueError('Version code must be a positive Android-compatible integer')
    return version


def validate_images(images, tag):
    if not isinstance(images, list) or not 1 <= len(images) <= 100:
        raise ValueError('Missing or excessive uploaded image list')
    result, names, asset_names, total = [], set(), set(), 0
    for image in images:
        name = image.get('name')
        if not isinstance(name, str) or not re.fullmatch('[a-z][a-z0-9_-]{0,39}', name) or name in names or name in FORBIDDEN_PARTITIONS:
            raise ValueError('Unexpected, duplicate or device-unique partition name')
        names.add(name)
        size, digest = require_size(image.get('size')), require_hash(image.get('sha256'))
        total += size
        if total > MAX_TOTAL_SIZE:
            raise ValueError('Update bundle exceeds maximum total size')
        chunks = image.get('chunks')
        if not isinstance(chunks, list) or not 1 <= len(chunks) <= 32:
            raise ValueError('Missing or excessive image chunks')
        normalized, offset = [], 0
        for number, chunk in enumerate(chunks):
            length = require_size(chunk.get('size'), MAX_ASSET_SIZE)
            if type(chunk.get('index')) is not int or chunk['index'] != number or type(chunk.get('offset')) is not int or chunk['offset'] != offset:
                raise ValueError('Image chunks are not contiguous and ordered')
            asset = chunk.get('asset_name')
            if asset in asset_names:
                raise ValueError('Duplicate release asset')
            asset_names.add(asset)
            normalized.append({'index': number, 'offset': offset, 'size': length,
                               'sha256': require_hash(chunk.get('sha256')), 'asset_name': asset,
                               'download_url': validate_asset_url(chunk.get('download_url'), tag, asset)})
            offset += length
        if offset != size:
            raise ValueError('Chunk sizes do not equal the image size')
        result.append({'name': name, 'size': size, 'sha256': digest, 'chunks': normalized})
    if names != SOURCE_PARTITIONS - LOGICAL_PARTITIONS | {'super'}:
        raise ValueError('Uploaded bundle must contain the exact physical set and super for the pinned base')
    for name, expected in RADIO.items():
        record = next(x for x in result if x['name'] == name)
        if any(record[key] != value for key, value in expected.items()):
            raise ValueError('Update substitutes the owner-selected EU radio pair')
    return result


def validate_assembly(manifest):
    required = {'schema': 1, 'repository': REPOSITORY, 'status': MANIFEST_STATUS,
                'device': 'xuanyuan', 'hardware_variant': 'global', 'rom_name': 'Molcer OS',
                'base_archive_sha256': BASE_SHA256, 'full_partition_chain_verified': True,
                'avb_flags': 0, 'release_draft': True, 'installer_included': False,
                'installation_allowed': False, 'installable_rom_produced': False,
                'runtime_verified': False, 'device_gpt_capacity_verified': False}
    for key, value in required.items():
        if type(manifest.get(key)) is not type(value) or manifest[key] != value:
            raise ValueError('Assembly has not passed the reviewed offline-candidate contract: ' + key)
    checks = manifest.get('offline_validation', {})
    if set(checks) != {'avb', 'super', 'hashes'} or any(value is not True for value in checks.values()):
        raise ValueError('Full offline AVB, super and hash checks must pass')
    reports = manifest.get('validation_report_sha256', {})
    if set(reports) != REPORT_NAMES:
        raise ValueError('Missing exact offline verification report digests')
    assets = manifest.get('small_assets', [])
    tag = safe_tag(manifest.get('release_tag'))
    for name in REPORT_NAMES:
        digest = require_hash(reports[name])
        matches = [x for x in assets if x.get('asset_name') == name]
        if len(matches) != 1 or matches[0].get('sha256') != digest:
            raise ValueError('Verification report is not bound to its released asset')
        require_size(matches[0].get('size'), 4 * 1024**2)
        validate_asset_url(matches[0].get('download_url'), tag, name)
    images = validate_images(manifest.get('uploaded_images'), tag)
    partitions = manifest.get('all_partition_images', [])
    if not isinstance(partitions, list) or not 1 <= len(partitions) <= 100:
        raise ValueError('Missing verified full partition inventory')
    by_name = {}
    for item in partitions + [manifest.get('super', {})]:
        name = item.get('name')
        if not isinstance(name, str) or name in by_name:
            raise ValueError('Invalid or duplicate verified partition inventory')
        by_name[name] = {'size': require_size(item.get('size')), 'sha256': require_hash(item.get('sha256'))}
    if set(by_name) != SOURCE_PARTITIONS | {'super'}:
        raise ValueError('Full verified partition inventory differs from the pinned base')
    for image in images:
        if by_name.get(image['name']) != {key: image[key] for key in ('size', 'sha256')}:
            raise ValueError('Uploaded bytes differ from the verified partition inventory')
    return images


def make_index(version, key, manifest=None, previous=None):
    validate_version(version)
    if previous is not None:
        validate_index(previous, key)
        if version['version_code'] <= previous['version']['version_code']:
            raise ValueError('Version code must increase beyond the previous signed index')
    index = {'schema': 1, 'product': 'Molcer OS', 'device': 'xuanyuan', 'hardware_variant': 'global',
             'channel': 'experimental', 'base': BASE, 'android': 17,
             'version': {'version_name': version['version_name'], 'version_code': version['version_code']},
             'update_mechanism': 'manual-full-package', 'automatic_installation': False,
             'android_ota_updater_implemented': False, 'public_release_available': False,
             'signing': {'algorithm': ALGORITHM, 'public_key_avb_sha256': key['avb_sha256']}, 'updates': []}
    if manifest is not None:
        images = validate_assembly(manifest)
        index['updates'].append({'version_name': version['version_name'], 'version_code': version['version_code'],
            'kind': 'offline-assembled-experimental-candidate', 'release_tag': manifest['release_tag'],
            'release_url': f"https://github.com/{REPOSITORY}/releases/tag/{manifest['release_tag']}",
            'public_release_available': False, 'installation_allowed': False, 'installer_included': False,
            'runtime_verified': False, 'source_manifest_sha256': sha256(canonical_bytes(manifest)),
            'offline_validation': manifest['offline_validation'],
            'validation_report_sha256': manifest['validation_report_sha256'], 'images': images})
    validate_index(index, key)
    return index


def validate_index(index, key, minimum_version_code=0):
    expected = {'schema': 1, 'product': 'Molcer OS', 'device': 'xuanyuan', 'hardware_variant': 'global',
                'channel': 'experimental', 'base': BASE, 'android': 17,
                'update_mechanism': 'manual-full-package', 'automatic_installation': False,
                'android_ota_updater_implemented': False, 'public_release_available': False}
    for field, value in expected.items():
        if type(index.get(field)) is not type(value) or index[field] != value:
            raise ValueError('Unexpected update index field: ' + field)
    version = {**expected, **index.get('version', {})}
    validate_version(version)
    if version['version_code'] < minimum_version_code:
        raise ValueError('Update index would downgrade the accepted version')
    if index.get('signing') != {'algorithm': ALGORITHM, 'public_key_avb_sha256': key['avb_sha256']}:
        raise ValueError('Update index does not use the pinned public key')
    updates = index.get('updates')
    if not isinstance(updates, list) or len(updates) > 1:
        raise ValueError('Expected zero or one explicit experimental candidate')
    for update in updates:
        if any(update.get(k) != version[k] for k in ('version_name', 'version_code')):
            raise ValueError('Candidate version differs from index version')
        checks = update.get('offline_validation', {})
        if (update.get('kind') != 'offline-assembled-experimental-candidate'
                or any(update.get(k) is not False for k in ('public_release_available', 'installation_allowed', 'installer_included', 'runtime_verified'))
                or set(checks) != {'avb', 'super', 'hashes'} or any(value is not True for value in checks.values())):
            raise ValueError('Candidate availability or verification state is invalid')
        tag = safe_tag(update.get('release_tag'))
        if update.get('release_url') != f'https://github.com/{REPOSITORY}/releases/tag/{tag}':
            raise ValueError('Unexpected release URL')
        require_hash(update.get('source_manifest_sha256'))
        reports = update.get('validation_report_sha256', {})
        if set(reports) != REPORT_NAMES:
            raise ValueError('Candidate verification reports are incomplete')
        for digest in reports.values():
            require_hash(digest)
        validate_images(update.get('images'), tag)
    canonical_bytes(index)
    return True


def signing_request(index, key):
    validate_index(index, key)
    canonical = canonical_bytes(index)
    return {'schema': 1, 'purpose': 'molcer-os-update-index', 'algorithm': ALGORITHM,
            'domain_hex': DOMAIN.hex(), 'canonical_index_sha256': sha256(canonical),
            'digest_sha256': sha256(DOMAIN + canonical), 'public_key_avb_sha256': key['avb_sha256'],
            'version_code': index['version']['version_code'], 'candidate_count': len(index['updates'])}


def validate_signing_request(index, request, key):
    if request != signing_request(index, key):
        raise ValueError('Signing request differs from the validated canonical index')
    return True


def verify_detached(index, signature, key, minimum_version_code=0):
    validate_index(index, key, minimum_version_code)
    request = signing_request(index, key)
    for field in ('schema', 'algorithm', 'digest_sha256', 'public_key_avb_sha256'):
        if signature.get(field) != request[field]:
            raise ValueError('Detached signature identity or digest mismatch')
    encoded = signature.get('signature_hex', '')
    if not isinstance(encoded, str) or not re.fullmatch('[0-9a-f]{1024}', encoded):
        raise ValueError('Expected a 512-byte RSA4096 signature')
    value = int(encoded, 16)
    if value >= key['n']:
        raise ValueError('RSA signature out of range')
    info = bytes.fromhex('3031300d060960864801650304020105000420' + request['digest_sha256'])
    expected = b'\0\1' + b'\xff' * (512 - len(info) - 3) + b'\0' + info
    if pow(value, key['e'], key['n']).to_bytes(512, 'big') != expected:
        raise ValueError('RSA PKCS1 SHA256 signature verification failed')
    return {'signature_verified': True, 'version_code': request['version_code'],
            'public_release_available': False, 'automatic_installation': False,
            'android_ota_updater_implemented': False}


def save_new(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-key', default='keys/avb-public.xml')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('empty', 'prepare'):
        item = sub.add_parser(command)
        item.add_argument('--version', default='version.json')
        item.add_argument('--output', required=True)
        item.add_argument('--request', required=True)
        item.add_argument('--previous-index')
        item.add_argument('--previous-signature')
        if command == 'prepare':
            item.add_argument('--manifest', required=True)
    check = sub.add_parser('validate-request')
    check.add_argument('--index', required=True)
    check.add_argument('--request', required=True)
    check = sub.add_parser('verify')
    check.add_argument('--index', required=True)
    check.add_argument('--signature', required=True)
    check.add_argument('--minimum-version-code', type=int, default=0)
    args = parser.parse_args()
    key = public_key(args.public_key)
    if args.command == 'verify':
        print(json.dumps(verify_detached(read_json(args.index), read_json(args.signature), key, args.minimum_version_code)))
    elif args.command == 'validate-request':
        validate_signing_request(read_json(args.index), read_json(args.request), key)
        print(json.dumps({'signing_request_valid': True, 'private_key_accessed': False}))
    else:
        if bool(args.previous_index) != bool(args.previous_signature):
            raise ValueError('Previous index requires its verified detached signature')
        previous = read_json(args.previous_index) if args.previous_index else None
        if previous is not None:
            verify_detached(previous, read_json(args.previous_signature), key)
        manifest = read_json(args.manifest) if args.command == 'prepare' else None
        index = make_index(read_json(args.version), key, manifest, previous)
        request = signing_request(index, key)
        if pathlib.Path(args.output).exists() or pathlib.Path(args.request).exists():
            raise ValueError('Refusing to overwrite prior release metadata')
        save_new(args.output, index)
        save_new(args.request, request)
        print(json.dumps({'index_prepared': True, 'candidate_count': len(index['updates']),
                          'public_release_available': False, 'digest_sha256': request['digest_sha256']}))


if __name__ == '__main__':
    main()
