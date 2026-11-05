"""Collect authenticated offline payload, AVB and fstab evidence; never install."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import struct
import subprocess
import sys
import zipfile

from inspect_ota import fields, partition_summary

MAX_METADATA = 16 * 1024**2
DEFAULT_PARTITIONS = ['vbmeta', 'vbmeta_system', 'init_boot', 'boot',
                      'vendor_boot', 'recovery', 'dtbo', 'product']
NAME = re.compile(r'[a-zA-Z0-9_][a-zA-Z0-9_-]*')


def sha256(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def one(message, key, default=None):
    values = message.get(key, [])
    if len(values) > 1:
        raise ValueError('Duplicate singular protobuf field ' + str(key))
    return values[0] if values else default


def utf8(value):
    if not isinstance(value, bytes):
        raise ValueError('Expected protobuf text')
    return value.decode('utf-8')


def safe_name(value):
    value = utf8(value)
    if not NAME.fullmatch(value):
        raise ValueError('Invalid partition/group name')
    return value


def metadata_fields(message):
    """Preserve unknown OEM/future protobuf fields without assigning semantics."""
    out = {}
    for number, values in message.items():
        out[str(number)] = []
        for value in values:
            if isinstance(value, int):
                item = {'integer': value}
            else:
                item = {'bytes_hex': value.hex()}
                try:
                    decoded = value.decode('utf-8')
                    if decoded.isprintable():
                        item['utf8'] = decoded
                except UnicodeDecodeError:
                    pass
            out[str(number)].append(item)
    return out


def parse_payload_manifest(manifest):
    parsed = fields(manifest)
    if one(parsed, 12, 0) != 0 or one(parsed, 16, 0):
        raise ValueError('Only a full, non-partial payload is accepted')
    parts = partition_summary(manifest)
    by_name = {p['name']: p for p in parts}
    if not parts or len(by_name) != len(parts):
        raise ValueError('Missing or duplicate payload partition')
    for p in parts:
        if not NAME.fullmatch(p['name']) or p['size'] <= 0 or len(p['sha256']) != 64:
            raise ValueError('Invalid payload partition identity')
    dynamic = fields(one(parsed, 15, b''))
    groups, group_names, assigned = [], set(), set()
    for raw in dynamic.get(1, []):
        g = fields(raw)
        name = safe_name(one(g, 1))
        maximum = one(g, 2)
        members = [safe_name(v) for v in g.get(3, [])]
        if name in group_names or not isinstance(maximum, int) or maximum <= 0:
            raise ValueError('Invalid or duplicate dynamic group')
        if not members or len(set(members)) != len(members) or assigned & set(members):
            raise ValueError('Duplicate or missing dynamic group membership')
        if not set(members) <= set(by_name):
            raise ValueError('Dynamic group references a missing partition')
        total = sum(by_name[n]['size'] for n in members)
        if total > maximum:
            raise ValueError('Dynamic partition images exceed group maximum')
        groups.append({'name': name, 'maximum_size_bytes': maximum,
                       'partition_names': members, 'stock_image_total_bytes': total,
                       'remaining_group_bytes_before_alignment': maximum - total})
        group_names.add(name)
        assigned.update(members)
    partition_options = []
    for raw in parsed.get(13, []):
        p = fields(raw)
        record = {'name': safe_name(one(p, 1)), 'run_postinstall': bool(one(p, 2, 0)),
                  'postinstall_optional': bool(one(p, 9, 0))}
        for number, key in [(3, 'postinstall_path'), (4, 'filesystem_type'), (17, 'version')]:
            value = one(p, number)
            if value is not None:
                record[key] = utf8(value)
        record['verity_and_fec_fields'] = metadata_fields({k: p[k] for k in range(10, 17) if k in p})
        partition_options.append(record)
    return {'block_size': one(parsed, 3, 4096), 'minor_version': one(parsed, 12, 0),
            'maximum_timestamp': one(parsed, 14),
            'security_patch_level': utf8(one(parsed, 18, b'')),
            'dynamic_groups': groups, 'snapshot_enabled': bool(one(dynamic, 2, 0)),
            'vabc_enabled': bool(one(dynamic, 3, 0)),
            'vabc_compression_parameter': utf8(one(dynamic, 4, b'')),
            'cow_version': one(dynamic, 5), 'compression_factor': one(dynamic, 7),
            'uninterpreted_dynamic_fields': metadata_fields({k: v for k, v in dynamic.items() if k not in (1, 2, 3, 4, 5, 7)}),
            'partitions': parts, 'partition_options': partition_options,
            'physical_partition_capacity_verified': False,
            'super_geometry_verified': False}


def inspect_payload(archive, config):
    archive = pathlib.Path(archive)
    if archive.stat().st_size != config['size'] or sha256(archive) != config['sha256']:
        raise ValueError('Source archive differs from pinned authenticated base')
    with zipfile.ZipFile(archive) as z:
        if z.namelist().count('payload.bin') != 1:
            raise ValueError('Missing or duplicate payload')
        payload = z.getinfo('payload.bin')
        if payload.compress_type != zipfile.ZIP_STORED:
            raise ValueError('Expected stored full payload')
        with z.open(payload) as stream:
            header = stream.read(24)
            if len(header) != 24 or header[:4] != b'CrAU':
                raise ValueError('Invalid payload header')
            version, size, signature_size = struct.unpack('>QQI', header[4:])
            if version != 2 or not 0 < size <= MAX_METADATA or 24 + size + signature_size > payload.file_size:
                raise ValueError('Invalid payload metadata bounds')
            manifest = stream.read(size)
            if len(manifest) != size:
                raise ValueError('Truncated payload metadata')
    return parse_payload_manifest(manifest)


def read_vbmeta_blob(image):
    """Read raw-image AVB data with bounds checks, without opening for writing."""
    image = pathlib.Path(image)
    size = image.stat().st_size
    footer = None
    with image.open('rb') as stream:
        magic = stream.read(4)
        if magic == b'\x3a\xff\x26\xed':
            raise ValueError('Expected reconstructed raw image, not sparse encoding')
        offset, maximum = 0, size
        if size >= 64:
            stream.seek(size - 64)
            raw = stream.read(64)
            if raw[:4] == b'AVBf':
                _, major, minor, original, offset, maximum, _ = struct.unpack('>4s2I3Q28s', raw)
                if major != 1 or original > offset or maximum < 256 or offset + maximum > size - 64:
                    raise ValueError('Invalid AVB footer bounds')
                footer = {'version_major': major, 'version_minor': minor,
                          'original_image_size': original, 'vbmeta_offset': offset,
                          'vbmeta_size': maximum}
        if footer is None and magic != b'AVB0':
            return None, None
        stream.seek(offset)
        header = stream.read(256)
        if len(header) != 256 or header[:4] != b'AVB0':
            raise ValueError('Invalid AVB header')
        auth, auxiliary = struct.unpack_from('>2Q', header, 12)
        total = 256 + auth + auxiliary
        if auth % 64 or auxiliary % 64 or total > min(maximum, MAX_METADATA):
            raise ValueError('Invalid AVB metadata block sizes')
        stream.seek(offset)
        blob = stream.read(total)
        if len(blob) != total:
            raise ValueError('Truncated AVB metadata')
    return footer, blob


def avb_object(value):
    if isinstance(value, bytes):
        return {'hex': value.hex(), 'sha256': hashlib.sha256(value).hexdigest()}
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise ValueError('Unsupported AVB metadata value')


def inspect_avb(image, tool_module, tool_path):
    footer, blob = read_vbmeta_blob(image)
    if blob is None:
        return {'avb_metadata_found': False, 'avb_cryptographic_chain_verified': False,
                'interpretation': 'No local AVB footer/header; a descriptor may live in another vbmeta partition.'}
    header = tool_module.AvbVBMetaHeader(blob[:256])
    aux_start = 256 + header.authentication_data_block_size
    aux = blob[aux_start:]
    for prefix in ('public_key', 'public_key_metadata', 'descriptors'):
        offset = getattr(header, prefix + '_offset')
        size = getattr(header, prefix + '_size')
        if offset < 0 or size < 0 or offset + size > len(aux):
            raise ValueError('AVB auxiliary range outside metadata')
    raw = aux[header.descriptors_offset:header.descriptors_offset + header.descriptors_size]
    descriptors = []
    for d in tool_module.parse_descriptors(raw):
        descriptors.append({'type': type(d).__name__, **{k: avb_object(v) for k, v in vars(d).items()}})
    if len(descriptors) > 1000:
        raise ValueError('Excessive AVB descriptors')
    result = subprocess.run([sys.executable, str(tool_path), 'info_image', '--image', str(image)],
                            capture_output=True, text=True, check=False, timeout=60)
    if result.returncode or len(result.stdout) + len(result.stderr) > 2 * 1024**2:
        raise ValueError('Pinned avbtool could not inspect AVB image: ' + result.stderr[:400])
    public_key = aux[header.public_key_offset:header.public_key_offset + header.public_key_size]
    return {'avb_metadata_found': True, 'footer': footer,
            'header': {k: avb_object(v) for k, v in vars(header).items()},
            'public_key_sha256': hashlib.sha256(public_key).hexdigest() if public_key else None,
            'descriptors': descriptors, 'avbtool_info_image': result.stdout,
            'avb_cryptographic_chain_verified': False,
            'interpretation': 'Structural inspection only; no signature/chain, device trust-root, rollback or boot acceptance is asserted.'}


def verify_image_source(path, expected):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing/non-regular source image: ' + path.name)
    if path.stat().st_size != expected['size'] or sha256(path) != expected['sha256']:
        raise ValueError('Image differs from authenticated payload: ' + path.name)
    return {'size': expected['size'], 'sha256': expected['sha256'], 'payload_hash_verified': True}


def collect_fstabs(root):
    root = pathlib.Path(root)
    if not root.is_dir():
        raise ValueError('Missing vendor mount directory')
    records = []
    for path in sorted((root / 'etc').glob('fstab*')):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Unexpected fstab path')
        if path.stat().st_size > 256 * 1024:
            raise ValueError('Oversized fstab')
        records.append({'path': path.relative_to(root).as_posix(), 'sha256': sha256(path),
                        'text': path.read_text(encoding='utf-8')})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='work/base.zip')
    parser.add_argument('--config', default='base.json')
    parser.add_argument('--images', default='work/images')
    parser.add_argument('--partitions', nargs='+', default=DEFAULT_PARTITIONS)
    parser.add_argument('--avbtool', default='tools/avbtool.py')
    parser.add_argument('--vendor-root')
    parser.add_argument('--output', default='reports/packaging-inspection.json')
    args = parser.parse_args()
    config = json.loads(pathlib.Path(args.config).read_text(encoding='utf-8'))
    payload = inspect_payload(args.archive, config)
    expected = {p['name']: p for p in payload['partitions']}
    if len(set(args.partitions)) != len(args.partitions) or not set(args.partitions) <= set(expected):
        raise ValueError('Unexpected/duplicate inspection partition list')
    # All images are authenticated before importing or executing the pinned tool.
    records = {}
    for name in args.partitions:
        records[name] = verify_image_source(pathlib.Path(args.images) / (name + '.img'), expected[name])
    tool_path = pathlib.Path(args.avbtool)
    spec = importlib.util.spec_from_file_location('packaging_avbtool', tool_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in args.partitions:
        records[name]['avb'] = inspect_avb(pathlib.Path(args.images) / (name + '.img'), module, tool_path)
    for required in ('vbmeta', 'vbmeta_system'):
        if required in records and not records[required]['avb']['avb_metadata_found']:
            raise ValueError('Expected AVB metadata is absent: ' + required)
    result = {'source_rom': config['version'], 'source_archive_sha256': config['sha256'],
              'source_archive_hash_verified': True, 'avbtool_sha256': sha256(tool_path),
              'payload': payload, 'images': records,
              'vendor_fstabs': collect_fstabs(args.vendor_root) if args.vendor_root else [],
              'phone_accessed': False, 'source_images_modified': False,
              'installable_rom_produced': False, 'avb_chain_verified': False,
              'device_gpt_or_rollback_state_verified': False,
              'scope': 'Offline packaging metadata; the complete firmware compatibility and installation path are not validated.'}
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(out), 'groups': payload['dynamic_groups'],
                      'inspected_images': list(records), 'phone_accessed': False}))


if __name__ == '__main__':
    main()
