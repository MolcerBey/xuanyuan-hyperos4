"""Build and inspect an offline sparse super candidate; never operate a device.

Launch Virtual A/B semantics follow the matching AOSP build-tools manifest:
https://android.googlesource.com/platform/build/+/57203e72d9d150a845e88b93c7fd91c9804376a2/tools/releasetools/build_super_image.py
Explicit _a/_b names use --virtual-ab and three metadata slots. The retrofit
--auto-slot-suffixing option must NOT be combined with these explicit names.
"""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import pathlib
import platform
import shutil
import struct
import subprocess
import tempfile
from typing import TypedDict

from inspect_eu_geometry import SOURCE_SHA256 as EU_SHA256
from inspect_eu_geometry import inspect_window, read_sparse_window
from inspect_packaging import read_vbmeta_blob
from prepare_host_tools import validate_config, verify_bytes


PARTITIONS = ('odm', 'product', 'system', 'system_dlkm', 'system_ext',
              'vendor', 'vendor_dlkm', 'mi_product', 'mi_ext')
GROUP = 'qti_dynamic_partitions'
BASE_SHA256 = 'bd19c93fa7c1cb90ed194c5cc2ebfe786f55f1382b172e344522ca805c63f1ea'
TOOL_COMMIT = '010d8a83d84ced4beef7779453766350db8c08cd'
UINT64_MAX = 2**64 - 1
SOURCE_URL = ('https://android.googlesource.com/platform/build/+/'
              '57203e72d9d150a845e88b93c7fd91c9804376a2/'
              'tools/releasetools/build_super_image.py')


@dataclass(frozen=True)
class Geometry:
    super_size: int = 11811160064
    group_size: int = 11800674304
    metadata_size: int = 65536
    metadata_slots: int = 3
    alignment: int = 1048576
    block_size: int = 4096


class ImageRecord(TypedDict):
    name: str
    path: str
    size: int
    sha256: str
    identity_source: str


class Layout(TypedDict):
    image_total_bytes: int
    group_limit_bytes: int
    group_remaining_bytes: int
    physical_data_start_bytes: int
    physical_end_upper_bound_bytes: int
    physical_remaining_bytes: int
    alignment_padding_upper_bound_bytes: int
    super_limit_bytes: int
    allocated_b_slot_bytes: int


def sha256(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    path = pathlib.Path(path)
    if not path.is_file() or path.stat().st_size > 4 * 1024**2:
        raise ValueError('Missing or oversized metadata JSON: ' + str(path))
    return json.loads(path.read_text(encoding='utf-8'))


def uint64(value, label):
    if type(value) is not int or not 0 < value <= UINT64_MAX:
        raise ValueError('Invalid positive uint64 ' + label)
    return value


def align_up(value, alignment):
    result = ((value + alignment - 1) // alignment) * alignment
    if result > UINT64_MAX:
        raise ValueError('Alignment overflow')
    return result


def plan_layout(sizes: dict[str, int], geometry: Geometry = Geometry()) -> Layout:
    if set(sizes) != set(PARTITIONS):
        raise ValueError('Missing or unknown dynamic partition')
    for key, value in asdict(geometry).items():
        uint64(value, key)
    if (geometry.metadata_size != 65536 or geometry.metadata_slots != 3 or
            geometry.block_size != 4096 or geometry.alignment != 1048576 or
            geometry.super_size % geometry.block_size or
            geometry.group_size % geometry.block_size or
            geometry.group_size >= geometry.super_size):
        raise ValueError('Unsupported launch Virtual A/B geometry')
    first = align_up(12288 + 2 * geometry.metadata_slots * geometry.metadata_size,
                     geometry.alignment)
    cursor, total = first, 0
    for name in PARTITIONS:
        size = uint64(sizes[name], name + ' image size')
        # Inputs are reconstructed raw block images, including their AVB tails.
        if size % geometry.block_size:
            raise ValueError('Image size is not block-aligned: ' + name)
        total += size
        if total > UINT64_MAX:
            raise ValueError('Image size sum overflow')
        cursor = align_up(cursor, geometry.alignment) + size
        if cursor > UINT64_MAX:
            raise ValueError('Physical extent overflow')
    if total > geometry.group_size:
        raise ValueError(f'Images including AVB tails exceed group budget: {total} > {geometry.group_size}')
    if cursor > geometry.super_size:
        raise ValueError('Metadata and alignment exceed the conservative super capacity')
    return {'image_total_bytes': total, 'group_limit_bytes': geometry.group_size,
            'group_remaining_bytes': geometry.group_size - total,
            'physical_data_start_bytes': first,
            'physical_end_upper_bound_bytes': cursor,
            'physical_remaining_bytes': geometry.super_size - cursor,
            'alignment_padding_upper_bound_bytes': cursor - first - total,
            'super_limit_bytes': geometry.super_size, 'allocated_b_slot_bytes': 0}


def geometry_from_report(report):
    expected = Geometry()
    if (report.get('source_archive_sha256') != EU_SHA256 or
            report.get('full_archive_sha256_verified') is not True or
            report.get('reference_super_declared_size_bytes') != expected.super_size or
            report.get('conservative_single_group_image_budget_bytes') != expected.group_size or
            report.get('reference_group_budgets') != {
                GROUP + '_a': expected.group_size, GROUP + '_b': expected.group_size}):
        raise ValueError('EU geometry evidence does not match the conservative pinned reference')
    geom = report.get('geometry', {})
    if (geom.get('checksum_verified') is not True or
            geom.get('metadata_max_size') != expected.metadata_size or
            geom.get('metadata_slot_count') != expected.metadata_slots or
            geom.get('logical_block_size') != expected.block_size):
        raise ValueError('EU metadata geometry is not verified')
    copies = report.get('metadata_copies', [])
    if len(copies) != 6 or {(c.get('slot'), c.get('copy')) for c in copies} != {
            (slot, copy) for slot in range(3) for copy in ('primary', 'backup')}:
        raise ValueError('Expected all six verified LP metadata copies')
    for copy in copies:
        devices = copy.get('block_devices', [])
        if (copy.get('header_checksum_verified') is not True or
                copy.get('table_checksum_verified') is not True or
                copy.get('header_flags') != 1 or len(devices) != 1):
            raise ValueError('EU LP metadata copy is unverified or unsupported')
        groups = copy.get('groups', [])
        if (len(groups) != 3 or any(g.get('flags') != 0 for g in groups) or
                {g.get('name'): g.get('maximum_size_bytes') for g in groups} != {
                    'default': 0, GROUP + '_a': expected.group_size,
                    GROUP + '_b': expected.group_size}):
            raise ValueError('EU metadata group limits differ between copies')
        device = devices[0]
        if (device.get('name') != 'super' or device.get('flags') != 0 or
                device.get('declared_size_bytes') != expected.super_size or
                device.get('alignment_bytes') != expected.alignment or
                device.get('alignment_offset_bytes') != 0 or
                device.get('first_logical_sector') != 2048):
            raise ValueError('EU block-device geometry differs')
    if len({c.get('metadata_sha256') for c in copies}) != 1 or not copies[0].get('metadata_sha256'):
        raise ValueError('EU initial metadata copies disagree')
    return expected


def source_records(inspection):
    if (inspection.get('source_archive_hash_verified') is not True or
            inspection.get('source_archive_sha256') != BASE_SHA256):
        raise ValueError('Expected the authenticated Android 17 base inspection')
    payload = inspection['payload']
    groups = payload.get('dynamic_groups', [])
    if (len(groups) != 1 or groups[0].get('name') != GROUP or
            len(groups[0].get('partition_names', [])) != len(PARTITIONS) or
            set(groups[0]['partition_names']) != set(PARTITIONS) or
            payload.get('snapshot_enabled') is not True or payload.get('block_size') != 4096):
        raise ValueError('Missing, duplicate or unknown Android 17 dynamic partition')
    records = payload.get('partitions', [])
    by_name = {record['name']: record for record in records}
    if len(by_name) != len(records) or not set(PARTITIONS) <= set(by_name):
        raise ValueError('Missing or duplicate authenticated partition records')
    return by_name


def image_record(name, path, expected, identity_source) -> ImageRecord:
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing or non-regular image: ' + str(path))
    size = path.stat().st_size
    if size != expected['size'] or size <= 0 or size % 4096:
        raise ValueError('Image length or block alignment differs: ' + name)
    with path.open('rb') as stream:
        if stream.read(4) == b'\x3a\xff\x26\xed':
            raise ValueError('Expected raw image, not sparse input: ' + name)
    digest = sha256(path)
    if digest != expected['sha256']:
        raise ValueError('Image differs from authenticated record: ' + name)
    return {'name': name, 'path': str(path.resolve()), 'size': size,
            'sha256': digest, 'identity_source': identity_source}


def collect_images(image_root, product, inspection, product_record):
    expected = source_records(inspection)
    prepared = [r for r in product_record.get('prepared_images', []) if r.get('partition') == 'product']
    if (len(prepared) != 1 or product_record.get('schema') != 1 or
            product_record.get('product_hashtree_verified') is not True):
        raise ValueError('Expected one verified prepared product AVB image record')
    root = pathlib.Path(image_root).resolve()
    product = pathlib.Path(product)
    if product.resolve() == root / 'product.img':
        raise ValueError('Rebuilt product must be separate from the source image')
    paths = {name: product if name == 'product' else root / (name + '.img') for name in PARTITIONS}
    # Fail before expensive hashing if any required partition is missing.
    if any(p.is_symlink() or not p.is_file() for p in paths.values()):
        raise ValueError('Missing or non-regular required dynamic image')
    records = {}
    for name in PARTITIONS:
        record = prepared[0] if name == 'product' else expected[name]
        identity = 'prepared-product-AVB-record' if name == 'product' else 'authenticated-Android17-payload'
        records[name] = image_record(name, paths[name], record, identity)
    footer, blob = read_vbmeta_blob(product)
    if footer is None or blob is None:
        raise ValueError('Rebuilt product has no valid AVB footer; its final overhead must be included')
    return records, footer


def verified_tool(tool_root, config_path):
    if platform.system() != 'Linux' or platform.machine().lower() not in {'x86_64', 'amd64'}:
        raise ValueError('lpmake execution requires Linux x86_64')
    config = read_json(config_path)
    validate_config(config)
    if config['upstream_commit'] != TOOL_COMMIT:
        raise ValueError('Unexpected AOSP host-tool revision')
    tool_root = pathlib.Path(tool_root).resolve()
    for item in config['files']:
        path = tool_root / item['path']
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item['size']:
            raise ValueError('Missing or changed pinned host tool/library')
        verify_bytes(path.read_bytes(), item)
    executable = tool_root / 'linux-x86/bin/lpmake'
    env = os.environ.copy()
    env.pop('LD_PRELOAD', None)
    env['LD_LIBRARY_PATH'] = str(tool_root / 'linux-x86/lib64')
    return executable, env, {'upstream_commit': TOOL_COMMIT, 'lpmake_sha256': sha256(executable),
                             'all_private_library_hashes_verified': True}


def lpmake_command(executable, records, geometry, output):
    plan_layout({name: record['size'] for name, record in records.items()}, geometry)
    command = [str(executable), '--metadata-size', str(geometry.metadata_size),
               '--metadata-slots', str(geometry.metadata_slots), '--super-name', 'super',
               '--device', f'super:{geometry.super_size}:{geometry.alignment}:0',
               '--block-size', str(geometry.block_size), '--virtual-ab', '--sparse',
               '--group', f'{GROUP}_a:{geometry.group_size}',
               '--group', f'{GROUP}_b:{geometry.group_size}']
    for name in PARTITIONS:
        command += ['--partition', f'{name}_a:readonly:{records[name]["size"]}:{GROUP}_a',
                    '--image', f'{name}_a={records[name]["path"]}',
                    '--partition', f'{name}_b:readonly:0:{GROUP}_b']
    return command + ['--output', str(output)]


def check_disk_space(directory, geometry, reserve=1024**3):
    # Sparse output cannot require more than a raw block plus a chunk header per
    # block. Reserve this upper bound even if most data is compressible/zero.
    upper_bound = geometry.super_size + (geometry.super_size // geometry.block_size) * 12 + 4096
    required = upper_bound + reserve
    free = shutil.disk_usage(directory).free
    if free < required:
        raise ValueError(f'Insufficient free disk space for super output: {free} < {required}')
    return {'free_bytes_before': free, 'output_upper_bound_bytes': upper_bound,
            'reserve_bytes': reserve, 'required_free_bytes': required}


def inspect_sparse_file(path, geometry):
    """Validate every sparse chunk's structural length without expanding it."""
    path = pathlib.Path(path)
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(28)
        if len(header) != 28:
            raise ValueError('Truncated sparse header')
        magic, major, minor, fh, ch, block, blocks, chunks, checksum = struct.unpack('<I4H4I', header)
        if (magic != 0xed26ff3a or (major, minor, fh, ch, block) != (1, 0, 28, 12, geometry.block_size)
                or blocks * block != geometry.super_size or not 0 < chunks <= blocks + 1024):
            raise ValueError('Unexpected sparse output header or expanded capacity')
        logical = 0
        for _ in range(chunks):
            raw = stream.read(ch)
            if len(raw) != ch:
                raise ValueError('Truncated sparse chunk header')
            kind, reserved, count, total = struct.unpack('<2H2I', raw)
            length = count * block
            payload_size = {0xcac1: length, 0xcac2: 4, 0xcac3: 0, 0xcac4: 4}.get(kind)
            if (payload_size is None or reserved or total != ch + payload_size or
                    (kind == 0xcac4 and count != 0) or (kind != 0xcac4 and count == 0) or
                    logical + length > geometry.super_size or stream.tell() + payload_size > size):
                raise ValueError('Invalid or out-of-bounds sparse chunk')
            stream.seek(payload_size, 1)
            logical += length
        if logical != geometry.super_size or stream.tell() != size:
            raise ValueError('Sparse expanded length or trailing data differs')
    return {'encoding': 'android-sparse-v1', 'size_bytes': size,
            'expanded_size_bytes': logical, 'chunk_count': chunks,
            'all_chunk_bounds_verified': True, 'crc32_verified': False,
            'checksum_field': checksum}


def inspect_output(path, records, geometry):
    sparse = inspect_sparse_file(path, geometry)
    with pathlib.Path(path).open('rb') as stream:
        data, known, prefix = read_sparse_window(stream)
    result = inspect_window(data, known, prefix)
    if (result['geometry']['metadata_max_size'] != geometry.metadata_size or
            result['geometry']['metadata_slot_count'] != geometry.metadata_slots or
            result['geometry']['logical_block_size'] != geometry.block_size):
        raise ValueError('Generated metadata geometry differs')
    expected_groups = {GROUP + '_a': geometry.group_size, GROUP + '_b': geometry.group_size}
    if result['reference_group_budgets'] != expected_groups:
        raise ValueError('Generated group capacities differ')
    expected_names = {name + suffix for name in PARTITIONS for suffix in ('_a', '_b')}
    hashes = set()
    for copy in result['metadata_copies']:
        hashes.add(copy['metadata_sha256'])
        device = copy['block_devices'][0]
        if (copy['header_flags'] != 1 or set(copy['partition_names']) != expected_names or
                device['flags'] != 0 or device['alignment_bytes'] != geometry.alignment or
                device['alignment_offset_bytes'] != 0 or device['first_logical_sector'] != 2048):
            raise ValueError('Generated Virtual A/B names, flags or alignment differ')
        offset, header_size = copy['offset'], copy['header_size']
        tables = data[offset + header_size:offset + header_size + copy['tables_size']]
        part_start, count, stride = struct.unpack_from('<3I', data, offset + 80)
        ext_start, _, ext_stride = struct.unpack_from('<3I', data, offset + 92)
        ranges = []
        for index in range(count):
            raw = tables[part_start + index * stride:part_start + (index + 1) * stride]
            raw_name, attrs, first, number, group = struct.unpack('<36s4I', raw)
            name = raw_name.split(b'\0', 1)[0].decode('ascii')
            slot, base = name[-1], name[:-2]
            if attrs != 1 or copy['groups'][group]['name'] != GROUP + '_' + slot:
                raise ValueError('Generated partition attributes/group differ')
            extent_bytes = 0
            for at in range(first, first + number):
                sectors, kind, target, source = struct.unpack_from('<QIQI', tables, ext_start + at * ext_stride)
                start, end = target * 512, (target + sectors) * 512
                if (kind != 0 or source != 0 or start % geometry.alignment or start < 1048576 or
                        any(start < old_end and end > old_start for old_start, old_end in ranges)):
                    raise ValueError('Generated partition extents overlap or violate alignment')
                ranges.append((start, end))
                extent_bytes += sectors * 512
            expected_size = records[base]['size'] if slot == 'a' else 0
            if extent_bytes != expected_size or (slot == 'b' and number):
                raise ValueError('Generated A/B allocated image sizes differ')
    if len(hashes) != 1:
        raise ValueError('Initial metadata slots must contain identical layout')
    return {**sparse, 'sha256': sha256(path), 'lp_geometry_checksums_verified': True,
            'all_six_metadata_copies_verified': True,
            'metadata_sha256': next(iter(hashes)), 'partition_count': len(expected_names),
            'a_slot_image_sizes_verified': True, 'b_slot_all_extents_empty': True,
            'partition_payload_contents_rehashed_from_output': False}


def build_image(records, geometry, executable, env, output, reserve=1024**3):
    output = pathlib.Path(output)
    layout = plan_layout({name: record['size'] for name, record in records.items()}, geometry)
    sources = {pathlib.Path(record['path']).resolve() for record in records.values()}
    if output.exists() or output.is_symlink() or output.resolve() in sources:
        raise ValueError('Output must be fresh and separate from every input')
    output.parent.mkdir(parents=True, exist_ok=True)
    disk = check_disk_space(output.parent, geometry, reserve)
    with tempfile.TemporaryDirectory(prefix='super-build-', dir=output.parent) as directory:
        candidate = pathlib.Path(directory) / 'super.img'
        command = lpmake_command(executable, records, geometry, candidate)
        result = subprocess.run(command, env=env, capture_output=True, text=True,
                                errors='replace', timeout=1800, check=False)
        if result.returncode:
            raise RuntimeError('Pinned lpmake failed: ' + result.stderr[:3000])
        inspected = inspect_output(candidate, records, geometry)
        # Source images remain read-only; prove their complete bytes did not
        # change while the candidate was generated.
        for record in records.values():
            if pathlib.Path(record['path']).stat().st_size != record['size'] or sha256(record['path']) != record['sha256']:
                raise ValueError('Input image changed during super construction')
        # Same-filesystem exclusive publication: never replace an existing file.
        os.link(candidate, output)
    return {'layout': layout, 'disk': disk, 'output': {**inspected, 'path': str(output.resolve())},
            'lpmake': {'exit_code': result.returncode, 'stdout': result.stdout[:16384],
                       'stderr': result.stderr[:16384], 'arguments': command[1:]},
            'source_image_hashes_reverified_after_build': True}


def tiny_linux_smoke(tool_root='.tools/aosp-host', config_path='host-tools.json'):
    executable, env, tool = verified_tool(tool_root, config_path)
    geometry = Geometry(super_size=16 * 1024**2, group_size=12 * 1024**2)
    with tempfile.TemporaryDirectory(prefix='molcer-super-smoke-') as directory:
        root = pathlib.Path(directory)
        records = {}
        for index, name in enumerate(PARTITIONS):
            path = root / (name + '.img')
            path.write_bytes(bytes([index + 1]) * 16384)
            records[name] = {'name': name, 'path': str(path), 'size': path.stat().st_size,
                             'sha256': sha256(path), 'identity_source': 'synthetic-smoke-data'}
        result = build_image(records, geometry, executable, env, root / 'super.img', reserve=16 * 1024**2)
    return {'schema': 1, 'status': 'synthetic-linux-lpmake-smoke-passed', 'tool': tool,
            'synthetic_inputs': True, 'temporary_files_removed': True,
            'runtime_verified': False, 'phone_accessed': False, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--geometry', default='reports/eu-super-geometry.json')
    parser.add_argument('--inspection', default='reports/packaging-inspection.json')
    parser.add_argument('--images', default='work/images')
    parser.add_argument('--product', default='out/avb-prepared/images/product.img')
    parser.add_argument('--product-record', default='out/avb-prepared/signing-requests.json')
    parser.add_argument('--tool-root', default='.tools/aosp-host')
    parser.add_argument('--tool-config', default='host-tools.json')
    parser.add_argument('--output', default='out/super/super.img')
    parser.add_argument('--report', default='reports/super-build.json')
    parser.add_argument('--plan-only', action='store_true')
    parser.add_argument('--smoke-test', action='store_true')
    args = parser.parse_args()
    report_path = pathlib.Path(args.report)
    protected = {pathlib.Path(p).resolve() for p in (
        args.geometry, args.inspection, args.product, args.product_record, args.tool_config, args.output)}
    image_root = pathlib.Path(args.images).resolve()
    if report_path.resolve() in protected or report_path.resolve().is_relative_to(image_root):
        raise ValueError('Report must not overwrite an input or output image')
    report = {'schema': 1, 'status': 'failed', 'phone_accessed': False,
              'runtime_verified': False, 'actual_phone_gpt_capacity_verified': False,
              'installable_rom_produced': False, 'repartition_performed': False}
    try:
        if args.smoke_test:
            report.update(tiny_linux_smoke(args.tool_root, args.tool_config))
        else:
            geometry = geometry_from_report(read_json(args.geometry))
            inspection, product_record = read_json(args.inspection), read_json(args.product_record)
            records, footer = collect_images(args.images, args.product, inspection, product_record)
            layout = plan_layout({name: item['size'] for name, item in records.items()}, geometry)
            report.update({'geometry': asdict(geometry), 'layout': layout,
                           'inputs': list(records.values()), 'product_avb_footer': footer,
                           'product_avb_overhead_included_in_image_size': True,
                           'evidence_sha256': {p: sha256(p) for p in (
                               args.geometry, args.inspection, args.product_record, args.tool_config)},
                           'source_semantics': SOURCE_URL, 'a_slot_populated': True,
                           'b_slot_sizes_zero': True, 'auto_slot_suffixing': False,
                           'scope': 'Offline super candidate within reference-package capacity; no device capacity, boot, OTA or AVB trust-root acceptance is asserted.'})
            if args.plan_only:
                report['status'] = 'verified-inputs-fit-conservative-reference'
            else:
                if pathlib.Path(args.output).resolve().is_relative_to(image_root):
                    raise ValueError('Super output must be outside the source image directory')
                executable, env, tool = verified_tool(args.tool_root, args.tool_config)
                report['tool'] = tool
                report.update(build_image(records, geometry, executable, env, args.output))
                report['status'] = 'offline-sparse-super-candidate-verified'
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': report['status'], 'report': str(report_path)}))


if __name__ == '__main__':
    main()
