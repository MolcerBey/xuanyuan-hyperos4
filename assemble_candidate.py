"""Assemble a signed offline candidate within the EU package geometry.

This reconstructs only authenticated images, verifies the full AVB chain, and
stores a draft bundle. It never emits or runs an installer or accesses a phone.
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading

from build_super import (PARTITIONS, Geometry, build_image, inspect_sparse_file,
                         verified_tool)
from inspect_eu_geometry import inspect_window, read_sparse_window
from extract_partition import extract
from integrate_radio import integrate
from prepare_avb import file_digest, read_json
from publish_candidate import (BUFFER_BYTES, CHUNK_BYTES, REPOSITORY, draft_release, gh,
                               save_json, stream_chunks, upload_asset)
from validate_signing_requests import validate_bundle

CUSTOM = {'product', 'init_boot', 'vbmeta', 'vbmeta_system'}
EXCLUDED_CN = {'modem', 'modemfirmware', 'countrycode'}
RESERVE = 1024**3
NOTE = ('OFFLINE MOLCER OS CANDIDATE - NOT INSTALLABLE.\n'
        'Image signatures, partition contents and conservative package geometry '
        'were checked offline. No installer is included. Device GPT capacity, '
        'bootloader trust-root acceptance, boot, camera, radio/IMS and OTA behavior '
        'remain unverified. No phone operation or private-key access occurred.\n')


def checked_hash(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('Expected a lowercase SHA256')
    return value


def protected_partition(name):
    value = name.lower()
    return (value.startswith(('persist', 'modemst', 'vm-persist'))
            or value in {'fsg', 'fsc', 'qmcs', 'userdata', 'metadata'})


def selected_partitions(inspection, verified):
    """Derive every selection from the fresh authenticated payload, not a count."""
    original = inspection['payload']['partitions']
    fresh = verified['partitions']
    def identities(items):
        result = {}
        for item in items:
            name = item['name']
            if (not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in result
                    or type(item['size']) is not int or item['size'] <= 0):
                raise ValueError('Unexpected payload partition identity')
            result[name] = (item['size'], checked_hash(item['sha256']))
        return result
    expected, current = identities(original), identities(fresh)
    if expected != current or not (CUSTOM | EXCLUDED_CN | set(PARTITIONS)) <= current.keys():
        raise ValueError('Authenticated payload differs from the inspected source')
    names = sorted(n for n in current if n not in CUSTOM | EXCLUDED_CN and not protected_partition(n))
    return names, current


def pinned_input(record):
    value = record['path']
    path = pathlib.PurePosixPath(value)
    if (not isinstance(value, str) or '\\' in value or path.is_absolute()
            or '..' in path.parts or len(path.parts) < 2 or path.parts[0] != 'inputs'
            or path.suffix != '.json'):
        raise ValueError('Signing inputs must be relative JSON files under inputs/')
    actual = pathlib.Path(*path.parts)
    if (actual.is_symlink() or not actual.resolve().is_relative_to(pathlib.Path('inputs').resolve())
            or not actual.is_file() or actual.stat().st_size > 1024**2
            or file_digest(actual) != checked_hash(record['sha256'])):
        raise ValueError('Signing input does not match the configured hash')
    return actual


def download_asset(asset_id, expected_size, expected_hash, output):
    """Stream a bounded authenticated GitHub asset without buffering a full chunk."""
    if (type(asset_id) is not int or asset_id <= 0
            or type(expected_size) is not int or not 0 < expected_size <= CHUNK_BYTES):
        raise ValueError('Invalid bounded GitHub asset identity')
    checked_hash(expected_hash)
    measured = hashlib.sha256()
    length = 0
    process = subprocess.Popen(['gh', 'api', f'repos/{REPOSITORY}/releases/assets/{asset_id}',
                                '-H', 'Accept: application/octet-stream'],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    timer = threading.Timer(1200, process.kill)
    timer.daemon = True
    timer.start()
    try:
        while data := process.stdout.read(BUFFER_BYTES):
            length += len(data)
            if length > expected_size:
                raise ValueError('Downloaded asset exceeds the pinned size')
            measured.update(data)
            output.write(data)
        if process.wait(timeout=30):
            raise ValueError('GitHub asset download failed or timed out')
        if length != expected_size or measured.hexdigest() != expected_hash:
            raise ValueError('Downloaded asset size/SHA256 mismatch')
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=30)
        process.stdout.close()


def validate_manifest(manifest, config, bundle):
    if (manifest.get('schema') != 1
            or manifest.get('status') != 'unsigned-candidate-awaiting-local-signatures'
            or manifest.get('repository') != REPOSITORY
            or manifest.get('commit') != config['source_commit']
            or manifest.get('requests_sha256') != config['signing_requests']['sha256']
            or manifest.get('release_draft') is not True
            or manifest.get('phone_accessed') is not False
            or manifest.get('installable_rom_produced') is not False
            or manifest.get('chunk_size_limit') != CHUNK_BYTES):
        raise ValueError('Draft candidate provenance differs from the configured signing inputs')
    records = bundle['prepared_images']
    if len(records) != 2 or {r['partition'] for r in records} != {'product', 'init_boot'}:
        raise ValueError('Expected exactly two prepared images')
    wanted = {r['partition']: r for r in records}
    images = manifest['images']
    if len(images) != 2 or {r['partition'] for r in images} != set(wanted):
        raise ValueError('Candidate manifest image set differs')
    asset_ids = set()
    for image in images:
        record = wanted[image['partition']]
        if (image['size'] != record['size'] or image['sha256'] != record['sha256']
                or type(image['size']) is not int or not 0 < image['size'] <= 5 * 1024**3):
            raise ValueError('Candidate image differs from signed image bindings')
        checked_hash(image['sha256'])
        chunks = image['chunks']
        if not 1 <= len(chunks) <= 4:
            raise ValueError('Unexpected bounded chunk count')
        offset = 0
        for index, chunk in enumerate(chunks):
            expected_name = f'NOT-INSTALLABLE-{image["partition"]}.img.part-{index:05d}'
            size = min(CHUNK_BYTES, image['size'] - offset)
            if (chunk['index'] != index or chunk['offset'] != offset or chunk['size'] != size
                    or size <= 0 or chunk['asset_name'] != expected_name
                    or type(chunk['asset_id']) is not int or chunk['asset_id'] <= 0
                    or chunk['asset_id'] in asset_ids):
                raise ValueError('Invalid candidate chunk order, extent or identity')
            checked_hash(chunk['sha256'])
            asset_ids.add(chunk['asset_id'])
            offset += size
        if offset != image['size']:
            raise ValueError('Candidate chunks do not cover the exact image')
    return images


def run_script(name, *arguments):
    print('Offline assembly step:', name, flush=True)
    subprocess.run([sys.executable, name, *map(str, arguments)], check=True, timeout=7200)


def restore_images(images, destination):
    destination = pathlib.Path(destination)
    for image in images:
        path = destination / (image['partition'] + '.img')
        if path.exists() or path.is_symlink():
            raise ValueError('Refusing to replace a preexisting prepared image')
        try:
            with path.open('xb') as output:
                for chunk in image['chunks']:
                    download_asset(chunk['asset_id'], chunk['size'], chunk['sha256'], output)
            if path.stat().st_size != image['size'] or file_digest(path) != image['sha256']:
                raise ValueError('Reassembled image does not match the signed request')
        except BaseException:
            if path.exists():
                path.unlink()
            raise


def logical_extents(data, metadata, records, geometry):
    """Validate exact A/B image allocation and return ordered physical ranges."""
    if set(records) != set(PARTITIONS):
        raise ValueError('Expected exactly all nine logical image identities')
    offset, header_size = metadata['offset'], metadata['header_size']
    tables = data[offset + header_size:offset + header_size + metadata['tables_size']]
    part_start, count, stride = struct.unpack_from('<3I', data, offset + 80)
    ext_start, extent_count, ext_stride = struct.unpack_from('<3I', data, offset + 92)
    if stride != 52 or ext_stride != 24 or count != 18:
        raise ValueError('Unexpected logical partition/extent table shape')
    names, ranges = set(), []
    for index in range(count):
        name_raw, attrs, first, number, group = struct.unpack_from('<36s4I', tables, part_start + index * stride)
        name = name_raw.split(b'\0', 1)[0].decode('ascii')
        if name in names or name[-2:] not in ('_a', '_b') or name[:-2] not in records or attrs != 1:
            raise ValueError('Unexpected duplicate or non-readonly logical partition')
        names.add(name)
        base, slot = name[:-2], name[-1]
        if (group >= len(metadata['groups'])
                or metadata['groups'][group]['name'] != 'qti_dynamic_partitions_' + slot
                or first + number > extent_count or (slot == 'b' and number)):
            raise ValueError('Invalid partition group or B-slot allocation')
        logical = 0
        for at in range(first, first + number):
            sectors, kind, target, source = struct.unpack_from('<QIQI', tables, ext_start + at * ext_stride)
            start, length = target * 512, sectors * 512
            if (kind != 0 or source != 0 or length <= 0 or length % geometry.block_size
                    or start < 1048576 or start % geometry.alignment
                    or start + length > geometry.super_size):
                raise ValueError('Invalid logical image extent bounds/type')
            ranges.append((start, start + length, base, logical))
            logical += length
        expected = records[base]['size'] if slot == 'a' else 0
        if logical != expected:
            raise ValueError('Logical image extents do not cover the exact image including padding/footer')
    if names != {n + suffix for n in PARTITIONS for suffix in ('_a', '_b')}:
        raise ValueError('Missing logical A/B partition')
    ranges.sort()
    if any(previous[1] > current[0] for previous, current in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping logical image extents')
    return ranges


def verify_super_payload(path, records, geometry):
    """Hash bytes inside sparse output without allocating an expanded super copy."""
    sparse = inspect_sparse_file(path, geometry)
    with pathlib.Path(path).open('rb') as stream:
        data, known, prefix = read_sparse_window(stream)
    layout = inspect_window(data, known, prefix)
    if len({item['metadata_sha256'] for item in layout['metadata_copies']}) != 1:
        raise ValueError('Super metadata slots disagree')
    ranges = logical_extents(data, layout['metadata_copies'][0], records, geometry)
    states = {name: {'hash': hashlib.sha256(), 'size': 0} for name in PARTITIONS}

    def consume(start, chunk):
        end = start + len(chunk)
        for lower, upper, name, logical in ranges:
            left, right = max(lower, start), min(upper, end)
            if left >= right:
                continue
            state = states[name]
            if logical + left - lower != state['size']:
                raise ValueError('Logical image extents are not in sequential content order')
            state['hash'].update(chunk[left - start:right - start])
            state['size'] += right - left

    with pathlib.Path(path).open('rb') as stream:
        header = stream.read(28)
        _, _, _, _, ch, block, _, chunks, _ = struct.unpack('<I4H4I', header)
        position = 0
        for _ in range(chunks):
            kind, _, count, _ = struct.unpack('<2H2I', stream.read(ch))
            length = count * block
            if kind == 0xcac3:
                if any(position < end and position + length > start for start, end, _, _ in ranges):
                    raise ValueError('Sparse DONT_CARE overlaps allocated logical image data')
            elif kind in (0xcac1, 0xcac2):
                fill = stream.read(4) if kind == 0xcac2 else None
                consumed = 0
                while consumed < length:
                    size = min(BUFFER_BYTES, length - consumed)
                    chunk = fill * (size // 4) if fill is not None else stream.read(size)
                    if len(chunk) != size:
                        raise ValueError('Truncated sparse logical image payload')
                    consume(position + consumed, chunk)
                    consumed += size
            elif kind == 0xcac4:
                stream.read(4)
            else:
                raise ValueError('Unexpected sparse chunk type')
            position += length
    actual = []
    for name in PARTITIONS:
        record = {'name': name, 'size': states[name]['size'], 'sha256': states[name]['hash'].hexdigest()}
        if (record['size'] != records[name]['size'] or record['sha256'] != records[name]['sha256']):
            raise ValueError('Sparse output logical image hash mismatch: ' + name)
        actual.append(record)
    return {'schema': 1, 'all_nine_logical_image_hashes_verified': True,
            'image_padding_and_avb_tails_included': True, 'allocated_dont_care_rejected': True,
            'unallocated_sparse_gaps_not_assumed_zero': True, 'images': actual,
            'sparse_size_bytes': sparse['size_bytes'], 'super_sha256': file_digest(path),
            'phone_accessed': False, 'runtime_verified': False}


def payload_smoke_test():
    """Exercise real lpmake output and corruption gates with tiny public fixtures."""
    executable, env, _ = verified_tool('.tools/aosp-host', 'host-tools.json')
    geometry = Geometry(super_size=16 * 1024**2, group_size=12 * 1024**2)
    rejected = []
    with tempfile.TemporaryDirectory(prefix='molcer-payload-smoke-') as directory:
        root = pathlib.Path(directory)
        records = {}
        for index, name in enumerate(PARTITIONS):
            image = root / (name + '.img')
            image.write_bytes(bytes([index]) * 16384)
            records[name] = {'name': name, 'path': str(image), 'size': image.stat().st_size,
                             'sha256': file_digest(image), 'identity_source': 'synthetic-smoke-data'}
        output = root / 'super.img'
        build_image(records, geometry, executable, env, output, reserve=16 * 1024**2)
        result = verify_super_payload(output, records, geometry)
        original = output.read_bytes()
        with output.open('rb') as stream:
            data, known, prefix = read_sparse_window(stream)
        metadata = inspect_window(data, known, prefix)['metadata_copies'][0]
        ranges = logical_extents(data, metadata, records, geometry)
        # Real zero-valued image bytes must hash exactly, not be treated as gaps.
        if records[PARTITIONS[0]]['sha256'] != hashlib.sha256(b'\0' * 16384).hexdigest():
            raise ValueError('Zero-image smoke fixture changed')
        chunk_count = struct.unpack_from('<I', original, 20)[0]
        at, logical, selected = 28, 0, None
        for _ in range(chunk_count):
            kind, _, count, total = struct.unpack_from('<2H2I', original, at)
            length = count * geometry.block_size
            if kind in (0xcac1, 0xcac2) and any(logical < end and logical + length > start for start, end, _, _ in ranges):
                selected = (at, kind, count, total)
                break
            at += total
            logical += length
        if selected is None:
            raise ValueError('No allocated sparse data fixture found')
        at, kind, count, total = selected
        altered = bytearray(original)
        altered[at + 12] ^= 1
        variants = [('changed logical data', bytes(altered)), ('truncated output', original[:-1]),
                    ('allocated DONT_CARE', original[:at] + struct.pack('<2H2I', 0xcac3, 0, count, 12) + original[at + total:])]
        for label, contents in variants:
            output.write_bytes(contents)
            try:
                verify_super_payload(output, records, geometry)
            except (ValueError, struct.error):
                rejected.append(label)
            else:
                raise ValueError('Malformed sparse smoke fixture was accepted: ' + label)
        output.write_bytes(original)
        # The metadata parser checks its checksums separately. Directly mutate a
        # validated table here to exercise the independent extent overlap gate.
        overlapping = bytearray(data)
        table = metadata['offset'] + metadata['header_size']
        ext_start, extent_count, stride = struct.unpack_from('<3I', data, metadata['offset'] + 92)
        if extent_count < 2 or stride != 24:
            raise ValueError('Expected multiple extents in the smoke fixture')
        first_target = struct.unpack_from('<Q', data, table + ext_start + 12)[0]
        struct.pack_into('<Q', overlapping, table + ext_start + stride + 12, first_target)
        try:
            logical_extents(overlapping, metadata, records, geometry)
        except ValueError:
            rejected.append('overlapping logical extents')
        else:
            raise ValueError('Overlapping logical extent fixture was accepted')
    return {'schema': 1, 'status': 'independent-super-payload-smoke-passed',
            'synthetic_inputs': True, 'rejected_corruptions': rejected,
            'zero_image_hash_verified': True, 'all_nine_logical_image_hashes_verified': True,
            'temporary_files_removed': True, 'phone_accessed': False,
            'runtime_verified': False, 'valid_output': result}


def prepare_radio():
    archive = pathlib.Path('work/eu-radio-reference.zip')
    cache = read_json('radio-cache.json')
    if cache.get('schema') != 1:
        raise ValueError('Expected the pinned durable EU radio cache')
    with archive.open('xb') as output:
        download_asset(cache['asset_id'], cache['size'], cache['sha256'], output)
    try:
        run_script('integrate_radio.py', '--artifact', archive)
    finally:
        archive.unlink()
    report = read_json('reports/rom-radio-integration.json')
    if (report.get('phone_accessed') is not False or report.get('installers_executed') is not False
            or len(report['files']) != 2
            or {r['partition'] for r in report['files']} != {'modem', 'modemfirmware'}):
        raise ValueError('Unexpected EU radio integration scope')
    for record in report['files']:
        source = pathlib.Path('out/rom-radio/images', record['partition'] + '.img')
        if source.stat().st_size != record['size'] or file_digest(source) != record['sha256']:
            raise ValueError('Staged EU radio image changed')
        os.link(source, pathlib.Path('work/images', source.name))
    return report


def publish_bundle(manifest, files, reports):
    commit = os.environ['GITHUB_SHA']
    run_id, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    if (not re.fullmatch(r'[0-9a-f]{40}', commit)
            or not re.fullmatch(r'[0-9]+', run_id) or not re.fullmatch(r'[0-9]+', attempt)):
        raise ValueError('Unexpected Actions publishing identity')
    tag = f'molcer-assembled-{commit[:12]}-{run_id}-{attempt}'
    output = pathlib.Path('out/assembled-candidate')
    output.mkdir(parents=True)
    note = output / 'NOT-INSTALLABLE.txt'
    note.write_text(NOTE, encoding='utf-8')
    path = pathlib.Path('reports/assembled-candidate-manifest.json')
    manifest.update({'assembly_commit': commit, 'run_id': run_id, 'run_attempt': attempt,
                     'release_tag': tag, 'release_draft': True, 'uploaded_images': [], 'small_assets': []})
    save_json(path, manifest)
    try:
        gh('release', 'create', tag, '--repo', REPOSITORY, '--draft', '--target', commit,
           '--title', 'Molcer OS assembled offline candidate - NOT INSTALLABLE', '--notes-file', note)
        release = draft_release(tag)
        if release.get('draft') is not True:
            raise ValueError('Expected a draft assembled candidate release')
        manifest.update({'release_id': release['id'], 'release_url': release['html_url']})
        for source, identity in files:
            if shutil.disk_usage('work').free < CHUNK_BYTES + RESERVE:
                raise ValueError('Need one bounded upload chunk plus reserve')
            record = {'name': identity['name'], 'size': identity['size'],
                      'sha256': identity['sha256'], 'chunks': []}
            manifest['uploaded_images'].append(record)
            with tempfile.TemporaryDirectory(prefix='assembly-upload-', dir='work') as directory:
                iterator = stream_chunks(source, directory, 'NOT-INSTALLABLE-' + identity['name'] + '.img')
                while True:
                    try:
                        chunk_path, chunk = next(iterator)
                    except StopIteration as finished:
                        if finished.value != {'size': identity['size'], 'sha256': identity['sha256']}:
                            raise ValueError('Output image changed during upload')
                        break
                    try:
                        chunk.update(upload_asset(tag, chunk_path, chunk['sha256'], chunk['size']))
                        record['chunks'].append(chunk)
                        save_json(path, manifest)
                    except BaseException:
                        iterator.close()
                        raise
        for source in [note, *reports]:
            if source.stat().st_size > 1024**2:
                raise ValueError('Small assembly evidence exceeds 1 MiB')
            item = {'asset_name': source.name, 'size': source.stat().st_size, 'sha256': file_digest(source)}
            item.update(upload_asset(tag, source, item['sha256'], item['size']))
            manifest['small_assets'].append(item)
        manifest['status'] = 'offline-assembled-candidate-awaiting-device-and-installer-validation'
        save_json(path, manifest)
        upload_asset(tag, path, file_digest(path), path.stat().st_size)
    except BaseException as error:
        manifest.update({'status': 'incomplete-assembly-upload-not-installable', 'error_type': type(error).__name__})
        save_json(path, manifest)
        raise
    return manifest


def assemble(config_path):
    config = read_json(config_path)
    if (config.get('schema') != 1 or config.get('build_enabled') is not True
            or not re.fullmatch(r'[0-9a-f]{40}', config.get('source_commit', ''))
            or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY):
        raise ValueError('Reviewed assembly configuration and repository identity are required')
    policy = read_json('radio-policy.json')
    if policy.get('phone_access_allowed') is not False or policy.get('installation_allowed') is not False:
        raise ValueError('No-phone/no-installation policy is required')
    for directory in ('work/images', 'work/stock-avb', 'work/assembly', 'work/candidate-images',
                      'out/avb-signed', 'out/metadata-precheck', 'out/super',
                      'out/assembled-candidate', 'out/rom-radio'):
        if pathlib.Path(directory).exists():
            raise ValueError('Assembly requires a fresh output directory: ' + directory)
    pathlib.Path('work/assembly').mkdir(parents=True)
    pathlib.Path('reports').mkdir(exist_ok=True)
    if shutil.disk_usage('work').free < 28 * 1024**3:
        raise ValueError('Assembly requires at least 28 GiB measured free disk')
    requests, signatures = pinned_input(config['signing_requests']), pinned_input(config['signatures'])
    bundle, responses = read_json(requests), read_json(signatures)
    if responses.get('requests_sha256') != config['signing_requests']['sha256']:
        raise ValueError('Signatures are bound to a different request file')
    for source, name in ((requests, 'signing-requests.json'), (signatures, 'signatures.json')):
        shutil.copyfile(source, pathlib.Path('work/assembly', name))
    selected = config['candidate_manifest']
    if type(selected['size']) is not int or not 0 < selected['size'] <= 1024**2:
        raise ValueError('Candidate manifest must be a bounded JSON asset')
    data = io.BytesIO()
    download_asset(selected['asset_id'], selected['size'], selected['sha256'], data)
    candidate = json.loads(data.getvalue())
    images = validate_manifest(candidate, config, bundle)
    pathlib.Path('work/assembly/candidate-manifest.json').write_bytes(data.getvalue())
    # Reject invalid public signatures before downloading multi-GB source data.
    run_script('prepare_avb.py', 'apply', '--requests', requests, '--signatures', signatures,
               '--output', 'out/metadata-precheck')
    run_script('download_base.py')
    verified, base = read_json('reports/verified-base.json'), read_json('base.json')
    if (verified.get('full_archive_hash_verified') is not True or verified.get('sha256') != base['sha256']
            or not all(verified['checks'].values())):
        raise ValueError('Fresh source authentication did not pass')
    inspection = read_json('reports/packaging-inspection.json')
    names, expected = selected_partitions(inspection, verified)
    extract('work/base.zip', names + ['product'], 'work/images')
    shutil.copyfile('reports/extracted-images.json', 'reports/assembly-source-images.json')
    extract('work/base.zip', ['vbmeta', 'vbmeta_system'], 'work/stock-avb')
    shutil.copyfile('reports/extracted-images.json', 'reports/assembly-stock-avb.json')
    pathlib.Path('work/base.zip').unlink()
    validation = validate_bundle(requests, stock_dir='work/stock-avb')
    save_json(pathlib.Path('reports/assembly-signing-scope.json'), validation)
    pathlib.Path('work/candidate-images').mkdir()
    restore_images(images, 'work/candidate-images')
    os.link('work/candidate-images/init_boot.img', 'work/images/init_boot.img')
    radio = prepare_radio()
    run_script('prepare_avb.py', 'apply', '--requests', requests, '--signatures', signatures,
               '--images', 'work/images', '--output', 'out/avb-signed')
    avb_path = pathlib.Path('out/avb-signed/avb-signature-verification.json')
    avb = read_json(avb_path)
    if (avb.get('full_partition_chain_verified') is not True or avb.get('metadata_signatures_verified') is not True
            or avb.get('avb_flags') != 0 or avb.get('requests_sha256') != config['signing_requests']['sha256']):
        raise ValueError('Complete AVB verification is mandatory before super construction')
    for name in ('vbmeta', 'vbmeta_system'):
        os.link(pathlib.Path('out/avb-signed', name + '.img'), pathlib.Path('work/images', name + '.img'))
    run_script('build_super.py', '--images', 'work/images', '--product', 'work/candidate-images/product.img',
               '--product-record', requests, '--output', 'out/super/super.img', '--report', 'reports/super-build.json')
    super_report = read_json('reports/super-build.json')
    if super_report.get('status') != 'offline-sparse-super-candidate-verified':
        raise ValueError('Super image verification did not complete')
    pathlib.Path('work/images/product.img').unlink()
    os.link('work/candidate-images/product.img', 'work/images/product.img')
    wanted = set(names) | CUSTOM | {'modem', 'modemfirmware'}
    found = {p.stem for p in pathlib.Path('work/images').glob('*.img')}
    if found != wanted or any(protected_partition(n) or n == 'countrycode' for n in found):
        raise ValueError('Final image set violates the explicit partition policy')
    expected_final = {name: expected[name] for name in names}
    expected_final.update({r['partition']: (r['size'], r['sha256']) for r in bundle['prepared_images']})
    expected_final.update({name: (r['size'], r['sha256']) for name, r in avb['images'].items()})
    expected_final.update({r['partition']: (r['size'], r['sha256']) for r in radio['files']})
    if set(expected_final) != found:
        raise ValueError('Every final partition needs an authenticated image binding')
    inventory, uploads = [], []
    for name in sorted(found):
        path = pathlib.Path('work/images', name + '.img')
        identity = {'name': name, 'size': path.stat().st_size, 'sha256': file_digest(path)}
        if (identity['size'], identity['sha256']) != expected_final[name]:
            raise ValueError('Final image differs from its authenticated source/signature binding: ' + name)
        inventory.append(identity)
        if name not in PARTITIONS:
            uploads.append((path, identity))
    super_path = pathlib.Path('out/super/super.img')
    super_identity = {'name': 'super', 'size': super_path.stat().st_size, 'sha256': file_digest(super_path)}
    if (super_identity['size'] != super_report['output']['size_bytes']
            or super_identity['sha256'] != super_report['output']['sha256']):
        raise ValueError('Super file changed after its geometry verification')
    payload_report = verify_super_payload(super_path, {r['name']: r for r in inventory if r['name'] in PARTITIONS},
                                          Geometry(**super_report['geometry']))
    payload_path = pathlib.Path('reports/super-payload-verification.json')
    save_json(payload_path, payload_report)
    uploads.append((super_path, super_identity))
    manifest = {'schema': 1, 'status': 'uploading-offline-assembled-candidate', 'repository': REPOSITORY,
                'device': 'xuanyuan', 'hardware_variant': 'global', 'rom_name': 'Molcer OS',
                'source_commit': config['source_commit'], 'candidate_manifest_sha256': selected['sha256'],
                'requests_sha256': file_digest(requests), 'signatures_sha256': file_digest(signatures),
                'base_archive_sha256': base['sha256'], 'all_partition_images': inventory,
                'super': super_identity, 'full_partition_chain_verified': True,
                'offline_validation': {'avb': True, 'super': True, 'hashes': True},
                'validation_report_sha256': {'avb-signature-verification.json': file_digest(avb_path),
                                            'super-build.json': file_digest('reports/super-build.json'),
                                            'super-payload-verification.json': file_digest(payload_path),
                                            'rom-radio-integration.json': file_digest('reports/rom-radio-integration.json')},
                'excluded_china_base_partitions': sorted(EXCLUDED_CN),
                'preserved_device_partition_exclusions': sorted(n for n in expected if protected_partition(n)),
                'eu_radio_source_archive_sha256': radio['source_archive_sha256'],
                'chunk_size_limit': CHUNK_BYTES, 'avb_flags': 0,
                'phone_accessed': False, 'private_key_accessed': False, 'installer_included': False,
                'installation_allowed': False, 'installable_rom_produced': False, 'runtime_verified': False,
                'device_gpt_capacity_verified': False}
    report = publish_bundle(manifest, uploads, [pathlib.Path('work/assembly/signing-requests.json'),
                            pathlib.Path('work/assembly/signatures.json'), avb_path,
                            pathlib.Path('reports/super-build.json'), payload_path,
                            pathlib.Path('reports/rom-radio-integration.json')])
    print(json.dumps({'status': report['status'], 'release_url': report['release_url']}))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='assemble-build.json')
    parser.add_argument('--smoke-test', action='store_true')
    parser.add_argument('--report', default='reports/assembly-payload-smoke.json')
    args = parser.parse_args()
    if args.smoke_test:
        result = payload_smoke_test()
        save_json(pathlib.Path(args.report), result)
        print(json.dumps({'status': result['status']}))
    else:
        assemble(args.config)


if __name__ == '__main__':
    main()
