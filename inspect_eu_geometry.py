"""Inspect authenticated EU sparse-super metadata without device operations."""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import zipfile

SOURCE_SHA256 = '9c1eced1591d5ad28998e7731a0555ce824074fdfe2061e7cad43b59da835157'
SOURCE_ROM = 'xiaomi.eu OS3.0.314.0.WOACNXM'
MEMBER = 'images/super.img.0'
WINDOW_SIZE = 1024**2
NAME = re.compile(r'[A-Za-z0-9_-]+')


def digest(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_sparse_window(stream, window_size=WINDOW_SIZE):
    """Materialize only the leading metadata window, marking don't-care holes."""
    consumed = 0
    limit = window_size + 1024**2

    def read_exact(size):
        nonlocal consumed
        if size < 0 or consumed + size > limit:
            raise ValueError('Sparse prefix input bound exceeded')
        data = stream.read(size)
        consumed += len(data)
        if len(data) != size:
            raise ValueError('Truncated sparse prefix')
        return data

    raw = read_exact(28)
    magic, major, minor, file_header, chunk_header, block, blocks, chunks, checksum = struct.unpack('<I4H4I', raw)
    if (magic != 0xed26ff3a or major != 1 or not 28 <= file_header <= 4096
            or not 12 <= chunk_header <= 4096 or block < 512 or block > 65536
            or block & (block - 1) or not blocks or not chunks):
        raise ValueError('Invalid sparse image header')
    expanded_size = block * blocks
    if expanded_size < window_size:
        raise ValueError('Sparse image cannot contain expected metadata window')
    read_exact(file_header - 28)
    window, known = bytearray(window_size), bytearray(window_size)
    logical, processed = 0, 0
    for _ in range(min(chunks, 100000)):
        h = read_exact(chunk_header)
        kind, _, chunk_blocks, total_size = struct.unpack_from('<2H2I', h)
        length = chunk_blocks * block
        if total_size < chunk_header or logical + length > expanded_size:
            raise ValueError('Sparse chunk exceeds declared expanded image')
        take = min(length, max(0, window_size - logical))
        if kind == 0xcac1:
            if total_size != chunk_header + length or not length:
                raise ValueError('Invalid sparse raw chunk')
            data = read_exact(take)
            window[logical:logical + take] = data
            known[logical:logical + take] = b'\1' * take
        elif kind == 0xcac2:
            if total_size != chunk_header + 4 or not length:
                raise ValueError('Invalid sparse fill chunk')
            word = read_exact(4)
            window[logical:logical + take] = (word * ((take + 3) // 4))[:take]
            known[logical:logical + take] = b'\1' * take
        elif kind == 0xcac3:
            if total_size != chunk_header or not length:
                raise ValueError('Invalid sparse dont-care chunk')
        elif kind == 0xcac4:
            if total_size != chunk_header + 4 or length:
                raise ValueError('Invalid sparse CRC chunk')
            read_exact(4)
        else:
            raise ValueError('Unknown sparse chunk kind')
        processed += 1
        logical += length
        if logical >= window_size:
            break
    if logical < window_size:
        raise ValueError('Sparse metadata window incomplete')
    return bytes(window), bytes(known), {
        'major_version': major, 'minor_version': minor, 'block_size': block,
        'total_blocks': blocks, 'expanded_image_bytes': expanded_size,
        'total_chunks': chunks, 'prefix_chunks_processed': processed,
        'member_uncompressed_bytes_read': consumed,
        'sparse_image_checksum_field': checksum, 'whole_sparse_crc_verified': False}


def checked_slice(data, known, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError('LP metadata exceeds bounded prefix')
    if known[offset:offset + size] != b'\1' * size:
        raise ValueError('LP metadata overlaps sparse dont-care bytes')
    return data[offset:offset + size]


def geometry(data, known, offset):
    prefix = checked_slice(data, known, offset, 52)
    magic, size, checksum, maximum, slots, block = struct.unpack('<2I32s3I', prefix)
    if (magic != 0x616c4467 or size != 52 or maximum < 512 or maximum % 512
            or not 1 <= slots <= 8 or block < 512 or block & (block - 1)):
        raise ValueError('Invalid LP geometry')
    hashed = prefix[:8] + b'\0' * 32 + prefix[40:]
    if hashlib.sha256(hashed).digest() != checksum:
        raise ValueError('LP geometry checksum mismatch')
    return {'metadata_max_size': maximum, 'metadata_slot_count': slots,
            'logical_block_size': block, 'sha256': hashlib.sha256(prefix).hexdigest(),
            'checksum_verified': True}


def lp_name(raw):
    name, separator, padding = raw.partition(b'\0')
    if separator and any(padding):
        raise ValueError('Nonzero LP name padding')
    text = name.decode('ascii')
    if not NAME.fullmatch(text):
        raise ValueError('Invalid LP name')
    return text


def metadata(data, known, offset, maximum):
    prefix = checked_slice(data, known, offset, 128)
    magic, major, minor, header_size = struct.unpack_from('<I2HI', prefix)
    if (magic != 0x414c5030 or major != 10 or minor > 2
            or header_size != (256 if minor >= 2 else 128)):
        raise ValueError('Unsupported LP metadata header')
    header = checked_slice(data, known, offset, header_size)
    stored_header_hash = header[12:44]
    hash_input = header[:12] + b'\0' * 32 + header[44:]
    if hashlib.sha256(hash_input).digest() != stored_header_hash:
        raise ValueError('LP header checksum mismatch')
    tables_size = struct.unpack_from('<I', header, 44)[0]
    if header_size + tables_size > maximum:
        raise ValueError('LP tables exceed metadata slot')
    tables = checked_slice(data, known, offset + header_size, tables_size)
    if hashlib.sha256(tables).digest() != header[48:80]:
        raise ValueError('LP table checksum mismatch')
    definitions = {}
    ranges = []
    for at, name, expected_size in [(80, 'partitions', 52), (92, 'extents', 24),
                                    (104, 'groups', 48), (116, 'block_devices', 64)]:
        start, count, size = struct.unpack_from('<3I', header, at)
        end = start + count * size
        if size != expected_size or count > 10000 or end > tables_size:
            raise ValueError('Invalid LP table bounds')
        if count:
            if any(start < old_end and end > old_start for old_start, old_end in ranges):
                raise ValueError('Overlapping LP tables')
            ranges.append((start, end))
        definitions[name] = [tables[start + i * size:start + (i + 1) * size] for i in range(count)]
    groups = []
    for raw in definitions['groups']:
        name, flags, maximum_size = struct.unpack('<36sIQ', raw)
        groups.append({'name': lp_name(name), 'flags': flags, 'maximum_size_bytes': maximum_size})
    devices = []
    for raw in definitions['block_devices']:
        first, alignment, alignment_offset, size, name, flags = struct.unpack('<Q2IQ36sI', raw)
        if first * 512 >= size or size % 512 or alignment_offset > alignment:
            raise ValueError('Invalid LP block device bounds')
        devices.append({'name': lp_name(name), 'first_logical_sector': first,
                        'alignment_bytes': alignment, 'alignment_offset_bytes': alignment_offset,
                        'declared_size_bytes': size, 'flags': flags})
    if len({g['name'] for g in groups}) != len(groups) or len({d['name'] for d in devices}) != len(devices):
        raise ValueError('Duplicate LP group or device')
    # Validate partition references without reconstructing filesystem contents.
    partition_names = []
    for raw in definitions['partitions']:
        name, attributes, first, count, group = struct.unpack('<36s4I', raw)
        if group >= len(groups) or first + count > len(definitions['extents']):
            raise ValueError('Invalid LP partition table reference')
        partition_names.append(lp_name(name))
    if len(set(partition_names)) != len(partition_names):
        raise ValueError('Duplicate LP partition')
    for raw in definitions['extents']:
        sectors, kind, target, source = struct.unpack('<QIQI', raw)
        if kind == 0:
            if source >= len(devices) or (target + sectors) * 512 > devices[source]['declared_size_bytes']:
                raise ValueError('LP extent outside declared device')
        elif kind != 1:
            raise ValueError('Unknown LP extent kind')
    return {'major_version': major, 'minor_version': minor,
            'header_size': header_size, 'header_checksum_verified': True,
            'table_checksum_verified': True, 'tables_size': tables_size,
            'header_flags': struct.unpack_from('<I', header, 128)[0] if minor >= 2 else 0,
            'groups': groups, 'block_devices': devices,
            'partition_names': partition_names,
            'extent_count': len(definitions['extents']),
            'metadata_sha256': hashlib.sha256(header + tables).hexdigest()}


def inspect_window(data, known, sparse):
    primary = geometry(data, known, 4096)
    backup = geometry(data, known, 8192)
    if primary != backup:
        raise ValueError('LP primary and backup geometry disagree')
    slots, maximum = primary['metadata_slot_count'], primary['metadata_max_size']
    copies = []
    for backup_copy in (False, True):
        for slot in range(slots):
            offset = 12288 + (slot + (slots if backup_copy else 0)) * maximum
            result = metadata(data, known, offset, maximum)
            result.update({'slot': slot, 'copy': 'backup' if backup_copy else 'primary', 'offset': offset})
            devices = result['block_devices']
            if (len(devices) != 1 or devices[0]['name'] != 'super'
                    or devices[0]['declared_size_bytes'] != sparse['expanded_image_bytes']):
                raise ValueError('Expected one super device matching sparse expanded length')
            copies.append(result)
    for slot in range(slots):
        if copies[slot]['metadata_sha256'] != copies[slot + slots]['metadata_sha256']:
            raise ValueError('LP primary and backup metadata differ')
    initial = copies[0]
    budgets = {g['name']: g['maximum_size_bytes'] for g in initial['groups'] if g['maximum_size_bytes']}
    if not budgets or len(set(budgets.values())) != 1:
        raise ValueError('Expected equal nonzero A/B reference group budgets')
    return {'sparse': sparse, 'geometry': primary, 'metadata_copies': copies,
            'reference_super_declared_size_bytes': initial['block_devices'][0]['declared_size_bytes'],
            'reference_group_budgets': budgets,
            'conservative_single_group_image_budget_bytes': min(budgets.values()),
            'budget_excludes_additional_alignment_and_rebuilt_avb_overhead': True,
            'actual_phone_gpt_capacity_verified': False,
            'target_android17_group_fit_verified': False,
            'scope': 'Geometry declared by the exact EU package. This is not a measurement of the phone GPT or permission to repartition. Group maxima are limits, not simultaneous allocated usage.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='eu-radio-source.json')
    parser.add_argument('--archive')
    parser.add_argument('--output', default='reports/eu-super-geometry.json')
    args = parser.parse_args()
    config = json.loads(pathlib.Path(args.config).read_text(encoding='utf-8'))
    if (config['device'] != 'xuanyuan' or config['hardware_variant'] != 'global'
            or config['rom'] != SOURCE_ROM or config['sha256'] != SOURCE_SHA256):
        raise ValueError('Expected exact owner-selected EU release configuration')
    archive = pathlib.Path(args.archive or pathlib.Path('work') / config['archive'])
    if archive.stat().st_size != config['size'] or digest(archive) != SOURCE_SHA256:
        raise ValueError('EU archive length/hash differs from published release')
    with zipfile.ZipFile(archive) as z:
        if z.namelist().count(MEMBER) != 1:
            raise ValueError('Expected one exact EU sparse-super member')
        info = z.getinfo(MEMBER)
        with z.open(info) as stream:
            data, known, sparse = read_sparse_window(stream)
    result = inspect_window(data, known, sparse)
    result.update({'source_rom': SOURCE_ROM, 'source_archive_sha256': SOURCE_SHA256,
                   'full_archive_sha256_verified': True, 'source_member': MEMBER,
                   'member_size': info.file_size, 'member_zip_crc32': f'{info.CRC:08x}',
                   'member_crc_verified_separately': False,
                   'source_authentication': 'Entire archive SHA256 verified before reading its bounded member prefix.',
                   'phone_accessed': False, 'source_modified': False})
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(out), 'source_verified': True,
                      'super_declared_bytes': result['reference_super_declared_size_bytes'],
                      'group_budgets': result['reference_group_budgets'], 'phone_accessed': False}))


if __name__ == '__main__':
    main()
