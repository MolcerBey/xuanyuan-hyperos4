"""Compare offline radio images; binary identity is not protocol/runtime compatibility."""
import argparse
import hashlib
import json
import pathlib
import re
import struct

PARTITIONS = ('modem', 'modemfirmware')
MAX_FILES = 10000
MAX_SCAN = 256 * 1024**2
MAX_VERSIONS = 50
MAX_CHANGED = 3000
VERSION = re.compile(
    rb'(?:QC_IMAGE_VERSION_STRING|IMAGE_VARIANT_STRING|OEM_IMAGE_VERSION_STRING)'
    rb'[\x00:= ]{0,8}[\x20-\x7e]{1,200}|'
    rb'(?<![A-Za-z0-9_])MPSS\.[A-Za-z0-9_.-]{1,190}|'
    rb'BASEBAND[\x00:= _.-]{1,8}[A-Za-z0-9_.-]{1,190}'
)
TURK_TELEKOM = 'TurkTelekom/Commercial/TR/mcfg_sw.mbn'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fat_header(data, image_size):
    result = {'image_file_bytes': image_size, 'gpt_partition_capacity_bytes': None,
              'partition_size_fit_verified': False, 'filesystem_allocation_integrity_verified': False}
    if len(data) < 512 or data[510:512] != b'\x55\xaa':
        return {**result, 'bpb_recognized': False}
    bps = struct.unpack_from('<H', data, 11)[0]
    spc = data[13]
    reserved = struct.unpack_from('<H', data, 14)[0]
    fats = data[16]
    root_entries = struct.unpack_from('<H', data, 17)[0]
    sectors = struct.unpack_from('<H', data, 19)[0] or struct.unpack_from('<I', data, 32)[0]
    fat_sectors = struct.unpack_from('<H', data, 22)[0]
    label = data[54:62].decode('ascii', errors='replace').strip()
    if bps not in (512, 1024, 2048, 4096) or not spc or spc & (spc - 1) or not sectors or not reserved or not fats:
        return {**result, 'bpb_recognized': False}
    logical = bps * sectors
    root_sectors = (root_entries * 32 + bps - 1) // bps
    data_sectors = sectors - (reserved + fats * fat_sectors + root_sectors)
    clusters = max(0, data_sectors) // spc
    result.update({'bpb_recognized': True, 'bytes_per_sector': bps, 'sectors_per_cluster': spc,
        'total_sectors': sectors, 'declared_logical_volume_bytes': logical,
        'fat_label': label, 'fat16_header_cluster_count': clusters,
        'image_shorter_than_declared_volume': image_size < logical,
        'size_interpretation': 'BPB volume length and stored image length are not GPT partition capacity. A shorter image may omit a free tail; this comparison neither proves corruption nor proves partition fit.'})
    return result


def elf_header(data):
    if len(data) < 20 or data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    endian = '<' if data[5] == 1 else '>'
    return {'class_bits': 32 if data[4] == 1 else 64, 'endianness': 'little' if data[5] == 1 else 'big',
        'machine': struct.unpack_from(endian + 'H', data, 18)[0],
        'elf_type': struct.unpack_from(endian + 'H', data, 16)[0], 'abi_version': data[8]}


def version_strings(path):
    found = set()
    scanned = 0
    tail = b''
    with path.open('rb') as stream:
        while scanned < MAX_SCAN:
            chunk = stream.read(min(1024**2, MAX_SCAN - scanned))
            if not chunk:
                break
            scanned += len(chunk)
            blob = tail + chunk
            # Keep a suffix until the next chunk to avoid recording a truncated
            # identifier solely because a chunk ended in its middle.
            complete_end = len(blob) if not chunk or scanned == path.stat().st_size else max(0, len(blob) - 512)
            for match in VERSION.finditer(blob):
                if match.end() <= complete_end:
                    found.add(match.group().replace(b'\0', b' ').decode('ascii')[:200])
                    if len(found) >= MAX_VERSIONS:
                        return {'identifiers': sorted(found), 'capture_limit_reached': True, 'bytes_scanned': scanned}
            tail = blob[-1024:]
    return {'identifiers': sorted(found), 'bytes_scanned': scanned,
        'scan_size_limit_reached': path.stat().st_size > scanned, 'capture_limit_reached': False}


def inventory(root):
    root = pathlib.Path(root)
    result = {'images': {}, 'files': {}, 'versions': [], 'elf_headers': [],
              'turk_telekom_profiles': [], 'profile_indexes': [], 'errors': [], 'omitted': []}
    for partition in PARTITIONS:
        image = root / 'images' / (partition + '.img')
        mount = root / ('mounted_' + partition)
        if not image.is_file() or not mount.is_dir():
            raise ValueError('Missing image or mounted source for ' + str(root / partition))
        with image.open('rb') as stream:
            header = stream.read(512)
        result['images'][partition] = {**fat_header(header, image.stat().st_size), 'sha256': digest(image)}
        resolved = mount.resolve()
        count = 0
        for path in sorted(mount.rglob('*')):
            if path.is_symlink():
                result['omitted'].append({'path': str(path.relative_to(mount)), 'reason': 'symlink not followed'})
                continue
            if not path.is_file() or not path.resolve().is_relative_to(resolved):
                continue
            count += 1
            if count > MAX_FILES:
                raise ValueError('Radio file inventory limit exceeded')
            relative = partition + '/' + path.relative_to(mount).as_posix()
            try:
                record = {'size': path.stat().st_size, 'sha256': digest(path)}
                result['files'][relative] = record
                if relative.casefold().endswith(TURK_TELEKOM.casefold()):
                    result['turk_telekom_profiles'].append({'path': relative, **record})
                if path.suffix.lower() in ('.mdt', '.elf'):
                    with path.open('rb') as stream:
                        parsed = elf_header(stream.read(64))
                    if parsed:
                        result['elf_headers'].append({'path': relative, **parsed})
                if path.suffix.lower() in ('.mbn', '.mdt', '.elf', '.txt') or re.fullmatch(r'\.b\d+', path.suffix.lower()):
                    identifiers = version_strings(path)
                    if identifiers['identifiers'] or identifiers.get('scan_size_limit_reached') or identifiers['capture_limit_reached']:
                        result['versions'].append({'path': relative, **identifiers})
                if path.suffix.lower() == '.txt' and ('mcfg' in relative.lower() or path.name == 'oem_sw.txt') and record['size'] <= 4 * 1024**2:
                    text = path.read_text(errors='replace')
                    matches = [line.strip()[:500] for line in text.splitlines() if TURK_TELEKOM.casefold() in line.casefold()]
                    if matches:
                        result['profile_indexes'].append({'path': relative, 'references': matches[:20], 'references_truncated': len(matches) > 20})
            except (OSError, ValueError) as exc:
                result['errors'].append({'path': relative, 'error': str(exc)[:300]})
    return result


def compare(eu, target):
    shared = sorted(eu['files'].keys() & target['files'].keys())
    changed = [p for p in shared if eu['files'][p]['sha256'] != target['files'][p]['sha256']]
    profiles = {}
    for name, source in [('eu', eu), ('target', target)]:
        profiles[name] = source['turk_telekom_profiles']
    hashes = {name: sorted(x['sha256'] for x in files) for name, files in profiles.items()}
    return {'evidence_scope': 'Offline file structures, hashes and literal identifiers only; proprietary firmware protocols and active profile are not tested',
        'conclusion': 'not-proven-full-compatible', 'runtime_verified': False,
        'selected_profile_verified': False, 'vendor_modem_protocol_compatibility_verified': False,
        'rollback_compatibility_verified': False, 'partition_capacity_verified': False,
        'phone_accessed': False, 'sources_modified': False,
        'shared_file_count': len(shared), 'identical_shared_file_count': len(shared) - len(changed),
        'changed_shared_file_count': len(changed),
        'changed_shared_files': [{'path': p, 'eu': eu['files'][p], 'target': target['files'][p]} for p in changed[:MAX_CHANGED]],
        'changed_list_truncated': len(changed) > MAX_CHANGED,
        'only_eu': sorted(eu['files'].keys() - target['files'].keys())[:MAX_CHANGED],
        'only_target': sorted(target['files'].keys() - eu['files'].keys())[:MAX_CHANGED],
        'turk_telekom_profile_hashes_equal': bool(hashes['eu']) and hashes['eu'] == hashes['target'],
        'eu': eu, 'target': target,
        'interpretation': 'Different firmware bytes or version identifiers are not alone proof of incompatibility. Identical hashes or matching ELF architecture are not proof of full interoperability.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--eu', default='work/compat/eu')
    parser.add_argument('--target', default='work/compat/target')
    parser.add_argument('--output', default='reports/eu-molcer-radio-compatibility.json')
    args = parser.parse_args()
    result = compare(inventory(args.eu), inventory(args.target))
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('conclusion', 'shared_file_count', 'identical_shared_file_count', 'changed_shared_file_count', 'turk_telekom_profile_hashes_equal', 'runtime_verified')}), flush=True)
    if result['eu']['errors'] or result['target']['errors'] or result['eu']['omitted'] or result['target']['omitted']:
        raise ValueError('Incomplete inventory; examine report before drawing conclusions')


if __name__ == '__main__':
    main()
