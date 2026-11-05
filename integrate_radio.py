"""Stage the selected, hash-pinned EU global radio pair into Molcer OS build inputs.

This is offline packaging only: it never executes an installer or accesses a phone.
"""
import argparse
import contextlib
import hashlib
import json
import pathlib
import re
import stat
import zipfile


SOURCE_ROM = 'xiaomi.eu OS3.0.314.0.WOACNXM'
SOURCE_SHA256 = '9c1eced1591d5ad28998e7731a0555ce824074fdfe2061e7cad43b59da835157'
APPROVED = {
    'images/modem.img': ('NOT-INSTALLABLE-modem.img', 'modem'),
    'images/modemfirmware_ww.img': ('NOT-INSTALLABLE-modemfirmware.img', 'modemfirmware'),
}
ARTIFACT_NAMES = {entry[0] for entry in APPROVED.values()} | {
    'radio-source.json', 'SHA256SUMS.txt', 'NOT-INSTALLABLE.txt',
}
NOTE = (
    'Molcer OS radio build inputs: common modem.img and global modemfirmware_ww.img '
    'from Xiaomi.eu OS3.0.314.0.WOACNXM. The WW source is packaged as images/modemfirmware.img. '
    'Both images are unchanged and verified against the pinned EU extraction report. '
    'This directory is NOT an installable ROM or standalone flashing package. '
    'Android16-to-Android17 vendor/IMS compatibility, boot and network behavior remain unverified. '
    'No phone was accessed and no installer was executed.\n'
)


def validate_selection(policy, config, reference):
    if policy.get('device') != 'xuanyuan' or policy.get('hardware_variant') != 'global':
        raise ValueError('Policy must select global xuanyuan')
    if policy.get('phone_access_allowed') is not False:
        raise ValueError('Offline packaging requires the no-phone policy')
    if (policy.get('selected_integration_radio_source') != 'eu-radio-source.json'
            or policy.get('selected_radio_report') != 'reports/eu-radio-reference.json'
            or policy.get('baseline_rom_version') != SOURCE_ROM):
        raise ValueError('Policy does not select the exact reviewed EU source')
    if (config.get('device') != 'xuanyuan' or config.get('hardware_variant') != 'global'
            or config.get('rom') != SOURCE_ROM or str(config.get('android')) != '16'
            or config.get('sha256') != SOURCE_SHA256):
        raise ValueError('Source must be the exact reviewed global EU release')
    if (reference.get('device') != 'xuanyuan' or reference.get('hardware_variant') != 'global'
            or reference.get('source_rom') != SOURCE_ROM
            or str(reference.get('source_android')) != '16'
            or reference.get('source_archive_sha256') != SOURCE_SHA256
            or reference.get('official_release_checksum_verified') is not True):
        raise ValueError('Pinned reference provenance does not match the selected EU release')
    members = config.get('members', [])
    records = reference.get('files', [])
    if (len(members) != 2 or len(records) != 2
            or {m.get('path'): m.get('output') for m in members}
            != {name: value[0] for name, value in APPROVED.items()}
            or {m.get('source_member'): m.get('output') for m in records}
            != {name: value[0] for name, value in APPROVED.items()}):
        raise ValueError('Only the reviewed common/global WW radio pair may be staged')
    by_source = {m['path']: m for m in members}
    for record in records:
        size = record.get('size')
        if (type(size) is not int or size <= 0 or size != by_source[record['source_member']]['size']
                or not re.fullmatch('[0-9a-f]{64}', str(record.get('sha256', '')))
                or record.get('zip_crc_verified') is not True):
            raise ValueError('Invalid pinned radio size, digest or extraction verification')
    return sorted(records, key=lambda item: item['source_member'])


def checked_digest(stream, expected_size):
    digest = hashlib.sha256()
    count = 0
    while chunk := stream.read(8 * 1024**2):
        count += len(chunk)
        if count > expected_size:
            raise ValueError('Radio image exceeds pinned size')
        digest.update(chunk)
    if count != expected_size:
        raise ValueError('Radio image size differs from pinned reference')
    return digest.hexdigest()


def integrate(policy, config, reference, output, *, source_dir=None, artifact=None):
    """Verify both inputs before creating output; verify their copied bytes again."""
    if (source_dir is None) == (artifact is None):
        raise ValueError('Choose exactly one source directory or artifact ZIP')
    records = validate_selection(policy, config, reference)
    output = pathlib.Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Use a fresh radio staging directory')
    with contextlib.ExitStack() as stack:
        if artifact is not None:
            archive = stack.enter_context(zipfile.ZipFile(artifact))
            names = archive.namelist()
            if len(names) != len(set(names)) or not set(names) <= ARTIFACT_NAMES:
                raise ValueError('Unexpected or duplicate artifact member; only the exact allowlist is accepted')
            for record in records:
                name = record['output']
                if name not in names or archive.getinfo(name).file_size != record['size']:
                    raise ValueError('Radio artifact member missing or size mismatch')
                mode = archive.getinfo(name).external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    raise ValueError('Radio artifact member must be a regular file')
            def opener(name):
                return archive.open(name)
        else:
            source_dir = pathlib.Path(source_dir)
            if source_dir.is_symlink() or not source_dir.is_dir():
                raise ValueError('Radio source must be a real directory')
            for record in records:
                path = source_dir / record['output']
                if (path.is_symlink() or not path.is_file()
                        or path.resolve().parent != source_dir.resolve()):
                    raise ValueError('Missing or non-regular radio source file')
                if path.stat().st_size != record['size']:
                    raise ValueError('Radio source size differs from pinned reference')
            def opener(name):
                return (source_dir / name).open('rb')
        # No output directories, report files or staged images exist before every hash passes.
        for record in records:
            with opener(record['output']) as stream:
                if checked_digest(stream, record['size']) != record['sha256']:
                    raise ValueError('Radio SHA256 differs from pinned EU reference')
        output.mkdir(parents=True)
        (output / 'NOT-INSTALLABLE.txt').write_text(NOTE, encoding='utf-8')
        (output / 'images').mkdir()
        files = []
        for record in records:
            partition = APPROVED[record['source_member']][1]
            relative = 'images/' + partition + '.img'
            target = output / relative
            digest = hashlib.sha256()
            count = 0
            with opener(record['output']) as stream, target.open('xb') as dest:
                while chunk := stream.read(8 * 1024**2):
                    count += len(chunk)
                    if count > record['size']:
                        raise ValueError('Radio source changed during staging')
                    dest.write(chunk)
                    digest.update(chunk)
            if count != record['size'] or digest.hexdigest() != record['sha256']:
                raise ValueError('Radio source changed during staging; output is incomplete')
            files.append({'source_member': record['source_member'], 'input_name': record['output'],
                          'partition': partition, 'path': relative, 'size': count,
                          'sha256': digest.hexdigest(), 'unchanged_from_verified_source': True})
    manifest = {
        'device': 'xuanyuan', 'hardware_variant': 'global', 'rom_name': 'Molcer OS',
        'source_rom': SOURCE_ROM, 'source_android': '16', 'target_android': '17',
        'source_archive_sha256': SOURCE_SHA256,
        'verification_reference': 'reports/eu-radio-reference.json',
        'source_mode': 'artifact-zip' if artifact is not None else 'directory',
        'radio_pair_included_in_build_staging': True, 'files': files,
        'china_base_radio_replaced_in_staging': True,
        'excluded_china_base_partitions': ['modem', 'modemfirmware', 'countrycode'],
        'device_unique_partitions_included': [],
        'phone_accessed': False, 'installers_executed': False,
        'ready_to_flash': False, 'installable_rom_produced': False,
        'android17_runtime_compatibility_verified': False,
        'status': 'selected-EU-global-radio-pair-staged; full-ROM-packaging-and-runtime-validation-pending',
    }
    (output / 'radio-integration.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    (output / 'SHA256SUMS.txt').write_text(''.join(f["sha256"] + '  ' + f['path'] + '\n' for f in files), encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--source-dir', help='Prepared EU reference directory; defaults to out/eu-radio-reference')
    group.add_argument('--artifact', help='Prepared EU reference artifact ZIP')
    parser.add_argument('--output', default='out/rom-radio')
    parser.add_argument('--report', default='reports/rom-radio-integration.json')
    args = parser.parse_args()
    source_dir = args.source_dir or ('out/eu-radio-reference' if not args.artifact else None)
    policy = json.loads(pathlib.Path('radio-policy.json').read_text(encoding='utf-8'))
    config = json.loads(pathlib.Path('eu-radio-source.json').read_text(encoding='utf-8'))
    reference = json.loads(pathlib.Path('reports/eu-radio-reference.json').read_text(encoding='utf-8'))
    manifest = integrate(policy, config, reference, args.output, source_dir=source_dir, artifact=args.artifact)
    report = pathlib.Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': manifest['status'], 'files': manifest['files'], 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
