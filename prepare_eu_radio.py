"""Extract the user's exact Xiaomi.eu global radio branch; never execute installers."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import zipfile


def extract_verified(archive, config, output):
    archive, output = pathlib.Path(archive), pathlib.Path(output)
    if archive.stat().st_size != config['size']:
        raise ValueError('EU archive length mismatch')
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != config['sha256']:
        raise ValueError('EU archive SHA256 differs from official release checksum')
    if config['device'] != 'xuanyuan' or config['hardware_variant'] != 'global':
        raise ValueError('EU radio source does not match requested global xuanyuan')
    records = []
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        for name, expected in config['installer_sha256'].items():
            if names.count(name) != 1 or source.getinfo(name).file_size > 150000:
                raise ValueError('Unexpected installer evidence')
            if hashlib.sha256(source.read(name)).hexdigest() != expected:
                raise ValueError('Installer hardware-selection logic changed')
        approved = {'images/modem.img': 'NOT-INSTALLABLE-modem.img', 'images/modemfirmware_ww.img': 'NOT-INSTALLABLE-modemfirmware.img'}
        if {m['path']: m['output'] for m in config['members']} != approved or len(config['members']) != 2:
            raise ValueError('Only the reviewed global radio pair may be extracted')
        for member in config['members']:
            if names.count(member['path']) != 1:
                raise ValueError('Missing or duplicate radio ZIP member')
            info = source.getinfo(member['path'])
            if info.file_size != member['size'] or info.CRC != int(member['crc32'], 16):
                raise ValueError('Radio ZIP member metadata changed')
        output.mkdir(parents=True, exist_ok=True)
        for member in config['members']:
            target = output / member['output']
            if target.exists():
                raise ValueError('Use a fresh radio output directory')
            h = hashlib.sha256()
            with source.open(member['path']) as data, target.open('xb') as dest:
                while chunk := data.read(8 * 1024**2):
                    dest.write(chunk)
                    h.update(chunk)
            records.append({'source_member': member['path'], 'output': member['output'], 'size': target.stat().st_size, 'sha256': h.hexdigest(), 'zip_crc_verified': True})
    return {'device': 'xuanyuan', 'hardware_variant': 'global', 'source_rom': config['rom'], 'source_android': config['android'], 'source_archive_sha256': digest, 'official_release_checksum_verified': True, 'source_url': config['url'], 'selection_evidence': config['selection_evidence'], 'files': records, 'installers_executed': False, 'phone_accessed': False, 'active_phone_contents_verified': False, 'ready_to_flash': False, 'android17_runtime_compatibility_verified': False}


def main():
    config = json.loads(pathlib.Path('eu-radio-source.json').read_text())
    work = pathlib.Path('work'); work.mkdir(exist_ok=True)
    if shutil.disk_usage(work).free < config['size'] + 1024**3:
        raise ValueError('Insufficient disk for EU source and radio pair')
    archive = work / config['archive']
    subprocess.run(['curl', '--fail', '--location', '--show-error', '--connect-timeout', '30', '--max-time', '1800', '--speed-limit', '131072', '--speed-time', '60', '--retry', '2', '--retry-max-time', '2000', '--output', str(archive), config['url']], check=True, timeout=2050)
    out = pathlib.Path('out/eu-radio-reference')
    report = extract_verified(archive, config, out)
    (out / 'radio-source.json').write_text(json.dumps(report, indent=2) + '\n')
    (out / 'SHA256SUMS.txt').write_text(''.join(x['sha256'] + '  ' + x['output'] + '\n' for x in report['files']))
    (out / 'NOT-INSTALLABLE.txt').write_text('Exact global radio branch from Xiaomi.eu OS3.0.314.0.WOACNXM, verified against the official full archive SHA256. Selected for Molcer OS integration at owner request. Android16-to-Android17 vendor/radio compatibility and full ROM packaging remain unverified. Do not flash these standalone files. No phone was accessed.\n')
    pathlib.Path('reports').mkdir(exist_ok=True)
    pathlib.Path('reports/eu-radio-reference.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
