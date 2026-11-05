"""Authenticate a manufacturer-hosted donor using the already pinned Xiaomi signer."""
import hashlib
import json
import pathlib
import shutil
import subprocess
from inspect_ota import inspect
from verify_signature import verify_signature


def main():
    cfg = json.loads(pathlib.Path('global-donor.json').read_text())
    work = pathlib.Path('work')
    work.mkdir(exist_ok=True)
    if shutil.disk_usage(work).free < cfg['size'] + 2 * 1024**3:
        raise ValueError('Insufficient disk for donor download')
    partial = work / 'global.zip.partial'
    urls = [cfg['url'].replace('https://bigota.d.miui.com/', 'https://bkt-sgp-miui-ota-update-alisgp.oss-ap-southeast-1.aliyuncs.com/'), cfg['url']]
    for url in urls:
        result = subprocess.run(['curl', '--fail', '--location', '--show-error', '--connect-timeout', '30', '--max-time', '1500', '--speed-limit', '131072', '--speed-time', '45', '--retry', '2', '--retry-max-time', '1800', '--output', str(partial), url], timeout=1850)
        if result.returncode == 0 and partial.stat().st_size == cfg['size']:
            break
    else:
        raise ValueError('Global source download failed or unexpected length')
    report = inspect(partial, cfg)
    if not all(report['checks'].values()):
        raise ValueError('Global OTA identity check failed')
    # No untrusted hash is accepted as proof of origin: verify CMS against the
    # manufacturer certificate pinned independently for the base first.
    report.update(verify_signature(partial, cfg['otacert_sha256_der']))
    modem = next(p for p in report['partitions'] if p['name'] == 'modem')
    if modem['sha256'] != cfg['expected_modem_sha256'] or modem['size'] != cfg['expected_modem_size']:
        raise ValueError('Authenticated donor modem differs from reviewed metadata')
    with partial.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    report.update({'archive_sha256': digest, 'source_url': cfg['url'], 'global_modem_runtime_compatibility_verified': False})
    pathlib.Path('reports').mkdir(exist_ok=True)
    pathlib.Path('reports/verified-global-donor.json').write_text(json.dumps(report, indent=2) + '\n')
    partial.replace(work / 'base.zip')
    print(json.dumps({'global_donor_authenticated': True, 'archive_sha256': digest, 'modem': modem}), flush=True)


if __name__ == '__main__':
    main()
