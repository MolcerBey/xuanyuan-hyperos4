"""Load only permanently signed own overlays bound to exact target APK bytes."""
import hashlib
import json
import pathlib
import re
import subprocess

from fetch_chrome_candidate import parse_apk_signers


def sha256(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(tools, manifest='assets/turkish-overlays/manifest.json', credit_path='etc/molcer-translation-credits.txt'):
    record = json.loads(pathlib.Path(manifest).read_text(encoding='utf-8'))
    certificate = sha256('keys/rro-certificate.der')
    if (record.get('schema') != 1 or record.get('permanent_local_signature') is not True
            or record.get('original_apks_modified') is not False
            or record.get('signer_certificate_sha256') != certificate):
        raise ValueError('Permanent overlay signing manifest is invalid')
    root = pathlib.Path(manifest).parent.resolve()
    additions, packages, targets = {}, [], {}
    for item in record['overlays']:
        package = item['package']
        if not re.fullmatch(r'com\.molcer\.os\.tr\.[a-z0-9_]+\.g[0-9]+', package) or package in packages:
            raise ValueError('Unexpected or duplicate own overlay package')
        path = pathlib.Path(item['path'])
        destination = 'overlay/MolcerTurkish/' + package + '.apk'
        if path.resolve().parent != root or path.name != package + '.apk' or item['destination'] != destination:
            raise ValueError('Overlay path differs from fixed own-package destination')
        if path.stat().st_size != item['size'] or sha256(path) != item['sha256']:
            raise ValueError('Signed overlay size/hash changed')
        target = pathlib.PurePosixPath(item['target_apk'])
        if (target.parts[0] not in ('system', 'system_ext', 'product') or target.is_absolute()
                or '..' in target.parts or '\\' in item['target_apk']):
            raise ValueError('Invalid target APK path')
        mounted = pathlib.Path('work/mounted_' + target.parts[0], *target.parts[1:])
        if sha256(mounted) != item['target_apk_sha256']:
            raise ValueError('Translation target differs from compiled resource binding')
        signature = subprocess.check_output([str(tools / 'apksigner'), 'verify', '--verbose', '--print-certs',
            '--min-sdk-version', '37', '--max-sdk-version', '37', str(path)], text=True, timeout=120)
        parse_apk_signers(signature, certificate)
        badging = subprocess.check_output([str(tools / 'aapt2'), 'dump', 'badging', str(path)], text=True, timeout=120)
        if not re.search(r"^package: name='" + re.escape(package) + "'", badging, re.M):
            raise ValueError('Signed own overlay package differs')
        additions[destination] = path.read_bytes()
        packages.append(package)
        targets[item['target_apk']] = item['target_apk_sha256']
    if not packages:
        raise ValueError('Permanent overlay pack is empty')
    if credit_path not in ('etc/molcer-translation-credits.txt', 'etc/molcer-oled-credits.txt'):
        raise ValueError('Unexpected overlay credits destination')
    additions[credit_path] = (record['credit'] + '\nResource-matched overlays; original OEM applications remain unchanged.\n').encode()
    pathlib.Path('reports/signed-overlays.json').write_text(json.dumps({
        'permanent_signatures_verified': True, 'signer_certificate_sha256': certificate,
        'original_apks_modified': False, 'runtime_verified': False,
        'manifest_sha256': sha256(manifest), 'packages': packages, 'targets': targets}, indent=2) + '\n')
    return additions, packages
