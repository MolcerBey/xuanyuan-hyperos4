"""Sign the audited OLED overlay locally and bind its manifest to the source report."""
import argparse
import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from fetch_chrome_candidate import parse_apk_signers
from prepare_avb import file_digest
from sign_avb_requests import private_material

PACKAGE = 'com.molcer.os.tr.oleddefaults.g0'
MANIFEST = 'assets/oled-overlays/manifest.json'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def validated_input(unsigned_root, report_path):
    report = json.loads(pathlib.Path(report_path).read_text(encoding='utf-8'))
    if (report.get('schema') != 1 or report.get('original_apks_modified') is not False
            or report.get('preview_signing_key') is not False
            or report.get('signing_status') != 'unsigned-local-signing-required'
            or report.get('runtime_verified') is not False):
        raise ValueError('Unexpected unsigned OLED report')
    targets = report.get('targets')
    if not isinstance(targets, list) or len(targets) != 1:
        raise ValueError('Expected exactly one OLED framework target')
    target = targets[0]
    if (target.get('package') != 'android'
            or target.get('target_apk') != 'system/system/framework/framework-res.apk'
            or target.get('overlays') != [PACKAGE]
            or target.get('compiled_resources') != ['integer/config_defaultNightMode', 'drawable/default_wallpaper']
            or not re.fullmatch(r'[0-9a-f]{64}', target.get('target_apk_sha256', ''))):
        raise ValueError('Unexpected OLED target or compiled resource scope')
    path = pathlib.Path(unsigned_root) / 'overlay/MolcerTurkish' / (PACKAGE + '.apk')
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024**2:
        raise ValueError('Missing, unsafe or excessive unsigned OLED APK')
    return path, report, target


def sign_overlay(unsigned_root, report_path, output, private_key, build_tools):
    source, report, target = validated_input(unsigned_root, report_path)
    output = pathlib.Path(output)
    manifest_path = output / 'manifest.json'
    if output.exists():
        raise ValueError('Use a fresh signed OLED output directory')
    tools = pathlib.Path(build_tools)
    apksigner = tools / ('apksigner.bat' if os.name == 'nt' else 'apksigner')
    aapt = tools / ('aapt2.exe' if os.name == 'nt' else 'aapt2')
    zipalign = tools / ('zipalign.exe' if os.name == 'nt' else 'zipalign')
    material = private_material(private_key, b'Molcer OS RRO signing identity v1')
    try:
        identity = json.loads(material)
        if (identity.get('schema') != 1 or set(identity) != {'schema', 'pfx', 'password'}
                or not isinstance(identity['password'], str)
                or not 16 <= len(identity['password']) <= 256):
            raise ValueError('Unexpected OLED signing identity')
        pfx = base64.b64decode(identity['pfx'], validate=True)
        if not 256 <= len(pfx) <= 16384:
            raise ValueError('Unexpected OLED PKCS12 size')
        with tempfile.TemporaryDirectory(prefix='molcer-oled-local-signer-') as directory:
            temporary = pathlib.Path(directory)
            pfx_path = temporary / 'identity.p12'
            password_path = temporary / 'password.txt'
            aligned = temporary / 'aligned.apk'
            signed = temporary / (PACKAGE + '.apk')
            pfx_path.write_bytes(pfx)
            pfx_path.chmod(0o600)
            password_path.write_text(identity['password'], encoding='utf-8')
            password_path.chmod(0o600)
            for command in ([str(zipalign), '-f', '-p', '4', str(source), str(aligned)],
                            [str(apksigner), 'sign', '--ks', str(pfx_path), '--ks-type', 'PKCS12',
                             '--ks-pass', 'file:' + str(password_path), '--min-sdk-version', '37',
                             '--max-sdk-version', '37', '--v4-signing-enabled', 'false',
                             '--out', str(signed), str(aligned)]):
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                if result.returncode:
                    raise ValueError('Android OLED alignment or signing failed')
            verification = subprocess.check_output([str(apksigner), 'verify', '--verbose', '--print-certs',
                                                    '--min-sdk-version', '37', '--max-sdk-version', '37',
                                                    str(signed)], text=True, timeout=120)
            certificate = file_digest('keys/rro-certificate.der')
            parse_apk_signers(verification, certificate)
            badging = subprocess.check_output([str(aapt), 'dump', 'badging', str(signed)],
                                              text=True, timeout=120)
            xml = subprocess.check_output([str(aapt), 'dump', 'xmltree', str(signed), '--file',
                                           'AndroidManifest.xml'], text=True, timeout=120)
            if (not re.search(r"^package: name='" + PACKAGE + r"'", badging, re.M)
                    or not re.search(r'hasCode[^\n]*(?:false|0x0\b)', xml)
                    or re.search(r'^\s*E: (?:activity|service|receiver|provider|uses-permission)\b', xml, re.M)):
                raise ValueError('Signed OLED identity or resource-only scope changed')
            output.mkdir(parents=True)
            destination = output / (PACKAGE + '.apk')
            shutil.copyfile(signed, destination)
            item = {'package': PACKAGE, 'path': str(destination).replace('\\', '/'),
                    'destination': 'overlay/MolcerTurkish/' + PACKAGE + '.apk',
                    'size': destination.stat().st_size, 'sha256': file_digest(destination),
                    'unsigned_sha256': file_digest(source), 'target_apk': target['target_apk'],
                    'target_apk_sha256': target['target_apk_sha256']}
            manifest = {'schema': 1, 'credit': report['credit'],
                        'signing_identity': 'Molcer OS Resource Overlays',
                        'signer_certificate_sha256': certificate, 'permanent_local_signature': True,
                        'original_apks_modified': False, 'runtime_verified': False,
                        'source_report_sha256': file_digest(report_path), 'overlays': [item]}
            manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    finally:
        if isinstance(material, bytearray):
            material[:] = b'\0' * len(material)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unsigned', default='out/unsigned-oled')
    parser.add_argument('--report', default='reports/oled-overlays.json')
    parser.add_argument('--private-key', default='.private/rro-key.dpapi')
    default_tools = (pathlib.Path(os.environ['ANDROID_HOME']) / 'build-tools/37.0.0'
                     if os.environ.get('ANDROID_HOME')
                     else pathlib.Path('.tools/android-build-tools/android-37.0'))
    parser.add_argument('--build-tools', default=str(default_tools))
    parser.add_argument('--output', default='assets/oled-overlays')
    args = parser.parse_args()
    result = sign_overlay(args.unsigned, args.report, args.output, args.private_key,
                          args.build_tools)
    print(json.dumps({'signed_overlays': len(result['overlays']), 'manifest': MANIFEST,
                      'permanent_signature_verified': True, 'runtime_verified': False}))


if __name__ == '__main__':
    main()
