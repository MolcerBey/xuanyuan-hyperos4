"""Fetch and inspect a pinned Chrome APK offline; failure does not approve an APK.

This prepares a candidate only. It neither alters build inputs nor accesses a phone.
Ordinary public HTTPS downloads only: no browser challenge solving or proxying.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import zipfile


def sha256(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inspect_apk(path, config, build_tools):
    if path.stat().st_size != config['size'] or sha256(path) != config['sha256']:
        raise ValueError('Candidate length/SHA256 does not match the exact published APK')
    signer_tool = build_tools / ('apksigner.bat' if os.name == 'nt' else 'apksigner')
    aapt_tool = build_tools / ('aapt2.exe' if os.name == 'nt' else 'aapt2')
    if not signer_tool.is_file() or not aapt_tool.is_file():
        raise ValueError('Android SDK Build Tools 37.0.0 are required for candidate approval')
    signature = subprocess.run([str(signer_tool), 'verify', '--verbose', '--print-certs',
                                '--min-sdk-version', '37', '--max-sdk-version', '37', str(path)],
                               capture_output=True, text=True, check=True, timeout=180).stdout
    signers = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$',
                         signature, flags=re.MULTILINE)
    if [value.lower() for value in signers] != [config['signer_certificate_sha256']]:
        raise ValueError('APK signer does not match the pinned Google signing certificate')
    badging = subprocess.run([str(aapt_tool), 'dump', 'badging', str(path)],
                             capture_output=True, text=True, check=True, timeout=120).stdout
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.MULTILINE)
    if not package or package.groups() != (config['package'], config['version_code'], config['version']):
        raise ValueError('APK package or version does not match the candidate')
    minimum = re.search(r"^sdkVersion:'(\d+)'", badging, re.MULTILINE)
    if not minimum or int(minimum.group(1)) > 37:
        raise ValueError('Candidate minimum Android SDK exceeds target SDK37')
    manifest = subprocess.run([str(aapt_tool), 'dump', 'xmltree', str(path), '--file', 'AndroidManifest.xml'],
                              capture_output=True, text=True, check=True, timeout=120).stdout
    if re.search(r'^\s*E: (uses-static-library|uses-split)\b', manifest, re.MULTILINE):
        raise ValueError('Candidate requires a separate static library or split; do not approve it as standalone')
    if re.search(r'isSplitRequired[^\n]*(?:0xffffffff|true)', manifest, re.IGNORECASE):
        raise ValueError('Candidate declares required APK splits')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate APK ZIP entries')
        native = [name for name in names if name.startswith('lib/arm64-v8a/') and name.endswith('.so')]
        turkish = [name for name in names if re.search(r'(?:^|/)(?:tr|tr-TR)\.pak$', name)]
    if not native:
        raise ValueError('Candidate lacks embedded ARM64 native libraries')
    locales = re.search(r'^locales:(.*)$', badging, re.MULTILINE)
    has_tr_locale = bool(locales and re.search(r"(?:^|\s)'tr(?:[-_][^']+)?'", locales.group(1)))
    if not turkish and not has_tr_locale:
        raise ValueError('No Turkish locale evidence found in the candidate')
    return {'signature_verified_for_sdk37': True, 'signer_certificate_sha256': signers[0].lower(),
            'package': package.group(1), 'version_code': package.group(2), 'version': package.group(3),
            'minimum_sdk': int(minimum.group(1)), 'requires_static_library_or_split': False,
            'arm64_native_libraries': native, 'turkish_pak_paths': turkish,
            'turkish_locale_in_badging': has_tr_locale,
            'signature_verification_output': signature,
            'manifest_runtime_compatibility_proven': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='chrome-candidate.json')
    parser.add_argument('--input', help='Inspect an already downloaded file instead of fetching')
    parser.add_argument('--build-tools', default=str(pathlib.Path(os.environ.get('ANDROID_HOME', '/usr/local/lib/android/sdk')) / 'build-tools/37.0.0'))
    parser.add_argument('--report', default='reports/chrome-candidate.json')
    args = parser.parse_args()
    config = json.loads(pathlib.Path(args.config).read_text(encoding='utf-8'))
    report = {'status': 'unavailable', 'candidate': {key: config[key] for key in
              ('package', 'version', 'version_code', 'size', 'sha256', 'signer_certificate_sha256')},
              'attempts': [], 'phone_accessed': False, 'apk_executed': False,
              'build_files_modified': False, 'runtime_verified': False}
    work = pathlib.Path('work/chrome-candidate'); work.mkdir(parents=True, exist_ok=True)
    candidate = pathlib.Path(args.input) if args.input else work / 'Chrome.download.apk'
    obtained = False
    if args.input:
        obtained = candidate.is_file()
        report['source'] = 'explicit-local-file'
    else:
        for source in config['sources']:
            try:
                result = subprocess.run(['curl', '--fail', '--location', '--show-error', '--silent',
                    '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '25',
                    '--max-time', '420', '--speed-limit', '131072', '--speed-time', '45',
                    '--max-filesize', str(config['size']), '--referer', source['referer'],
                    '--output', str(candidate), source['url']], capture_output=True, text=True, timeout=450)
                if result.returncode:
                    report['attempts'].append({'source': source['name'], 'status': 'download-unavailable',
                                               'curl_exit_code': result.returncode})
                    continue
                if candidate.stat().st_size != config['size'] or sha256(candidate) != config['sha256']:
                    report['attempts'].append({'source': source['name'], 'status': 'rejected-length-or-hash'})
                    continue
                report['attempts'].append({'source': source['name'], 'status': 'exact-bytes-downloaded'})
                report['source'] = source['name']; obtained = True; break
            except (OSError, subprocess.TimeoutExpired) as exc:
                report['attempts'].append({'source': source['name'], 'status': 'download-unavailable',
                                           'error_type': type(exc).__name__})
    if obtained:
        try:
            inspected = inspect_apk(candidate, config, pathlib.Path(args.build_tools))
            output = pathlib.Path('out/chrome-candidate/Chrome.apk')
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists():
                raise ValueError('Use a fresh candidate output directory')
            shutil.copyfile(candidate, output)
            if sha256(output) != config['sha256']:
                raise ValueError('Candidate copy changed')
            report.update({'status': 'verified-offline-candidate', 'output': output.as_posix(),
                           'inspection': inspected, 'approved_for_builder_review': True})
        except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
            report.update({'status': 'rejected-or-unverified', 'error_type': type(exc).__name__,
                           'error': str(exc)[:500], 'approved_for_builder_review': False})
    path = pathlib.Path(args.report); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'attempts', 'phone_accessed', 'runtime_verified')}))
    # This optional acquisition step must not suppress independent ROM metadata checks.
    # Callers may upload the APK only when status is verified-offline-candidate.


if __name__ == '__main__':
    main()
