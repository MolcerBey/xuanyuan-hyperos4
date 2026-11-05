"""Prepare pinned AOSP Linux lpmake/fec and their complete private library set.

All bytes are checked before any program is run. The bin/lib64 layout retains
the prebuilts' relative RPATH. This script never accesses a connected device.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import tempfile
import time
import urllib.request


REPOSITORY = 'https://android.googlesource.com/kernel/prebuilts/build-tools'
EXPECTED_FILES = {
    'linux-x86/bin/lpmake', 'linux-x86/bin/fec',
    *('linux-x86/lib64/' + name for name in (
        'libbase.so', 'liblog.so', 'liblp.so', 'libc++.so',
        'libcrypto-host.so', 'libcrypto_utils.so', 'libsparse-host.so',
        'libext4_utils.so', 'libz-host.so')),
}


def validate_config(config):
    if (config.get('schema_version') != 1 or
            config.get('repository') != REPOSITORY or
            config.get('encoding') != 'base64' or
            config.get('platform') != 'linux-x86_64-glibc' or
            not re.fullmatch(r'[0-9a-f]{40}', config.get('upstream_commit', ''))):
        raise ValueError('Unexpected AOSP host-tools configuration')
    files = config.get('files', [])
    paths = [item['path'] for item in files]
    if len(paths) != len(EXPECTED_FILES) or set(paths) != EXPECTED_FILES:
        raise ValueError('A complete, duplicate-free host-tool dependency set is required')
    for item in files:
        if (not isinstance(item['size'], int) or not 0 < item['size'] < 20 * 1024**2 or
                not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            raise ValueError('Invalid pinned length or SHA256')
    if config.get('required_lpmake_options') != ['--virtual-ab', '--auto-slot-suffixing']:
        raise ValueError('Required lpmake capabilities were changed')


def verify_bytes(data, item):
    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('Pinned length/SHA256 mismatch: ' + item['path'])
    if not data.startswith(b'\x7fELF\x02\x01') or data[18:20] != b'\x3e\x00':
        raise ValueError('Expected a Linux x86_64 ELF: ' + item['path'])


def download(item, commit):
    url = f"{REPOSITORY}/+/{commit}/{item['path']}?format=TEXT"
    # Gitiles returns base64, not raw bytes. Bound both encoding and decoded size.
    limit = 4 * ((item['size'] + 2) // 3) + 1024
    deadline = time.monotonic() + 120
    chunks = []
    total = 0
    with urllib.request.urlopen(url, timeout=30) as response:
        if not response.geturl().startswith(REPOSITORY + '/'):
            raise ValueError('Unexpected host-tool download redirect')
        length = response.headers.get('Content-Length')
        if length is not None and int(length) > limit:
            raise ValueError('Encoded host-tool response exceeds the size limit')
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Host-tool download exceeded 120 seconds')
            chunk = response.read(min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError('Encoded host-tool response exceeds the size limit')
    encoded = b''.join(chunks)
    data = base64.b64decode(encoded, validate=True)
    verify_bytes(data, item)
    return data, url


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + '.',
                                         suffix='.tmp', delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            stream.write(data)
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def smoke_test(tool, root, expected_options):
    executable = (root / 'linux-x86' / 'bin' / tool).resolve()
    env = os.environ.copy()
    # Run this verification against the adjacent pinned libraries, without a
    # caller's preload or custom library directory affecting the result.
    env.pop('LD_PRELOAD', None)
    env['LD_LIBRARY_PATH'] = str((root / 'linux-x86' / 'lib64').resolve())
    result = subprocess.run([str(executable), '--help'], capture_output=True,
                            text=True, errors='replace', timeout=30, env=env)
    output = result.stdout + '\n' + result.stderr
    if tool == 'lpmake':
        markers = ['command-line tool for creating Android Logical Partition images.',
                   *expected_options]
    else:
        markers = ['fec: a tool for encoding and decoding files using RS(255, N).',
                   '--encode', '--decode', '--roots']
    # These command-line tools may print their complete usage with a nonzero
    # usage exit status; recognize the tool's help, and still record that code.
    accepted = result.returncode >= 0 and all(marker in output for marker in markers)
    evidence = {
        'command': [str(executable), '--help'], 'exit_code': result.returncode,
        'help_recognized': accepted, 'stdout': result.stdout[:16384],
        'stderr': result.stderr[:16384],
        'stdout_truncated': len(result.stdout) > 16384,
        'stderr_truncated': len(result.stderr) > 16384,
        'required_options': expected_options if tool == 'lpmake' else [],
    }
    return accepted, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=pathlib.Path, default=pathlib.Path('host-tools.json'))
    parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('.tools/aosp-host'))
    parser.add_argument('--report', type=pathlib.Path, default=pathlib.Path('reports/host-tools.json'))
    args = parser.parse_args()
    report = {'status': 'failed', 'platform': platform.platform(), 'files': [], 'smoke_tests': {}}
    try:
        config = json.loads(args.config.read_text(encoding='utf-8'))
        validate_config(config)
        report.update({
            'source': config['source'], 'repository': config['repository'],
            'upstream_commit': config['upstream_commit'],
            'source_revisions': config['source_revisions'],
            'version_identity': 'AOSP prebuilt commit ' + config['upstream_commit'],
            'output': str(args.output.resolve()),
        })
        for item in config['files']:
            destination = args.output / item['path']
            cached = False
            if destination.is_file() and destination.stat().st_size == item['size']:
                data = destination.read_bytes()
                try:
                    verify_bytes(data, item)
                    cached = True
                except ValueError:
                    pass
            url = f"{REPOSITORY}/+/{config['upstream_commit']}/{item['path']}?format=TEXT"
            if not cached:
                data, url = download(item, config['upstream_commit'])
                atomic_write(destination, data)
            destination.chmod(0o755 if '/bin/' in item['path'] else 0o644)
            report['files'].append({**item, 'url': url, 'verified': True, 'cached': cached})

        # Recheck the complete installed set before the first process starts.
        for item in config['files']:
            verify_bytes((args.output / item['path']).read_bytes(), item)
        report['all_bytes_verified_before_execution'] = True
        if platform.system() == 'Linux' and platform.machine().lower() in {'x86_64', 'amd64'}:
            for tool in ('lpmake', 'fec'):
                accepted, evidence = smoke_test(tool, args.output, config['required_lpmake_options'])
                report['smoke_tests'][tool] = evidence
                if not accepted:
                    raise RuntimeError(tool + ' help smoke test failed; see report')
            report['status'] = 'verified-and-smoke-tested'
        else:
            report['status'] = 'verified-bytes-execution-not-tested'
            report['execution_note'] = 'Linux x86_64 is required; tools were not executed on this host.'
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': report['status'], 'report': str(args.report)}))


if __name__ == '__main__':
    main()
