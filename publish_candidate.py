"""Publish unsigned AVB candidates to a draft release, one bounded chunk at a time.

Only the explicitly prepared public images and reports are uploaded. This never
creates an installer, signs metadata, publishes a release, or accesses a phone.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from prepare_avb import file_digest, read_json
from validate_signing_requests import validate_bundle

REPOSITORY = 'MolcerBey/xuanyuan-hyperos4'
CHUNK_BYTES = 1900 * 1024**2
BUFFER_BYTES = 8 * 1024**2


def gh(*arguments, parse_json=False):
    result = subprocess.run(['gh', *map(str, arguments)], check=True,
                            capture_output=True, text=True, timeout=1800)
    return json.loads(result.stdout) if parse_json else result.stdout.strip()


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def stream_chunks(source, directory, prefix, chunk_size=CHUNK_BYTES):
    """Yield one temporary chunk; remove it before producing the following one."""
    if type(chunk_size) is not int or not 0 < chunk_size <= CHUNK_BYTES:
        raise ValueError('Invalid bounded chunk size')
    source = pathlib.Path(source)
    total_hash = hashlib.sha256()
    offset = 0
    index = 0
    with source.open('rb') as stream:
        while True:
            first = stream.read(min(BUFFER_BYTES, chunk_size))
            if not first:
                break
            path = pathlib.Path(directory) / f'{prefix}.part-{index:05d}'
            chunk_hash = hashlib.sha256()
            size = 0
            try:
                with path.open('xb') as output:
                    data = first
                    while data:
                        output.write(data)
                        chunk_hash.update(data)
                        total_hash.update(data)
                        size += len(data)
                        if size == chunk_size:
                            break
                        data = stream.read(min(BUFFER_BYTES, chunk_size - size))
                yield path, {'index': index, 'offset': offset, 'size': size,
                             'sha256': chunk_hash.hexdigest(), 'asset_name': path.name}
            finally:
                if path.exists():
                    path.unlink()
            offset += size
            index += 1
    return {'size': offset, 'sha256': total_hash.hexdigest()}


def draft_release(tag):
    releases = gh('api', f'repos/{REPOSITORY}/releases?per_page=100', parse_json=True)
    matches = [release for release in releases
               if release.get('draft') is True and release.get('tag_name') == tag]
    if len(matches) != 1:
        raise ValueError('Expected exactly one draft release with the candidate tag')
    return matches[0]


def upload_asset(tag, path, expected_hash, expected_size):
    # A fresh tag and no --clobber prevent silently replacing prior evidence.
    gh('release', 'upload', tag, path, '--repo', REPOSITORY)
    release = draft_release(tag)
    if release.get('draft') is not True:
        raise ValueError('Candidate release unexpectedly became public')
    matches = [a for a in release['assets'] if a['name'] == path.name]
    if len(matches) != 1 or matches[0]['size'] != expected_size:
        raise ValueError('Uploaded release asset length/identity mismatch')
    asset = matches[0]
    remote_digest = asset.get('digest')
    if remote_digest is not None and remote_digest != 'sha256:' + expected_hash:
        raise ValueError('GitHub asset digest differs from the uploaded chunk')
    return {'asset_id': asset['id'], 'api_url': asset['url'],
            'download_url': asset['browser_download_url'],
            'remote_sha256_verified': remote_digest is not None}


def publish(args):
    config = read_json('candidate-build.json')
    if config.get('schema') != 1 or config.get('build_enabled') is not True:
        raise ValueError('Candidate build is not enabled by the reviewed configuration')
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('Candidate publishing requires the intended repository')
    commit = os.environ.get('GITHUB_SHA', '')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if (not re.fullmatch(r'[0-9a-f]{40}', commit)
            or not re.fullmatch(r'[0-9]+', run_id)
            or not re.fullmatch(r'[0-9]+', attempt)):
        raise ValueError('Expected an immutable Actions commit/run identity')
    prepared = pathlib.Path(args.prepared)
    request_path = prepared / 'signing-requests.json'
    # This verifies the full descriptor/header allowlist and EU capacity budget
    # using public material; the cloud stage has already verified actual images.
    validation = validate_bundle(request_path, stock_dir=args.stock_avb)
    save_json(pathlib.Path('reports/candidate-signing-scope.json'), validation)
    bundle = read_json(request_path)
    images = []
    for record in bundle['prepared_images']:
        path = prepared / record['path']
        if (path.is_symlink() or not path.is_file()
                or path.stat().st_size != record['size']
                or file_digest(path) != record['sha256']):
            raise ValueError('Prepared image differs from the audited signing request')
        images.append((path, record))
    temporary_parent = pathlib.Path('work/candidate-upload')
    temporary_parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(temporary_parent).free < CHUNK_BYTES + 1024**3:
        raise ValueError('Need one 1900 MiB chunk plus 1 GiB reserve to publish')
    tag = f'molcer-candidate-{commit[:12]}-{run_id}-{attempt}'
    note = prepared / 'NOT-INSTALLABLE.txt'
    if not note.is_file() or note.stat().st_size > 16384:
        raise ValueError('Expected bounded non-installable candidate notice')
    manifest_path = pathlib.Path(args.report)
    if manifest_path.exists():
        raise ValueError('Refusing to overwrite a prior candidate manifest')
    manifest = {'schema': 1, 'status': 'uploading-unsigned-candidate',
                'repository': REPOSITORY, 'commit': commit, 'run_id': run_id,
                'run_attempt': attempt, 'release_tag': tag, 'release_draft': True,
                'requests_sha256': file_digest(request_path),
                'chunk_size_limit': CHUNK_BYTES, 'images': [], 'small_assets': [],
                'phone_accessed': False, 'private_key_accessed': False,
                'installation_allowed': False, 'installable_rom_produced': False,
                'runtime_verified': False}
    save_json(manifest_path, manifest)
    try:
        gh('release', 'create', tag, '--repo', REPOSITORY, '--draft',
           '--target', commit, '--title', 'Molcer OS unsigned candidate - NOT INSTALLABLE',
           '--notes-file', note)
        release = draft_release(tag)
        if release.get('draft') is not True:
            raise ValueError('Expected a draft candidate release')
        manifest.update({'release_id': release['id'], 'release_url': release['html_url']})
        for path, record in images:
            image = {'partition': record['partition'], 'size': record['size'],
                     'sha256': record['sha256'], 'chunks': []}
            manifest['images'].append(image)
            with tempfile.TemporaryDirectory(prefix='chunk-', dir=temporary_parent) as directory:
                chunks = stream_chunks(path, directory, 'NOT-INSTALLABLE-' + record['partition'] + '.img')
                while True:
                    try:
                        chunk_path, chunk = next(chunks)
                    except StopIteration as stopped:
                        if stopped.value != {'size': record['size'], 'sha256': record['sha256']}:
                            raise ValueError('Image changed while streaming release chunks')
                        break
                    try:
                        chunk.update(upload_asset(tag, chunk_path, chunk['sha256'], chunk['size']))
                        image['chunks'].append(chunk)
                        save_json(manifest_path, manifest)
                    except BaseException:
                        chunks.close()
                        raise
        # Never glob the workspace: only public, explicitly named small files.
        for path in (request_path, note, pathlib.Path('reports/candidate-signing-scope.json')):
            if path.stat().st_size > 1024**2:
                raise ValueError('Small candidate evidence exceeds 1 MiB')
            sha = file_digest(path)
            asset = {'asset_name': path.name, 'size': path.stat().st_size, 'sha256': sha}
            asset.update(upload_asset(tag, path, sha, asset['size']))
            manifest['small_assets'].append(asset)
        manifest['status'] = 'unsigned-candidate-awaiting-local-signatures'
        save_json(manifest_path, manifest)
        # The manifest deliberately excludes its own asset ID/hash to avoid a
        # recursive document hash; the Actions report preserves identical bytes.
        upload_asset(tag, manifest_path, file_digest(manifest_path), manifest_path.stat().st_size)
    except BaseException as error:
        manifest['status'] = 'incomplete-upload-not-installable'
        manifest['error_type'] = type(error).__name__
        save_json(manifest_path, manifest)
        raise
    print(json.dumps({'status': manifest['status'], 'release_url': manifest['release_url'],
                      'requests_sha256': manifest['requests_sha256']}))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', default='out/avb-prepared')
    parser.add_argument('--stock-avb', default='work/images')
    parser.add_argument('--report', default='reports/candidate-manifest.json')
    publish(parser.parse_args())


if __name__ == '__main__':
    main()
