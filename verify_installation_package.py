"""Verify a complete local image bundle without accessing or flashing a phone."""
import argparse
import hashlib
import json
import pathlib

from release_metadata import canonical_bytes, read_json, sha256, validate_assembly


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_package(manifest, image_root):
    images = validate_assembly(manifest)
    root = pathlib.Path(image_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Installation images must be in a real directory')
    expected = {image['name'] + '.img': image for image in images}
    actual = {}
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Installation bundle accepts only regular image files')
        if path.name not in expected:
            raise ValueError('Unexpected installation bundle entry: ' + path.name)
        actual[path.name] = path
    if set(actual) != set(expected):
        raise ValueError('Installation bundle does not contain the exact uploaded image set')
    verified = []
    for filename, image in sorted(expected.items()):
        path = actual[filename]
        if path.stat().st_size != image['size'] or file_sha256(path) != image['sha256']:
            raise ValueError('Installation image differs from the verified assembly: ' + image['name'])
        verified.append({'name': image['name'], 'size': image['size'], 'sha256': image['sha256']})
    return {
        'schema': 1,
        'status': 'offline-package-bytes-verified; device-installation-not-implemented',
        'device': manifest['device'],
        'hardware_variant': manifest['hardware_variant'],
        'release_tag': manifest['release_tag'],
        'source_manifest_sha256': sha256(canonical_bytes(manifest)),
        'images': verified,
        'image_count': len(verified),
        'all_image_bytes_verified': True,
        'device_gpt_capacity_verified': False,
        'bootloader_trust_root_verified': False,
        'installation_order_defined': False,
        'fastboot_execution_implemented': False,
        'installer_included': False,
        'installation_allowed': False,
        'ready_to_flash': False,
        'phone_accessed': False,
        'runtime_verified': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', default='reports/assembled-candidate-manifest.json')
    parser.add_argument('--images', required=True, help='Directory containing only the exact physical/super images')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = verify_package(read_json(args.manifest), args.images)
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'image_count': result['image_count'],
                      'ready_to_flash': False, 'phone_accessed': False}))


if __name__ == '__main__':
    main()
