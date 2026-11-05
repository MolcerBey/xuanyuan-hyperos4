"""Download pinned AOSP inspection tools, verify bytes before use."""
import base64
import hashlib
import json
import pathlib
import urllib.request


def main():
    configs = json.loads(pathlib.Path('packaging-tools.json').read_text())
    output = pathlib.Path('.tools'); output.mkdir(exist_ok=True)
    for name, item in configs.items():
        if name != 'avbtool' or item['encoding'] != 'base64':
            raise ValueError('Unexpected tool')
        with urllib.request.urlopen(item['url'], timeout=60) as response:
            encoded = response.read(2 * 1024**2)
        data = base64.b64decode(encoded, validate=True)
        if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Pinned AOSP tool checksum mismatch')
        (output / 'avbtool.py').write_bytes(data)
        print('Verified avbtool', item['upstream_commit'], item['sha256'])


if __name__ == '__main__':
    main()
