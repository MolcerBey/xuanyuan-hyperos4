"""Stage only hash-pinned EU artifact images for offline radio comparison."""
import hashlib
import json
import pathlib
import shutil
import zipfile


def main():
    report = json.loads(pathlib.Path('reports/eu-radio-reference.json').read_text())
    out = pathlib.Path('work/compat/eu/images')
    out.mkdir(parents=True, exist_ok=True)
    approved = {'NOT-INSTALLABLE-modem.img': 'modem.img', 'NOT-INSTALLABLE-modemfirmware.img': 'modemfirmware.img'}
    if {x['output'] for x in report['files']} != set(approved):
        raise ValueError('Unexpected reference radio file list')
    with zipfile.ZipFile('work/eu-reference.zip') as z:
        for item in report['files']:
            name = item['output']
            if z.namelist().count(name) != 1 or z.getinfo(name).file_size != item['size']:
                raise ValueError('Radio artifact member mismatch')
            target = out / approved[name]
            with z.open(name) as data, target.open('xb') as dest:
                shutil.copyfileobj(data, dest, 8 * 1024**2)
            with target.open('rb') as data:
                digest = hashlib.file_digest(data, 'sha256').hexdigest()
            if digest != item['sha256']:
                raise ValueError('EU artifact SHA256 mismatch')
            print('Verified EU comparison input: ' + approved[name] + ' ' + digest)


if __name__ == '__main__':
    main()
