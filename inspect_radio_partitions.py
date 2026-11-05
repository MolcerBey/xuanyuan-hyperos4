"""Inspect one authenticated partition at a time within the free runner disk limit."""
import json
import pathlib
import subprocess
from extract_partition import extract
from inspect_radio import inspect


def main():
    work = pathlib.Path('work')
    reports = pathlib.Path('reports')
    reports.mkdir(exist_ok=True)
    combined = None
    image_reports = []
    for part in ('modem', 'vendor', 'odm', 'product', 'system', 'system_ext'):
        extract(work / 'base.zip', [part], work / 'images')
        image_reports.extend(json.loads((reports / 'extracted-images.json').read_text()))
        image = work / 'images' / (part + '.img')
        mount = work / ('mounted_' + part)
        mount.mkdir(exist_ok=True)
        fs = subprocess.check_output(['blkid', '-p', '-s', 'TYPE', '-o', 'value', str(image)], text=True).strip()
        if fs not in ('vfat', 'erofs', 'ext4'):
            raise ValueError('Unsupported source filesystem: ' + fs)
        options = 'loop,ro,noload' if fs == 'ext4' else 'loop,ro'
        subprocess.run(['mount', '-t', fs, '-o', options, str(image), str(mount)], check=True)
        try:
            report = inspect(work)
        finally:
            subprocess.run(['umount', str(mount)], check=True)
        mount.rmdir()
        if combined is None:
            combined = report
        else:
            combined['partitions'][part] = report['partitions'][part]
            for key, value in report.items():
                if isinstance(value, list):
                    combined[key].extend(value)
            for key, value in report['omitted'].items():
                combined['omitted'][key] = combined['omitted'].get(key, 0) + value
        # Only the generated, verified temporary image is removed. Firmware is
        # never written to a device and the original signed archive is retained.
        image.unlink()
    combined['mbn_candidate_count'] = len(combined['mbn_files'])
    (reports / 'extracted-images.json').write_text(json.dumps(image_reports, indent=2) + '\n')
    (reports / 'radio-static.json').write_text(json.dumps(combined, indent=2) + '\n')
    print(json.dumps(combined), flush=True)
    if combined['errors'] or combined['omitted']:
        raise ValueError('Radio inspection incomplete; examine evidence before integration')


if __name__ == '__main__':
    main()
