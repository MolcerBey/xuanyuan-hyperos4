"""Prepare authenticated global modem firmware for offline review, never flash it."""
import hashlib
import json
import pathlib
import shutil
from download_global_donor import main as authenticate_donor
from extract_partition import extract


def main():
    cfg = json.loads(pathlib.Path('global-donor.json').read_text())
    policy = json.loads(pathlib.Path('radio-policy.json').read_text())
    if policy['hardware_variant'] != 'global' or cfg['device'] != policy['device'] or cfg['android'] != '17':
        raise ValueError('Global radio candidate target mismatch')
    authenticate_donor()
    verified = json.loads(pathlib.Path('reports/verified-global-donor.json').read_text())
    extract('work/base.zip', ['modem', 'modemfirmware'], 'work/images')
    source = pathlib.Path('work/images/modem.img')
    with source.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != cfg['expected_modem_sha256'] or source.stat().st_size != cfg['expected_modem_size']:
        raise ValueError('Global modem hash or size mismatch')
    if digest == policy['base_modem_sha256']:
        raise ValueError('Refusing China modem as a global radio candidate')
    out = pathlib.Path('out/global-radio-candidate')
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, out / 'NOT-INSTALLABLE-global-modem.img')
    firmware = pathlib.Path('work/images/modemfirmware.img')
    with firmware.open('rb') as stream:
        firmware_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if firmware_digest != cfg['expected_modemfirmware_sha256'] or firmware.stat().st_size != cfg['expected_modemfirmware_size']:
        raise ValueError('Global modemfirmware hash or size mismatch')
    shutil.copyfile(firmware, out / 'NOT-INSTALLABLE-global-modemfirmware.img')
    manifest = {
        'device': cfg['device'], 'hardware_variant': 'global', 'operator_target': policy['operator'],
        'source_version': cfg['version'], 'android': cfg['android'], 'source_url': cfg['url'],
        'source_archive_sha256': verified['archive_sha256'],
        'whole_file_signature_verified': verified['whole_file_signature_verified'],
        'signer_certificate_sha256': verified['signer_certificate_sha256'],
        'modem_sha256': digest, 'modem_size': source.stat().st_size,
        'modemfirmware_sha256': firmware_digest, 'modemfirmware_size': firmware.stat().st_size,
        'china_base_modem_sha256': policy['base_modem_sha256'],
        'ready_to_flash': False, 'runtime_compatibility_verified': False,
        'phone_modified': False, 'nv_or_calibration_data_included': False,
        'pending': ['identify working device baseband', 'validate modem/vendor pairing on target build', 'call, SMS, data and IMS verification']
    }
    (out / 'global-radio-candidate.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (out / 'SHA256SUMS.txt').write_text(digest + '  NOT-INSTALLABLE-global-modem.img\n' + firmware_digest + '  NOT-INSTALLABLE-global-modemfirmware.img\n')
    (out / 'NOT-INSTALLABLE.txt').write_text('Authenticated global Android17 modem candidate only. Integration and runtime compatibility with the China-based Molcer OS are unverified. Do not flash this standalone candidate. No NV, IMEI or calibration data is included.\n')
    pathlib.Path('reports/global-radio-candidate.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest), flush=True)


if __name__ == '__main__':
    main()
