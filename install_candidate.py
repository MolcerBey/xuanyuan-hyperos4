"""Verify and optionally install the offline candidate with explicit owner action."""
import argparse
import json
import pathlib
import re
import subprocess

from verify_installation_package import verify_package


FLASH_ORDER = (
    'abl', 'xbl', 'xbl_config', 'cpucp_dtb', 'shrm', 'aop', 'aop_config',
    'tz', 'devcfg', 'featenabler', 'hyp', 'uefi', 'uefisecapp', 'spuservice',
    'modem', 'modemfirmware', 'bluetooth', 'dsp', 'keymaster', 'qupfw',
    'multiimgqti', 'cpucp', 'pdp_cdb', 'soccp_debug', 'soccp_dcd', 'pdp',
    'xbl_ramdump', 'imagefv', 'pvmfw', 'init_boot', 'idmanager', 'super',
    'vendor_boot', 'dtbo', 'vm-bootsys', 'vbmeta', 'vbmeta_system', 'recovery', 'boot',
)
FORBIDDEN = {'countrycode', 'userdata', 'metadata', 'persist', 'modemst1', 'modemst2',
             'fsg', 'fsc', 'frp', 'logfs', 'storsec', 'toolsfv', 'misc', 'rescue'}


def installation_plan():
    if len(FLASH_ORDER) != 39 or len(set(FLASH_ORDER)) != 39 or FORBIDDEN.intersection(FLASH_ORDER):
        raise ValueError('Invalid or unsafe installation order')
    return [{'image': name, 'target': 'super' if name == 'super' else name + '_ab'}
            for name in FLASH_ORDER]


def getvar_output(result):
    text = (result.stdout or '') + '\n' + (result.stderr or '')
    if result.returncode:
        raise ValueError('Fastboot query failed: ' + text.strip()[-1000:])
    return text


def parse_getvar(text, name):
    match = re.search(r'(?m)^' + re.escape(name) + r':\s*([^\r\n]+)', text)
    if not match:
        raise ValueError('Fastboot did not provide required variable: ' + name)
    return match.group(1).strip()


def parse_partition_size(text, target):
    value = parse_getvar(text, 'partition-size:' + target)
    if not re.fullmatch(r'(?:0x[0-9a-fA-F]+|[0-9]+)', value):
        raise ValueError('Invalid partition capacity for ' + target)
    size = int(value, 0)
    if size <= 0:
        raise ValueError('Empty partition capacity for ' + target)
    return size


def run_query(fastboot, variable):
    result = subprocess.run([fastboot, 'getvar', variable], capture_output=True,
                            text=True, timeout=60)
    return getvar_output(result)


def preflight(fastboot, image_root, plan):
    product = parse_getvar(run_query(fastboot, 'product'), 'product')
    unlocked = parse_getvar(run_query(fastboot, 'unlocked'), 'unlocked').lower()
    slot = parse_getvar(run_query(fastboot, 'current-slot'), 'current-slot').lower()
    if product != 'xuanyuan' or unlocked != 'yes' or slot not in ('a', 'b'):
        raise ValueError('Device model, unlocked bootloader or A/B slot precondition failed')
    capacities = {}
    for item in plan:
        image = pathlib.Path(image_root) / (item['image'] + '.img')
        targets = ['super'] if item['target'] == 'super' else [item['image'] + '_a', item['image'] + '_b']
        for target in targets:
            size = parse_partition_size(run_query(fastboot, 'partition-size:' + target), target)
            if image.stat().st_size > size:
                raise ValueError('Image exceeds actual device partition capacity: ' + target)
            capacities[target] = size
    return {'product': product, 'bootloader_unlocked': True, 'previous_slot': slot,
            'partition_capacities': capacities}


def run_checked(command):
    print('Running:', ' '.join(map(str, command)), flush=True)
    result = subprocess.run(list(map(str, command)), timeout=1800)
    if result.returncode:
        raise ValueError('Installation command failed; no further writes were attempted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', default='reports/assembled-candidate-manifest.json')
    parser.add_argument('--images', required=True)
    parser.add_argument('--fastboot', default='fastboot')
    parser.add_argument('--execute', action='store_true',
                        help='Access the phone and flash after checks and an interactive confirmation')
    parser.add_argument('--reboot', action='store_true', help='Reboot only after every write succeeds')
    args = parser.parse_args()
    report = verify_package(json.loads(pathlib.Path(args.manifest).read_text(encoding='utf-8')),
                            args.images)
    plan = installation_plan()
    if {item['name'] for item in report['images']} != {item['image'] for item in plan}:
        raise ValueError('Verified image set differs from the reviewed installation plan')
    if not args.execute:
        print(json.dumps({'status': 'local-images-verified-no-phone-access', 'image_count': 39,
                          'plan': plan, 'reboot_requested': args.reboot}, indent=2))
        return
    evidence = preflight(args.fastboot, args.images, plan)
    print(json.dumps(evidence, indent=2))
    confirmation = input('Type XUANYUAN-INSTALL to flash both slots without wiping userdata: ')
    if confirmation != 'XUANYUAN-INSTALL':
        raise ValueError('Installation cancelled before any write')
    for item in plan:
        source = pathlib.Path(args.images) / (item['image'] + '.img')
        run_checked([args.fastboot, 'flash', item['target'], source])
    run_checked([args.fastboot, 'set_active', 'a'])
    if args.reboot:
        run_checked([args.fastboot, 'reboot'])
    print(json.dumps({'status': 'all-flash-commands-completed', 'runtime_verified': False,
                      'active_slot': 'a', 'rebooted': args.reboot}))


if __name__ == '__main__':
    main()
