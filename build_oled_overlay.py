"""Compile an unsigned own overlay for default dark mode and a black wallpaper."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import xml.etree.ElementTree as ET

from build_brand_assets import DISPLAY_SIZE, encode_png

ANDROID = 'http://schemas.android.com/apk/res/android'
PACKAGE = 'com.molcer.os.tr.oleddefaults.g0'


def main():
    tools = pathlib.Path(os.environ['ANDROID_HOME'], 'build-tools/37.0.0')
    framework = pathlib.Path('work/mounted_system/system/framework/framework-res.apk')
    aapt = str(tools / 'aapt2')
    resources = subprocess.check_output([aapt, 'dump', 'resources', str(framework)], text=True)
    overlayable = subprocess.check_output([aapt, 'dump', 'overlayable', str(framework)], text=True)
    if overlayable.strip():
        raise ValueError('Framework overlay policy changed; named policies must be reviewed')
    if not re.search(r'resource 0x[0-9a-f]+ integer/config_defaultNightMode\s+\(\) 1\b', resources):
        raise ValueError('Expected reviewed default night-mode integer')
    if ' drawable/default_wallpaper\n' not in resources:
        raise ValueError('Expected framework default wallpaper drawable')
    root = pathlib.Path('work/oled-overlay')
    if root.exists():
        raise ValueError('Use fresh OLED compilation directory')
    res = root / 'res'
    for folder in ('values', 'xml', 'drawable-nodpi'):
        (res / folder).mkdir(parents=True, exist_ok=True)
    (res / 'values/defaults.xml').write_text('<resources><integer name="molcer_default_night_mode">2</integer></resources>\n')
    (res / 'xml/overlays.xml').write_text('<overlay><item target="integer/config_defaultNightMode" value="@integer/molcer_default_night_mode"/><item target="drawable/default_wallpaper" value="@drawable/molcer_black_wallpaper"/></overlay>\n')
    (res / 'drawable-nodpi/molcer_black_wallpaper.png').write_bytes(encode_png(*DISPLAY_SIZE, bytes(DISPLAY_SIZE[0] * DISPLAY_SIZE[1])))
    ET.register_namespace('android', ANDROID)
    manifest = ET.Element('manifest', {'package': PACKAGE, f'{{{ANDROID}}}versionCode': '1', f'{{{ANDROID}}}versionName': '0.2.0'})
    ET.SubElement(manifest, 'uses-sdk', {f'{{{ANDROID}}}minSdkVersion': '37', f'{{{ANDROID}}}targetSdkVersion': '37'})
    ET.SubElement(manifest, 'application', {f'{{{ANDROID}}}hasCode': 'false'})
    ET.SubElement(manifest, 'overlay', {f'{{{ANDROID}}}targetPackage': 'android', f'{{{ANDROID}}}isStatic': 'true',
        f'{{{ANDROID}}}priority': '999', f'{{{ANDROID}}}resourcesMap': '@xml/overlays'})
    manifest_path = root / 'AndroidManifest.xml'
    ET.ElementTree(manifest).write(manifest_path, encoding='utf-8', xml_declaration=True)
    compiled = root / 'compiled.zip'
    output = pathlib.Path('out/unsigned-oled/overlay/MolcerTurkish', PACKAGE + '.apk')
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([aapt, 'compile', '--dir', str(res), '-o', str(compiled)], check=True)
    subprocess.run([aapt, 'link', '-I', str(framework), '--manifest', str(manifest_path),
        '--no-resource-deduping', '--no-resource-removal', '-o', str(output), str(compiled)], check=True)
    report = {'schema': 1, 'original_apks_modified': False, 'preview_signing_key': False,
        'signing_status': 'unsigned-local-signing-required', 'credit': 'Molcer OS original black wallpaper and default dark-mode overlay.',
        'runtime_verified': False, 'all_app_backgrounds_black': False, 'user_can_change_theme': True,
        'sources': ['https://developer.android.com/reference/android/app/UiModeManager#MODE_NIGHT_YES',
        'https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/UiModeManagerService.java'],
        'targets': [{'package': 'android', 'purpose': 'default-dark-mode-and-wallpaper',
            'target_apk': 'system/system/framework/framework-res.apk', 'target_apk_sha256': hashlib.sha256(framework.read_bytes()).hexdigest(),
            'compiled_resources': ['integer/config_defaultNightMode', 'drawable/default_wallpaper'],
            'overlays': [PACKAGE]}]}
    pathlib.Path('reports/oled-overlays.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'unsigned_overlay': str(output), 'compiled_resources': 2, 'runtime_verified': False}))


if __name__ == '__main__':
    main()
