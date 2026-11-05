"""Keep optimization claims tied to exact package changes and preserved OEM policy."""
import hashlib
import re

ALLOWED_KEYS = {'ro.product.locale', 'ro.build.display.id', 'ro.molcer.os.name',
                'ro.molcer.os.version', 'persist.sys.timezone'}
ANALYTICS = {'com.miui.analytics', 'com.miui.systemAdSolution', 'com.miui.uireporter', 'com.miui.bugreport'}


def validate_product_properties(original, modified, version):
    expected = {'ro.product.locale': 'tr-TR', 'ro.build.display.id': 'Molcer OS ' + version,
                'ro.molcer.os.name': 'Molcer OS', 'ro.molcer.os.version': version,
                'persist.sys.timezone': 'Europe/Istanbul'}
    if not re.fullmatch(r'[0-9][a-zA-Z0-9.-]{0,63}', version):
        raise ValueError('Invalid Molcer OS version')
    def split(text):
        retained, selected = [], {}
        for line in text.splitlines():
            key, separator, value = line.partition('=')
            if separator and key in ALLOWED_KEYS:
                if key in selected:
                    raise ValueError('Duplicate customized product property: ' + key)
                selected[key] = value
            elif line:
                retained.append(line)
        return retained, selected
    old, old_custom = split(original)
    new, new_custom = split(modified)
    if old != new or new_custom != expected:
        raise ValueError('Unapproved OEM property change or incomplete localization/branding')
    if old_custom.get('ro.product.locale') != 'zh-CN':
        raise ValueError('Unexpected source locale')
    return {'permitted_property_changes': {key: {'before': old_custom.get(key), 'after': value}
            for key, value in expected.items()}, 'other_oem_property_lines_unchanged': True,
            'unchanged_lines_sha256': hashlib.sha256('\n'.join(old).encode()).hexdigest(),
            'cpu_gpu_scheduler_thermal_modem_properties_changed': False}


def optimization_report(properties, removed):
    analytics = sorted(set(removed.values()) & ANALYTICS)
    return {'schema': 1, 'phone_accessed': False, 'runtime_verified': False,
            'measured_battery_or_performance_improvement': False,
            'strategy': 'Remove reviewed optional applications and analytics packages; preserve OEM power and thermal policy.',
            'removed_analytics_ad_reporting_packages': analytics,
            'optional_app_count_removed': len(removed), 'removed_packages': removed,
            'selinux_or_verity_disabled': False, 'forced_cpu_gpu_clocks': False,
            'forced_display_refresh_rate': False, 'network_provisioning_bypassed': False,
            'all_telemetry_eliminated': False, 'property_preservation': properties}
