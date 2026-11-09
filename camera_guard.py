"""Fail closed if debloat changes identified product camera/core dependencies.

This guard consumes tree_audit snapshots. It does not access a device, change a
file, infer runtime compatibility, or approve firmware from another release.
"""
import copy
import hashlib
import json
import pathlib
import re

APPROVED_REMOVALS = {
    'app/AnalyticsCore': 'com.miui.analytics',
    'app/MSA': 'com.miui.systemAdSolution',
    'app/MIUIReporter': 'com.miui.uireporter',
    'app/MiBugReportOS4': 'com.miui.bugreport',
    'data-app/MIUIDuokanReader': 'com.duokan.reader',
    'data-app/MIUIGameCenter': 'com.xiaomi.gamecenter',
    'data-app/MIUIMusicT': 'com.miui.player',
    'data-app/MIUIVideo': 'com.miui.video',
    'data-app/MIUIYoupin': 'com.xiaomi.youpin',
    'data-app/MiShop': 'com.xiaomi.shop',
    'data-app/wps-lite': 'cn.wps.moffice_eng.xiaomi.lite',
    'data-app/Health': 'com.mi.health',
    'data-app/MIpay': 'com.mipay.wallet',
    'data-app/SmartHome': 'com.xiaomi.smarthome',
    'data-app/OS4VipAccount': 'com.xiaomi.vipaccount',
}
DEPENDENCY_REVIEW_REQUIRED = frozenset({
    'com.mi.health', 'com.mipay.wallet', 'com.xiaomi.smarthome', 'com.xiaomi.vipaccount',
})
APPROVED_REPLACEMENTS = {
    'priv-app/MIUIBrowser': 'com.android.browser',
    'priv-app/GooglePlayServicesUpdater': 'com.android.vending',
}
REQUIRED_CAMERA_PACKAGES = {
    'com.android.camera': 'priv-app/MiuiCamera/MiuiCamera.apk',
    'com.miui.gallery': 'data-app/MIUIGallery/MIUIGallery.apk',
    'com.miui.mediaeditor': 'data-app/MiMediaEditor/MiMediaEditor.apk',
    'com.hyper.gallery.plugin': 'data-app/HyperGalleryPluginCn/HyperGalleryPluginCn.apk',
    'com.miui.extraphoto': 'priv-app/MiuiExtraPhoto/MiuiExtraPhoto.apk',
    'com.xiaomi.cameratools': 'app/CameraTools_beta/CameraTools_beta.apk',
    'com.miui.mediaviewer': 'app/MediaViewer/MediaViewer.apk',
}
PROTECTED_PACKAGE_IDS = frozenset(REQUIRED_CAMERA_PACKAGES) | {
    'com.android.cameraextensions', 'com.xiaomi.cameramind',
    'com.android.imsserviceentitlement', 'com.android.carrierconfig.overlay.common',
    'com.miui.systemui.carriers.overlay', 'com.mfashiongallery.emag',
}
PROTECTED_PREFIXES = ('lib', 'lib64', 'framework', 'apex', 'etc/permissions', 'etc/sysconfig')
PROTECTED_PATH_MARKERS = ('camera', 'gallery', 'mediaeditor', 'extraphoto', 'mediaviewer',
                          'camx', 'chromatix', 'cameraopt', 'leica', 'codec', 'media_profiles',
                          'ims', 'carrier', 'thermal', 'powerhint', 'power_policy')


def clean_path(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise ValueError('Invalid product image path')
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(p in ('.', '..') for p in value.split('/')) or str(path) != value:
        raise ValueError('Unsafe or noncanonical product image path')
    return value


def overlaps(first, second):
    return first == second or first.startswith(second + '/') or second.startswith(first + '/')


def inventory_packages(inventory):
    result = {}
    for item in inventory.get('apk_packages', []):
        path = clean_path(item['path'])
        if path in result:
            raise ValueError('Duplicate inventory path: ' + path)
        raw = item.get('package', '')
        match = re.search(r"^package: name='([^']+)'", raw)
        if not match:
            # Unknown identities cannot be used to justify a removal.
            result[path] = None
        else:
            result[path] = match.group(1)
    return result


def validate_debloat_policy(config, inventory, dependency_report=None):
    if config.get('device') != 'xuanyuan' or config.get('base') != 'OS4.0.0.18.XOACNXM':
        raise ValueError('Guard is pinned to the reviewed xuanyuan source')
    observed = inventory_packages(inventory)
    selected, reviewed = {}, []
    for action, approved in [('remove', APPROVED_REMOVALS), ('replace', APPROVED_REPLACEMENTS)]:
        entries = config.get(action, {})
        if not isinstance(entries, dict):
            raise ValueError('Debloat actions must be exact directory/package mappings')
        for directory, identity in entries.items():
            clean_path(directory)
            if directory not in approved or approved[directory] != identity:
                raise ValueError('Unreviewed removal or replacement: ' + directory)
            if identity in PROTECTED_PACKAGE_IDS or any(overlaps(directory, old) for old in selected):
                raise ValueError('Protected or overlapping debloat selection: ' + directory)
            matching = {path: package for path, package in observed.items()
                        if path == directory or path.startswith(directory + '/')}
            if not matching or any(package != identity for package in matching.values()):
                raise ValueError('Inventory does not prove exact removal identity: ' + directory)
            if identity in DEPENDENCY_REVIEW_REQUIRED:
                if not dependency_report or not dependency_report.get('dependency_scan_complete'):
                    raise ValueError('Complete dependency inspection required for ' + identity)
                candidate = dependency_report.get('candidates', {}).get(identity, {})
                findings = candidate.get('hard_dependency_findings')
                if (not candidate.get('exact_candidate_found')
                        or candidate.get('expected_path') not in ['product/' + path for path in matching]
                        or not isinstance(findings, list)
                        or candidate.get('required_library_findings')
                        or candidate.get('shared_user_id_findings')):
                    raise ValueError('Unresolved declared dependency or candidate mismatch: ' + identity)
                if findings:
                    review = config.get('dependency_reviews', {}).get(identity, {})
                    canonical = json.dumps(findings, sort_keys=True, separators=(',', ':'),
                                           ensure_ascii=False).encode('utf-8')
                    if (not all(item.get('kind') == 'permission-defined-by-candidate' for item in findings)
                            or review.get('hard_findings_sha256') != hashlib.sha256(canonical).hexdigest()):
                        raise ValueError('Unresolved declared dependency or candidate mismatch: ' + identity)
                reviewed.append(identity)
            selected[directory] = identity
    return observed, selected, reviewed


def prepare_product_guard(before, config, product_inventory, dependency_report=None):
    """Call after stock snapshot and before deleting or modifying staged files."""
    observed, removed, reviewed = validate_debloat_policy(config, product_inventory, dependency_report)
    for path in observed:
        if any(path.startswith(directory + '/') for directory in removed):
            if path not in before or 'sha256' not in before[path]:
                raise ValueError('Removal inventory is not backed by the stock snapshot: ' + path)
    required = {}
    for identity, path in REQUIRED_CAMERA_PACKAGES.items():
        if observed.get(path) != identity:
            raise ValueError('Required camera/media package missing or changed: ' + identity)
        record = before.get(path)
        if not record or not re.fullmatch('[0-9a-f]{64}', str(record.get('sha256', ''))):
            raise ValueError('Missing actual stock file hash for ' + path)
        required[identity] = path
    package_roots = {str(pathlib.PurePosixPath(path).parent) for path, identity in observed.items()
                     if identity in PROTECTED_PACKAGE_IDS}
    protected = {}
    reasons = {}
    for path, record in before.items():
        clean_path(path)
        why = []
        if any(path == root or path.startswith(root + '/') for root in package_roots):
            why.append('declared-protected-package')
        if any(path == root or path.startswith(root + '/') for root in PROTECTED_PREFIXES):
            why.append('shared-library-framework-apex-or-permissions')
        if any(marker in path.casefold() for marker in PROTECTED_PATH_MARKERS):
            why.append('camera-media-ims-carrier-or-thermal-path')
        if why:
            if any(overlaps(path, directory) for directory in removed):
                raise ValueError('Debloat intersects protected asset: ' + path)
            if not {'mode', 'uid', 'gid', 'xattrs'} <= record.keys():
                raise ValueError('Incomplete filesystem metadata evidence for ' + path)
            if 'sha256' in record:
                required_fields = {'sha256', 'size', 'mode', 'uid', 'gid', 'xattrs'}
                if not required_fields <= record.keys():
                    raise ValueError('Incomplete hash/permission evidence for ' + path)
            protected[path] = copy.deepcopy(record)
            reasons[path] = why
    if not protected:
        raise ValueError('No protected assets were identified')
    return {'protected_snapshot': protected, 'path_reasons': reasons,
            'required_camera_packages': required, 'reviewed_removals': removed,
            'new_optional_dependencies_checked': reviewed,
            'scope': 'Identified product camera/media assets and shared code/configuration; no runtime or cross-partition guarantee'}


def verify_product_guard(plan, after):
    """Return preservation evidence only after every protected entry matches."""
    protected = plan['protected_snapshot']
    for path, original in protected.items():
        if after.get(path) != original:
            raise ValueError('Protected dependency changed or removed: ' + path)
    # Record an aggregate over metadata as well as individual APK hashes so the
    # verdict can be tied to the exact audited bytes without embedding a huge tree.
    canonical = json.dumps(protected, sort_keys=True, separators=(',', ':')).encode()
    return {
        'scope': plan['scope'], 'phone_accessed': False, 'runtime_verified': False,
        'camera_runtime_verified': False, 'cross_partition_compatibility_verified': False,
        'camera_dependency_preserved': True,
        'camera_dependency_preserved_definition': 'All identified product paths match their stock hashes and filesystem metadata',
        'protected_entry_count': len(protected),
        'protected_file_count': sum('sha256' in record for record in protected.values()),
        'protected_snapshot_sha256': hashlib.sha256(canonical).hexdigest(),
        'protected_paths': sorted(protected),
        'required_camera_packages': {identity: {'path': path, 'sha256': protected[path]['sha256'],
                                               'size': protected[path]['size']}
                                     for identity, path in plan['required_camera_packages'].items()},
        'reviewed_removals': plan['reviewed_removals'],
        'new_optional_dependencies_checked': plan['new_optional_dependencies_checked'],
        'limitations': ['Static product preservation does not test camera behavior.',
                       'Vendor, ODM, DSP and selected EU radio interoperability are outside this product-tree check.',
                       'Manifest/XML inspection cannot establish absence of reflective runtime dependencies.'],
    }
