"""Inspect downloaded, mounted ROM apps; never access a phone or remove an app."""
import argparse
import collections
import concurrent.futures
import gzip
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from xml.parsers import expat

PARTITIONS = ('product', 'system', 'system_ext', 'vendor')
CANDIDATES = {
    'com.mi.health': 'product/data-app/Health/Health.apk',
    'com.mipay.wallet': 'product/data-app/MIpay/MIpay.apk',
    'com.xiaomi.smarthome': 'product/data-app/SmartHome/SmartHome.apk',
    'com.xiaomi.vipaccount': 'product/data-app/OS4VipAccount/OS4VipAccount.apk',
}
TARGETS = {
    'framework-res': 'system/system/framework/framework-res.apk',
    'Provision': 'system_ext/priv-app/Provision/Provision.apk',
    'MiuiHome': 'product/priv-app/MiuiHome/MiuiHome.apk',
    'MiuiSystemUI': 'system_ext/priv-app/MiuiSystemUI/MiuiSystemUI.apk',
    'Settings': 'system_ext/priv-app/Settings/Settings.apk',
}
MAX_APKS = 1500
MAX_MANIFEST = 2 * 1024**2
MAX_XML = 4 * 1024**2
ANDROID_ATTRIBUTE_PREFIX = 'http://schemas.android.com/apk/res/android:'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def decode_attribute(raw):
    match = re.search(r'\(Raw: (".*")\)\s*$', raw)
    literal = match.group(1) if match else raw.strip()
    if literal.startswith('"') and literal.endswith('"'):
        try:
            return json.loads(literal)
        except (ValueError, TypeError):
            return literal[1:-1]
    return literal


def parse_manifest(text):
    """Parse the indentation tree of aapt2 dump xmltree, not arbitrary XML."""
    root, stack = None, []
    for line in text.splitlines():
        element = re.match(r'^(\s*)E: ([^\s(]+)', line)
        if element:
            indent = len(element.group(1))
            node = {'tag': element.group(2), 'attrs': {}, 'children': []}
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1]['children'].append(node)
            elif root is None:
                root = node
            else:
                raise ValueError('Multiple manifest roots')
            stack.append((indent, node))
            continue
        attribute = re.match(r'^\s*A: ([^\s(=]+)(?:\(0x[0-9a-fA-F]+\))?=(.*)$', line)
        if attribute and stack:
            name = attribute.group(1)
            # SDK 37 emits the full namespace URI, while older aapt2 versions
            # use android:name. Downstream dependency keys use the latter.
            if name.startswith(ANDROID_ATTRIBUTE_PREFIX):
                name = 'android:' + name[len(ANDROID_ATTRIBUTE_PREFIX):]
            attrs = stack[-1][1]['attrs']
            if name in attrs:
                raise ValueError('Duplicate normalized manifest attribute: ' + name)
            attrs[name] = decode_attribute(attribute.group(2))
    if not root or root['tag'] != 'manifest':
        raise ValueError('No manifest root in aapt2 dump')
    package = root['attrs'].get('package', '')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', package):
        raise ValueError('Missing or unrecognized manifest package')
    nodes = []
    pending = [root]
    while pending:
        node = pending.pop()
        nodes.append(node)
        pending.extend(node['children'])
    def selected(tags):
        return [dict(n['attrs'], tag=n['tag']) for n in nodes if n['tag'] in tags]
    return {
        'package': package, 'shared_user_id': root['attrs'].get('android:sharedUserId'),
        'provided_libraries': selected({'library', 'static-library', 'sdk-library'}),
        'used_libraries': selected({'uses-library', 'uses-static-library', 'uses-sdk-library', 'uses-native-library'}),
        'defined_permissions': selected({'permission', 'permission-tree'}),
        'used_permissions': selected({'uses-permission', 'uses-permission-sdk-23', 'uses-permission-sdk-m'}),
        'providers': [dict(child['attrs'], tag=child['tag']) for node in nodes if node['tag'] == 'application'
                      for child in node['children'] if child['tag'] == 'provider'],
        'queries': selected({'package'}),
        'application': selected({'application'}),
        'overlays': selected({'overlay'}),
    }


def inspect_apk(item, aapt):
    partition, path, relative = item
    result = {'path': partition + '/' + relative, 'size': path.stat().st_size,
              'sha256': digest(path)}
    try:
        with tempfile.TemporaryDirectory(prefix='molcer-manifest-') as tmp:
            apk = path
            if path.name.endswith('.gz'):
                apk = pathlib.Path(tmp) / path.stem
                total = 0
                with gzip.open(path, 'rb') as source, apk.open('xb') as target:
                    while chunk := source.read(4 * 1024**2):
                        total += len(chunk)
                        if total > 1024**3:
                            raise ValueError('Decompressed APK exceeds inventory bound')
                        target.write(chunk)
            proc = subprocess.run([aapt, 'dump', 'xmltree', '--file', 'AndroidManifest.xml', str(apk)],
                                  text=True, encoding='utf-8', errors='replace',
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if proc.returncode:
            raise ValueError('aapt2 failed: ' + proc.stderr[:500])
        if len(proc.stdout.encode()) > MAX_MANIFEST:
            raise ValueError('Manifest exceeds inspection bound')
        result.update(parse_manifest(proc.stdout))
        if result['path'] in CANDIDATES.values():
            result['manifest_text'] = proc.stdout[:262144]
            result['manifest_text_truncated'] = len(proc.stdout) > 262144
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)[:700]
    return result


def build_reverse_dependencies(apps):
    packages = collections.defaultdict(list)
    for app in apps:
        if 'package' in app:
            packages[app['package']].append(app)
    result = {}
    for identity, expected_path in CANDIDATES.items():
        matches = packages.get(identity, [])
        selected = [a for a in matches if a['path'] == expected_path]
        item = {'expected_path': expected_path, 'exact_candidate_found': len(selected) == 1,
                'package_paths': [a['path'] for a in matches], 'hard_dependency_findings': [],
                'soft_reference_findings': [], 'runtime_optional_status_verified': False}
        if len(selected) != 1:
            result[identity] = item
            continue
        candidate = selected[0]
        item['manifest'] = candidate
        libraries = {x.get('android:name') for x in candidate['provided_libraries']} - {None}
        permissions = {x.get('android:name') for x in candidate['defined_permissions']} - {None}
        item['provider_authorities'] = sorted({authority for p in candidate['providers']
            for authority in p.get('android:authorities', '').split(';') if authority})
        for app in apps:
            if app.get('package') == identity or 'package' not in app:
                continue
            base = {'consumer': app['package'], 'path': app['path']}
            shared = candidate.get('shared_user_id')
            if shared and shared == app.get('shared_user_id'):
                item['hard_dependency_findings'].append({**base, 'kind': 'shared-user-id', 'name': shared,
                    'interpretation': 'Coupling requiring review, not proof the app cannot be removed'})
            for lib in app['used_libraries']:
                name = lib.get('android:name')
                if name in libraries:
                    optional = lib.get('android:required') in ('false', '(type 0x12)0x0', '(type 0x12)0x00000000')
                    finding = {**base, 'kind': lib['tag'], 'name': name, 'required': not optional}
                    item['soft_reference_findings' if optional else 'hard_dependency_findings'].append(finding)
            for permission in app['used_permissions']:
                name = permission.get('android:name')
                if name in permissions:
                    item['hard_dependency_findings'].append({**base, 'kind': 'permission-defined-by-candidate', 'name': name,
                        'interpretation': 'Declared permission dependency; feature criticality requires review'})
            if any(q.get('android:name') == identity for q in app['queries']):
                item['soft_reference_findings'].append({**base, 'kind': 'package-query', 'name': identity})
        result[identity] = item
    return result


def parse_xml_reference(text):
    """Read a document, or explicitly reported multiple-root OEM fragments.

    Only Expat's exact trailing-document-element error permits this fallback.
    Keep all elements and the original text; never repair mismatched XML or
    discard arbitrary non-XML data following a valid root.
    """
    try:
        return ET.fromstring(text), {'parse_mode': 'xml-document'}
    except ET.ParseError as exc:
        if exc.code != expat.errors.codes[expat.errors.XML_ERROR_JUNK_AFTER_DOC_ELEMENT]:
            raise
        initial_error = str(exc)
    stripped, declarations = re.subn(r'\A\ufeff?\s*<\?xml\s[^?]*\?>', '', text, count=1)
    wrapped = ET.fromstring('<molcer-xml-fragments>\n' + stripped + '\n</molcer-xml-fragments>')
    if (len(wrapped) < 2 or (wrapped.text or '').strip() or
            any((child.tail or '').strip() for child in wrapped)):
        raise ValueError('Trailing XML content is not a sequence of complete root fragments')
    return wrapped, {'parse_mode': 'xml-fragments-wrapped',
                     'initial_parse_error': initial_error,
                     'leading_xml_declaration_removed_for_parsing': bool(declarations),
                     'fragment_root_count': len(wrapped)}


def inspect_xml(roots, candidates):
    findings, errors = [], []
    needles = set(candidates)
    for candidate in candidates.values():
        needles.add('/' + candidate['expected_path'])
        needles.add('/' + str(pathlib.PurePosixPath(candidate['expected_path']).parent))
        needles.update(candidate.get('provider_authorities', []))
        manifest = candidate.get('manifest', {})
        needles.update(x.get('android:name', '') for x in manifest.get('provided_libraries', []))
        needles.update(x.get('android:name', '') for x in manifest.get('defined_permissions', []))
    needles.discard('')
    files = []
    for partition, root in roots.items():
        for etc in [root / 'etc', root / 'system/etc']:
            if etc.is_dir():
                files.extend((partition, root, p) for p in etc.rglob('*.xml') if p.is_file() and not p.is_symlink())
    if len(files) > 12000:
        raise ValueError('XML inventory exceeds bound')
    for partition, root, path in files:
        evidence = {'path': partition + '/' + path.relative_to(root).as_posix(),
                    'raw_text_limit_bytes': MAX_XML}
        if path.stat().st_size > MAX_XML:
            errors.append({**evidence, 'error': 'XML exceeds bound',
                           'parse_mode': 'not-parsed-size-limit', 'raw_text_truncated': True})
            continue
        try:
            with path.open('rb') as stream:
                raw = stream.read(MAX_XML + 1)
            if len(raw) > MAX_XML:
                raise ValueError('XML grew beyond inspection bound')
            evidence.update({'sha256': hashlib.sha256(raw).hexdigest(), 'raw_size_bytes': len(raw),
                             'raw_text': raw.decode('utf-8', errors='replace'),
                             'raw_text_truncated': False})
            text = raw.decode('utf-8')
            hits = sorted(n for n in needles if n in text)
            if not hits:
                continue
            parsed, parse_evidence = parse_xml_reference(text)
            evidence.update(parse_evidence)
            entries = []
            for node in parsed.iter():
                if any(n in str(node.attrib) or n in (node.text or '') for n in hits):
                    entries.append({'tag': node.tag, 'attributes': dict(node.attrib),
                                    'text': (node.text or '').strip()[:500]})
            findings.append({**evidence,
                             'references': hits, 'entries': entries[:100], 'entries_truncated': len(entries) > 100,
                             'interpretation': 'Configuration reference; inspect semantics before classifying as a hard dependency'})
        except (OSError, UnicodeError, ValueError, ET.ParseError) as exc:
            errors.append({**evidence, 'parse_mode': 'failed', 'error': str(exc)[:300]})
    return {'files_considered': len(files), 'candidate_references': findings, 'errors': errors}


def dump_translation_targets(roots, aapt, output):
    output.mkdir(parents=True, exist_ok=True)
    report = []
    for name, relative in TARGETS.items():
        partition, path = relative.split('/', 1)
        apk = roots[partition] / path
        item = {'target': name, 'path': relative}
        try:
            item['sha256'] = digest(apk)
            for kind in ('resources', 'overlayable'):
                target = output / (name + '.' + kind + '.txt')
                with target.open('w', encoding='utf-8') as dest:
                    proc = subprocess.run([aapt, 'dump', kind, str(apk)], stdout=dest, stderr=subprocess.PIPE,
                                          text=True, encoding='utf-8', errors='replace', timeout=120)
                if proc.returncode:
                    raise ValueError(kind + ' dump failed: ' + proc.stderr[:500])
                if target.stat().st_size > 64 * 1024**2:
                    raise ValueError('Translation dump exceeds bound')
                item[kind + '_dump'] = str(target)
                item[kind + '_sha256'] = digest(target)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            item['error'] = str(exc)[:700]
        report.append(item)
    return report


def inspect_media(roots):
    files, errors = [], []
    for partition, paths in [('product', ['media']), ('system', ['system/media', 'media'])]:
        root = roots[partition]
        seen = set()
        for relative in paths:
            directory = root / relative
            if not directory.is_dir():
                continue
            for path in directory.rglob('*'):
                if not path.is_file() or path.is_symlink() or path in seen:
                    continue
                seen.add(path)
                if len(seen) > 3000:
                    raise ValueError('Media file inventory exceeds bound')
                if not any(x in path.as_posix().lower() for x in ('bootanimation', 'wallpaper', 'lockscreen')):
                    continue
                record = {'path': partition + '/' + path.relative_to(root).as_posix(), 'size': path.stat().st_size}
                try:
                    record['sha256'] = digest(path)
                    if 'bootanimation' in path.name.lower() and zipfile.is_zipfile(path):
                        with zipfile.ZipFile(path) as z:
                            members = [i for i in z.infolist() if i.filename == 'desc.txt']
                            if len(members) == 1 and members[0].file_size <= 65536:
                                record['desc_txt'] = z.read(members[0]).decode('utf-8', errors='replace')
                            else:
                                record['desc_error'] = 'Missing, duplicate or oversized desc.txt'
                except (OSError, ValueError, zipfile.BadZipFile) as exc:
                    errors.append({'path': record['path'], 'error': str(exc)[:300]})
                files.append(record)
    return {'files': files, 'errors': errors}


def inspect_overlay_configuration(product_root):
    """Collect stock overlay ordering and bounded merges without resolving IDs."""
    base = product_root / 'overlay/config'
    initial = base / 'config.xml'
    report = {'exists': initial.is_file(), 'files': [], 'errors': [], 'max_total_bytes': 65536,
              'merge_path_interpretation': 'Paths resolved relative to the containing configuration file; no execution'}
    if not initial.is_file():
        return report
    pending, seen, total = [initial], set(), 0
    while pending:
        path = pending.pop(0)
        relative = path.relative_to(product_root).as_posix()
        if path in seen:
            report['errors'].append({'path': relative, 'error': 'Repeated merge path; possible cycle'})
            continue
        seen.add(path)
        try:
            if len(seen) > 32 or path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
                raise ValueError('Unsafe or excessive overlay configuration merges')
            size = path.stat().st_size
            if total + size > 65536:
                raise ValueError('Overlay configuration corpus exceeds 64 KiB')
            raw = path.read_bytes()
            total += len(raw)
            text = raw.decode('utf-8')
            tree = ET.fromstring(text)
            if tree.tag != 'config':
                raise ValueError('Unexpected overlay configuration root')
            merges = []
            for node in tree:
                if node.tag != 'merge':
                    continue
                value = node.get('path', '')
                pure = pathlib.PurePosixPath(value)
                if not value or pure.is_absolute() or '..' in pure.parts or '\\' in value:
                    raise ValueError('Unsafe overlay merge path')
                merges.append(value)
                pending.append(path.parent / value)
            report['files'].append({'path': 'product/' + relative, 'size': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest(), 'text': text, 'merge_paths': merges})
        except (OSError, UnicodeError, ValueError, ET.ParseError) as exc:
            report['errors'].append({'path': relative, 'error': str(exc)[:500]})
    report['total_bytes'] = total
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aapt2', default=str(pathlib.Path(os.environ.get('ANDROID_HOME', ''), 'build-tools/37.0.0/aapt2')))
    parser.add_argument('--work', default='work')
    parser.add_argument('--output', default='reports/app-dependencies.json')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.workers <= 4:
        raise ValueError('Use one to four manifest workers')
    work = pathlib.Path(args.work)
    roots = {part: work / ('mounted_' + part) for part in PARTITIONS}
    if any(not root.is_dir() for root in roots.values()):
        raise ValueError('All four downloaded image mount directories are required')
    apks = []
    for part, root in roots.items():
        for path in sorted(set(root.rglob('*.apk')) | set(root.rglob('*.apk.gz'))):
            if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()):
                apks.append((part, path, path.relative_to(root).as_posix()))
    if not apks or len(apks) > MAX_APKS:
        raise ValueError('Unexpected APK inventory size')
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        apps = list(pool.map(lambda item: inspect_apk(item, args.aapt2), apks))
    candidates = build_reverse_dependencies(apps)
    report = {'phone_accessed': False, 'source_files_modified': False, 'apps_removed': False,
              'scope': 'Declared APK/XML dependencies only; reflective calls and runtime optionality are unverified',
              'apps': apps, 'candidates': candidates, 'xml': inspect_xml(roots, candidates),
              'translation_dumps': dump_translation_targets(roots, args.aapt2, work / 'translation-dumps'),
              'media': inspect_media(roots), 'overlay_configuration': inspect_overlay_configuration(roots['product'])}
    errors = [{'path': x['path'], 'error': x['error']} for x in apps if 'error' in x]
    report['manifest_errors'] = errors
    report['dependency_scan_complete'] = not errors and not report['xml']['errors']
    report['automatic_removal_approved'] = False
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'apk_count': len(apps), 'manifest_errors': len(errors),
          'xml_errors': len(report['xml']['errors']), 'dependency_scan_complete': report['dependency_scan_complete'],
          'candidates': {name: {'found': x['exact_candidate_found'], 'hard_findings': len(x['hard_dependency_findings']),
                               'soft_findings': len(x['soft_reference_findings'])} for name, x in candidates.items()},
          'translation_dump_errors': sum('error' in x for x in report['translation_dumps']),
          'media_files': len(report['media']['files']), 'automatic_removal_approved': False}), flush=True)
    if errors or any('error' in x for x in report['translation_dumps']):
        raise ValueError('Incomplete manifest/resource inspection; see saved report')


if __name__ == '__main__':
    main()
