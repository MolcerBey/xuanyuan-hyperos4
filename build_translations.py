"""Build resource-only Turkish overlays without modifying OEM APKs or signatures."""
import collections
import copy
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

ANDROID = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID)
TARGETS = {
    "framework-res.apk": ("system/system/framework/framework-res.apk", "android"),
    "Provision.apk": ("system_ext/priv-app/Provision/Provision.apk", "com.android.provision"),
    "AndroidDefaults.apk": ("system/system/framework/framework-res.apk", "android"),
    "MiuiHome.apk": ("product/priv-app/MiuiHome/MiuiHome.apk", "com.miui.home"),
    "MiuiSystemUI.apk": ("system_ext/priv-app/MiuiSystemUI/MiuiSystemUI.apk", "com.android.systemui"),
    "Settings.apk": ("system_ext/priv-app/Settings/Settings.apk", "com.android.settings"),
}


def allowed_resources(text):
    mapping, name, permitted = {}, None, False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('name="'):
            name = re.match(r'name="([^"]+)"', line).group(1)
            permitted = False
        elif line.startswith('policies="'):
            policies = re.findall(r"[a-z_]+", line.split('"')[1])
            permitted = bool(set(policies) & {"public", "product"})
        elif name and permitted and line.startswith("string/"):
            mapping[line] = name
    return mapping


def target_strings(text):
    result, current = {}, None
    for line in text.splitlines():
        match = re.match(r"\s*resource 0x[0-9a-fA-F]+ (\S+)", line)
        if match:
            current = match.group(1)
            result[current] = []
        elif current:
            result[current].append(line)
    return {key: "\n".join(value) for key, value in result.items() if key.startswith("string/")}


def default_string(resource_block):
    """Read only one unambiguous literal in aapt2's default () configuration.

    Localized values cannot establish the argument contract used by callers.
    References, styled values, multiline literals and unknown dump syntax are
    deliberately left for review instead of guessing their resolved value.
    """
    values = []
    for line in resource_block.splitlines():
        match = re.match(r'^\s*\(\)\s+(.*)$', line)
        if match:
            values.append(match.group(1).strip())
    if not values:
        return None, 'missing'
    if len(values) != 1:
        return None, 'ambiguous'
    raw = values[0]
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return None, 'non_literal'
    # aapt2 output uses quoted human-readable strings. Decode its common escape
    # sequences without evaluating arbitrary escapes or treating text as code.
    raw = raw[1:-1]
    output, index = [], 0
    escapes = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\', '"': '"', "'": "'"}
    while index < len(raw):
        char = raw[index]
        if char == '"':
            return None, 'ambiguous_literal'
        if char != '\\':
            output.append(char)
            index += 1
            continue
        index += 1
        if index == len(raw) or raw[index] not in escapes:
            return None, 'unknown_escape'
        output.append(escapes[raw[index]])
        index += 1
    return ''.join(output), 'literal'


FORMAT_TOKEN = re.compile(
    r'%(?:(?P<index>[1-9][0-9]*)\$)?(?P<flags>[-#+ 0,(<]*)'
    r'(?P<width>[1-9][0-9]*)?(?:\.(?P<precision>[0-9]+))?'
    r'(?:(?P<date>[tT])(?P<suffix>[A-Za-z])|(?P<conversion>[A-Za-z%]))'
)
DATE_SUFFIXES = frozenset('HIklMSLNpzZsQBbhAaCYyjmdeRTrDFc')


def format_signature(value):
    """Conservatively parse Java Formatter tokens into an argument contract.

    Explicit indices do not advance the ordinary-index counter. The '<' flag
    reuses the previous argument; %% and %n consume no argument. Conversion,
    flags, width, precision and token multiplicity must all survive translation.
    Unsupported or invalid syntax raises ValueError instead of assuming safety.
    """
    tokens = collections.Counter()
    ordinary, previous, position = 0, None, 0
    while True:
        start = value.find('%', position)
        if start < 0:
            return tokens
        match = FORMAT_TOKEN.match(value, start)
        if not match:
            raise ValueError('unrecognized percent sequence')
        position = match.end()
        flags = match['flags']
        if len(flags) != len(set(flags)):
            raise ValueError('duplicate formatter flag')
        width = int(match['width']) if match['width'] else None
        precision = int(match['precision']) if match['precision'] else None
        explicit = int(match['index']) if match['index'] else None
        if (width is not None and width > 10000 or precision is not None and precision > 10000
                or explicit is not None and explicit > 1000):
            raise ValueError('formatter bounds require manual review')
        reuse = '<' in flags
        effective_flags = set(flags) - {'<'}
        conversion = match['conversion']
        if match['date']:
            if match['suffix'] not in DATE_SUFFIXES:
                raise ValueError('unsupported date/time conversion')
            conversion = 't' + match['suffix']
            allowed, precision_allowed = {'-'}, False
        else:
            lower = conversion.lower()
            # Case-sensitive exceptions: Java has no %D, %O, %F, %N or %P.
            if conversion not in 'bBhHsScCdoxXeEfgGaA%n':
                raise ValueError('unsupported conversion')
            allowed = {
                'b': set('-'), 'h': set('-'), 's': set('-'), 'c': set('-'),
                'd': set('-+ 0,('), 'o': set('-#0'), 'x': set('-#0'),
                'e': set('-+ 0(#'), 'f': set('-+ 0,(#'),
                'g': set('-+ 0,('), 'a': set('-+ 0#'),
                '%': set('-'), 'n': set(),
            }[lower]
            precision_allowed = lower in 'bhs efga'.replace(' ', '')
            conversion = lower
        if not effective_flags <= allowed:
            raise ValueError('unsupported flag/conversion combination')
        if precision is not None and not precision_allowed:
            raise ValueError('precision is invalid for conversion')
        if ('-' in effective_flags or '0' in effective_flags) and width is None:
            raise ValueError('flag requires a width')
        if {'-', '0'} <= effective_flags or {'+', ' '} <= effective_flags:
            raise ValueError('incompatible formatter flags')
        if conversion in ('%', 'n'):
            if explicit is not None or reuse or conversion == 'n' and (width is not None or flags):
                raise ValueError('invalid non-argument conversion')
            argument = None
        elif reuse:
            if previous is None or explicit is not None:
                raise ValueError('invalid previous-argument reference')
            argument = previous
        elif explicit is not None:
            argument = explicit
        else:
            ordinary += 1
            argument = ordinary
        if argument is not None:
            previous = argument
        tokens[(argument, conversion, ''.join(sorted(effective_flags)), width, precision)] += 1


def format_check(value, resource_block):
    """Return (rejection reason or None, evidence) without executing a format."""
    target, status = default_string(resource_block)
    evidence = {'target_default_text': target, 'target_default_status': status,
                'format_checked': False}
    if '%' not in value and '%' not in resource_block:
        return None, evidence
    if target is None:
        return 'format_default_' + status, evidence
    evidence['format_checked'] = True
    try:
        original = format_signature(target)
    except ValueError as exc:
        evidence['format_error'] = str(exc)
        return 'format_invalid_target_default', evidence
    try:
        translated = format_signature(value)
    except ValueError as exc:
        evidence['format_error'] = str(exc)
        return 'format_invalid_translation', evidence
    if original != translated:
        return 'format_signature_mismatch', evidence
    return None, evidence


def positional_format(value):
    """Make verified argument indices explicit for aapt2's format validation."""
    format_signature(value)  # The normalizer is not an alternative validator.
    output, position, ordinary, previous = [], 0, 0, None
    for match in FORMAT_TOKEN.finditer(value):
        output.append(value[position:match.start()])
        if match['conversion'] in ('%', 'n'):
            output.append(match.group())
        else:
            if '<' in match['flags']:
                argument = previous
            elif match['index']:
                argument = int(match['index'])
            else:
                ordinary += 1
                argument = ordinary
            previous = argument
            flags = match['flags'].replace('<', '')
            precision = '.' + match['precision'] if match['precision'] is not None else ''
            conversion = match['date'] + match['suffix'] if match['date'] else match['conversion']
            output.append('%' + str(argument) + '$' + flags + (match['width'] or '') + precision + conversion)
        position = match.end()
    output.append(value[position:])
    result = ''.join(output)
    if format_signature(result) != format_signature(value):
        raise ValueError('Positional formatting changed the argument contract')
    return result


def select_entries(data, names, allowed, has_overlayable, *, defaults=False):
    """Keep resource/policy checks separate from auditable format validation."""
    groups = collections.defaultdict(list)
    skipped = collections.Counter()
    details = []
    format_verified = []
    for entry in ET.fromstring(data):
        name = entry.get('name', '')
        resource = 'string/' + name
        value = entry.text or ''
        block = names.get(resource, '')
        target, status = default_string(block)
        evidence = {'target_default_text': target, 'target_default_status': status}
        if entry.tag != 'string' or len(entry) or entry.get('translatable') == 'false':
            reason = 'non_plain_string'
        elif resource not in names:
            reason = 'not_in_this_base'
        elif not defaults and (re.match(r'(?:config|key|pref_key|uri|url|action|default)_', name)
                               or value.startswith(('@', '?')) or '://' in value):
            reason = 'non_ui_configuration'
        elif has_overlayable and resource not in allowed:
            reason = 'not_product_overlayable'
        else:
            reason, evidence = format_check(value, block)
        if reason:
            skipped[reason] += 1
            details.append({'name': name, 'resource': resource, 'source_tag': entry.tag,
                            'reason': reason, **evidence})
        else:
            if evidence.get('format_checked'):
                entry = copy.deepcopy(entry)
                entry.text = positional_format(value)
                format_verified.append(name)
            groups[allowed.get(resource, '')].append(entry)
    return groups, skipped, details, format_verified


def build(preview_sign=True):
    config = json.loads(pathlib.Path("translations.json").read_text())
    tools = pathlib.Path(os.environ["ANDROID_HOME"], "build-tools/37.0.0")
    aapt = str(tools / "aapt2")
    base = pathlib.Path("work/mounted_system/system/framework/framework-res.apk")
    work = pathlib.Path("work/translations")
    work.mkdir(parents=True, exist_ok=True)
    if preview_sign:
        password = work / "password.txt"
        password.write_text(secrets.token_urlsafe(32))
        password.chmod(0o600)
        key = work / "preview-key.p12"
        subprocess.run(["keytool", "-genkeypair", "-keystore", str(key), "-storetype", "PKCS12", "-storepass:file", str(password), "-keypass:file", str(password), "-alias", "molcer-preview", "-keyalg", "RSA", "-keysize", "3072", "-validity", "3650", "-dname", "CN=Molcer OS Preview", "-noprompt"], check=True)
        key.chmod(0o600)
    report = {"source": config["source"], "commit": config["commit"], "credit": config["credit"], "original_apks_modified": False, "runtime_verified": False, "complete_translation": False,
              "preview_signing_key": preview_sign,
              "signing_status": "temporary-preview-key" if preview_sign else "unsigned-local-signing-required", "targets": []}
    additions, overlays = {}, []
    for item in config["targets"] + [{"path": "internal/AndroidDefaults.apk"}]:
        filename = item["path"].split("/")[1]
        defaults = filename == "AndroidDefaults.apk"
        target_path, target_package = TARGETS[filename]
        partition, relative = target_path.split("/", 1)
        apk = pathlib.Path("work/mounted_" + partition, relative)
        resource_table = subprocess.check_output([aapt, "dump", "resources", str(apk)], text=True)
        overlayable = subprocess.check_output([aapt, "dump", "overlayable", str(apk)], text=True)
        names = target_strings(resource_table)
        allowed = allowed_resources(overlayable)
        if defaults:
            data = b'<resources><string name="config_defaultBrowser">com.android.chrome</string></resources>'
        else:
            url = f"https://raw.githubusercontent.com/{config['source']}/{config['commit']}/{item['path']}"
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(item["size"] + 1)
            digest = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
            if len(data) != item["size"] or digest != item["blob_sha1"]:
                raise ValueError("Translation source blob checksum mismatch")
        groups, skipped, details, format_verified = select_entries(
            data, names, allowed, bool(overlayable.strip()), defaults=defaults)
        target_report = {"package": target_package, "purpose": "default-browser" if defaults else "turkish-ui",
                         "source_path": item["path"], "target_apk": target_path,
                         "target_apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
                         "resource_dump_sha256": hashlib.sha256(resource_table.encode()).hexdigest(),
                         "compiled_strings": 0, "skipped": dict(skipped), "skipped_entries": details,
                         "format_verified_strings": len(format_verified), "format_verified_names": format_verified,
                         "overlays": []}
        for number, (target_name, entries) in enumerate(sorted(groups.items())):
            component = re.sub(r"[^a-z0-9_]", "_", filename[:-4].lower())
            overlay_package = f"com.molcer.os.tr.{component}.g{number}"
            directory = work / overlay_package
            res = directory / "res"
            qualifier = "values" if defaults else "values-tr"
            (res / qualifier).mkdir(parents=True)
            (res / "xml").mkdir()
            values = ET.Element("resources")
            mapping = ET.Element("overlay")
            for entry in entries:
                values.append(entry)
                ET.SubElement(mapping, "item", target="string/" + entry.get("name"), value="@string/" + entry.get("name"))
            ET.ElementTree(values).write(res / qualifier / "strings.xml", encoding="utf-8", xml_declaration=True)
            ET.ElementTree(mapping).write(res / "xml/overlays.xml", encoding="utf-8", xml_declaration=True)
            manifest = ET.Element("manifest", {"package": overlay_package, f"{{{ANDROID}}}versionCode": "1", f"{{{ANDROID}}}versionName": "0.1-preview"})
            ET.SubElement(manifest, "uses-sdk", {f"{{{ANDROID}}}minSdkVersion": "37", f"{{{ANDROID}}}targetSdkVersion": "37"})
            ET.SubElement(manifest, "application", {f"{{{ANDROID}}}hasCode": "false"})
            attributes = {f"{{{ANDROID}}}targetPackage": target_package, f"{{{ANDROID}}}isStatic": "true", f"{{{ANDROID}}}priority": "999", f"{{{ANDROID}}}resourcesMap": "@xml/overlays"}
            if target_name:
                attributes[f"{{{ANDROID}}}targetName"] = target_name
            ET.SubElement(manifest, "overlay", attributes)
            manifest_path = directory / "AndroidManifest.xml"
            ET.ElementTree(manifest).write(manifest_path, encoding="utf-8", xml_declaration=True)
            compiled, unsigned, signed = directory / "compiled.zip", directory / "unsigned.apk", directory / "signed.apk"
            subprocess.run([aapt, "compile", "--dir", str(res), "-o", str(compiled)], check=True)
            subprocess.run([aapt, "link", "-I", str(base), "--manifest", str(manifest_path), "--no-resource-deduping", "--no-resource-removal", "-o", str(unsigned), str(compiled)], check=True)
            if preview_sign:
                subprocess.run([str(tools / "apksigner"), "sign", "--ks", str(key), "--ks-pass", "file:" + str(password), "--out", str(signed), str(unsigned)], check=True)
                subprocess.run([str(tools / "apksigner"), "verify", str(signed)], check=True)
            additions[f"overlay/MolcerTurkish/{overlay_package}.apk"] = (signed if preview_sign else unsigned).read_bytes()
            overlays.append(overlay_package)
            target_report["overlays"].append(overlay_package)
            target_report["compiled_strings"] += len(entries)
        report["targets"].append(target_report)
    pathlib.Path("reports/translations.json").write_text(json.dumps(report, indent=2) + "\n")
    additions["etc/molcer-translation-credits.txt"] = (config["credit"] + "\nhttps://github.com/" + config["source"] + "/tree/" + config["commit"] + "\nResource-matched partial Turkish overlays; original OEM applications are unchanged.\n").encode()
    print(json.dumps({"complete_translation": False, "runtime_verified": False, "signing_status": report['signing_status'],
                      "targets": [{key: target[key] for key in ('package', 'purpose', 'compiled_strings',
                                  'skipped', 'format_verified_strings')} for target in report['targets']]}), flush=True)
    return additions, overlays
