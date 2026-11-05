"""Build resource-only Turkish overlays without modifying OEM APKs or signatures."""
import collections
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


def build():
    config = json.loads(pathlib.Path("translations.json").read_text())
    tools = pathlib.Path(os.environ["ANDROID_HOME"], "build-tools/37.0.0")
    aapt = str(tools / "aapt2")
    base = pathlib.Path("work/mounted_system/system/framework/framework-res.apk")
    work = pathlib.Path("work/translations")
    work.mkdir(parents=True, exist_ok=True)
    password = work / "password.txt"
    password.write_text(secrets.token_urlsafe(32))
    password.chmod(0o600)
    key = work / "preview-key.p12"
    subprocess.run(["keytool", "-genkeypair", "-keystore", str(key), "-storetype", "PKCS12", "-storepass:file", str(password), "-keypass:file", str(password), "-alias", "molcer-preview", "-keyalg", "RSA", "-keysize", "3072", "-validity", "3650", "-dname", "CN=Molcer OS Preview", "-noprompt"], check=True)
    key.chmod(0o600)
    report = {"source": config["source"], "commit": config["commit"], "credit": config["credit"], "original_apks_modified": False, "runtime_verified": False, "complete_translation": False, "preview_signing_key": True, "targets": []}
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
        groups = collections.defaultdict(list)
        skipped = collections.Counter()
        for entry in ET.fromstring(data):
            name = entry.get("name", "")
            resource = "string/" + name
            value = entry.text or ""
            if entry.tag != "string" or len(entry) or entry.get("translatable") == "false":
                skipped["non_plain_string"] += 1
            elif resource not in names:
                skipped["not_in_this_base"] += 1
            elif not defaults and (re.match(r"(?:config|key|pref_key|uri|url|action|default)_", name) or value.startswith(("@", "?")) or "://" in value):
                skipped["non_ui_configuration"] += 1
            elif "%" in value or "%" in names[resource]:
                skipped["format_requires_manual_review"] += 1
            elif overlayable.strip() and resource not in allowed:
                skipped["not_product_overlayable"] += 1
            else:
                groups[allowed.get(resource, "")].append(entry)
        target_report = {"package": target_package, "purpose": "default-browser" if defaults else "turkish-ui", "compiled_strings": 0, "skipped": dict(skipped), "overlays": []}
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
            subprocess.run([str(tools / "apksigner"), "sign", "--ks", str(key), "--ks-pass", "file:" + str(password), "--out", str(signed), str(unsigned)], check=True)
            subprocess.run([str(tools / "apksigner"), "verify", str(signed)], check=True)
            additions[f"overlay/MolcerTurkish/{overlay_package}.apk"] = signed.read_bytes()
            overlays.append(overlay_package)
            target_report["overlays"].append(overlay_package)
            target_report["compiled_strings"] += len(entries)
        report["targets"].append(target_report)
    pathlib.Path("reports/translations.json").write_text(json.dumps(report, indent=2) + "\n")
    additions["etc/molcer-translation-credits.txt"] = (config["credit"] + "\nhttps://github.com/" + config["source"] + "/tree/" + config["commit"] + "\nResource-matched partial Turkish overlays; original OEM applications are unchanged.\n").encode()
    print(json.dumps(report), flush=True)
    return additions, overlays
