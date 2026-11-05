"""Build and audit a product image preview. AVB and installation remain separate."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

from prepare_root import fetch
from tree_audit import snapshot, compare_retained
from load_overlays import load as load_signed_overlays
from fetch_chrome_candidate import inspect_apk
from camera_guard import prepare_product_guard, verify_product_guard
from policy_audit import validate_product_properties, optimization_report

ROOT = pathlib.Path("work/mounted_product")
STAGE = pathlib.Path("work/staged_product")
OUT = pathlib.Path("out/product-preview")
TOOLS = pathlib.Path(os.environ["ANDROID_HOME"], "build-tools/37.0.0")


def package(path):
    text = subprocess.check_output([str(TOOLS / "aapt2"), "dump", "badging", str(path)], text=True)
    match = re.search(r"^package: name='([^']+)'", text, re.M)
    if not match:
        raise ValueError(f"Missing package identity: {path}")
    return match.group(1)


def valid_relative(value):
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value:
        raise ValueError("Unsafe planned image path")
    return path


def main():
    if os.geteuid() != 0 or STAGE.exists():
        raise ValueError("Build requires root and a fresh staging directory")
    config = json.loads(pathlib.Path("debloat.json").read_text())
    version_info = json.loads(pathlib.Path('version.json').read_text(encoding='utf-8'))
    version = version_info['version_name']
    removed = {**config["remove"], **config["replace"]}
    for directory, identity in removed.items():
        valid_relative(directory)
        apks = list(ROOT.joinpath(directory).rglob("*.apk"))
        if not apks or any(package(apk) != identity for apk in apks):
            raise ValueError(f"Removal package identity mismatch: {directory}")
    # Preflight approved replacement APKs before removing either stock browser or Play stub.
    inputs = pathlib.Path("work/product-inputs")
    inputs.mkdir(parents=True, exist_ok=True)
    gapps = json.loads(pathlib.Path("gapps-assets.json").read_text())
    archive = fetch(gapps["core"], inputs)
    additions = {}
    additions['etc/molcer-version.json'] = (json.dumps(version_info, indent=2) + '\n').encode()
    google_core = []
    with zipfile.ZipFile(archive) as source:
        for member, stock in [
            ("system/product/apex/com.google.android.gmssystem.prodvic.apex", ROOT / "apex/com.google.android.gmssystem.prodvic.apex"),
            ("system/system_ext/priv-app/GoogleServicesFramework/GoogleServicesFramework.apk", pathlib.Path("work/mounted_system_ext/priv-app/GoogleServicesFramework/GoogleServicesFramework.apk")),
        ]:
            expected = hashlib.sha256(source.read(member)).hexdigest()
            with stock.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            google_core.append({"path": member, "selected_release_sha256": expected, "stock_sha256": actual, "identical": actual == expected})
        additions["priv-app/Phonesky/Phonesky.apk"] = source.read("system/product/priv-app/Phonesky/Phonesky.apk")
        permissions = ET.fromstring(source.read("system/product/etc/permissions/privapp-permissions-google-product.xml"))
        selected = [element for element in permissions if element.tag == "privapp-permissions" and element.get("package") == "com.android.vending"]
        if len(selected) != 1:
            raise ValueError("Expected exact Play Store privileged permission entry")
        merged = ET.Element("permissions")
        merged.append(selected[0])
        additions["etc/permissions/molcer-google-play.xml"] = ET.tostring(merged, encoding="utf-8", xml_declaration=True)
    chrome = json.loads(pathlib.Path('chrome-candidate.json').read_text())
    if chrome.get('build_integration_approved') is not True:
        raise ValueError('Current Chrome candidate is not approved for integration')
    chrome_path = pathlib.Path('out/chrome-candidate/Chrome.apk')
    chrome_inspection = inspect_apk(chrome_path, chrome, TOOLS, {})
    additions['app/Chrome/Chrome.apk'] = chrome_path.read_bytes()
    manager = list(pathlib.Path("out/root-candidate").glob("KernelSU_Next_*-release.apk"))
    if len(manager) != 1:
        raise ValueError("Verified KernelSU Next manager was not prepared")
    additions["app/KernelSUNext/KernelSUNext.apk"] = manager[0].read_bytes()
    required = {"priv-app/Phonesky/Phonesky.apk": "com.android.vending", "app/Chrome/Chrome.apk": "com.android.chrome", "app/KernelSUNext/KernelSUNext.apk": "com.rifsxd.ksunext"}
    for relative, identity in required.items():
        temporary = inputs / (identity + ".apk")
        temporary.write_bytes(additions[relative])
        subprocess.run([str(TOOLS / "apksigner"), "verify", "--min-sdk-version", "37", str(temporary)], check=True)
        if package(temporary) != identity:
            raise ValueError("Replacement APK package identity mismatch")
    translated_files, overlays = load_signed_overlays(TOOLS)
    additions.update(translated_files)
    modified = {"etc/build.prop"}
    overlay_configuration = ROOT / "overlay/config/config.xml"
    overlay_configuration_bytes = None
    if overlays and overlay_configuration.exists():
        xml = ET.fromstring(overlay_configuration.read_bytes())
        if xml.tag != "config":
            raise ValueError("Unexpected OEM overlay configuration")
        # Immutable overlays must precede mutable overlays; keep all OEM entries.
        for identity in reversed(overlays):
            xml.insert(0, ET.Element("overlay", package=identity, mutable="false", enabled="true"))
        overlay_configuration_bytes = ET.tostring(xml, encoding="utf-8", xml_declaration=True)
        modified.add("overlay/config/config.xml")
    if shutil.disk_usage("work").free < 17 * 1024**3:
        raise ValueError("Need 17 GiB free for product staging and verified output")
    before = snapshot(ROOT)
    inventory = json.loads(pathlib.Path('reports/product-inventory.json').read_text(encoding='utf-8'))
    dependency_path = pathlib.Path('reports/app-dependencies.json')
    dependencies = json.loads(dependency_path.read_text(encoding='utf-8')) if dependency_path.is_file() else None
    camera_plan = prepare_product_guard(before, config, inventory, dependencies)
    STAGE.mkdir()
    subprocess.run(["cp", "-a", str(ROOT) + "/.", str(STAGE)], check=True)
    for relative in removed:
        target = STAGE / valid_relative(relative)
        if not target.resolve().is_relative_to(STAGE.resolve()) or target.is_symlink():
            raise ValueError("Removal escaped staging")
        shutil.rmtree(target)
    new_paths = set()
    label = os.getxattr(ROOT / "priv-app/MiuiCamera/MiuiCamera.apk", "security.selinux")
    for relative, data in additions.items():
        valid_relative(relative)
        target = STAGE / relative
        if target.exists() or target.is_symlink():
            raise ValueError(f"Unapproved overwrite: {relative}")
        parents = []
        parent = target.parent
        while not parent.exists():
            parents.append(parent)
            parent = parent.parent
        if not parent.resolve().is_relative_to(STAGE.resolve()):
            raise ValueError("Addition escaped staging")
        for directory in reversed(parents):
            directory.mkdir(mode=0o755)
            os.chown(directory, 0, 0)
            os.setxattr(directory, "security.selinux", label)
            new_paths.add(str(directory.relative_to(STAGE)))
        target.write_bytes(data)
        target.chmod(0o644)
        os.chown(target, 0, 0)
        os.setxattr(target, "security.selinux", label)
        new_paths.add(relative)
    props = STAGE / "etc/build.prop"
    original_properties = props.read_text()
    text = original_properties
    if text.count("ro.product.locale=zh-CN\n") != 1:
        raise ValueError("Unexpected stock locale declaration")
    text = text.replace("ro.product.locale=zh-CN\n", "ro.product.locale=tr-TR\n")
    text, count = re.subn(r"(?m)^ro.build.display.id=.*$", "ro.build.display.id=Molcer OS " + version, text)
    if count != 1:
        raise ValueError("Unexpected stock display ID declaration")
    text += '\nro.molcer.os.name=Molcer OS\nro.molcer.os.version=' + version + '\npersist.sys.timezone=Europe/Istanbul\n'
    property_evidence = validate_product_properties(original_properties, text, version)
    props.write_text(text)
    if overlay_configuration_bytes is not None:
        target = STAGE / "overlay/config/config.xml"
        if target.is_symlink():
            raise ValueError("Unexpected overlay configuration symlink")
        target.write_bytes(overlay_configuration_bytes)
    staged = snapshot(STAGE)
    retained = compare_retained(before, staged, list(removed), modified, new_paths)
    camera_report = verify_product_guard(camera_plan, staged)
    OUT.mkdir(parents=True, exist_ok=True)
    image = OUT / "product.img"
    subprocess.run(["mkfs.erofs", "-zlz4hc,9", str(image), str(STAGE)], check=True)
    if image.stat().st_size > pathlib.Path("work/images/product.img").stat().st_size:
        raise ValueError("Preview image exceeds stock partition size")
    subprocess.run(["fsck.erofs", str(image)], check=True)
    remount = pathlib.Path("work/verify_product")
    remount.mkdir()
    subprocess.run(["mount", "-t", "erofs", "-o", "loop,ro", str(image), str(remount)], check=True)
    try:
        if snapshot(remount) != staged:
            raise ValueError("Repacked image did not retain staged content and filesystem metadata")
    finally:
        subprocess.run(["umount", str(remount)], check=True)
    with image.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {"name": "Molcer OS", "stage": "product image preview only", "ready_to_flash": False, "product_sha256": digest, "image_size": image.stat().st_size, "retained_entries_verified": retained, "removed_packages": removed, "added_files": sorted(additions), "stock_camera_unchanged": True, "stock_google_runtime_preserved": True, "full_google_runtime_update": False, "complete_turkish_translation": False, "default_locale": "tr-TR", "default_browser_role_verified": False, "pending": ["full Turkish resource integration", "Google runtime/APEX integration assessment", "AVB chain and complete installation packaging", "boot and telephony verification"]}
    report["google_core_comparison"] = google_core
    pathlib.Path('reports/camera-preservation.json').write_text(json.dumps(camera_report, indent=2) + '\n')
    pathlib.Path('reports/optimization-policy.json').write_text(json.dumps(optimization_report(property_evidence, config['remove']), indent=2) + '\n')
    report['chrome'] = chrome_inspection
    report['chrome_sha256'] = chrome['sha256']
    report["google_core_matches_selected_release"] = all(item["identical"] for item in google_core)
    if report["google_core_matches_selected_release"]:
        report["pending"].remove("Google runtime/APEX integration assessment")
    pathlib.Path("reports/product-preview.json").write_text(json.dumps(report, indent=2) + "\n")
    (OUT / "NOT-INSTALLABLE.txt").write_text("Product image preview only. Full Turkish UI, Google runtime update, AVB and complete installation packaging remain pending. Do not flash this standalone image.\n")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
