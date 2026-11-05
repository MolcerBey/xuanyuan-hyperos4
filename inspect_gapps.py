"""Inspect pinned Android 17 GApps and Chrome payloads without running installers."""
import gzip
import hashlib
import json
import pathlib
import shutil
import subprocess
import zipfile

from prepare_root import fetch


def inspect_zip(path, root):
    result = {"archive": path.name, "files": [], "apks": [], "installer_notes": {}}
    with zipfile.ZipFile(path) as archive:
        if sum(x.file_size for x in archive.infolist()) > 4 * 1024**3:
            raise ValueError("GApps archive exceeds size limit")
        for item in archive.infolist():
            name = pathlib.PurePosixPath(item.filename)
            if name.is_absolute() or ".." in name.parts or "\\" in item.filename:
                raise ValueError("Unsafe GApps archive path")
            if item.is_dir():
                continue
            result["files"].append({"path": item.filename, "size": item.file_size})
            if item.filename.endswith((".apk", ".apk.gz", ".apex")):
                target = root.joinpath(*name.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as source, target.open("wb") as out:
                    shutil.copyfileobj(source, out)
                if target.suffix == ".gz":
                    unpacked = target.with_suffix("")
                    with gzip.open(target, "rb") as source, unpacked.open("wb") as out:
                        shutil.copyfileobj(source, out)
                    target = unpacked
                badging = subprocess.run(["aapt2", "dump", "badging", str(target)], text=True, capture_output=True, timeout=90)
                signatures = subprocess.run(["apksigner", "verify", "--print-certs", str(target)], text=True, capture_output=True, timeout=90)
                result["apks"].append({"path": item.filename, "badging_exit": badging.returncode, "signature_exit": signatures.returncode, "signature": signatures.stdout, "signature_errors": signatures.stderr, "badging_errors": badging.stderr, "details": [line for line in badging.stdout.splitlines() if line.startswith(("package:", "sdkVersion:", "targetSdkVersion:", "uses-library", "uses-static-library", "native-code:", "locales:"))]})
            elif item.filename.endswith(("update-binary", "g.prop", "build.prop")) and item.file_size < 1024**2:
                result["installer_notes"][item.filename] = archive.read(item).decode(errors="replace")
    return result


def main():
    config = json.loads(pathlib.Path("gapps-assets.json").read_text())
    chrome = json.loads(pathlib.Path("chrome-assets.json").read_text())
    work = pathlib.Path("work/gapps")
    work.mkdir(parents=True, exist_ok=True)
    assets = [config["core"]]
    for package in chrome["packages"]:
        meta = package["metadata"]
        if "17" not in meta["supportedAndroidVersions"]:
            raise ValueError("Chrome catalog lacks Android 17 support")
        assets.append({"name": package["id"] + ".zip", **meta["artifact"]})
    report = {"android": 17, "architecture": "arm64", "runtime_compatibility_verified": False, "excluded_optional_paths": config["excluded_optional_paths"], "archives": []}
    for asset in assets:
        path = fetch(asset, work)
        record = inspect_zip(path, work / path.stem)
        record["sha256"] = asset["sha256"]
        report["archives"].append(record)
    pathlib.Path("reports").mkdir(exist_ok=True)
    pathlib.Path("reports/gapps-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)
    if any(a["signature_exit"] != 0 or a["badging_exit"] != 0 for r in report["archives"] for a in r["apks"] if a["path"] not in config["excluded_optional_paths"]):
        raise ValueError("GApps APK inspection failed; examine report before integration")


if __name__ == "__main__":
    main()
