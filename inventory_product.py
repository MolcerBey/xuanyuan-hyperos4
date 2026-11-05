"""Read-only product inventory; no APK execution or phone access."""
import json
import pathlib
import subprocess
import sys
import gzip
import shutil
import tempfile

partition = sys.argv[1] if len(sys.argv) > 1 else "product"
if partition not in {"product", "system", "system_ext"}:
    raise ValueError("Unsupported inventory partition")
root = pathlib.Path("work/mounted_" + partition)
tool = sys.argv[2] if len(sys.argv) > 2 else "aapt2"
report = {"build_properties": {}, "apk_packages": [], "apex_files": []}
for file in sorted(root.rglob("build.prop")):
    report["build_properties"][str(file.relative_to(root))] = file.read_text(errors="replace")
for file in sorted(set(root.rglob("*.apk")) | set(root.rglob("*.apk.gz"))):
    with tempfile.TemporaryDirectory() as tmp:
        apk = file
        if file.name.endswith(".gz"):
            apk = pathlib.Path(tmp, file.stem)
            with gzip.open(file, "rb") as source, apk.open("wb") as target:
                shutil.copyfileobj(source, target)
        result = subprocess.run([tool, "dump", "badging", str(apk)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    package = next((line for line in result.stdout.splitlines() if line.startswith("package:")), "")
    details = [line for line in result.stdout.splitlines() if line.startswith(("locales:", "uses-library", "uses-static-library", "application-label-tr:"))]
    report["apk_packages"].append({"path": str(file.relative_to(root)), "package": package, "size": file.stat().st_size, "aapt_exit": result.returncode, "details": details, "errors": result.stderr})
for file in sorted(list(root.rglob("*.apex")) + list(root.rglob("*.capex"))):
    import hashlib
    with file.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    report["apex_files"].append({"path": str(file.relative_to(root)), "size": file.stat().st_size, "sha256": digest})
pathlib.Path(f"reports/{partition}-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report), flush=True)
print(f"Inventoried {len(report['apk_packages'])} APK files")
