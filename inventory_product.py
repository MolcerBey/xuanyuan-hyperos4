"""Read-only product inventory; no APK execution or phone access."""
import json
import pathlib
import subprocess
import sys

partition = sys.argv[1] if len(sys.argv) > 1 else "product"
if partition not in {"product", "system", "system_ext"}:
    raise ValueError("Unsupported inventory partition")
root = pathlib.Path("work/mounted_" + partition)
report = {"build_properties": {}, "apk_packages": []}
for file in sorted(root.rglob("build.prop")):
    report["build_properties"][str(file.relative_to(root))] = file.read_text(errors="replace")
for file in sorted(root.rglob("*.apk")):
    result = subprocess.run(["aapt", "dump", "badging", str(file)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    package = next((line for line in result.stdout.splitlines() if line.startswith("package:")), "")
    details = [line for line in result.stdout.splitlines() if line.startswith(("locales:", "uses-library", "uses-static-library", "application-label-tr:"))]
    report["apk_packages"].append({"path": str(file.relative_to(root)), "package": package, "size": file.stat().st_size, "aapt_exit": result.returncode, "details": details})
pathlib.Path(f"reports/{partition}-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report), flush=True)
print(f"Inventoried {len(report['apk_packages'])} APK files")
