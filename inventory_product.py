"""Read-only product inventory; no APK execution or phone access."""
import json
import pathlib
import subprocess

root = pathlib.Path("work/mounted_product")
report = {"build_properties": {}, "apk_packages": []}
for file in sorted(root.rglob("build.prop")):
    report["build_properties"][str(file.relative_to(root))] = file.read_text(errors="replace")
for file in sorted(root.rglob("*.apk")):
    result = subprocess.run(["aapt", "dump", "badging", str(file)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    package = next((line for line in result.stdout.splitlines() if line.startswith("package:")), "")
    report["apk_packages"].append({"path": str(file.relative_to(root)), "package": package, "size": file.stat().st_size, "aapt_exit": result.returncode})
pathlib.Path("reports/product-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"Inventoried {len(report['apk_packages'])} APK files")
