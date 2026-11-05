"""Inspect stock Turkish APN entries; never modify radio or carrier configuration."""
import json
import pathlib
import xml.etree.ElementTree as ET

report = {"runtime_verified": False, "radio_files_modified": False, "turkish_apns": [], "parse_errors": []}
for partition in ("product", "system", "system_ext", "vendor"):
    root = pathlib.Path("work/mounted_" + partition)
    for path in root.rglob("*apn*.xml"):
        if path.stat().st_size > 16 * 1024**2:
            continue
        try:
            tree = ET.parse(path)
            for entry in tree.iter("apn"):
                if entry.get("mcc") == "286":
                    report["turkish_apns"].append({"source": partition + "/" + str(path.relative_to(root)), "mcc": "286", "mnc": entry.get("mnc"), "carrier": entry.get("carrier"), "type": entry.get("type")})
        except (ET.ParseError, OSError) as exc:
            report["parse_errors"].append({"path": str(path), "error": str(exc)})
report["mnc_codes_present"] = sorted({x["mnc"] for x in report["turkish_apns"] if x["mnc"]})
pathlib.Path("reports/telephony-static.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report), flush=True)
