"""Read-only stock radio inventory. File/profile hints never prove runtime activation."""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET
import zipfile

PARTITIONS = ("modem", "modemfirmware", "vendor", "odm", "product", "system_ext", "system")
MAX_TEXT = 4 * 1024**2
MAX_ENTRIES = 5000
MAX_REPORT = 8 * 1024**2
TR_NAMES = re.compile(r"turkcell|turk[ _-]*telekom|turkey|turkiye|türkiye|avea|netgsm", re.I)
OP_NAMES = re.compile(TR_NAMES.pattern + r"|vodafone", re.I)
MCC_NAME = re.compile(r"(?:mccmnc|mcc)[_-]?286(?:\d{2,3})?(?!\d)", re.I)
RADIO_PROP = re.compile(r"(?:^|\.)(?:radio|ril|ims|volte|vowifi|wfc|mcfg|mbn)(?:\.|_|$)", re.I)
REGION_PROPS = {"ro.miui.region", "ro.miui.cust_variant", "ro.product.mod_device", "ro.miui.has_gmscore"}


def path_hints(value):
    """A name is evidence of a named candidate, not of selection or compatibility."""
    hints = []
    if TR_NAMES.search(value):
        hints.append("turkey_or_turkish_operator_name")
    if MCC_NAME.search(value):
        hints.append("mcc_286_filename")
    if re.search(r"vodafone", value, re.I):
        hints.append("vodafone_name_country_not_established")
    return hints


def snippets(data, limit=10):
    text = data.decode("utf-8", errors="replace")
    specific = list(TR_NAMES.finditer(text))
    generic = [match for match in re.finditer(r"vodafone", text, re.I)]
    matches = (specific + generic)[:limit]
    return [re.sub(r"[^\x20-\x7e\u0080-\uffff]", " ", text[max(0, m.start()-90):m.end()+170]) for m in matches]


def xml_evidence(data, filename):
    result = {"filename_hints": path_hints(filename), "parsed_xml": False,
              "mcc_286_elements": [], "operator_name_snippets": snippets(data, 5)}
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result["binary_or_invalid_xml"] = True
        return result
    result["parsed_xml"] = True
    for element in root.iter():
        attrs = element.attrib
        country_match = attrs.get("mcc") == "286" or bool(re.fullmatch(r"286\d{2,3}", attrs.get("mccmnc", "")))
        if country_match:
            result["mcc_286_elements"].append({"tag": element.tag, "attributes": attrs,
                "xml_excerpt": ET.tostring(element, encoding="unicode")[:3000]})
            if len(result["mcc_286_elements"]) == 20:
                result["mcc_matches_truncated"] = True
                break
    # A matching filename can select the carrier while its XML contains only settings.
    if result["filename_hints"]:
        result["selected_file_excerpt"] = ET.tostring(root, encoding="unicode")[:3500]
    return result


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inspect(work):
    work = pathlib.Path(work)
    report = {"runtime_verified": False, "turkey_compatibility_verified": False,
        "active_mbn_profile_verified": False, "source_files_modified": False,
        "evidence_scope": "Static names, hashes and configuration only; no modem activation, SIM or network tests",
        "partitions": {}, "partition_images": [], "mbn_files": [], "modem_firmware_files": [],
        "radio_properties": [], "configuration_candidates": [], "carrier_apk_assets": [],
        "unparsed_carrier_xml": [], "errors": [], "omitted": {}}
    omitted = collections.Counter()

    def add(section, value, limit=MAX_ENTRIES):
        if len(report[section]) < limit:
            report[section].append(value)
        else:
            omitted[section] += 1

    for partition in PARTITIONS:
        root = work / ("mounted_" + partition)
        report["partitions"][partition] = {"available": root.is_dir(), "files_seen": 0}
        image = work / "images" / (partition + ".img")
        if partition in ("modem", "modemfirmware") and image.is_file():
            add("partition_images", {"partition": partition, "size": image.stat().st_size, "sha256": sha256(image)})
        if not root.is_dir():
            continue
        root_resolved = root.resolve()
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root_resolved):
                continue
            report["partitions"][partition]["files_seen"] += 1
            name = path.relative_to(root).as_posix()
            label = partition + "/" + name
            lower = name.lower()
            try:
                size = path.stat().st_size
                if path.suffix.lower() == ".mbn":
                    entry = {"path": label, "size": size, "sha256": sha256(path), "name_hints": path_hints(name)}
                    if size <= MAX_TEXT:
                        entry["operator_name_snippets"] = snippets(path.read_bytes())
                    else:
                        entry["text_scan_omitted_size_limit"] = True
                    add("mbn_files", entry)
                elif partition in ("modem", "modemfirmware") and not any(part in lower.split("/") for part in ("mcfg_sw", "mcfg_hw")):
                    add("modem_firmware_files", {"path": label, "size": size, "sha256": sha256(path)}, 1000)
                if path.name == "build.prop" and size <= MAX_TEXT:
                    for line in path.read_text(errors="replace").splitlines():
                        if line.startswith("#") or "=" not in line:
                            continue
                        key, value = line.split("=", 1)
                        if RADIO_PROP.search(key) or key in REGION_PROPS:
                            add("radio_properties", {"path": label, "key": key, "value": value[:512]}, 1000)
                if size <= MAX_TEXT and path.suffix.lower() in (".xml", ".txt", ".conf", ".json") and re.search(r"carrier|mcfg|mbn|ims|radio|apn", lower):
                    data = path.read_bytes()
                    hints = path_hints(name)
                    evidence = xml_evidence(data, name) if path.suffix.lower() == ".xml" else {"filename_hints": hints, "operator_name_snippets": snippets(data)}
                    # Indexes can establish which carrier-name paths are shipped, not active selection.
                    is_index = "mcfg" in lower or "mbn" in lower
                    if hints or evidence.get("mcc_286_elements") or evidence.get("operator_name_snippets") or is_index:
                        add("configuration_candidates", {"path": label, "size": size, "sha256": hashlib.sha256(data).hexdigest(), **evidence}, 300)
                if path.suffix.lower() == ".apk" and re.search(r"carrier|telephony|ims|qti.*config", lower):
                    with zipfile.ZipFile(path) as archive:
                        for member in archive.infolist():
                            if not member.filename.startswith("assets/") or not member.filename.endswith(".xml"):
                                continue
                            if member.file_size > MAX_TEXT:
                                omitted["oversized_apk_xml"] += 1
                                continue
                            data = archive.read(member)
                            evidence = xml_evidence(data, member.filename)
                            if not evidence["parsed_xml"]:
                                add("unparsed_carrier_xml", {"apk": label, "asset": member.filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}, 100)
                            if evidence["filename_hints"] or evidence["mcc_286_elements"] or evidence["operator_name_snippets"]:
                                add("carrier_apk_assets", {"apk": label, "asset": member.filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), **evidence}, 300)
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                add("errors", {"path": label, "error": str(exc)[:300]}, 50)
    report["omitted"] = dict(omitted)
    report["mbn_candidate_count"] = len(report["mbn_files"])
    # A hard cap makes accidental huge firmware inventories explicit rather than silently dropping data.
    if len(json.dumps(report).encode()) > MAX_REPORT:
        raise ValueError("Radio report exceeds 8 MiB limit; narrow inspection before accepting results")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", default="work")
    parser.add_argument("--output", default="reports/radio-static.json")
    args = parser.parse_args()
    report = inspect(args.work)
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
