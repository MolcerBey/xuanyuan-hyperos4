"""Download the pinned OTA with bounded size, disk checks and checksum verification."""
import hashlib
import json
import pathlib
import shutil
import urllib.request

from inspect_ota import inspect
from verify_signature import verify_signature


def main():
    config = json.loads(pathlib.Path("base.json").read_text())
    pathlib.Path("reports").mkdir(exist_ok=True)
    work = pathlib.Path("work")
    work.mkdir(exist_ok=True)
    if shutil.disk_usage(work).free < config["size"] + 2 * 1024**3:
        raise RuntimeError("Insufficient free disk for the pinned OTA plus 2 GiB reserve")
    target = work / "base.zip.partial"
    md5, sha256, length = hashlib.md5(), hashlib.sha256(), 0
    with urllib.request.urlopen(config["url"], timeout=120) as response, target.open("wb") as output:
        if int(response.headers.get("Content-Length", "0")) != config["size"]:
            raise RuntimeError("Server content length changed")
        while chunk := response.read(8 * 1024**2):
            length += len(chunk)
            if length > config["size"]:
                raise RuntimeError("Download exceeded expected length")
            output.write(chunk)
            md5.update(chunk)
            sha256.update(chunk)
            if length % (256 * 1024**2) == 0:
                print(f"Downloaded {length / 1024**3:.2f} GiB", flush=True)
    measurements = {"bytes": length, "expected_bytes": config["size"], "md5": md5.hexdigest(), "expected_md5": config["md5"], "sha256": sha256.hexdigest(), "source_url": config["url"]}
    pathlib.Path("reports/download-measurements.json").write_text(json.dumps(measurements, indent=2) + "\n")
    print(json.dumps(measurements, indent=2), flush=True)
    if length != config["size"] or md5.hexdigest() != config["md5"] or sha256.hexdigest() != config["sha256"]:
        raise RuntimeError("OTA checksum/length mismatch; partial file will not be used")
    report = inspect(target, config)
    if not all(report["checks"].values()):
        raise RuntimeError("OTA identity mismatch")
    report.update(verify_signature(target, config["otacert_sha256_der"]))
    target.replace(work / "base.zip")
    report.update({"full_archive_hash_verified": True, "md5": md5.hexdigest(), "sha256": sha256.hexdigest(), "source_url": config["url"]})
    pathlib.Path("reports").mkdir(exist_ok=True)
    pathlib.Path("reports/verified-base.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Verified source archive SHA256: {sha256.hexdigest()}", flush=True)


if __name__ == "__main__":
    main()
