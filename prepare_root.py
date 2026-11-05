"""Prepare an offline KernelSU Next init_boot candidate; never flash a device."""
import gzip
import hashlib
import json
import pathlib
import re
import struct
import subprocess


def kernel_kmi(image):
    data = pathlib.Path(image).read_bytes()
    if data[:8] != b"ANDROID!" or struct.unpack_from("<I", data, 40)[0] not in (3, 4):
        raise ValueError("Expected Android boot header v3 or v4")
    size = struct.unpack_from("<I", data, 8)[0]
    if not 0 < size <= len(data) - 4096:
        raise ValueError("Invalid kernel size")
    kernel = data[4096:4096 + size]
    if kernel.startswith(b"\x1f\x8b"):
        kernel = gzip.decompress(kernel)
    elif kernel[:4] in (b"\x02\x21\x4c\x18", b"\x04\x22\x4d\x18"):
        kernel = subprocess.run(["lz4", "-dc"], input=kernel, stdout=subprocess.PIPE, check=True).stdout
    matches = set(re.findall(rb"Linux version (\d+\.\d+)\.[^\x00\s]*?(android\d+)[^\x00\s]*", kernel))
    if len(matches) != 1:
        raise ValueError("Cannot uniquely determine stock kernel KMI")
    version, android = matches.pop()
    return (android + b"-" + version).decode()


def fetch(asset, directory):
    path = directory / asset["name"]
    if not asset.get("sha256") or len(asset["sha256"]) != 64:
        raise ValueError("Release asset has no pinned SHA256")
    subprocess.run(["curl", "-fL", "--retry", "2", "--connect-timeout", "30", "--max-time", "300", "-o", str(path), asset["url"]], check=True, timeout=900)
    if path.stat().st_size != asset["size"] or hashlib.sha256(path.read_bytes()).hexdigest() != asset["sha256"]:
        raise ValueError("KernelSU Next release asset checksum mismatch")
    return path


def main():
    config = json.loads(pathlib.Path("root-assets.json").read_text())
    assets = {a["name"]: a for a in config["assets"]}
    kmi = kernel_kmi("work/images/boot.img")
    print("Stock boot KMI: " + kmi, flush=True)
    module_name = f"aarch64_{kmi}_kernelsu.ko"
    if module_name not in assets:
        raise ValueError("No pinned KernelSU Next module for stock KMI")
    destination = pathlib.Path("work/root-tools")
    destination.mkdir(parents=True, exist_ok=True)
    output = pathlib.Path("out/root-candidate")
    output.mkdir(parents=True, exist_ok=True)
    ksud = fetch(assets["ksud-x86_64-unknown-linux-musl"], destination).resolve()
    ksud.chmod(0o755)
    module = fetch(assets[module_name], destination)
    manager = next(a for a in assets.values() if a["name"].endswith("-release.apk"))
    fetch(manager, output)
    subprocess.run([str(ksud), "boot-patch", "--boot", "work/images/init_boot.img", "--module", str(module), "--kmi", kmi, "--out", str(output), "--out-name", "init_boot.img"], check=True, timeout=180)
    original = pathlib.Path("work/images/init_boot.img").read_bytes()
    patched = (output / "init_boot.img").read_bytes()
    if patched[:8] != b"ANDROID!" or len(patched) > len(original) or patched == original:
        raise ValueError("Unexpected patched init_boot output")
    report = {"release": config["release"], "kmi": kmi, "stock_kernel_preserved": True, "init_boot_sha256": hashlib.sha256(patched).hexdigest(), "stock_init_boot_sha256": hashlib.sha256(original).hexdigest(), "runtime_tested": False, "ready_to_flash": False, "status": "Offline root candidate; AVB and installation integration pending"}
    pathlib.Path("reports/root-candidate.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "README.txt").write_text("OFFLINE CANDIDATE ONLY. Not a complete ROM or installation package. AVB/boot validation pending. Do not flash this standalone artifact.\n")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
