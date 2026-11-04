"""Inspect an OTA ZIP with bounded HTTP ranges; never flash or execute its files."""
import argparse
import hashlib
import io
import json
import pathlib
import struct
import urllib.request
import zipfile


def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError("Truncated protobuf varint")
        b = data[pos]
        pos += 1
        value |= (b & 127) << shift
        if not b & 128:
            return value, pos
    raise ValueError("Oversized protobuf varint")


def fields(data):
    result, pos = {}, 0
    while pos < len(data):
        key, pos = varint(data, pos)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("Invalid protobuf field")
        if wire == 0:
            value, pos = varint(data, pos)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, pos = varint(data, pos)
            else:
                length = 8 if wire == 1 else 4
            if pos + length > len(data):
                raise ValueError("Truncated protobuf value")
            value, pos = data[pos:pos + length], pos + length
        else:
            raise ValueError("Unsupported protobuf wire type")
        result.setdefault(number, []).append(value)
    return result


def partition_summary(manifest):
    parsed = fields(manifest)
    result = []
    for raw in parsed.get(13, []):
        part = fields(raw)
        info = fields(part[7][0])
        operations = [fields(x) for x in part.get(8, [])]
        result.append({
            "name": part[1][0].decode(), "size": info[1][0],
            "sha256": info[2][0].hex(), "operation_count": len(operations),
            "operation_types": sorted({x[1][0] for x in operations}),
            "compressed_data_size": sum(x.get(3, [0])[0] for x in operations),
        })
    return result


class RemoteFile(io.RawIOBase):
    def __init__(self, url, expected_size):
        self.url = url
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60) as r:
            self.size = int(r.headers["Content-Length"])
            self.etag = r.headers.get("ETag")
        if self.size != expected_size:
            raise ValueError(f"Unexpected archive length: {self.size}")
        self.pos = 0
        self.transferred = 0
        self.cache = {}

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        new = offset + (0 if whence == 0 else self.pos if whence == 1 else self.size)
        if new < 0:
            raise ValueError("Negative seek")
        self.pos = new
        return new

    def read(self, n=-1):
        n = self.size - self.pos if n < 0 else min(n, self.size - self.pos)
        if n <= 0:
            return b""
        if n > 16 * 1024 * 1024:
            raise ValueError("Unbounded remote read refused")
        out = bytearray()
        while n:
            block = self.pos // 65536
            if block not in self.cache:
                start = block * 65536
                end = min(self.size - 1, start + 65535)
                headers = {"Range": f"bytes={start}-{end}", "Accept-Encoding": "identity"}
                if self.etag:
                    headers["If-Match"] = self.etag
                with urllib.request.urlopen(urllib.request.Request(self.url, headers=headers), timeout=60) as r:
                    if r.status != 206 or r.headers.get("Content-Range") != f"bytes {start}-{end}/{self.size}":
                        raise ValueError("Server did not honor the requested byte range")
                    data = r.read(end - start + 2)
                if len(data) != end - start + 1:
                    raise ValueError("Truncated or oversized response")
                self.cache[block] = data
                self.transferred += len(data)
            data = self.cache[block]
            offset = self.pos % 65536
            part = data[offset:offset + n]
            out.extend(part)
            self.pos += len(part)
            n -= len(part)
        return bytes(out)


def inspect(source, expected):
    with zipfile.ZipFile(source) as z:
        info = z.getinfo("META-INF/com/android/metadata")
        if info.file_size > 1024 * 1024:
            raise ValueError("Oversized OTA metadata")
        metadata = dict(line.split("=", 1) for line in z.read(info).decode().splitlines() if "=" in line)
        checks = {
            "device": metadata.get("pre-device") == expected["device"],
            "incremental": metadata.get("post-build-incremental") == expected["incremental"],
            "android": metadata.get("post-build", "").split(":")[1].split("/")[0] == expected["android"],
            "sdk": metadata.get("post-sdk-level") == expected["sdk"],
            "ab_ota": metadata.get("ota-type") == "AB",
            "full_ota": "pre-build" not in metadata and "pre-build-incremental" not in metadata,
        }
        payload = z.getinfo("payload.bin")
        if payload.compress_type != zipfile.ZIP_STORED:
            raise ValueError("Expected an uncompressed payload entry")
        with z.open(payload) as f:
            header = f.read(24)
        if len(header) != 24 or header[:4] != b"CrAU":
            raise ValueError("Invalid payload header")
        version, manifest_size, signature_size = struct.unpack(">QQI", header[4:])
        checks["payload_v2"] = version == 2
        if manifest_size > 16 * 1024 * 1024:
            raise ValueError("Oversized payload manifest")
        with z.open(payload) as f:
            f.read(24)
            manifest = f.read(manifest_size)
        partitions = partition_summary(manifest)
        checks["full_payload"] = fields(manifest).get(12, [0])[0] == 0
        checks["partitions_present"] = bool(partitions)
        result = {
            "metadata": metadata, "checks": checks,
            "archive_entries": [{"name": x.filename, "size": x.file_size, "compressed_size": x.compress_size} for x in z.infolist()],
            "payload": {"version": version, "manifest_size": manifest_size, "metadata_signature_size": signature_size},
            "partitions": partitions,
            "partition_image_bytes": sum(x["size"] for x in partitions),
            "otacert_sha256": hashlib.sha256(z.read("META-INF/com/android/otacert")).hexdigest(),
            "full_archive_hash_verified": False,
            "camera_runtime_tests": "omitted at user request",
            "flashable_custom_rom_produced": False,
        }
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="base.json")
    parser.add_argument("--output", default="reports/ota-inspection.json")
    parser.add_argument("--local")
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text(encoding="utf-8"))
    source = args.local or RemoteFile(cfg["url"], cfg["size"])
    report = inspect(source, cfg)
    if isinstance(source, RemoteFile):
        report["bytes_downloaded"] = source.transferred
        report["etag"] = source.etag
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("STOP: OTA identity checks failed; no ROM build allowed")
