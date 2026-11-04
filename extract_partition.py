"""Extract full OTA partitions; validate each operation and final image SHA256."""
import argparse
import bz2
import hashlib
import json
import lzma
import pathlib
import shutil
import struct
import zipfile

from inspect_ota import fields


def extract(archive, names, destination):
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        entry = z.getinfo("payload.bin")
        if entry.compress_type != zipfile.ZIP_STORED:
            raise ValueError("Payload must be stored uncompressed")
        with open(archive, "rb") as stream:
            stream.seek(entry.header_offset)
            header = stream.read(30)
            if header[:4] != b"PK\x03\x04":
                raise ValueError("Invalid local ZIP header")
            name_len, extra_len = struct.unpack_from("<HH", header, 26)
            payload_start = entry.header_offset + 30 + name_len + extra_len
            stream.seek(payload_start)
            header = stream.read(24)
            if header[:4] != b"CrAU":
                raise ValueError("Invalid payload")
            major, manifest_size, signature_size = struct.unpack(">QQI", header[4:])
            if major != 2 or manifest_size > 16 * 1024**2:
                raise ValueError("Unsupported payload header")
            manifest = fields(stream.read(manifest_size))
            if manifest.get(12, [0])[0] != 0:
                raise ValueError("Delta OTA is not supported")
            block_size = manifest.get(3, [4096])[0]
            data_start = payload_start + 24 + manifest_size + signature_size
            available = {}
            for raw in manifest[13]:
                part = fields(raw)
                available[part[1][0].decode()] = part
            if not set(names) <= available.keys():
                raise ValueError("Requested partition missing")
            required = sum(fields(available[name][7][0])[1][0] for name in names)
            if shutil.disk_usage(destination).free < required + 1024**3:
                raise ValueError("Insufficient disk for partition extraction")
            reports = []
            for name in names:
                if not name.replace("_", "").isalnum():
                    raise ValueError("Invalid partition name")
                part = available[name]
                info = fields(part[7][0])
                image_size = info[1][0]
                path = destination / (name + ".img")
                with path.open("w+b") as output:
                    output.truncate(image_size)
                    for raw in part.get(8, []):
                        op = fields(raw)
                        kind = op[1][0]
                        if kind not in (0, 1, 6, 7, 8):
                            raise ValueError(f"Unsupported operation {kind}")
                        extents = [fields(e) for e in op.get(6, [])]
                        expected_length = sum(e[2][0] * block_size for e in extents)
                        if expected_length > 64 * 1024**2:
                            raise ValueError("Oversized operation output")
                        if kind in (6, 7):
                            decoded = b"\0" * expected_length
                        else:
                            offset, length = op.get(2, [0])[0], op.get(3, [0])[0]
                            if length > 64 * 1024**2 or data_start + offset + length > payload_start + entry.file_size:
                                raise ValueError("Operation data outside payload")
                            stream.seek(data_start + offset)
                            encoded = stream.read(length)
                            if len(encoded) != length or 8 not in op or hashlib.sha256(encoded).digest() != op[8][0]:
                                raise ValueError("Operation checksum mismatch")
                            if kind == 0:
                                decoded = encoded
                            else:
                                decoder = bz2.BZ2Decompressor() if kind == 1 else lzma.LZMADecompressor()
                                decoded = decoder.decompress(encoded, max_length=expected_length + 1)
                                if not decoder.eof or decoder.unused_data:
                                    raise ValueError("Unexpected compressed operation length")
                        if len(decoded) != expected_length:
                            raise ValueError("Operation extent size mismatch")
                        pos = 0
                        for extent in extents:
                            start, length = extent[1][0] * block_size, extent[2][0] * block_size
                            if start + length > image_size:
                                raise ValueError("Extent outside partition")
                            output.seek(start)
                            output.write(decoded[pos:pos + length])
                            pos += length
                with path.open("rb") as image:
                    digest = hashlib.file_digest(image, "sha256").digest()
                if digest != info[2][0]:
                    raise ValueError(f"Final image checksum mismatch: {name}")
                reports.append({"name": name, "size": image_size, "sha256": digest.hex()})
                print(f"Extracted and verified {name}: {digest.hex()}", flush=True)
            pathlib.Path("reports").mkdir(exist_ok=True)
            pathlib.Path("reports/extracted-images.json").write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--archive", default="work/base.zip")
    p.add_argument("--partitions", nargs="+", default=["product"])
    p.add_argument("--output", default="work/images")
    args = p.parse_args()
    extract(args.archive, args.partitions, args.output)
