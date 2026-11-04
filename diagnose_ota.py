"""Quarantine diagnostics only. Success never overrides the pinned checksum gate."""
import hashlib
import json
import pathlib
import struct
import subprocess
import zipfile


def main():
    path = pathlib.Path("work/base.zip.partial")
    if not path.exists():
        print("No quarantined download to inspect")
        return
    output = pathlib.Path("reports")
    output.mkdir(exist_ok=True)
    report = {"quarantined": True, "checksum_gate_bypassed": False}
    with zipfile.ZipFile(path) as z:
        cert = z.read("META-INF/com/android/otacert")
        (output / "source-otacert.pem").write_bytes(cert)
        report["otacert_sha256"] = hashlib.sha256(cert).hexdigest()
        report["payload_properties"] = z.read("payload_properties.txt").decode()
    with path.open("rb") as f:
        f.seek(-6, 2)
        signature_start, marker, comment_size = struct.unpack("<HHH", f.read(6))
        if marker != 65535 or not 6 < signature_start <= comment_size:
            raise ValueError("Invalid OTA whole-file signature footer")
        f.seek(-signature_start, 2)
        signature = f.read(signature_start - 6)
    signature_file = output / "ota-signature.der"
    signature_file.write_bytes(signature)
    signed_length = path.stat().st_size - comment_size - 2
    command = ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(signature_file), "-content", "/dev/stdin", "-noverify", "-out", "/dev/null"]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with path.open("rb") as f:
            left = signed_length
            while left:
                chunk = f.read(min(left, 8 * 1024**2))
                if not chunk:
                    raise ValueError("Truncated signed region")
                proc.stdin.write(chunk)
                left -= len(chunk)
        proc.stdin.close()
    except BrokenPipeError:
        pass
    errors = proc.stderr.read().decode(errors="replace")
    report["embedded_signature_valid"] = proc.wait() == 0
    report["manufacturer_identity_authenticated"] = False
    report["signature_verifier_output"] = errors
    subject = subprocess.run(["openssl", "x509", "-in", str(output / "source-otacert.pem"), "-noout", "-subject", "-issuer", "-fingerprint", "-sha256"], capture_output=True, text=True)
    report["certificate_info"] = subject.stdout
    (output / "signature-diagnostic.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
