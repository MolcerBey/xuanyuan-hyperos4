"""Verify the OTA whole-file signature with a pinned Xiaomi certificate."""
import hashlib
import pathlib
import ssl
import struct
import subprocess
import tempfile
import zipfile


def verify_signature(path, expected_certificate):
    path = pathlib.Path(path)
    with zipfile.ZipFile(path) as z:
        cert = z.read("META-INF/com/android/otacert")
    der = ssl.PEM_cert_to_DER_cert(cert.decode())
    if hashlib.sha256(der).hexdigest() != expected_certificate:
        raise ValueError("OTA signing certificate does not match pinned Xiaomi certificate")
    with path.open("rb") as f:
        f.seek(-6, 2)
        signature_start, marker, comment_size = struct.unpack("<HHH", f.read(6))
        if marker != 65535 or not 6 < signature_start <= comment_size:
            raise ValueError("Invalid OTA signature footer")
        f.seek(-signature_start, 2)
        signature = f.read(signature_start - 6)
    with tempfile.TemporaryDirectory() as tmp:
        cert_path, sig_path = pathlib.Path(tmp, "cert.pem"), pathlib.Path(tmp, "sig.der")
        cert_path.write_bytes(cert)
        sig_path.write_bytes(signature)
        command = ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(sig_path), "-nointern", "-certfile", str(cert_path), "-content", "/dev/stdin", "-noverify", "-out", "/dev/null"]
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            with path.open("rb") as f:
                left = path.stat().st_size - comment_size - 2
                while left:
                    chunk = f.read(min(left, 8 * 1024**2))
                    if not chunk:
                        raise ValueError("Truncated signed content")
                    proc.stdin.write(chunk)
                    left -= len(chunk)
            proc.stdin.close()
        except BrokenPipeError:
            pass
        errors = proc.stderr.read().decode(errors="replace")
        if proc.wait() != 0:
            raise ValueError("Pinned Xiaomi signature verification failed: " + errors)
    return {"whole_file_signature_verified": True, "signer_certificate_sha256": expected_certificate}
