"""Compare public OTA certificates from Xiaomi's CDN; does not approve a build."""
import hashlib
import json
import pathlib
import ssl
import zipfile

from inspect_ota import RemoteFile

sources = [
    ("reference_hyperos3", "https://bigota.d.miui.com/OS3.0.314.0.WOACNXM/xuanyuan-ota_full-OS3.0.314.0.WOACNXM-user-16.0-9f74d1725b.zip", 10049399042),
    ("candidate_hyperos4", "https://bigota.d.miui.com/OS4.0.0.18.XOACNXM/xuanyuan-ota_full-OS4.0.0.18.XOACNXM-user-17.0-bfc6faa7f2.zip", 10321978949),
]
report = {}
for name, url, size in sources:
    source = RemoteFile(url, size)
    with zipfile.ZipFile(source) as z:
        cert = z.read("META-INF/com/android/otacert")
    der = ssl.PEM_cert_to_DER_cert(cert.decode())
    pathlib.Path("reports").mkdir(exist_ok=True)
    pathlib.Path("reports", name + "-otacert.pem").write_bytes(cert)
    report[name] = {"source": url, "certificate_sha256": hashlib.sha256(der).hexdigest()}
report["certificate_matches"] = report["reference_hyperos3"]["certificate_sha256"] == report["candidate_hyperos4"]["certificate_sha256"]
pathlib.Path("reports/certificate-comparison.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
