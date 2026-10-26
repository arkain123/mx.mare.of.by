import socket
import ssl
from datetime import datetime, timezone

import dns.exception
import dns.resolver

TIMEOUT = 6


def _resolve_mx(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8.0)
    except Exception:
        return []
    pairs = []
    for r in answers:
        pairs.append((int(r.preference), str(r.exchange).rstrip(".")))
    pairs.sort(key=lambda x: x[0])
    return pairs


def _resolve_a(host: str):
    try:
        return [str(r) for r in dns.resolver.resolve(host, "A", lifetime=5.0)]
    except Exception:
        return []


def _get_cert(host: str, port: int = 25):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        sock.recv(1024)
        sock.sendall(b"EHLO mx.local\r\n")
        resp = sock.recv(4096).decode("utf-8", "replace")
        if "STARTTLS" not in resp.upper():
            sock.close()
            return None, "STARTTLS not advertised"

        sock.sendall(b"STARTTLS\r\n")
        tls_resp = sock.recv(1024).decode("utf-8", "replace")
        if not tls_resp.startswith("220"):
            sock.close()
            return None, f"STARTTLS failed: {tls_resp.strip()}"

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(sock, server_hostname=host)
        der = tls_sock.getpeercert(binary_form=True)
        tls_sock.close()

        import tempfile, os

        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(pem)
            cert = ssl._ssl._test_decode_cert(path)
        finally:
            os.unlink(path)

        return cert, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _summarize_cert(cert: dict):
    if not cert:
        return {}
    subject = {}
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            subject[k] = v
    issuer = {}
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            issuer[k] = v

    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expires - datetime.now(timezone.utc)).days
        except Exception:
            pass

    san = []
    for typ, val in cert.get("subjectAltName", ()):
        san.append(f"{typ}:{val}")

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "expires_utc": expires.isoformat() if expires else None,
        "days_left": days_left,
        "subject_alt_name": san,
        "serial": cert.get("serialNumber"),
        "version": cert.get("version"),
    }


def check(domain: str) -> dict:
    mx_records = _resolve_mx(domain)
    if not mx_records:
        return {"valid": False, "domain": domain, "error": "No MX records"}

    hosts = []
    for priority, host in mx_records:
        entry = {"priority": priority, "host": host, "ips": [], "certs": []}
        for ip in _resolve_a(host):
            cert, err = _get_cert(host)
            if err:
                entry["ips"].append({"ip": ip, "error": err})
            else:
                summary = _summarize_cert(cert)
                san = summary.get("subject_alt_name", [])
                match = any(
                    s.lower() == f"dns:{host.lower()}" for s in san
                ) or summary.get("subject", {}).get("commonName", "").lower() == host.lower()
                summary["hostname_match"] = match
                entry["ips"].append({"ip": ip, "cert": summary})
        hosts.append(entry)

    return {"valid": True, "domain": domain, "hosts": hosts}
