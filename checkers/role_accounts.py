import smtplib
import socket
import ssl

import dns.exception
import dns.resolver

TIMEOUT = 6
ROLE_ADDRESSES = ["postmaster", "abuse", "hostmaster", "webmaster"]


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


def _probe_rcpt(host: str, address: str):
    try:
        smtp = smtplib.SMTP(host, 25, timeout=TIMEOUT)
        smtp.ehlo("mx.local")
        code, msg = smtp.rcpt(address)
        smtp.quit()
        return {"code": code, "message": msg.decode("utf-8", "replace")[:200]}
    except Exception as e:
        return {"code": None, "error": f"{type(e).__name__}: {e}"}


def check(domain: str) -> dict:
    mx_records = _resolve_mx(domain)
    if not mx_records:
        return {"valid": False, "domain": domain, "error": "No MX records"}

    host = mx_records[0][1]
    results = []
    for role in ROLE_ADDRESSES:
        address = f"{role}@{domain}"
        r = _probe_rcpt(host, address)
        exists = r.get("code") in (250, 251)
        results.append({"role": role, "address": address, **r, "exists": exists})

    return {
        "valid": True,
        "domain": domain,
        "mx_host": host,
        "results": results,
        "missing_required": [
            r["role"]
            for r in results
            if r["role"] in ("postmaster", "abuse") and not r["exists"]
        ],
    }
