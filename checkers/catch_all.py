import secrets
import smtplib
import string

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


def _random_local():
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(12))


def _probe(host: str, address: str):
    try:
        smtp = smtplib.SMTP(host, 25, timeout=TIMEOUT)
        smtp.ehlo("mx.local")
        code, msg = smtp.rcpt(address)
        smtp.quit()
        return code, msg.decode("utf-8", "replace")[:200]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def check(domain: str) -> dict:
    mx_records = _resolve_mx(domain)
    if not mx_records:
        return {"valid": False, "domain": domain, "error": "No MX records"}

    host = mx_records[0][1]
    fake = f"{_random_local()}@{domain}"
    code, msg = _probe(host, fake)

    catch_all = code in (250, 251)

    return {
        "valid": True,
        "domain": domain,
        "mx_host": host,
        "probe_address": fake,
        "rcpt_code": code,
        "rcpt_message": msg,
        "catch_all": catch_all,
        "warnings": (
            ["Server accepts RCPT for random address — catch-all is enabled"]
            if catch_all
            else []
        ),
    }
