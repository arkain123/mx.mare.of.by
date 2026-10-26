import re

import dns.exception
import dns.resolver
import requests

TIMEOUT = 8


def _txt(name: str):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=6.0)
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
    except Exception:
        return []


def _fetch_policy(domain: str):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return url, r.status_code, r.text
    except Exception as e:
        return url, None, f"{type(e).__name__}: {e}"


def _parse_policy(text: str):
    if not text or not isinstance(text, str):
        return {}
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "mx":
            fields.setdefault("mx", []).append(v)
        else:
            fields[k] = v
    return fields


def check(domain: str) -> dict:
    txts = _txt(f"_mta-sts.{domain}")
    sts_record = None
    for t in txts:
        if t.lower().startswith("v=stsv1"):
            sts_record = t
            break

    if not sts_record:
        return {
            "valid": False,
            "domain": domain,
            "error": "No _mta-sts TXT record (v=STSv1)",
            "dns_txt": txts,
        }

    url, status, body = _fetch_policy(domain)
    if status != 200:
        return {
            "valid": False,
            "domain": domain,
            "error": f"Policy fetch failed: {body}",
            "sts_record": sts_record,
            "policy_url": url,
            "policy_status": status,
        }

    policy = _parse_policy(body)
    return {
        "valid": True,
        "domain": domain,
        "sts_record": sts_record,
        "policy_url": url,
        "policy_status": status,
        "policy": policy,
        "raw_policy": body,
        "warnings": (
            ["MTA-STS mode is not 'enforce'"]
            if policy.get("mode") != "enforce"
            else []
        ),
    }
