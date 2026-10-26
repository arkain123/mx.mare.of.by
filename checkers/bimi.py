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


def _parse_bimi(txt: str):
    tags = {}
    for part in txt.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _head(url: str):
    try:
        r = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.headers.get("content-type")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def check(domain: str) -> dict:
    name = f"default._bimi.{domain}"
    txts = _txt(name)
    record = None
    tags = {}
    for t in txts:
        if "v=bimi1" in t.lower():
            record = t
            tags = _parse_bimi(t)
            break

    if not record:
        return {
            "valid": False,
            "domain": domain,
            "error": "No default._bimi TXT record (v=BIMI1)",
            "dns_txt": txts,
        }

    logo_url = tags.get("l")
    logo_check = None
    if logo_url:
        status, ctype = _head(logo_url)
        logo_check = {
            "url": logo_url,
            "status": status,
            "content_type": ctype,
            "ok": status == 200 and ctype and "svg" in ctype.lower(),
        }

    return {
        "valid": True,
        "domain": domain,
        "record": record,
        "tags": tags,
        "logo": logo_check,
        "warnings": (
            []
            if logo_check and logo_check.get("ok")
            else ["BIMI logo is missing or not an SVG"]
        ),
    }
