from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver

DEFAULT_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2",
    "k1", "k2", "dkim", "mail", "smtp", "mandrill", "amazonses",
    "everlytickey1", "cm", "protonmail",
]


def _query(name: str):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=3.0)
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return None
    except Exception:
        return None


def _parse(txt: str):
    cleaned = txt.replace(" ", "")
    if not cleaned.lower().startswith("v=dkim1"):
        return None
    tags = {}
    for part in cleaned.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags or None


def _check_one(domain: str, selector: str) -> dict:
    name = f"{selector}._domainkey.{domain}"
    records = _query(name)
    if not records:
        return {"selector": selector, "name": name, "found": False}
    for raw in records:
        parsed = _parse(raw)
        if parsed:
            pubkey = parsed.get("p", "")
            return {
                "selector": selector, "name": name, "found": True,
                "valid": bool(pubkey), "raw": raw, "tags": parsed,
                "key_bits_hint": (len(pubkey) * 6) if pubkey else 0,
            }
    return {
        "selector": selector, "name": name, "found": True, "valid": False,
        "records": records, "error": "TXT present but not v=DKIM1",
    }


def check(domain: str, selector: str = "") -> dict:
    if selector:
        result = _check_one(domain, selector)
        return {
            "domain": domain, "selector": selector,
            "valid": bool(result.get("valid")), "details": result,
        }

    found = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_check_one, domain, sel): sel for sel in DEFAULT_SELECTORS}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                if r.get("found") and r.get("valid"):
                    found.append(r)
            except Exception:
                pass

    if found:
        return {
            "domain": domain, "valid": True, "auto_discovered": True,
            "selectors": [f["selector"] for f in found],
            "details": found, "tried": DEFAULT_SELECTORS,
        }
    return {
        "domain": domain, "valid": False, "auto_discovered": False,
        "error": "No DKIM record for common selectors. Specify selector explicitly.",
        "tried": DEFAULT_SELECTORS,
    }
