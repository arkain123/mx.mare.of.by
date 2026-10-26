import dns.exception
import dns.resolver
import dns.reversename


def _resolve_mx(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return []
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


def _ptr_for_ip(ip: str):
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=5.0)
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


def check(domain: str) -> dict:
    mx_records = _resolve_mx(domain)
    if not mx_records:
        return {"valid": False, "domain": domain, "error": "No MX records"}

    results = []
    mismatches = 0
    for priority, host in mx_records:
        ips = _resolve_a(host)
        entry = {"priority": priority, "host": host, "ipv4": ips, "ptr": {}}
        for ip in ips:
            ptrs = _ptr_for_ip(ip)
            entry["ptr"][ip] = ptrs
            if not ptrs:
                mismatches += 1
            else:
                if not any(p == host for p in ptrs):
                    mismatches += 1
        results.append(entry)

    return {
        "valid": True,
        "domain": domain,
        "records": results,
        "mismatch_count": mismatches,
        "warnings": (
            [f"PTR не совпадает с hostname MX для {mismatches} IP"]
            if mismatches
            else []
        ),
    }
