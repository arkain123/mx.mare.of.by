import dns.exception
import dns.resolver


def _txt(name: str):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=6.0)
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
    except Exception:
        return []


def check(domain: str) -> dict:
    name = f"_smtp._tls.{domain}"
    txts = _txt(name)
    record = None
    for t in txts:
        if t.lower().startswith("v=tlsrptv1"):
            record = t
            break

    if not record:
        return {
            "valid": False,
            "domain": domain,
            "error": "No _smtp._tls TXT record (v=TLSRPTv1)",
            "dns_txt": txts,
        }

    rua = []
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("rua="):
            rua = [x.strip() for x in part[4:].split(",") if x.strip()]
            break

    return {
        "valid": True,
        "domain": domain,
        "record": record,
        "rua": rua,
        "warnings": [] if rua else ["TLS-RPT record has no rua= destinations"],
    }
