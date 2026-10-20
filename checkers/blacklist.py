import dns.exception
import dns.resolver

BLACKLISTS = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("spam.dnsbl.sorbs.net", "SORBS Spam"),
    ("psbl.surriel.com", "PSBL"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT L1"),
    ("all.s5h.net", "s5h.net"),
    ("bl.mailspike.net", "Mailspike"),
    ("dnsbl.justspam.org", "JustSpam"),
    ("spamsources.fabel.dk", "SpamSources"),
    ("bl.blocklist.de", "blocklist.de"),
]


def _resolve_a(domain: str):
    try:
        return str(dns.resolver.resolve(domain, "A", lifetime=6.0)[0])
    except Exception as e:
        return f"__error__:{e}"


def check(domain: str) -> dict:
    ip = _resolve_a(domain)
    if ip.startswith("__error__:"):
        return {"valid": False, "domain": domain, "error": ip[10:]}

    reversed_ip = ".".join(reversed(ip.split(".")))
    results = []
    listed_count = 0

    for zone, label in BLACKLISTS:
        query = f"{reversed_ip}.{zone}"
        listed = False
        status = "not listed"
        try:
            dns.resolver.resolve(query, "A", lifetime=5.0)
            listed = True
            status = "LISTED"
            listed_count += 1
        except dns.resolver.NXDOMAIN:
            status = "not listed"
        except dns.resolver.NoAnswer:
            status = "not listed"
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            status = "timeout"
            listed = None
        except Exception as e:
            status = f"error: {e}"
            listed = None
        results.append(
            {"zone": zone, "label": label, "query": query, "listed": listed, "status": status}
        )

    return {
        "valid": True,
        "domain": domain,
        "ip": ip,
        "reversed_ip": reversed_ip,
        "listed_count": listed_count,
        "results": results,
    }
