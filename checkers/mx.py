import socket

import dns.exception
import dns.resolver


def _tcp_check(host: str, port: int = 25, timeout: float = 5.0) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"reachable": True, "port": port}
    except socket.timeout:
        return {"reachable": False, "port": port, "error": "timeout"}
    except Exception as e:
        return {"reachable": False, "port": port, "error": str(e)}


def check(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8.0)
    except dns.resolver.NXDOMAIN:
        return {"valid": False, "domain": domain, "error": "Domain does not exist"}
    except dns.resolver.NoAnswer:
        return {"valid": False, "domain": domain, "error": "No MX records"}
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return {"valid": False, "domain": domain, "error": "DNS timeout"}
    except Exception as e:
        return {"valid": False, "domain": domain, "error": str(e)}

    records = []
    for r in answers:
        host = str(r.exchange).rstrip(".")
        records.append({"priority": int(r.preference), "host": host})
    records.sort(key=lambda x: x["priority"])

    for rec in records:
        rec["port25"] = _tcp_check(rec["host"], 25)

    return {"valid": True, "domain": domain, "records": records}
