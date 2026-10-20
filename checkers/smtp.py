import smtplib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver

TIMEOUT = 6
SMTP_PORTS = [(25, "plain"), (587, "starttls"), (2525, "plain"), (465, "ssl")]
PORT_ORDER = {p: i for i, (p, _) in enumerate(SMTP_PORTS)}


def _resolve_mx_chain(domain):
    mx_pairs = []
    source = "mx"
    try:
        for r in dns.resolver.resolve(domain, "MX", lifetime=8.0):
            mx_pairs.append((int(r.preference), str(r.exchange).rstrip(".")))
        mx_pairs.sort(key=lambda x: x[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        pass
    except Exception:
        pass

    if not mx_pairs:
        source = "a-record-fallback"
        mx_pairs = [(0, domain)]

    chain = []
    for prio, host in mx_pairs:
        v4, v6 = [], []
        try:
            for r in dns.resolver.resolve(host, "A", lifetime=5.0):
                v4.append(str(r))
        except Exception:
            pass
        try:
            for r in dns.resolver.resolve(host, "AAAA", lifetime=5.0):
                v6.append(str(r))
        except Exception:
            pass
        chain.append({"priority": prio, "host": host, "ipv4": v4, "ipv6": v6})
    return {"source": source, "chain": chain}


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None:
        return ""
    return str(value)


def _probe(ip, ehlo_name, port, tls_mode):
    out = {
        "ip": ip, "port": port, "tls": tls_mode,
        "status": "unknown", "connected": False,
    }
    smtp = None
    try:
        if tls_mode == "ssl":
            smtp = smtplib.SMTP_SSL(ip, port, timeout=TIMEOUT, context=_ssl_ctx())
        else:
            smtp = smtplib.SMTP(ip, port, timeout=TIMEOUT)
    except (socket.timeout, TimeoutError):
        out["status"] = "connect_error"
        out["error"] = "connect timeout"
        return out
    except ConnectionRefusedError:
        out["status"] = "connect_error"
        out["error"] = "connection refused"
        return out
    except OSError as e:
        out["status"] = "connect_error"
        out["error"] = "{}: {}".format(type(e).__name__, e)
        return out
    except Exception as e:
        out["status"] = "connect_error"
        out["error"] = "{}: {}".format(type(e).__name__, e)
        return out

    try:
        out["connected"] = True
        try:
            out["banner"] = _decode(smtp.getwelcome())[:200]
        except Exception as e:
            out["banner_error"] = "{}: {}".format(type(e).__name__, e)

        try:
            smtp.ehlo(ehlo_name)
        except smtplib.SMTPException:
            try:
                smtp.helo(ehlo_name)
            except smtplib.SMTPException as e:
                out["status"] = "smtp_error"
                out["error"] = "helo failed: {}".format(e)
                return out

        features = smtp.esmtp_features or {}
        out["supports_starttls"] = "starttls" in features
        out["supports_auth"] = "auth" in features
        out["supports_size"] = "size" in features
        out["features"] = sorted(features.keys())

        if tls_mode == "starttls":
            if "starttls" in features:
                try:
                    smtp.starttls(context=_ssl_ctx())
                    smtp.ehlo(ehlo_name)
                    out["tls_used"] = True
                    out["features"] = sorted(smtp.esmtp_features.keys())
                except Exception as e:
                    out["tls_error"] = "{}: {}".format(type(e).__name__, e)
                    out["status"] = "tls_error"
                    return out
            else:
                out["tls_note"] = "starttls not advertised"

        out["status"] = "ok"
    except smtplib.SMTPServerDisconnected:
        out["status"] = "disconnected"
    except Exception as e:
        out["status"] = "error"
        out["error"] = "{}: {}".format(type(e).__name__, e)
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass
    return out


def _probe_all_ports(ip, ehlo_name):
    results = []
    with ThreadPoolExecutor(max_workers=len(SMTP_PORTS)) as ex:
        futures = {
            ex.submit(_probe, ip, ehlo_name, port, tls): (port, tls)
            for port, tls in SMTP_PORTS
        }
        for fut in as_completed(futures):
            port, tls = futures[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"ip": ip, "port": port, "tls": tls,
                     "status": "error", "connected": False,
                     "error": "{}: {}".format(type(e).__name__, e)}
            results.append(r)
    results.sort(key=lambda x: PORT_ORDER.get(x["port"], 99))
    return results


def check(domain):
    try:
        mx_info = _resolve_mx_chain(domain)
    except Exception as e:
        return {"valid": False, "domain": domain,
                "error": "{}: {}".format(type(e).__name__, e)}

    chain = mx_info["chain"]
    if not chain:
        return {"valid": False, "domain": domain, "error": "no MX / A records"}

    hosts = []
    any_ok = False

    for entry in chain:
        host_entry = {
            "priority": entry["priority"],
            "host": entry["host"],
            "ipv4": entry["ipv4"],
            "ipv6": entry["ipv6"],
            "attempts": [],
        }
        for ip in entry["ipv4"] + entry["ipv6"]:
            results = _probe_all_ports(ip, entry["host"])
            host_entry["attempts"].extend(results)
            if any(r["status"] == "ok" for r in results):
                any_ok = True
        hosts.append(host_entry)

    return {
        "valid": any_ok,
        "domain": domain,
        "mx_source": mx_info["source"],
        "hosts": hosts,
    }
